"""Optional foreground worker. No API startup hook, queue, or secret storage."""

import argparse
import logging
import os
import signal
from threading import Event
from time import monotonic
from uuid import UUID

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.engine import make_url

from app.auth import get_current_principal
from app.config import settings
from app.db import SessionLocal
from app.wazuh_status import safe_sync_error
from app.wazuh_sync import WazuhSyncError, WazuhSyncStopped, sync_wazuh


logger = logging.getLogger(__name__)


class ScheduledJob(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    integration_id: UUID
    tenant_id: UUID
    api_key_env: str = Field(pattern=r'^AI_SOC_WORKER_[A-Z0-9_]+_API_KEY$', max_length=200)
    interval_seconds: int = Field(default=60, ge=5, le=86400, strict=True)
    page_size: int = Field(default=50, ge=1, le=100, strict=True)


def load_jobs():
    try:
        jobs = tuple(ScheduledJob(integration_id=UUID(identity), **value)
                     for identity, value in settings.wazuh_scheduler_jobs.items())
        if not 1 <= len(jobs) <= 100 or len({job.integration_id for job in jobs}) != len(jobs):
            raise ValueError()
        return jobs
    except (ValueError, TypeError, AttributeError):
        raise ValueError('invalid_wazuh_scheduler_jobs') from None


def run_scheduled_job(job, stop_event, *, session_factory=SessionLocal):
    if stop_event.is_set():
        raise WazuhSyncStopped()
    with session_factory() as db:
        try:
            principal = get_current_principal(x_api_key=os.environ.get(job.api_key_env), db=db)
        except HTTPException:
            raise WazuhSyncError('worker_authentication_failed', 401) from None
        if principal.tenant_id != job.tenant_id:
            raise WazuhSyncError('worker_tenant_mismatch', 403)
        return sync_wazuh(db, principal, job.integration_id,
                          page_size=job.page_size, stop_event=stop_event)


class WazuhScheduler:
    """Serial, completion-based polling with O(configured jobs) state."""

    def __init__(self, jobs, *, runner=None, clock=monotonic, stop_event=None):
        self.jobs = tuple(jobs)
        if (not 1 <= len(self.jobs) <= 100
                or not all(isinstance(job, ScheduledJob) for job in self.jobs)
                or len({job.integration_id for job in self.jobs}) != len(self.jobs)):
            raise ValueError('invalid_wazuh_scheduler_jobs')
        self.runner = runner if runner is not None else run_scheduled_job
        self.clock = clock
        self.stop_event = stop_event if stop_event is not None else Event()
        start = clock()
        self.next_due = {job.integration_id: start for job in self.jobs}
        self.failures = {job.integration_id: 0 for job in self.jobs}

    def run_due(self):
        ran = 0
        for job in self.jobs:
            if self.stop_event.is_set():
                break
            if self.clock() < self.next_due[job.integration_id]:
                continue
            ran += 1
            try:
                result = self.runner(job, self.stop_event)
                if not isinstance(result, dict) or result.get('status') not in ('completed', 'not_due'):
                    raise ValueError('invalid_worker_result')
                self.failures[job.integration_id] = 0
                delay = job.interval_seconds
            except WazuhSyncStopped:
                self.stop_event.set()
                break
            except Exception as exc:
                if isinstance(exc, WazuhSyncError) and str(exc) == 'wazuh_sync_busy':
                    self.failures[job.integration_id] = 0
                    delay = job.interval_seconds
                else:
                    failures = min(self.failures[job.integration_id] + 1, 11)
                    self.failures[job.integration_id] = failures
                    delay = min(job.interval_seconds * (2 ** (failures - 1)),
                                max(job.interval_seconds, 3600))
                    code = safe_sync_error(str(exc)) if isinstance(exc, WazuhSyncError) else 'processing_failed'
                    # No repr, traceback, credential value, or upstream message.
                    logger.warning('wazuh_worker_job_failed integration=%s code=%s', job.integration_id, code)
            self.next_due[job.integration_id] = self.clock() + delay
        return ran

    def run(self):
        while not self.stop_event.is_set():
            self.run_due()
            if self.stop_event.is_set():
                break
            delay = max(0.0, min(self.next_due.values()) - self.clock())
            self.stop_event.wait(min(delay, 60.0))


def main(argv=None):
    parser = argparse.ArgumentParser(description='Optional tenant-scoped Wazuh polling worker')
    parser.add_argument('--once', action='store_true', help='Run each due job at most once, then exit')
    parser.add_argument('--allow-production', action='store_true',
                        help='Explicit production activation; requires separate operator approval')
    args = parser.parse_args(argv)
    if not settings.wazuh_scheduler_enabled:
        print('wazuh_scheduler_disabled')
        return 2
    try:
        production = (settings.app_env.lower() in ('production', 'prod')
                      or make_url(settings.database_url).database == 'ai_soc')
        if production and not args.allow_production:
            print('production_scheduling_requires_separate_approval')
            return 2
        jobs = load_jobs()
    except (ValueError, TypeError):
        print('invalid_wazuh_scheduler_configuration')
        return 2
    stop = Event()
    previous = {}
    def shutdown(signum, frame):
        stop.set()
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, shutdown)
        scheduler = WazuhScheduler(jobs, stop_event=stop)
        if args.once:
            scheduler.run_due()
            return 1 if any(scheduler.failures.values()) else 0
        scheduler.run()
        return 0
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
