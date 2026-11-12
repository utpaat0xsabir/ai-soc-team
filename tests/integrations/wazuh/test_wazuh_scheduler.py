from threading import Event
from uuid import uuid4

import pytest

from app.core.config import settings
from app.integrations.wazuh.scheduler import ScheduledJob, WazuhScheduler, load_jobs, main
from app.integrations.wazuh.sync import WazuhSyncError


def job(**changes):
    args = dict(integration_id=uuid4(), tenant_id=uuid4(),
                api_key_env='AI_SOC_WORKER_TEST_API_KEY', interval_seconds=10, page_size=50)
    args.update(changes)
    return ScheduledJob(**args)


class Clock:
    def __init__(self): self.value = 100.0
    def __call__(self): return self.value
    def advance(self, seconds): self.value += seconds


def test_completion_based_interval_has_no_catch_up_burst():
    clock = Clock(); calls = []
    def runner(current, stop):
        calls.append(clock()); clock.advance(3)
        return {'status': 'completed'}
    scheduler = WazuhScheduler((job(),), runner=runner, clock=clock)
    assert scheduler.run_due() == 1
    clock.advance(9); assert scheduler.run_due() == 0
    clock.advance(1); assert scheduler.run_due() == 1
    clock.advance(1000); assert scheduler.run_due() == 1
    assert scheduler.run_due() == 0 and len(calls) == 3


def test_failures_back_off_and_success_resets_delay(caplog):
    clock = Clock(); fails = [True]
    def runner(current, stop):
        if fails[0]: raise RuntimeError('secret-token-must-not-leak')
        return {'status': 'completed'}
    scheduler = WazuhScheduler((job(),), runner=runner, clock=clock)
    assert scheduler.run_due() == 1
    clock.advance(10); assert scheduler.run_due() == 1
    clock.advance(19); assert scheduler.run_due() == 0
    clock.advance(1); fails[0] = False; assert scheduler.run_due() == 1
    clock.advance(10); assert scheduler.run_due() == 1
    assert 'secret-token-must-not-leak' not in caplog.text


def test_busy_worker_is_deferred_without_extra_retries():
    clock = Clock(); calls = []
    def busy(current, stop):
        calls.append(1); raise WazuhSyncError('wazuh_sync_busy')
    scheduler = WazuhScheduler((job(),), runner=busy, clock=clock)
    scheduler.run_due(); clock.advance(10); scheduler.run_due()
    clock.advance(10); scheduler.run_due()
    assert len(calls) == 3


def test_one_job_failure_does_not_block_other_due_jobs():
    first, second = job(), job(); calls = []
    def runner(current, stop):
        calls.append(current.integration_id)
        if current.integration_id == first.integration_id: raise RuntimeError('failure')
        return {'status': 'completed'}
    scheduler = WazuhScheduler((first, second), runner=runner)
    assert scheduler.run_due() == 2
    assert set(calls) == {first.integration_id, second.integration_id}


def test_shutdown_stops_before_next_job():
    stop = Event(); calls = []
    def runner(current, event):
        calls.append(1); event.set(); return {'status': 'completed'}
    scheduler = WazuhScheduler((job(), job()), runner=runner, stop_event=stop)
    assert scheduler.run_due() == 1 and calls == [1]
    assert scheduler.run_due() == 0


def test_shutdown_wait_is_interruptible_without_real_sleep():
    clock = Clock(); calls = []
    class Stop:
        stopped = False
        waits = []
        def is_set(self): return self.stopped
        def set(self): self.stopped = True
        def wait(self, seconds): self.waits.append(seconds); self.set(); return True
    stop = Stop()
    scheduler = WazuhScheduler((job(),), runner=lambda *args: calls.append(1) or {'status': 'completed'},
                               clock=clock, stop_event=stop)
    scheduler.run()
    assert calls == [1] and stop.waits == [10]


def test_worker_state_stays_bounded():
    clock = Clock(); jobs = tuple(job() for _ in range(100))
    scheduler = WazuhScheduler(jobs, runner=lambda *args: {'status': 'completed'}, clock=clock)
    for _ in range(50):
        scheduler.run_due(); clock.advance(100)
    assert len(scheduler.next_due) == len(scheduler.failures) == 100
    with pytest.raises(ValueError): WazuhScheduler(jobs + (job(),))
    with pytest.raises(ValueError): WazuhScheduler((jobs[0], jobs[0]))


@pytest.mark.parametrize('changes', [
    {'interval_seconds': 0}, {'interval_seconds': True}, {'interval_seconds': 1.5},
    {'interval_seconds': 86401}, {'page_size': 101}, {'page_size': True},
    {'api_key_env': 'AWS_SECRET_ACCESS_KEY'}, {'api_key_env': 'raw-api-key'},
    {'tenant_id': 'bad'}, {'password': 'not-allowed'},
])
def test_invalid_job_configuration(changes):
    with pytest.raises(ValueError): job(**changes)


def test_load_jobs_rejects_duplicate_normalized_ids(monkeypatch):
    identity = uuid4()
    value = dict(tenant_id=str(uuid4()), api_key_env='AI_SOC_WORKER_TEST_API_KEY')
    monkeypatch.setattr(settings, 'wazuh_scheduler_jobs', {str(identity): value, identity.hex: value})
    with pytest.raises(ValueError): load_jobs()


def test_disabled_worker_never_starts_runner(monkeypatch, capsys):
    monkeypatch.setattr(settings, 'wazuh_scheduler_enabled', False)
    monkeypatch.setattr('app.integrations.wazuh.scheduler.run_scheduled_job', lambda *args: pytest.fail('disabled worker ran'))
    assert main(['--once']) == 2
    assert 'disabled' in capsys.readouterr().out


def test_production_requires_explicit_activation_flag(monkeypatch, capsys):
    monkeypatch.setattr(settings, 'wazuh_scheduler_enabled', True)
    monkeypatch.setattr(settings, 'app_env', 'production')
    monkeypatch.setattr('app.integrations.wazuh.scheduler.run_scheduled_job', lambda *args: pytest.fail('production worker ran'))
    assert main(['--once']) == 2
    assert 'production' in capsys.readouterr().out


def configure_cli(monkeypatch):
    current = job()
    monkeypatch.setattr(settings, 'wazuh_scheduler_enabled', True)
    monkeypatch.setattr(settings, 'app_env', 'test')
    monkeypatch.setattr(settings, 'database_url', 'postgresql+psycopg://test@localhost/ai_soc_test')
    monkeypatch.setattr(settings, 'wazuh_scheduler_jobs', {
        str(current.integration_id): current.model_dump(mode='json', exclude={'integration_id'})})
    return current


def test_once_cli_runs_only_configured_job_without_database(monkeypatch):
    current = configure_cli(monkeypatch); calls = []
    def runner(selected, stop):
        calls.append(selected.integration_id); return {'status': 'completed'}
    monkeypatch.setattr('app.integrations.wazuh.scheduler.run_scheduled_job', runner)
    assert main(['--once']) == 0 and calls == [current.integration_id]


def test_cli_rejects_raw_key_configuration_without_printing_it(monkeypatch, capsys):
    current = configure_cli(monkeypatch)
    settings.wazuh_scheduler_jobs[str(current.integration_id)]['password'] = 'configuration-secret'
    assert main(['--once']) == 2
    assert 'configuration-secret' not in capsys.readouterr().out


def test_sigterm_sets_stop_and_previous_handlers_are_restored(monkeypatch):
    import signal
    configure_cli(monkeypatch); handlers = {}; calls = []; previous = object()
    def register(signum, handler):
        calls.append((signum, handler)); handlers[signum] = handler; return previous
    monkeypatch.setattr('app.integrations.wazuh.scheduler.signal.signal', register)
    class Worker:
        def __init__(self, jobs, stop_event): self.stop = stop_event
        def run(self):
            handlers[signal.SIGTERM](signal.SIGTERM, None)
            assert self.stop.is_set()
    monkeypatch.setattr('app.integrations.wazuh.scheduler.WazuhScheduler', Worker)
    assert main([]) == 0
    assert calls[-2:] == [(signal.SIGINT, previous), (signal.SIGTERM, previous)]


def test_repeated_failures_have_capped_backoff_and_bounded_counters():
    clock = Clock(); current = job()
    def fail(*args): raise RuntimeError('failure')
    scheduler = WazuhScheduler((current,), runner=fail, clock=clock)
    for _ in range(30):
        assert scheduler.run_due() == 1
        delay = scheduler.next_due[current.integration_id] - clock()
        assert 0 < delay <= 3600
        clock.advance(delay)
    assert scheduler.failures[current.integration_id] <= 11
