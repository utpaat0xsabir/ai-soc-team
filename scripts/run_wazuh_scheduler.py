"""Explicit entry point; importing the API never starts this worker."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'services' / 'api'))

from app.integrations.wazuh.scheduler import main  # noqa: E402


if __name__ == '__main__':
    raise SystemExit(main())
