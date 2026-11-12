"""Print reviewed role SQL only; no connection, credentials, or apply option."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'services' / 'api'))

from app.database.roles import main  # noqa: E402


if __name__ == '__main__':
    raise SystemExit(main())
