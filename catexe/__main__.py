"""Permet de lancer l'application avec ``python -m catexe``."""

import sys

from .diagnostics import run as run_diagnostics


if __name__ == "__main__":
    try:
        if "--diagnostic" in sys.argv:
            raise SystemExit(run_diagnostics(as_json="--json" in sys.argv))
        from .app import main
        main()
    except KeyboardInterrupt:
        pass
