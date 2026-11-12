#!/usr/bin/env python3
"""Point d'entrée de CAT.EXE."""

import sys

from catexe.diagnostics import run as run_diagnostics


if __name__ == "__main__":
    try:
        if "--diagnostic" in sys.argv:
            raise SystemExit(run_diagnostics(as_json="--json" in sys.argv))
        from catexe.app import main
        main()
    except KeyboardInterrupt:
        pass
