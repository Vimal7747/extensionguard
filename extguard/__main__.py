# `python -m extguard <file>` runs the pre-install scanner (same as `extguard`).
import sys

from extguard.main import main

sys.exit(main())
