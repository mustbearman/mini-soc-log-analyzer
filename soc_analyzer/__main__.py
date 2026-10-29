"""Allows running the tool with:  python -m soc_analyzer <logfile>"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
