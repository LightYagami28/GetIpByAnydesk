from __future__ import annotations

import asyncio
import sys

if sys.platform.startswith("win"):
    from .windows.main import *
elif sys.platform.startswith("linux"):
    from .linux.main import *
else:  # pragma: no cover - platform guard
    raise NotImplementedError(f"Unsupported platform: {sys.platform}")

if __name__ == "__main__":
    asyncio.run(main())
