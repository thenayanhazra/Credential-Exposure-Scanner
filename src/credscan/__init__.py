"""credscan: credential exposure scanner."""
from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("credscan")
except PackageNotFoundError:  # running from a source tree without install
    __version__ = "0.0.0+local"

USER_AGENT = f"credscan/{__version__}"
