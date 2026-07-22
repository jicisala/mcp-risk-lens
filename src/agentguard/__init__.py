"""MCP Risk Lens public API."""

from .scanner import ScanError, scan_config, scan_file

__all__ = ["ScanError", "scan_config", "scan_file"]
__version__ = "0.1.0"

