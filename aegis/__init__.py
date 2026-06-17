"""AEGIS Guard — input/output safety for AI agents."""
from .injection_guard import scan_text
from .output_qc import check_output

__version__ = "1.0.0"
__all__ = ["scan_text", "check_output", "__version__"]
