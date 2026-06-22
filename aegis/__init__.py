"""AEGIS Guard — input/output safety for AI agents."""
from .injection_guard import scan_text, fence_untrusted, wrap_code_for_review
from .output_qc import check_output

__version__ = "1.1.2"
__all__ = ["scan_text", "fence_untrusted", "wrap_code_for_review", "check_output", "__version__"]
