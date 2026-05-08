"""Report serializers for audit results (JSON + Markdown)."""

from .json_emit import build_report, emit_json
from .markdown import emit_markdown

__all__ = ["build_report", "emit_json", "emit_markdown"]
