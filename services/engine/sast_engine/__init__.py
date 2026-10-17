"""Pacote principal do motor SAST."""

from .models import Finding, Severity
from .scanner import Scanner, scan_directory
from .taint import TaintAnalyzer, analyze_taint

__all__ = ["Finding", "Scanner", "Severity", "TaintAnalyzer", "analyze_taint", "scan_directory"]
