"""Correlation engine for matching local logs against threat intelligence."""

from .correlator import Correlator
from .ioc_database import IOCDatabase

__all__ = ["Correlator", "IOCDatabase"]
