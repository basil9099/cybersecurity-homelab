"""
protocols
=========
Honeypot protocol handler registry.

Importing this package auto-discovers all built-in handlers so
they register themselves via the ``@register`` decorator.
"""

from protocols.base import (
    ProtocolHandler,
    register,
    get_handler,
    available_protocols,
)

# Auto-import built-in handlers to trigger registration.
from protocols import ssh, http, ftp, telnet

__all__ = [
    "ProtocolHandler",
    "register",
    "get_handler",
    "available_protocols",
]
