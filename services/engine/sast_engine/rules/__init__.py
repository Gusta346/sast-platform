"""Regras AST da plataforma SAST."""

from .base import BaseRule
from .command_injection import CommandInjectionRule
from .dangerous_functions import DangerousFunctionsRule
from .debug_enabled import DebugEnabledRule
from .hardcoded_secret import HardcodedSecretRule
from .path_traversal import PathTraversalRule
from .sql_injection import SqlInjectionRule
from .weak_crypto import WeakCryptoRule

ALL_RULES: tuple[type[BaseRule], ...] = (
    HardcodedSecretRule,
    DangerousFunctionsRule,
    SqlInjectionRule,
    CommandInjectionRule,
    WeakCryptoRule,
    DebugEnabledRule,
    PathTraversalRule,
)

__all__ = ["ALL_RULES", "BaseRule"]
