from .admin_portal import AdminPortal
from .base import Context, Module
from .clickjacking import Clickjacking
from .cookie_flags import CookieFlags
from .jwt import JsonWebToken
from .open_redirect import OpenRedirect
from .path_traversal import PathTraversal
from .reflected_xss import ReflectedXSS
from .secrets import Secrets
from .sensitive_exposure import SensitiveExposure
from .sqli_blind import SqlInjectionBlind
from .sqli_error import SqlInjectionError
from .ssrf import SSRF
from .subdomain_takeover import SubdomainTakeover
from .transport_security import TransportSecurity
from .verbose_error import VerboseError
from .xxe import XXE

ALL_MODULES: tuple[type[Module], ...] = (
    SensitiveExposure,
    Secrets,
    SqlInjectionError,
    SqlInjectionBlind,
    PathTraversal,
    XXE,
    SSRF,
    AdminPortal,
    ReflectedXSS,
    OpenRedirect,
    SubdomainTakeover,
    TransportSecurity,
    CookieFlags,
    Clickjacking,
    JsonWebToken,
    VerboseError,
)

__all__ = ["Context", "Module", "ALL_MODULES"]
