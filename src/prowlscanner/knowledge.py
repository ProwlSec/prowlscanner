from __future__ import annotations

from . import vrt

_ENTRIES: dict[str, dict[str, str]] = {
    "server_side_injection/sql_injection": {
        "description": (
            "The application builds a SQL query using unsanitized user input. An attacker can inject SQL "
            "syntax through the affected parameter to alter the query the database executes, reading, modifying "
            "or destroying data and in many cases taking control of the database server."
        ),
        "impact": (
            "SQL injection can expose or corrupt the entire application database, including user credentials and "
            "personal data, leading to severe financial, legal and reputational damage for the business."
        ),
    },
    "server_side_injection/file_inclusion/local": {
        "description": (
            "A request parameter is used to build a filesystem path without validation. By supplying directory "
            "traversal sequences an attacker can read arbitrary files outside the web root, such as system and "
            "configuration files."
        ),
        "impact": (
            "Local file inclusion discloses sensitive server files (credentials, source code, configuration), "
            "often enabling further compromise and full system takeover."
        ),
    },
    "cross_site_scripting_xss/reflected/non_self": {
        "description": (
            "A request parameter is reflected into the HTML response without correct output encoding. An attacker "
            "can craft a URL that executes arbitrary JavaScript in the victim's browser in the context of the "
            "application's origin."
        ),
        "impact": (
            "Reflected XSS lets an attacker hijack sessions, perform actions as the victim and steal data, "
            "damaging user trust and the reputation of the business."
        ),
    },
    "unvalidated_redirects_and_forwards/open_redirect/get_based": {
        "description": (
            "The application redirects users to a URL taken from a request parameter without validating the "
            "destination. An attacker can craft a link on the trusted domain that sends victims to an "
            "attacker-controlled site."
        ),
        "impact": (
            "Open redirects are abused for convincing phishing and to bypass redirect-based security controls, "
            "harming users and the brand's reputation."
        ),
    },
    "sensitive_data_exposure/disclosure_of_secrets/for_publicly_accessible_asset": {
        "description": (
            "A secret (API key, token, credential or private key) is exposed in a publicly accessible asset "
            "delivered by the application. Anyone retrieving the asset obtains the secret."
        ),
        "impact": (
            "Exposed secrets allow attackers to authenticate to services as the application, incurring financial "
            "loss, data exposure and abuse of connected systems."
        ),
    },
    "server_security_misconfiguration/missing_secure_or_httponly_cookie_flag/session_token": {
        "description": (
            "A session cookie is set without the HttpOnly and/or Secure attribute, leaving the session token "
            "accessible to client-side script or transmittable over cleartext channels."
        ),
        "impact": (
            "Missing cookie protections make session hijacking easier, allowing account takeover and unauthorized "
            "actions on behalf of users."
        ),
    },
    "broken_authentication_and_session_management/weak_login_function/over_http": {
        "description": (
            "An authentication form is served and/or submitted over cleartext HTTP. Credentials transit the "
            "network unencrypted and can be captured by any party on the path."
        ),
        "impact": (
            "Cleartext authentication exposes user credentials to interception, directly enabling account "
            "takeover and loss of user trust."
        ),
    },
    "sensitive_data_exposure/sensitive_token_in_url/user_facing": {
        "description": (
            "A sensitive token is transmitted in the URL query string. URLs are stored in browser history, server "
            "logs, proxies and the Referer header, exposing the token to parties that should not receive it."
        ),
        "impact": (
            "Leaked tokens can be replayed to impersonate users or access protected resources, leading to "
            "unauthorized access."
        ),
    },
    "server_security_misconfiguration/server_side_request_forgery_ssrf/internal_data_exposure": {
        "description": (
            "A request parameter is used to build a server-side HTTP request without validation. An attacker can "
            "point it at internal addresses (cloud metadata, loopback, internal services) and have the server "
            "fetch and return their contents."
        ),
        "impact": (
            "SSRF exposes internal services and cloud credentials, frequently escalating to internal network "
            "access and full environment compromise."
        ),
    },
    "server_security_misconfiguration/misconfigured_dns/subdomain_takeover": {
        "description": (
            "A DNS record points at a third-party service resource that is no longer claimed. An attacker can "
            "register the dangling resource and serve content from the organisation's subdomain."
        ),
        "impact": (
            "Subdomain takeover enables convincing phishing, cookie theft and brand abuse from a trusted hostname."
        ),
    },
    "sensitive_data_exposure/visible_detailed_error_page/detailed_server_configuration": {
        "description": (
            "The application returns a detailed error page containing stack traces or server configuration when "
            "it encounters an unexpected condition."
        ),
        "impact": (
            "Detailed errors reveal internal paths, framework versions and logic that accelerate further attacks."
        ),
    },
    "server_security_misconfiguration/exposed_portal/admin_portal": {
        "description": (
            "An administrative interface is reachable from the public internet. Administrative portals expose "
            "privileged functionality and are high-value targets for credential and exploitation attacks."
        ),
        "impact": (
            "A publicly reachable admin portal exposes privileged functions to attackers, risking full "
            "application or infrastructure takeover."
        ),
    },
    "broken_authentication_and_session_management/authentication_bypass": {
        "description": (
            "The application's authentication can be bypassed. For JWT-based auth this occurs when the server "
            "accepts unsigned ('none') tokens or uses a weak, guessable signing secret, letting an attacker forge "
            "tokens for any user."
        ),
        "impact": (
            "Authentication bypass allows full account takeover and access to privileged functionality, with "
            "severe data-exposure, financial and reputational consequences."
        ),
    },
    "server_security_misconfiguration/clickjacking/sensitive_action": {
        "description": (
            "A page containing a sensitive action can be framed by any origin because framing protections "
            "(X-Frame-Options or CSP frame-ancestors) are absent. An attacker can overlay the page and trick "
            "users into performing the action."
        ),
        "impact": (
            "Clickjacking tricks users into unintended sensitive actions, causing unauthorized changes and "
            "reputational harm."
        ),
    },
}

_GENERIC_DESC = (
    "The application exhibits a condition matching this Vulnerability Rating Taxonomy entry, confirmed by the "
    "evidence recorded with the finding."
)
_GENERIC_IMPACT = (
    "Exploitation can compromise the confidentiality, integrity or availability of the application and its data, "
    "with associated reputational and financial impact."
)


def description(vrt_id: str) -> str:
    entry = _ENTRIES.get(vrt_id)
    if entry:
        return entry["description"]
    return _GENERIC_DESC


def business_impact(vrt_id: str) -> str:
    entry = _ENTRIES.get(vrt_id)
    if entry:
        return entry["impact"]
    return _GENERIC_IMPACT


def readable(vrt_id: str) -> str:
    return vrt.readable_chain(vrt_id)
