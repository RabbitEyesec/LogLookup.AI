"""API identity: who is calling, resolved on the server.

Three ways to be someone, evaluated in order:

1. ``Authorization: Bearer <token>`` - a hashed token in ``api_tokens``
   carrying a role (created with ``loglookup token create``).
2. A reverse proxy listed in ``access.trusted_proxy_ips`` asserting the
   authenticated user/role in headers. Headers from any other peer are
   ignored - an arbitrary client cannot claim an identity.
3. A direct loopback connection with no proxy headers: the local owner
   (administrator). Mutating requests additionally need a custom header and
   a same-origin ``Origin`` so a web page in the browser cannot drive it.
"""

from __future__ import annotations

import hashlib
import ipaddress
import secrets
from dataclasses import dataclass

from fastapi import HTTPException, Request

from engine.response.models import ROLE_RANK, ROLES

LOCAL_USER = "local-admin"
CSRF_HEADER = "x-loglookup-client"
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
TOKEN_PREFIX = "llk_"


@dataclass(frozen=True)
class Principal:
    username: str
    role: str
    scope_id: str
    via: str  # token | proxy | local

    def at_least(self, role: str) -> bool:
        return ROLE_RANK[self.role] >= ROLE_RANK[role]


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def _is_loopback(host: str | None) -> bool:
    if not host:
        return False
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def _in_networks(host: str | None, entries: tuple[str, ...]) -> bool:
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    for entry in entries:
        try:
            if ip in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


def _host_of(request: Request) -> str:
    raw = request.headers.get("host", "")
    if raw.startswith("["):  # [::1]:8080
        return raw[1:].split("]", 1)[0].lower()
    return raw.rsplit(":", 1)[0].lower() if raw.count(":") == 1 else raw.lower()


def _local_hosts(config) -> set[str]:
    from urllib.parse import urlsplit

    configured = urlsplit(config.output.dashboard_base_url).hostname or ""
    return {"localhost", "127.0.0.1", "::1", configured.lower()} - {""}


async def authenticate(request: Request) -> Principal:
    state = request.app.state
    rt = state.v2
    config = state.config
    peer = request.client.host if request.client else None

    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        row = await rt.db.fetchone(
            "SELECT username, role, scope_id FROM api_tokens "
            "WHERE token_hash=? AND revoked=0", (hash_token(auth[7:].strip()),))
        if row is None or row["scope_id"] != rt.scope_id:
            raise HTTPException(401, "invalid or revoked API token")
        return Principal(row["username"], row["role"], row["scope_id"], "token")

    access = config.access
    if _in_networks(peer, access.trusted_proxy_ips):
        user = request.headers.get(access.proxy_user_header, "").strip()
        role = request.headers.get(access.proxy_role_header, "viewer").strip().lower()
        if not user:
            raise HTTPException(401, "proxy did not supply an authenticated user")
        if role not in ROLES:
            role = "viewer"
        return Principal(user[:128], role, rt.scope_id, "proxy")

    forwarded = any(h in request.headers for h in
                    ("x-forwarded-for", "forwarded", "x-real-ip"))
    if _is_loopback(peer) and not forwarded:
        # DNS rebinding: a hostile page can make its own hostname resolve to
        # 127.0.0.1 and look same-origin. Ambient local authority therefore
        # requires a Host header we recognise as ours.
        if _host_of(request) not in _local_hosts(config):
            raise HTTPException(
                403, "unrecognised Host header for local access; use "
                     "localhost or the configured dashboard host")
        if request.method not in SAFE_METHODS:
            if CSRF_HEADER not in request.headers:
                raise HTTPException(
                    403, f"mutating requests need the {CSRF_HEADER} header")
            origin = request.headers.get("origin")
            if origin and origin.split("://", 1)[-1] != request.headers.get("host"):
                raise HTTPException(403, "cross-origin request refused")
        return Principal(LOCAL_USER, "administrator", rt.scope_id, "local")

    raise HTTPException(401, "authentication required (use an API token)")


def require(principal: Principal, role: str) -> None:
    if not principal.at_least(role):
        raise HTTPException(403, f"requires role {role}")
