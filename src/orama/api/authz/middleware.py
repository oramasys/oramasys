"""ASGI middleware: route capability → bearer enforcement."""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from orama.api.authz.manifest import capability_for, requires_auth
from orama.api.authz.tokens import (
    auth_enforced,
    extract_bearer,
    get_control_plane_token,
    token_matches,
)


AUTHENTICATED_CONTROL_PLANE_PRINCIPAL = "local-operator"
_AUTHENTICATED_PRINCIPAL_STATE_KEY = "orama_authenticated_principal"


def authenticated_control_plane_principal(request: Request) -> str | None:
    """Return the capability principal established by this middleware, if any.

    The bearer itself is deliberately not exposed to application handlers.  A
    request only receives this principal after the configured control-plane
    capability has been verified.
    """
    principal = getattr(request.state, _AUTHENTICATED_PRINCIPAL_STATE_KEY, None)
    return principal if isinstance(principal, str) and principal else None


class AuthzMiddleware(BaseHTTPMiddleware):
    """Protect non-public routes with Authorization: Bearer.

    Optional AuthProviders never authorize mutate alone — Bearer remains the
    HTTP control-plane root. Cookie / S-Session acceptance is out of scope.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        # CORS preflight (if ever added) skips auth; no CORS middleware here.
        """Authorize the request's capability before the handler runs; refuse otherwise."""
        if request.method.upper() == "OPTIONS":
            return await call_next(request)

        capability = capability_for(request.method, request.url.path)
        if not requires_auth(capability):
            return await call_next(request)

        if not auth_enforced(request.scope):
            return await call_next(request)

        configured = get_control_plane_token()
        if configured is None:
            return JSONResponse(
                {"detail": "Control plane token not configured"},
                status_code=503,
            )

        presented = extract_bearer(request.headers.get("authorization"))
        if presented is None or not token_matches(presented, (configured,)):
            return JSONResponse(
                {"detail": "Unauthorized"},
                status_code=401,
            )

        setattr(
            request.state,
            _AUTHENTICATED_PRINCIPAL_STATE_KEY,
            AUTHENTICATED_CONTROL_PLANE_PRINCIPAL,
        )
        return await call_next(request)


def install_authz(app) -> None:
    """Attach S-AuthZ middleware to a FastAPI/Starlette app."""
    app.add_middleware(AuthzMiddleware)
