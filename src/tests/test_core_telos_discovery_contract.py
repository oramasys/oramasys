from __future__ import annotations

import ast
import inspect
from textwrap import dedent

import pytest
from perpetua_core.discovery import probe

_FORBIDDEN_TRANSPORT_IMPORTS = frozenset(
    {"httpx", "requests", "aiohttp", "urllib.request", "socket"}
)
_FORBIDDEN_TRANSPORT_CALL_PREFIXES = (
    "httpx.",
    "requests.",
    "aiohttp.",
    "urllib.request.",
    "socket.",
)
_FORBIDDEN_HTTP_CLIENT_CALLS = frozenset(
    {"http.client.HTTPConnection", "http.client.HTTPSConnection"}
)
_REQUIRED_POLICY_FLAGS = {
    "allow_public": False,
    "allow_private": True,
    "allow_loopback": True,
    "require_https_for_public": True,
}


def _import_bindings(tree: ast.AST) -> dict[str, str]:
    """Resolve local import aliases to canonical dotted names."""
    bindings: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                canonical = alias.name if alias.asname else alias.name.split(".", 1)[0]
                bindings[local] = canonical
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name == "*":
                    continue
                bindings[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return bindings


def _qualified_name(node: ast.AST, bindings: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return bindings.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _qualified_name(node.value, bindings)
        if base is not None:
            return f"{base}.{node.attr}"
    return None


def _function(tree: ast.AST, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    matches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    ]
    assert len(matches) == 1, f"expected exactly one {name}() definition"
    return matches[0]


def _keyword_map(call: ast.Call) -> dict[str, ast.AST]:
    return {kw.arg: kw.value for kw in call.keywords if kw.arg is not None}


def _assert_bool_keyword(keywords: dict[str, ast.AST], name: str, expected: bool) -> None:
    value = keywords.get(name)
    assert isinstance(value, ast.Constant), f"{name} must be a literal bool"
    assert value.value is expected, f"{name} must be {expected}"


def _assert_no_forbidden_transport_imports(tree: ast.AST) -> None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not any(
                    alias.name == banned or alias.name.startswith(f"{banned}.")
                    for banned in _FORBIDDEN_TRANSPORT_IMPORTS
                ), f"raw transport import is forbidden: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            candidates = [node.module]
            candidates.extend(
                f"{node.module}.{alias.name}"
                for alias in node.names
                if alias.name != "*"
            )
            for candidate in candidates:
                assert not any(
                    candidate == banned or candidate.startswith(f"{banned}.")
                    for banned in _FORBIDDEN_TRANSPORT_IMPORTS
                ), f"raw transport import is forbidden: {candidate}"


def _assert_no_raw_transport_calls(tree: ast.AST, bindings: dict[str, str]) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = _qualified_name(node.func, bindings)
        if target is None:
            continue
        assert target not in _FORBIDDEN_HTTP_CLIENT_CALLS, (
            f"raw HTTP connection bypass is forbidden: {target}"
        )
        assert not target.startswith(_FORBIDDEN_TRANSPORT_CALL_PREFIXES), (
            f"raw transport call bypass is forbidden: {target}"
        )


def _assert_exact_candidate_authorizer(
    tree: ast.AST, bindings: dict[str, str]
) -> None:
    function = _function(tree, "_candidate_authorizer")

    endpoint_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and _qualified_name(node.func, bindings) == "telos.endpoint_from_url"
    ]
    assert len(endpoint_calls) == 1, "candidate must be normalized by telos.endpoint_from_url"
    assert len(endpoint_calls[0].args) == 1
    assert isinstance(endpoint_calls[0].args[0], ast.Name)
    assert endpoint_calls[0].args[0].id == "url"

    exact_rule_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and _qualified_name(node.func, bindings)
        == "telos.EndpointAuthorizer.from_exact_rules"
    ]
    assert len(exact_rule_calls) == 1, "authorizer must use Telos exact endpoint rules"
    exact_call = exact_rule_calls[0]
    assert exact_call.args and isinstance(exact_call.args[0], ast.Dict)
    rules = exact_call.args[0]
    assert len(rules.keys) == 1 and len(rules.values) == 1
    assert _qualified_name(rules.keys[0], bindings) == "telos.EndpointPurpose.HEALTH_PROBE"

    allowed = rules.values[0]
    assert isinstance(allowed, ast.Set) and len(allowed.elts) == 1
    member = allowed.elts[0]
    assert (
        isinstance(member, ast.Attribute)
        and isinstance(member.value, ast.Name)
        and member.value.id == "candidate"
        and member.attr == "key"
    ), "authorization must be scoped to candidate.key"


def _assert_transport_policy(tree: ast.AST, bindings: dict[str, str]) -> None:
    policy_calls: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(isinstance(target, ast.Name) and target.id == "_POLICY" for target in targets):
            continue
        value = node.value
        if isinstance(value, ast.Call):
            policy_calls.append(value)

    assert len(policy_calls) == 1, "expected exactly one module-level _POLICY constructor"
    policy_call = policy_calls[0]
    assert _qualified_name(policy_call.func, bindings) == "telos.TransportPolicy"
    keywords = _keyword_map(policy_call)
    for name, expected in _REQUIRED_POLICY_FLAGS.items():
        _assert_bool_keyword(keywords, name, expected)


def _assert_health_probe_calls_telos_request(
    tree: ast.AST, bindings: dict[str, str]
) -> None:
    function = _function(tree, "health_probe")
    thread_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and _qualified_name(node.func, bindings) == "asyncio.to_thread"
    ]
    secure_calls = [
        call
        for call in thread_calls
        if call.args and _qualified_name(call.args[0], bindings) == "telos.request"
    ]
    assert len(secure_calls) == 1, (
        "health_probe must dispatch exactly one outbound call through telos.request"
    )

    call = secure_calls[0]
    assert len(call.args) >= 3
    method = call.args[1]
    assert isinstance(method, ast.Constant) and method.value == "GET"
    assert isinstance(call.args[2], ast.Name) and call.args[2].id == "url"

    keywords = _keyword_map(call)
    authorizer = keywords.get("authorizer")
    assert isinstance(authorizer, ast.Call)
    assert _qualified_name(authorizer.func, bindings) == "_candidate_authorizer"
    assert len(authorizer.args) == 1
    assert isinstance(authorizer.args[0], ast.Name) and authorizer.args[0].id == "url"

    transport_policy = keywords.get("transport_policy")
    assert isinstance(transport_policy, ast.Name) and transport_policy.id == "_POLICY"

    purpose = keywords.get("purpose")
    assert purpose is not None
    assert _qualified_name(purpose, bindings) == "telos.EndpointPurpose.HEALTH_PROBE"

    actor_id = keywords.get("actor_id")
    workflow_id = keywords.get("workflow_id")
    assert isinstance(actor_id, ast.Constant) and isinstance(actor_id.value, str) and actor_id.value
    assert isinstance(workflow_id, ast.Constant) and isinstance(workflow_id.value, str) and workflow_id.value
    assert "run_id" in keywords, "Telos request must carry a run_id"
    assert "timeout" in keywords, "Telos request must receive the probe timeout"
    assert "resolver" in keywords, "Telos request must receive the vetted resolver"


def _assert_telos_probe_contract(source: str) -> None:
    tree = ast.parse(source)
    bindings = _import_bindings(tree)

    _assert_no_forbidden_transport_imports(tree)
    _assert_no_raw_transport_calls(tree, bindings)
    assert not any(
        isinstance(node, ast.ClassDef) and node.name == "AlwaysAllowHealthProbeAuthorizer"
        for node in ast.walk(tree)
    )
    _assert_exact_candidate_authorizer(tree, bindings)
    _assert_transport_policy(tree, bindings)
    _assert_health_probe_calls_telos_request(tree, bindings)


def _minimal_probe_source(*, request_target: str = "request", allow_public: bool = False) -> str:
    return dedent(
        f'''\
        import asyncio
        from telos import EndpointAuthorizer, EndpointPurpose, TransportPolicy, endpoint_from_url, request

        _POLICY = TransportPolicy(
            allow_public={allow_public},
            allow_private=True,
            allow_loopback=True,
            require_https_for_public=True,
        )

        def _candidate_authorizer(url):
            candidate = endpoint_from_url(url)
            return EndpointAuthorizer.from_exact_rules(
                {{EndpointPurpose.HEALTH_PROBE: {{candidate.key}}}},
                version="test",
            )

        async def health_probe(base_url, timeout=1.5):
            url = base_url.rstrip("/") + "/models"
            return await asyncio.to_thread(
                {request_target},
                "GET",
                url,
                authorizer=_candidate_authorizer(url),
                transport_policy=_POLICY,
                actor_id="core",
                workflow_id="health-probe",
                purpose=EndpointPurpose.HEALTH_PROBE,
                run_id="run-1",
                timeout=timeout,
                resolver=lambda host: (),
            )
        '''
    )


def test_core_health_probe_structurally_uses_telos_security_contract() -> None:
    _assert_telos_probe_contract(inspect.getsource(probe))


def test_contract_rejects_decoy_telos_import_with_raw_httpx_fallback() -> None:
    source = "import httpx as h\n" + _minimal_probe_source(request_target="h.AsyncClient")
    with pytest.raises(AssertionError, match="raw transport import"):
        _assert_telos_probe_contract(source)


def test_contract_rejects_decoy_request_import_not_used_for_outbound_call() -> None:
    source = _minimal_probe_source(request_target="fake_request").replace(
        "import asyncio\n",
        "import asyncio\ndef fake_request(*args, **kwargs): return None\n",
        1,
    )
    with pytest.raises(AssertionError, match="telos.request"):
        _assert_telos_probe_contract(source)


def test_contract_rejects_public_health_probe_policy() -> None:
    with pytest.raises(AssertionError, match="allow_public must be False"):
        _assert_telos_probe_contract(_minimal_probe_source(allow_public=True))


def test_contract_rejects_non_exact_candidate_authorization() -> None:
    source = _minimal_probe_source().replace(
        "{EndpointPurpose.HEALTH_PROBE: {candidate.key}}",
        "{EndpointPurpose.HEALTH_PROBE: {('http', '0.0.0.0', 80)}}",
    )
    with pytest.raises(AssertionError, match="candidate.key"):
        _assert_telos_probe_contract(source)
