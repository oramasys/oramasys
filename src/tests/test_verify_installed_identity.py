"""Mock installed metadata, imports and consumer provenance; no network."""

import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def helper():
    spec = importlib.util.spec_from_file_location(
        "verify_installed_identity", ROOT / "scripts/verify_installed_identity.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def installed(tmp_path):
    plan = json.loads(
        (ROOT / "requirements/final-producers-install-plan.v1.json").read_text()
    )
    site = tmp_path / "venv/lib/python3.12/site-packages"
    site.mkdir(parents=True)
    wheel = tmp_path / "oramasys.whl"
    wheel.write_bytes(b"wheel fixture")
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    provenance = tmp_path / "provenance.json"
    provenance.write_text(
        json.dumps(
            {"source_commit": plan["consumer"]["commit"], "wheel_sha256": digest}
        )
    )
    modules, distributions = {}, {}
    for entry in [plan["consumer"], *plan["producers"].values()]:
        name = entry["module"]
        file = site / name / "__init__.py"
        file.parent.mkdir()
        file.write_text("")
        modules[name] = SimpleNamespace(__file__=str(file), __path__=[str(file.parent)])
        direct = (
            {
                "url": entry["url"],
                "vcs_info": {
                    "vcs": "git",
                    "commit_id": entry["commit"],
                    "requested_revision": entry["commit"],
                },
            }
            if entry["install_mode"] == "vcs"
            else {"url": wheel.as_uri(), "archive_info": {"hashes": {"sha256": digest}}}
        )
        distributions[entry["distribution"]] = SimpleNamespace(
            metadata={"Name": entry["distribution"]},
            files=[Path(name) / "__init__.py"],
            locate_file=lambda path, site=site: site / path,
            read_text=lambda name, direct=direct: (
                json.dumps(direct) if name == "direct_url.json" else None
            ),
        )
    return (
        dict(
            plan=plan,
            consumer_wheel=wheel,
            consumer_provenance=provenance,
            distribution_getter=distributions.__getitem__,
            importer=modules.__getitem__,
            site_roots=[site],
            cwd=tmp_path,
            isolated=True,
        ),
        modules,
        distributions,
    )


def test_verified_exact_set(helper, installed):
    args, _, _ = installed
    result = helper.verify_identity(**args)
    assert result["verified"] is True and len(result["producers"]) == 4


@pytest.mark.parametrize(
    "mutation", ["url", "commit", "requested", "editable", "archive", "missing", "name"]
)
def test_bad_producer_metadata(helper, installed, mutation):
    args, _, distributions = installed
    dist = distributions["perpetua-core"]
    direct = json.loads(dist.read_text("direct_url.json"))
    if mutation == "url":
        direct["url"] = "https://evil.invalid/core.git"
    elif mutation == "commit":
        direct["vcs_info"]["commit_id"] = "a" * 40
    elif mutation == "requested":
        direct["vcs_info"]["requested_revision"] = "main"
    elif mutation == "editable":
        direct["dir_info"] = {"editable": True}
    elif mutation == "archive":
        direct = {"url": direct["url"], "archive_info": {"hash": "sha256=abc"}}
    elif mutation == "name":
        dist.metadata["Name"] = "wrong-distribution"
    dist.read_text = lambda _: None if mutation == "missing" else json.dumps(direct)
    with pytest.raises(ValueError):
        helper.verify_identity(**args)


@pytest.mark.parametrize(
    "mutation",
    ["outside", "wrong-owner", "symlink", "package-path", "isolated", "checkout"],
)
def test_import_and_execution_isolation(helper, installed, tmp_path, mutation):
    args, modules, distributions = installed
    module = modules["perpetua_core"]
    if mutation == "outside":
        module.__file__ = str(tmp_path / "checkout/perpetua_core/__init__.py")
    elif mutation == "wrong-owner":
        distributions["perpetua-core"].files = [Path("unrelated.py")]
    elif mutation == "symlink":
        file = Path(module.__file__)
        file.unlink()
        target = tmp_path / "source.py"
        target.write_text("")
        file.symlink_to(target)
    elif mutation == "package-path":
        module.__path__.append(str(tmp_path / "checkout"))
    elif mutation == "isolated":
        args["isolated"] = False
    else:
        (tmp_path / ".git").mkdir()
    with pytest.raises(ValueError):
        helper.verify_identity(**args)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-wheel",
        "missing-provenance",
        "source",
        "digest",
        "installed-digest",
        "installed-url",
        "consumer-vcs",
    ],
)
def test_consumer_provenance_is_bound_to_installed_wheel(helper, installed, mutation):
    args, _, distributions = installed
    if mutation == "missing-wheel":
        args["consumer_wheel"] = None
    elif mutation == "missing-provenance":
        args["consumer_provenance"] = None
    elif mutation in {"source", "digest"}:
        p = args["consumer_provenance"]
        data = json.loads(p.read_text())
        data["source_commit" if mutation == "source" else "wheel_sha256"] = "a" * (
            40 if mutation == "source" else 64
        )
        p.write_text(json.dumps(data))
    else:
        dist = distributions["oramasys"]
        direct = json.loads(dist.read_text("direct_url.json"))
        if mutation == "installed-digest":
            direct["archive_info"]["hashes"]["sha256"] = "b" * 64
        elif mutation == "installed-url":
            direct["url"] = "file:///different.whl"
        else:
            direct = {
                "url": "https://github.com/oramasys/oramasys.git",
                "vcs_info": {
                    "vcs": "git",
                    "commit_id": args["plan"]["consumer"]["commit"],
                },
            }
        dist.read_text = lambda _: json.dumps(direct)
    with pytest.raises(ValueError):
        helper.verify_identity(**args)


def test_cli_requires_isolated_python(helper, capsys):
    assert (
        helper.main([str(ROOT / "requirements/final-producers-install-plan.v1.json")])
        != 0
    )
    assert json.loads(capsys.readouterr().out)["verified"] is False


def test_cli_failure_reason_goes_to_stderr_not_the_json_verdict(helper, capsys, installed):
    """A failed run must be diagnosable from CI logs; the stdout verdict stays stable."""
    args, _, _ = installed
    helper.main(
        [
            str(ROOT / "requirements/final-producers-install-plan.v1.json"),
            "--consumer-wheel",
            str(args["consumer_wheel"]),
            "--consumer-provenance",
            str(args["consumer_provenance"]),
        ]
    )
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "schema": 1,
        "verified": False,
        "classification": "identity-verification-failed",
    }
    assert captured.err.startswith("identity-verification-failed: ")
