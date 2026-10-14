"""Verify installed final-set identities from isolated Python outside a checkout.

Consumer verification requires both a wheel and its source/digest provenance. This is
installation identity evidence, not a pip-check result or producer archive provenance.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata
import importlib.util
import json
from pathlib import Path
import re
import sys
import sysconfig

# Explicit sibling loading also works under python -I, which excludes the script directory.
_spec = importlib.util.spec_from_file_location("_final_set_plan", Path(__file__).with_name("final_set_install_plan.py"))
_plan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_plan)


def _inside(path, root):
    return path == root or root in path.parents


def _distribution(entry, getter):
    dist = getter(entry["distribution"])
    normalize = lambda name: re.sub(r"[-_.]+", "-", name).lower()
    if normalize(dist.metadata.get("Name", "")) != normalize(entry["distribution"]):
        raise ValueError("distribution name mismatch")
    text = dist.read_text("direct_url.json")
    if not text:
        raise ValueError("missing direct URL evidence")
    direct = json.loads(text, object_pairs_hook=_plan.unique_object)
    if not isinstance(direct, dict) or "dir_info" in direct:
        raise ValueError("local or editable installation refused")
    return dist, direct


def _verify_import(entry, dist, importer, roots):
    installed_root = Path(dist.locate_file("")).resolve()
    if installed_root not in roots:
        raise ValueError("distribution outside installed site-packages")
    module = importer(entry["module"])
    origin = getattr(module, "__file__", None)
    if not origin:
        raise ValueError("module has no verifiable origin")
    origin = Path(origin).resolve()
    if not _inside(origin, installed_root) or not origin.is_file():
        raise ValueError("import outside installed site-packages")
    owned = {Path(dist.locate_file(file)).resolve() for file in (dist.files or [])}
    if origin not in owned:
        raise ValueError("import not owned by expected distribution")
    for location in getattr(module, "__path__", []):
        if not _inside(Path(location).resolve(), installed_root):
            raise ValueError("package search path outside installed site-packages")


def verify_identity(plan, consumer_wheel=None, consumer_provenance=None, *,
                    distribution_getter=None, importer=None, site_roots=None, cwd=None, isolated=None):
    _plan.validate_structure(plan)
    if not (sys.flags.isolated if isolated is None else isolated):
        raise ValueError("python -I required")
    directory = Path.cwd().resolve() if cwd is None else Path(cwd).resolve()
    if any((parent / ".git").exists() for parent in (directory, *directory.parents)):
        raise ValueError("working directory must be outside a checkout")
    if consumer_wheel is None or consumer_provenance is None:
        raise ValueError("consumer wheel and provenance required")
    wheel = Path(consumer_wheel).resolve()
    provenance = _plan.load_json(consumer_provenance)
    digest = hashlib.file_digest(wheel.open("rb"), "sha256").hexdigest()
    if not isinstance(provenance, dict) or provenance.get("source_commit") != plan["consumer"]["commit"] or provenance.get("wheel_sha256") != digest:
        raise ValueError("consumer source or wheel digest mismatch")
    getter = distribution_getter or importlib.metadata.distribution
    importer = importer or importlib.import_module
    roots = {Path(root).resolve() for root in (site_roots if site_roots is not None else
             [sysconfig.get_path("purelib"), sysconfig.get_path("platlib")])}
    verified = {}
    for role, entry in plan["producers"].items():
        dist, direct = _distribution(entry, getter)
        vcs = direct.get("vcs_info")
        if direct.get("url") != entry["url"] or "archive_info" in direct or not isinstance(vcs, dict):
            raise ValueError("producer lacks matching VCS evidence")
        if vcs.get("vcs") != "git" or vcs.get("commit_id") != entry["commit"]:
            raise ValueError("producer VCS commit mismatch")
        if "requested_revision" in vcs and vcs["requested_revision"] != entry["commit"]:
            raise ValueError("producer was not requested at the exact commit")
        _verify_import(entry, dist, importer, roots)
        verified[role] = {"distribution": entry["distribution"], "module": entry["module"], "commit": entry["commit"], "evidence": "vcs"}
    consumer = plan["consumer"]
    dist, direct = _distribution(consumer, getter)
    archive = direct.get("archive_info")
    if direct.get("url") != wheel.as_uri() or "vcs_info" in direct or not isinstance(archive, dict):
        raise ValueError("consumer is not installed from the supplied wheel")
    hashes = archive.get("hashes", {})
    if not isinstance(hashes, dict):
        raise ValueError("invalid consumer archive hashes")
    evidence = hashes.get("sha256", archive.get("hash", "").removeprefix("sha256="))
    if evidence != digest:
        raise ValueError("installed consumer wheel digest mismatch")
    _verify_import(consumer, dist, importer, roots)
    return {"schema": 1, "verified": True, "producers": verified,
            "consumer": {"distribution": consumer["distribution"], "module": consumer["module"],
                         "source_commit": consumer["commit"], "wheel_sha256": digest, "evidence": "built-wheel"}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan")
    parser.add_argument("--consumer-wheel")
    parser.add_argument("--consumer-provenance")
    args = parser.parse_args(argv)
    try:
        result = verify_identity(_plan.load_json(args.plan), args.consumer_wheel, args.consumer_provenance)
    except Exception:
        print(json.dumps({"schema": 1, "verified": False, "classification": "identity-verification-failed"}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
