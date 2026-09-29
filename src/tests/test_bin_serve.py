"""Launcher tests: bin/serve host-flag last-wins and duplicate stripping."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

SERVE = Path(__file__).resolve().parents[2] / "bin" / "serve"
SYSTEM_BASH = Path("/bin/bash")


def _run_lib(script: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["ORAMA_SERVE_LIB"] = "1"
    return subprocess.run(
        [str(SYSTEM_BASH), "-c", f'source "{SERVE}"\n{script}'],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def _write_fake_python(tmp_path: Path) -> Path:
    fake_python = tmp_path / "python"
    fake_python.write_text(
        "#!/usr/bin/env bash\n"
        "if [[ \"$1\" == \"-c\" ]]; then\n"
        "  printf '%s\\n' \"${ORAMA_EXPLICIT_HOST:-127.0.0.1}\"\n"
        "  exit 0\n"
        "fi\n"
        "printf '<%s>\\n' \"$@\"\n"
    )
    fake_python.chmod(0o755)
    return fake_python


def test_parse_explicit_host_last_wins():
    result = _run_lib(
        'parse_explicit_host --reload --host 127.0.0.1 --host=::1 --port 9\n'
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "::1"


def test_parse_explicit_host_equals_then_space_last_wins():
    result = _run_lib(
        'parse_explicit_host --host=127.0.0.1 --host 0.0.0.0\n'
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "0.0.0.0"


@pytest.mark.parametrize(
    ("script", "stderr_fragment"),
    [
        ('parse_explicit_host --host -x\n', "empty or looks like an option"),
        ('parse_explicit_host --host=--port\n', "empty or looks like an option"),
        ('parse_explicit_host --host " "\n', "empty or looks like an option"),
        ('parse_explicit_host --host=" "\n', "empty or looks like an option"),
        ('parse_explicit_host --host\n', "requires a value"),
    ],
)
def test_parse_explicit_host_rejects_malformed_values(
    script: str,
    stderr_fragment: str,
) -> None:
    result = _run_lib(script)
    assert result.returncode == 1, result.stderr
    assert result.stdout == ""
    assert stderr_fragment in result.stderr


def test_collect_non_host_args_strips_all_host_flags():
    result = _run_lib(
        "collect_non_host_args --reload --host 127.0.0.1 --host=0.0.0.0 --port 8080\n"
        'printf "%s\\n" "${ORAMA_NON_HOST_ARGS[@]}"\n'
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["--reload", "--port", "8080"]


def test_collect_non_host_args_allows_an_empty_result():
    result = _run_lib(
        "collect_non_host_args --host 127.0.0.1\n"
        'printf "%s\\n" "${ORAMA_NON_HOST_ARGS[@]+"${ORAMA_NON_HOST_ARGS[@]}"}"\n'
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "\n"


def test_serve_allows_host_only_with_bash32_nounset(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["PYTHON"] = str(_write_fake_python(tmp_path))

    result = subprocess.run(
        [str(SYSTEM_BASH), str(SERVE), "--host", "127.0.0.1"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "<-m>",
        "<uvicorn>",
        "<--app-dir>",
        "<src>",
        "<orama.api.server:app>",
        "<--host>",
        "<127.0.0.1>",
    ]


def test_serve_preserves_non_host_argument_boundaries_with_bash32(
    tmp_path: Path,
) -> None:
    env = os.environ.copy()
    env["PYTHON"] = str(_write_fake_python(tmp_path))

    result = subprocess.run(
        [
            str(SYSTEM_BASH),
            str(SERVE),
            "--host",
            "127.0.0.1",
            "--log-config",
            "config with spaces.ini",
            "",
            "--host=127.0.0.1",
            "--port",
            "8123",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "<-m>",
        "<uvicorn>",
        "<--app-dir>",
        "<src>",
        "<orama.api.server:app>",
        "<--host>",
        "<127.0.0.1>",
        "<--log-config>",
        "<config with spaces.ini>",
        "<>",
        "<--port>",
        "<8123>",
    ]


@pytest.mark.parametrize(
    ("args", "stderr_fragment"),
    [
        (("--host",), "requires a value"),
        (("--host", "127.0.0.1", "--host"), "requires a value"),
        (("--host=",), "empty or looks like an option"),
        (("--host", "--port", "8123"), "empty or looks like an option"),
        (("--host", "-x"), "empty or looks like an option"),
        (("--host=--port",), "empty or looks like an option"),
        (("--host", " "), "empty or looks like an option"),
        (("--host= ",), "empty or looks like an option"),
    ],
)
def test_serve_rejects_malformed_host_flags_before_launch(
    tmp_path: Path,
    args: tuple[str, ...],
    stderr_fragment: str,
) -> None:
    env = os.environ.copy()
    env["PYTHON"] = str(_write_fake_python(tmp_path))

    result = subprocess.run(
        [str(SYSTEM_BASH), str(SERVE), *args],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode == 64, result.stderr
    assert stderr_fragment in result.stderr
    assert result.stdout == ""
