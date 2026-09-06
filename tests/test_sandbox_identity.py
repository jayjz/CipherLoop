import json
import subprocess
from pathlib import Path

from cipherloop.main import ensure_sandbox_running


def _completed(command, stdout="", returncode=0):
    return subprocess.CompletedProcess(command, returncode, stdout=stdout)


def test_reuses_sandbox_only_when_its_target_mount_matches(monkeypatch):
    target = Path("fixtures/safe").resolve()
    expected_mount = str(target.resolve())
    commands = []

    def fake_run(command, **_):
        commands.append(command)
        if command[:3] == ["docker", "ps", "-q"]:
            return _completed(command, "sandbox-id\n")
        if command[:2] == ["docker", "inspect"]:
            return _completed(
                command,
                json.dumps(
                    [
                        {
                            "Mounts": [
                                {
                                    "Source": expected_mount,
                                    "Destination": "/workspace/target_repo",
                                }
                            ]
                        }
                    ]
                ),
            )
        raise AssertionError(f"Unexpected Docker command: {command}")

    monkeypatch.setattr("cipherloop.main.subprocess.run", fake_run)

    ensure_sandbox_running(str(target))

    assert commands == [
        ["docker", "ps", "-q", "-f", "name=cipherloop-sandbox"],
        ["docker", "inspect", "sandbox-id"],
    ]


def test_replaces_sandbox_when_its_target_mount_differs(monkeypatch):
    target = Path("fixtures/safe").resolve()
    stale_target = Path("fixtures/toy").resolve()
    commands = []

    def fake_run(command, **_):
        commands.append(command)
        if command[:3] == ["docker", "ps", "-q"]:
            return _completed(command, "sandbox-id\n")
        if command[:2] == ["docker", "inspect"]:
            return _completed(
                command,
                json.dumps(
                    [
                        {
                            "Mounts": [
                                {
                                    "Source": str(stale_target.resolve()),
                                    "Destination": "/workspace/target_repo",
                                }
                            ]
                        }
                    ]
                ),
            )
        return _completed(command)

    monkeypatch.setattr("cipherloop.main.subprocess.run", fake_run)

    ensure_sandbox_running(str(target))

    assert ["docker", "rm", "-f", "cipherloop-sandbox"] in commands
    assert ["docker", "build", "-t", "cipherloop-sandbox-img", "./sandbox"] in commands
    assert [
        "docker",
        "run",
        "-d",
        "--name",
        "cipherloop-sandbox",
        "--network",
        "none",
        "-v",
        f"{target.resolve()}:/workspace/target_repo:ro",
        "cipherloop-sandbox-img",
    ] in commands
