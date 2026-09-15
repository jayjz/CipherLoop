from cipherloop.tools import filesystem


class _Container:
    def __init__(self, exec_run):
        self._exec_run = exec_run

    def exec_run(self, **kwargs):
        return self._exec_run(**kwargs)


class _Client:
    def __init__(self, container):
        self.containers = type("Containers", (), {"get": lambda _self, _name: container})()


def test_successful_sandbox_execution_is_bounded_without_a_shell(monkeypatch):
    calls = []

    def exec_run(**kwargs):
        calls.append(kwargs)
        return 0, b"sandbox listing\n"

    monkeypatch.setattr(filesystem, "_get_docker_client", lambda: _Client(_Container(exec_run)))

    assert filesystem.execute_in_sandbox(["tree", "-L", "2", "."]) == "sandbox listing"
    assert calls == [{
        "cmd": [
            "timeout",
            "--signal=TERM",
            "--kill-after=5s",
            "30s",
            "tree",
            "-L",
            "2",
            ".",
        ],
        "workdir": filesystem.WORKDIR,
        "demux": False,
        "environment": None,
    }]
    assert "shell" not in calls[0]
    assert all(part not in {"sh", "bash"} for part in calls[0]["cmd"])


def test_timeout_exit_code_returns_deterministic_timeout(monkeypatch):
    def exec_run(**_kwargs):
        return 124, b""

    monkeypatch.setattr(filesystem, "_get_docker_client", lambda: _Client(_Container(exec_run)))

    assert (
        filesystem.execute_in_sandbox(["tree", "-L", "2", "."])
        == "Tool Execution Timeout: Sandbox command exceeded 30 seconds."
    )


def test_kill_escalation_exit_code_returns_deterministic_timeout(monkeypatch):
    def exec_run(**_kwargs):
        return 137, b"killed"

    monkeypatch.setattr(filesystem, "_get_docker_client", lambda: _Client(_Container(exec_run)))

    assert (
        filesystem.execute_in_sandbox(["tree", "-L", "2", "."])
        == "Tool Execution Timeout: Sandbox command exceeded 30 seconds."
    )


def test_non_timeout_nonzero_exit_remains_tool_error(monkeypatch):
    def exec_run(**_kwargs):
        return 2, b"invalid option"

    monkeypatch.setattr(filesystem, "_get_docker_client", lambda: _Client(_Container(exec_run)))

    assert (
        filesystem.execute_in_sandbox(["tree", "-L", "2", "."])
        == "Tool Execution Error (Code 2):\ninvalid option"
    )


def test_semgrep_execution_disables_ancillary_network_behavior(monkeypatch):
    calls = []

    def exec_run(**kwargs):
        calls.append(kwargs)
        return 0, b'{"results": [], "errors": []}'

    monkeypatch.setattr(filesystem, "_get_docker_client", lambda: _Client(_Container(exec_run)))

    filesystem.run_semgrep.invoke({"target_path": "."})

    assert calls[0]["environment"] == {
        "SEMGREP_SEND_METRICS": "off",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
    }
