"""`ff ui` and the bundled Streamlit config. These run without the `ui` extra."""

import ast
import importlib.util
import subprocess
import tomllib
from pathlib import Path

import pytest

from failure_forensics import cli
from failure_forensics.cli import main

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "src" / "failure_forensics" / "ui"


def test_ui_needs_streamlit(monkeypatch, capsys):
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: None)
    assert main(["ui", "--db", str(ROOT / "examples" / "demo.db")]) == 3
    assert "uv sync --extra ui" in capsys.readouterr().err


def test_ui_missing_db(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: object())
    assert main(["ui", "--db", str(tmp_path / "nope.db")]) == 3
    assert "no database" in capsys.readouterr().err


def test_ui_command_binds_localhost_and_disables_telemetry(monkeypatch, capsys):
    seen = {}

    def fake_call(cmd, cwd, env):
        seen.update(cmd=cmd, cwd=cwd, env=env)
        return 0

    monkeypatch.setattr(importlib.util, "find_spec", lambda name: object())
    monkeypatch.setattr(subprocess, "call", fake_call)
    assert main(["ui", "--db", str(ROOT / "examples" / "demo.db"), "--port", "8777", "--no-browser"]) == 0
    cmd = seen["cmd"]
    assert cmd[cmd.index("--server.address") + 1] == "127.0.0.1"
    assert cmd[cmd.index("--server.port") + 1] == "8777"
    assert cmd[cmd.index("--browser.gatherUsageStats") + 1] == "false"
    assert cmd[cmd.index("--server.headless") + 1] == "true"
    assert seen["cwd"] == UI and (seen["cwd"] / ".streamlit" / "config.toml").is_file()
    assert seen["env"]["FF_UI_DB"].endswith("examples/demo.db")
    assert seen["env"]["STREAMLIT_BROWSER_GATHER_USAGE_STATS"] == "false"
    assert "127.0.0.1:8777" in capsys.readouterr().err
    assert cli.build_parser().parse_args(["ui"]).port == 8501


def test_bundled_config_is_local_and_quiet():
    cfg = tomllib.loads((UI / ".streamlit" / "config.toml").read_text())
    assert cfg["browser"]["gatherUsageStats"] is False
    assert cfg["server"]["address"] == "127.0.0.1"
    assert cfg["theme"]["primaryColor"] and "dark" in cfg["theme"]


def test_no_unsafe_html_anywhere_in_the_ui():
    needle = "unsafe_allow" + "_html"
    hits = [p.name for p in UI.rglob("*.py") if needle in p.read_text()]
    assert hits == []
    # st.html takes constant markup only: the CSS constant or a plain string literal (no f-string, no variables)
    for p in UI.rglob("*.py"):
        for node in ast.walk(ast.parse(p.read_text())):
            if isinstance(node, ast.Call) and ast.unparse(node.func) == "st.html":
                arg = node.args[0]
                assert (isinstance(arg, ast.Name) and arg.id == "CSS") or (
                    isinstance(arg, ast.Constant) and isinstance(arg.value, str)), ast.unparse(node)


def test_port_range():
    p = cli.build_parser()
    assert p.parse_args(["ui", "--port", "65535"]).port == 65535
    for bad in ("0", "65536", "-1", "x"):
        with pytest.raises(SystemExit) as e:
            p.parse_args(["ui", "--port", bad])
        assert e.value.code == 3


@pytest.mark.skipif(importlib.util.find_spec("streamlit") is not None, reason="only without the ui extra")
def test_ui_data_layer_imports_without_streamlit():
    from failure_forensics.ui import data  # noqa: F401
