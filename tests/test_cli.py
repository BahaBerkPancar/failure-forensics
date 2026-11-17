import pytest

from failure_forensics import __version__
from failure_forensics.cli import main


def test_main_says_hello(capsys):
    assert main([]) == 0
    assert "Hello" in capsys.readouterr().out


def test_version(capsys):
    with pytest.raises(SystemExit):
        main(["--version"])
    assert __version__ in capsys.readouterr().out
