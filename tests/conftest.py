"""
Configure PyTest

Use this module to configure pytest
https://docs.pytest.org/en/latest/pythonpath.html

"""
import pytest

from keri.help import helping


@pytest.fixture()
def mockHelpingNowIso8601(monkeypatch):
    """keri.help.helping.nowIso8601() mocked to return 2021-05-30T17:42:26.716070+00:00"""

    def mock_nowIso8601():
        return "2021-05-30T17:42:26.716070+00:00"

    monkeypatch.setattr(helping, "nowIso8601", mock_nowIso8601)