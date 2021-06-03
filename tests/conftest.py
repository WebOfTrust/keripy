"""
Configure PyTest

Use this module to configure pytest
https://docs.pytest.org/en/latest/pythonpath.html

"""
import pytest

from keri.help import helping

@pytest.fixture()
def mockHelpingNowUTC(monkeypatch):
    """
    Replace nowUTC universally with fixed value for testing
    """
    def mockNowUTC():
        """
        Use predetermined value for now
        "2021-01-01T00:00:00.000000+00:00"
        """
        return helping.fromIso8601("2021-05-30T17:42:26.716070+00:00" )

    monkeypatch.setattr(helping, "nowUTC", mockNowUTC)

