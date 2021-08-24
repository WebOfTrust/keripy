"""
Configure PyTest

Use this module to configure pytest
https://docs.pytest.org/en/latest/pythonpath.html

"""
import pytest

from keri.app import obtaining
from keri.help import helping


@pytest.fixture()
def mockHelpingNowUTC(monkeypatch):
    """
    Replace nowUTC universally with fixed value for testing
    """

    def mockNowUTC():
        """
        Use predetermined value for now (current time)
        '2021-01-01T00:00:00.000000+00:00'
        """
        return helping.fromIso8601("2021-01-01T00:00:00.000000+00:00")

    monkeypatch.setattr(helping, "nowUTC", mockNowUTC)


@pytest.fixture()
def mockGetWitnessByPrefix(monkeypatch):
    """
    Replace getwitnessbyprefix universally with fixed cache for testing
    """
    # override the in memory cache for this demo, should probably use a mock
    witnesses = {
        "B6KBd3GmnWvjcmE775zNRPCsJfOhasjBbyLjUpYOWvyw": obtaining.Location(ip4="127.0.0.1", tcp=5632),  # wan
        "B7L80wOpOxsItVk1p4tYiK6vNjVVLExvhB5yGEuk864U": obtaining.Location(ip4="127.0.0.1", tcp=5633),  # wil
        "B3y3efWXFxXRJYYkggXjp-lJSoDsyqt7kok03edvHeas": obtaining.Location(ip4="127.0.0.1", tcp=5634),  # wes
    }


    def getwitnessbyprefix(qb64):
        """
        Use predetermined value for now (current time)
        '2021-01-01T00:00:00.000000+00:00'
        """
        return witnesses[qb64]

    monkeypatch.setattr(obtaining, "getwitnessbyprefix", getwitnessbyprefix)


@pytest.fixture()
def mockGetWitnessByPrefixOneWitness(monkeypatch):
    """
    Replace getwitnessbyprefix universally with fixed cache for testing
    """

    def getwitnessbyprefix(qb64):
        """
        Use predetermined value for now (current time)
        '2021-01-01T00:00:00.000000+00:00'
        """
        return obtaining.Location(ip4="127.0.0.1", tcp=5634, http=5644)

    monkeypatch.setattr(obtaining, "getwitnessbyprefix", getwitnessbyprefix)
