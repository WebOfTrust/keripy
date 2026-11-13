# -*- encoding: utf-8 -*-
"""
tests.cli.commands.oobi.test_resolve module

"""
import pytest
from hio.base import tyming

from keri.app import Result, openHby
from keri.cli.commands.oobi import resolve
from keri.recording import OobiRecord

URL = "http://127.0.0.1:5555/oobi/BL7Lizsh2-O5W3PL6LujFAzyBNUlwbuFJoDG05UD4it1/controller"


@pytest.fixture
def doer(monkeypatch):
    with openHby(name="resolve-cli", temp=True) as hby:
        monkeypatch.setattr(resolve, "setupHby", lambda **kwa: hby)

        def make(force=False):
            return resolve.OobiDoer(name="resolve-cli", oobi=URL, oobiAlias=None, force=force)

        yield hby, make


def _failed():
    return OobiRecord(date="2026-01-01T00:00:00.000000+00:00",
                      cid="BL7Lizsh2-O5W3PL6LujFAzyBNUlwbuFJoDG05UD4it1",
                      role="controller", state=Result.failed)


def test_resolve_raises_when_the_oobi_fails(doer):
    """kli turns an escaping exception into a nonzero exit, so a failed OOBI must raise
    rather than print 'failed' and exit 0."""
    hby, make = doer
    oobiDoer = make()
    hby.db.roobi.pin(keys=(URL,), val=_failed())
    gen = oobiDoer.waitDo(tymth=tyming.Tymist().tymen())
    next(gen)

    with pytest.raises(Exception, match="did not resolve"):
        next(gen)


def test_resolve_force_does_not_wait_forever_on_a_failed_oobi(doer):
    """With --force the doer waits for the AID's key state, which a failed OOBI never
    delivers. It must report the failure instead of looping."""
    hby, make = doer
    oobiDoer = make(force=True)
    gen = oobiDoer.waitDo(tymth=tyming.Tymist().tymen())
    next(gen)  # entered
    next(gen)  # --force cleared roobi; now waiting for a record
    hby.db.roobi.pin(keys=(URL,), val=_failed())

    with pytest.raises(Exception, match="did not resolve"):
        for _ in range(20):
            next(gen)
