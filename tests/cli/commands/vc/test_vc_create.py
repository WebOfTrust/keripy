"""Tests for credential issuance timestamp selection."""

import copy
from types import SimpleNamespace

import pytest

from keri.acdc import acdcagg
from keri.cli.commands.vc import create as create_cmd
from keri.core import Diger, SerderACDC
from keri.help import helping
from keri.kering import Kinds
from keri.vc.proving import credential


class RegistryIssued(Exception):
    """Stop the issuer immediately after recording its registry issue call."""


class RegistrySpy:
    """Capture issuance arguments without starting registry workflows."""

    def __init__(self):
        self.hab = object()
        self.issued = []

    def issue(self, said, dt):
        self.issued.append((said, dt))
        raise RegistryIssued


def _issue_explicit_credential(monkeypatch, sad):
    """Run the explicit credential path through the registry issue boundary."""
    registry = RegistrySpy()
    hby = SimpleNamespace(habByName=lambda alias: object())
    rgy = SimpleNamespace(reger=object(), registryByName=lambda name: registry)
    credentialer = SimpleNamespace(validate=lambda creder: None)

    monkeypatch.setattr(create_cmd.existing, "setupHby", lambda **kwa: hby)
    monkeypatch.setattr(create_cmd, "Regery", lambda **kwa: rgy)
    monkeypatch.setattr(create_cmd, "Credentialer", lambda **kwa: credentialer)
    monkeypatch.setattr(create_cmd, "loadHandlers", lambda *args, **kwa: None)
    for name in ("HaberyDoer", "Counselor", "Organizer", "Poster", "Notifier",
                 "Multiplexor", "Exchanger", "Verifier", "MailboxDirector"):
        monkeypatch.setattr(create_cmd, name, lambda *args, **kwa: object())

    issuer = create_cmd.CredentialIssuer(
        name="test", alias="test", base="", bran=None,
        registryName="test", credential=sad,
    )
    assert isinstance(issuer.creder, SerderACDC)

    doer = issuer.createDo(lambda: 0.0)
    next(doer)
    with pytest.raises(RegistryIssued):
        next(doer)

    assert len(registry.issued) == 1
    return registry.issued[0][1]


def test_aggregate_credential_uses_issuance_time_fallback(monkeypatch):
    """An aggregate without top-level attributes uses the current time."""
    now = "2026-10-15T12:00:00.000000+00:00"
    monkeypatch.setattr(helping, "nowIso8601", lambda: now)
    issuer = Diger(ser=b"aggregate credential issuer").qb64
    creder = acdcagg(israid=issuer, aggregate=[], kind=Kinds.json)

    assert isinstance(creder, SerderACDC)
    assert creder.attrib is None
    assert _issue_explicit_credential(monkeypatch, creder.sad) == now


def test_attributive_credential_preserves_explicit_issuance_time(monkeypatch):
    """An explicit top-level a.dt continues to control issuance time."""
    fallback = "2026-10-15T12:00:00.000000+00:00"
    explicit = "2020-02-03T04:05:06.000000+00:00"
    monkeypatch.setattr(helping, "nowIso8601", lambda: fallback)
    issuer = Diger(ser=b"attributive credential issuer").qb64
    creder = credential(
        schema="EAv8omZ-o3Pk45h72_WnIpt6LTWNzc8hmLjeblpxB9vz",
        issuer=issuer,
        data={"d": "", "dt": explicit},
        kind=Kinds.json,
    )

    assert isinstance(creder, SerderACDC)
    assert creder.attrib["dt"] == explicit
    assert _issue_explicit_credential(monkeypatch, creder.sad) == explicit


def test_attributive_credential_without_issuance_time_uses_fallback(
        monkeypatch):
    """An attributive credential without a.dt uses the current time."""
    now = "2026-10-15T12:00:00.000000+00:00"
    monkeypatch.setattr(helping, "nowIso8601", lambda: now)
    issuer = Diger(ser=b"attributive credential issuer").qb64
    creder = credential(
        schema="EAv8omZ-o3Pk45h72_WnIpt6LTWNzc8hmLjeblpxB9vz",
        issuer=issuer,
        data={"d": "", "dt": "temporary"},
        kind=Kinds.json,
    )
    sad = copy.deepcopy(creder.sad)
    del sad["a"]["dt"]
    sad["d"] = ""
    creder = SerderACDC(sad=sad, makify=True)

    assert isinstance(creder, SerderACDC)
    assert "dt" not in creder.attrib
    assert _issue_explicit_credential(monkeypatch, creder.sad) == now
