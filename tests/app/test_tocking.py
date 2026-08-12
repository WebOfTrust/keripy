# -*- encoding: utf-8 -*-
"""Tests for centralized scheduler tock configuration."""

import pytest

from hio.base import doing

from keri import kering
from keri.app import configing, habbing, tocking


def test_tocking_defaults_are_effective_runtime_defaults():
    tocks = tocking.resolveTocks(environ={})

    assert isinstance(tocks, dict)
    assert len(tocks) == 29
    assert set(tocks) == set(tocking.TOCKS)
    assert set(tocking.TOCK_ALIASES) == {"vdrEscrow"}
    nonzero_defaults = {
        "witnessEscrow": 1.0,
        "indirectorEscrow": 1.0,
        "mailboxEscrow": 1.0,
        "pollerConnect": 0.5,
        "reactorEscrow": 1.0,
        "reactantEscrow": 1.0,
        "witnessReceiptorIdle": 1.0,
        "registrarEscrow": 0.5,
        "credentialerEscrow": 0.5,
        "counselorEscrow": 0.5,
        "anchorerEscrow": 0.5,
    }
    assert {key: tocks[key] for key in nonzero_defaults} == nonzero_defaults

    zero_defaults = set(tocks) - set(nonzero_defaults)
    assert all(tocks[key] == 0.0 for key in zero_defaults)


def test_tocking_specific_config_precedes_coarse_config():
    tocks = tocking.resolveTocks(
        {
            "pollerEvent": 0.4,
            "pollerConnect": 0.125,
            "vdrEscrow": 0.6,
            "registrarEscrow": 0.2,
        },
        environ={},
    )

    assert tocks["pollerEvent"] == 0.4
    assert tocks["pollerConnect"] == 0.125

    # cascaded from vdrEscrow
    assert tocks["credentialerEscrow"] == 0.6
    # specific config override
    assert tocks["registrarEscrow"] == 0.2


def test_tocking_environment_precedes_config_and_coarse_environment():
    tocks = tocking.resolveTocks(
        {
            "pollerEvent": 0.9,
            "pollerConnect": 0.8,
            "registrarEscrow": 0.7,
            "credentialerEscrow": 0.6,
        },
        environ={
            "KERI_POLLER_EVENT_TOCK": "0.5",
            "KERI_POLLER_CONNECT_TOCK": "0.25",
            "KERI_VDR_ESCROW_TOCK": "0.4",
            "KERI_REGISTRAR_ESCROW_TOCK": "0.125",
        },
    )

    assert tocks["pollerEvent"] == 0.5
    assert tocks["pollerConnect"] == 0.25
    assert tocks["registrarEscrow"] == 0.125
    assert tocks["credentialerEscrow"] == 0.4


def test_every_tock_has_an_environment_override():
    # return dict with all tocks set to values like 0.001, 0.002, and so forth
    expected = {
        key: (idx + 1) / 1000
        for idx, key in enumerate(tocking.TOCKS)
    }
    # set tock associated environment vars to expected values set above
    environ = {
        tocking.TOCKS[key].env: str(value)
        for key, value in expected.items()
    }

    # verify that tock resolution from environment uses highest precedence for env vars
    assert tocking.resolveTocks(environ=environ) == expected


# Tocks must be finite, non-negative numeric values; booleans are not numeric here.
@pytest.mark.parametrize("value", [
    True,
    False,
    None,
    "",
    "0.25",
    -0.1,
    float("nan"),
    float("inf"),
    float("-inf"),
])
def test_tocking_rejects_invalid_config_values(value):
    with pytest.raises(kering.ConfigurationError, match="tocks.witnessMsg"):
        tocking.resolveTocks({"witnessMsg": value}, environ={})


# Invalid env var values should not be allowed either
@pytest.mark.parametrize("value", [
    True,
    "",
    "not-a-number",
    "-0.1",
    "nan",
    "NaN",
    "inf",
    "+inf",
    "-inf",
])
def test_tocking_rejects_invalid_environment_values(value):
    with pytest.raises(kering.ConfigurationError,
                       match="KERI_WITNESS_MSG_TOCK"):
        tocking.resolveTocks(
            environ={"KERI_WITNESS_MSG_TOCK": value}
        )


def test_tocking_rejects_invalid_config_even_when_environment_shadows_it():
    with pytest.raises(kering.ConfigurationError, match="tocks.witnessMsg"):
        tocking.resolveTocks(
            {"witnessMsg": float("nan")},
            environ={"KERI_WITNESS_MSG_TOCK": "0.25"},
        )


def test_tocking_rejects_invalid_coarse_environment_when_specifics_shadow_it():
    with pytest.raises(kering.ConfigurationError,
                       match="KERI_VDR_ESCROW_TOCK"):
        tocking.resolveTocks(
            environ={
                "KERI_VDR_ESCROW_TOCK": "not-a-number",
                "KERI_REGISTRAR_ESCROW_TOCK": "0.1",
                "KERI_CREDENTIALER_ESCROW_TOCK": "0.2",
            }
        )


def test_tocking_accepts_zero_and_sub_hio_tick_values():
    tocks = tocking.resolveTocks(
        {"witnessMsg": 0.0, "counselorEscrow": 0.001},
        environ={"KERI_REGISTRAR_ESCROW_TOCK": "0"},
    )

    assert tocks["witnessMsg"] == 0.0
    assert tocks["counselorEscrow"] == 0.001
    assert tocks["registrarEscrow"] == 0.0


def test_tocking_rejects_unknown_keys_but_reserves_signify():
    tocks = tocking.resolveTocks({"signify": {"escrower": 1.0}}, environ={})
    assert tocks["witnessMsg"] == 0.0

    with pytest.raises(kering.ConfigurationError, match="unknownTock"):
        tocking.resolveTocks({"unknownTock": 1.0}, environ={})


def test_tocking_supports_caller_owned_registry():
    specs = {
        "worker": tocking.Tock(env="KERIA_WORKER_TOCK", default=0.0)
    }

    tocks = tocking.resolveTocks(
        {"worker": 1.0},
        tocks=specs,
        aliases={},
        environ={"KERIA_WORKER_TOCK": "0.125"},
        reserved=(),
    )
    assert tocks == {"worker": 0.125}


def test_habery_resolves_config_and_shares_tocks_with_hab():
    with configing.openCF(name="tocks", temp=True) as cf:
        cf.put({"tocks": {"witnessMsg": 0.007}})
        with habbing.openHby(name="tocks", temp=True, cf=cf) as hby:
            hab = hby.makeHab(name="tocks")
            assert hby.tocks["witnessMsg"] == 0.007
            assert hab.tocks is hby.tocks


def test_doify_delivers_resolved_nonzero_and_zero_tocks():
    seen = []

    def sampleDo(tymth=None, tock=0.0, **kwa):
        seen.append(tock)
        yield tock

    configured = tocking.resolveTocks(
        {"witnessMsg": 0.007}, environ={}
    )
    nonzero = doing.doify(sampleDo, tock=configured["witnessMsg"])
    zero = doing.doify(sampleDo, tock=0.0)

    doist = doing.Doist(tock=0.03125, limit=0.1)
    doist.do(doers=[nonzero, zero])

    assert seen == [0.007, 0.0]
