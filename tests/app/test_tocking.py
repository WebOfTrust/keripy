# -*- encoding: utf-8 -*-
"""
tests.app.test_tocking module

Tests for centralized tock configuration.
"""
import os
import importlib

import pytest


def test_tocking_defaults():
    """
    Test default tock values when no environment variables are set
    """
    # Clear any existing env vars that might affect the test
    env_keys = [
        "KERI_WITNESS_MSG_TOCK",
        "KERI_WITNESS_ESCROW_TOCK",
        "KERI_WITNESS_CUE_TOCK",
        "KERI_INDIRECTOR_MSG_TOCK",
        "KERI_INDIRECTOR_CUE_TOCK",
        "KERI_INDIRECTOR_ESCROW_TOCK",
        "KERI_MAILBOX_POLL_TOCK",
        "KERI_MAILBOX_MSG_TOCK",
        "KERI_MAILBOX_ESCROW_TOCK",
        "KERI_POLLER_EVENT_TOCK",
        "KERI_RECEIPT_INTERCEPT_TOCK",
        "KERI_REACTOR_MSG_TOCK",
        "KERI_REACTOR_CUE_TOCK",
        "KERI_REACTOR_ESCROW_TOCK",
        "KERI_REACTANT_MSG_TOCK",
        "KERI_REACTANT_CUE_TOCK",
        "KERI_REACTANT_ESCROW_TOCK",
        "KERI_RESPONDANT_CUE_TOCK",
        "KERI_WITNESS_RECEIPTOR_TOCK",
        "KERI_WITNESS_INQUISITOR_TOCK",
        "KERI_WITNESS_PUBLISHER_TOCK",
    ]

    # Save and clear existing env vars
    saved_env = {}
    for key in env_keys:
        if key in os.environ:
            saved_env[key] = os.environ.pop(key)

    try:
        # Reload module to pick up cleared env vars
        from keri.app import tocking
        importlib.reload(tocking)

        # Witness component tocks
        assert tocking.WitnessMsgTock == 0.0
        assert tocking.WitnessEscrowTock == 1.0
        assert tocking.WitnessCueTock == 0.25

        # Indirector component tocks
        assert tocking.IndirectorMsgTock == 0.0
        assert tocking.IndirectorCueTock == 0.25
        assert tocking.IndirectorEscrowTock == 1.0

        # MailboxDirector component tocks
        assert tocking.MailboxPollTock == 0.5
        assert tocking.MailboxMsgTock == 0.0
        assert tocking.MailboxEscrowTock == 1.0

        # Poller component tocks
        assert tocking.PollerEventTock == 0.5

        # ReceiptEnd component tocks
        assert tocking.ReceiptInterceptTock == 0.1

        # Reactor component tocks
        assert tocking.ReactorMsgTock == 0.0
        assert tocking.ReactorCueTock == 0.25
        assert tocking.ReactorEscrowTock == 1.0

        # Reactant component tocks
        assert tocking.ReactantMsgTock == 0.0
        assert tocking.ReactantCueTock == 0.25
        assert tocking.ReactantEscrowTock == 1.0

        # Respondant component tocks
        assert tocking.RespondantCueTock == 0.25

        # WitnessReceiptor component tocks
        assert tocking.WitnessReceiptorTock == 0.0

        # WitnessInquisitor component tocks
        assert tocking.WitnessInquisitorTock == 1.0

        # WitnessPublisher component tocks
        assert tocking.WitnessPublisherTock == 0.25

    finally:
        # Restore saved env vars
        for key, value in saved_env.items():
            os.environ[key] = value
        # Reload to restore original state
        importlib.reload(tocking)

    """Done Test"""


def test_tocking_env_override():
    """
    Test that environment variables properly override default tock values
    """
    # Save existing env vars
    env_overrides = {
        "KERI_WITNESS_MSG_TOCK": "2.5",
        "KERI_WITNESS_ESCROW_TOCK": "3.0",
        "KERI_WITNESS_CUE_TOCK": "0.5",
        "KERI_INDIRECTOR_MSG_TOCK": "1.0",
        "KERI_INDIRECTOR_CUE_TOCK": "0.75",
        "KERI_INDIRECTOR_ESCROW_TOCK": "2.0",
        "KERI_MAILBOX_POLL_TOCK": "1.5",
        "KERI_MAILBOX_MSG_TOCK": "0.1",
        "KERI_MAILBOX_ESCROW_TOCK": "2.5",
        "KERI_POLLER_EVENT_TOCK": "1.0",
        "KERI_RECEIPT_INTERCEPT_TOCK": "0.5",
        "KERI_REACTOR_MSG_TOCK": "0.5",
        "KERI_REACTOR_CUE_TOCK": "0.5",
        "KERI_REACTOR_ESCROW_TOCK": "2.0",
        "KERI_REACTANT_MSG_TOCK": "0.5",
        "KERI_REACTANT_CUE_TOCK": "0.5",
        "KERI_REACTANT_ESCROW_TOCK": "2.0",
        "KERI_RESPONDANT_CUE_TOCK": "0.5",
        "KERI_WITNESS_RECEIPTOR_TOCK": "0.5",
        "KERI_WITNESS_INQUISITOR_TOCK": "2.0",
        "KERI_WITNESS_PUBLISHER_TOCK": "0.5",
    }

    # Save and set env vars
    saved_env = {}
    for key, value in env_overrides.items():
        if key in os.environ:
            saved_env[key] = os.environ[key]
        os.environ[key] = value

    try:
        # Reload module to pick up new env vars
        from keri.app import tocking
        importlib.reload(tocking)

        # Witness component tocks
        assert tocking.WitnessMsgTock == 2.5
        assert tocking.WitnessEscrowTock == 3.0
        assert tocking.WitnessCueTock == 0.5

        # Indirector component tocks
        assert tocking.IndirectorMsgTock == 1.0
        assert tocking.IndirectorCueTock == 0.75
        assert tocking.IndirectorEscrowTock == 2.0

        # MailboxDirector component tocks
        assert tocking.MailboxPollTock == 1.5
        assert tocking.MailboxMsgTock == 0.1
        assert tocking.MailboxEscrowTock == 2.5

        # Poller component tocks
        assert tocking.PollerEventTock == 1.0

        # ReceiptEnd component tocks
        assert tocking.ReceiptInterceptTock == 0.5

        # Reactor component tocks
        assert tocking.ReactorMsgTock == 0.5
        assert tocking.ReactorCueTock == 0.5
        assert tocking.ReactorEscrowTock == 2.0

        # Reactant component tocks
        assert tocking.ReactantMsgTock == 0.5
        assert tocking.ReactantCueTock == 0.5
        assert tocking.ReactantEscrowTock == 2.0

        # Respondant component tocks
        assert tocking.RespondantCueTock == 0.5

        # WitnessReceiptor component tocks
        assert tocking.WitnessReceiptorTock == 0.5

        # WitnessInquisitor component tocks
        assert tocking.WitnessInquisitorTock == 2.0

        # WitnessPublisher component tocks
        assert tocking.WitnessPublisherTock == 0.5

    finally:
        # Restore or remove env vars
        for key in env_overrides:
            if key in saved_env:
                os.environ[key] = saved_env[key]
            else:
                os.environ.pop(key, None)
        # Reload to restore original state
        importlib.reload(tocking)

    """Done Test"""


def test_tocking_keys():
    """
    Test that environment variable keys are correctly defined
    """
    from keri.app import tocking

    # Witness component keys
    assert tocking.KERI_WITNESS_MSG_TOCK_KEY == "KERI_WITNESS_MSG_TOCK"
    assert tocking.KERI_WITNESS_ESCROW_TOCK_KEY == "KERI_WITNESS_ESCROW_TOCK"
    assert tocking.KERI_WITNESS_CUE_TOCK_KEY == "KERI_WITNESS_CUE_TOCK"

    # Indirector component keys
    assert tocking.KERI_INDIRECTOR_MSG_TOCK_KEY == "KERI_INDIRECTOR_MSG_TOCK"
    assert tocking.KERI_INDIRECTOR_CUE_TOCK_KEY == "KERI_INDIRECTOR_CUE_TOCK"
    assert tocking.KERI_INDIRECTOR_ESCROW_TOCK_KEY == "KERI_INDIRECTOR_ESCROW_TOCK"

    # MailboxDirector component keys
    assert tocking.KERI_MAILBOX_POLL_TOCK_KEY == "KERI_MAILBOX_POLL_TOCK"
    assert tocking.KERI_MAILBOX_MSG_TOCK_KEY == "KERI_MAILBOX_MSG_TOCK"
    assert tocking.KERI_MAILBOX_ESCROW_TOCK_KEY == "KERI_MAILBOX_ESCROW_TOCK"

    # Poller component keys
    assert tocking.KERI_POLLER_EVENT_TOCK_KEY == "KERI_POLLER_EVENT_TOCK"

    # ReceiptEnd component keys
    assert tocking.KERI_RECEIPT_INTERCEPT_TOCK_KEY == "KERI_RECEIPT_INTERCEPT_TOCK"

    # Reactor component keys
    assert tocking.KERI_REACTOR_MSG_TOCK_KEY == "KERI_REACTOR_MSG_TOCK"
    assert tocking.KERI_REACTOR_CUE_TOCK_KEY == "KERI_REACTOR_CUE_TOCK"
    assert tocking.KERI_REACTOR_ESCROW_TOCK_KEY == "KERI_REACTOR_ESCROW_TOCK"

    # Reactant component keys
    assert tocking.KERI_REACTANT_MSG_TOCK_KEY == "KERI_REACTANT_MSG_TOCK"
    assert tocking.KERI_REACTANT_CUE_TOCK_KEY == "KERI_REACTANT_CUE_TOCK"
    assert tocking.KERI_REACTANT_ESCROW_TOCK_KEY == "KERI_REACTANT_ESCROW_TOCK"

    # Respondant component keys
    assert tocking.KERI_RESPONDANT_CUE_TOCK_KEY == "KERI_RESPONDANT_CUE_TOCK"

    # WitnessReceiptor component keys
    assert tocking.KERI_WITNESS_RECEIPTOR_TOCK_KEY == "KERI_WITNESS_RECEIPTOR_TOCK"

    # WitnessInquisitor component keys
    assert tocking.KERI_WITNESS_INQUISITOR_TOCK_KEY == "KERI_WITNESS_INQUISITOR_TOCK"

    # WitnessPublisher component keys
    assert tocking.KERI_WITNESS_PUBLISHER_TOCK_KEY == "KERI_WITNESS_PUBLISHER_TOCK"

    """Done Test"""


if __name__ == "__main__":
    test_tocking_defaults()
    test_tocking_env_override()
    test_tocking_keys()
