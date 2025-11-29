# -*- encoding: utf-8 -*-
"""
keri.app.tocking module

Centralized tock configuration for doer timing control.
Environment variables allow production tuning without code changes.

Tock values control how frequently doer methods execute:
- 0.0 = run as soon as possible (~31ms doist interval)
- 1.0 = run once per second
- Higher values = less frequent execution, lower CPU usage

"""
import os

# Witness component tocks (indirecting.py - WitnessStart)
KERI_WITNESS_MSG_TOCK_KEY = "KERI_WITNESS_MSG_TOCK"
KERI_WITNESS_ESCROW_TOCK_KEY = "KERI_WITNESS_ESCROW_TOCK"
KERI_WITNESS_CUE_TOCK_KEY = "KERI_WITNESS_CUE_TOCK"

WitnessMsgTock = float(os.getenv(KERI_WITNESS_MSG_TOCK_KEY, "0.0"))
WitnessEscrowTock = float(os.getenv(KERI_WITNESS_ESCROW_TOCK_KEY, "1.0"))
WitnessCueTock = float(os.getenv(KERI_WITNESS_CUE_TOCK_KEY, "0.25"))

# Indirector component tocks (indirecting.py - Indirector)
KERI_INDIRECTOR_MSG_TOCK_KEY = "KERI_INDIRECTOR_MSG_TOCK"
KERI_INDIRECTOR_CUE_TOCK_KEY = "KERI_INDIRECTOR_CUE_TOCK"
KERI_INDIRECTOR_ESCROW_TOCK_KEY = "KERI_INDIRECTOR_ESCROW_TOCK"

IndirectorMsgTock = float(os.getenv(KERI_INDIRECTOR_MSG_TOCK_KEY, "0.0"))
IndirectorCueTock = float(os.getenv(KERI_INDIRECTOR_CUE_TOCK_KEY, "0.25"))
IndirectorEscrowTock = float(os.getenv(KERI_INDIRECTOR_ESCROW_TOCK_KEY, "1.0"))

# MailboxDirector component tocks (indirecting.py - MailboxDirector)
KERI_MAILBOX_POLL_TOCK_KEY = "KERI_MAILBOX_POLL_TOCK"
KERI_MAILBOX_MSG_TOCK_KEY = "KERI_MAILBOX_MSG_TOCK"
KERI_MAILBOX_ESCROW_TOCK_KEY = "KERI_MAILBOX_ESCROW_TOCK"

MailboxPollTock = float(os.getenv(KERI_MAILBOX_POLL_TOCK_KEY, "0.5"))
MailboxMsgTock = float(os.getenv(KERI_MAILBOX_MSG_TOCK_KEY, "0.0"))
MailboxEscrowTock = float(os.getenv(KERI_MAILBOX_ESCROW_TOCK_KEY, "1.0"))

# Poller component tocks (indirecting.py - Poller)
KERI_POLLER_EVENT_TOCK_KEY = "KERI_POLLER_EVENT_TOCK"

PollerEventTock = float(os.getenv(KERI_POLLER_EVENT_TOCK_KEY, "0.5"))

# ReceiptEnd component tocks (indirecting.py - ReceiptEnd)
KERI_RECEIPT_INTERCEPT_TOCK_KEY = "KERI_RECEIPT_INTERCEPT_TOCK"

ReceiptInterceptTock = float(os.getenv(KERI_RECEIPT_INTERCEPT_TOCK_KEY, "0.1"))

# Reactor component tocks (directing.py - Reactor)
KERI_REACTOR_MSG_TOCK_KEY = "KERI_REACTOR_MSG_TOCK"
KERI_REACTOR_CUE_TOCK_KEY = "KERI_REACTOR_CUE_TOCK"
KERI_REACTOR_ESCROW_TOCK_KEY = "KERI_REACTOR_ESCROW_TOCK"

ReactorMsgTock = float(os.getenv(KERI_REACTOR_MSG_TOCK_KEY, "0.0"))
ReactorCueTock = float(os.getenv(KERI_REACTOR_CUE_TOCK_KEY, "0.25"))
ReactorEscrowTock = float(os.getenv(KERI_REACTOR_ESCROW_TOCK_KEY, "1.0"))

# Reactant component tocks (directing.py - Reactant)
KERI_REACTANT_MSG_TOCK_KEY = "KERI_REACTANT_MSG_TOCK"
KERI_REACTANT_CUE_TOCK_KEY = "KERI_REACTANT_CUE_TOCK"
KERI_REACTANT_ESCROW_TOCK_KEY = "KERI_REACTANT_ESCROW_TOCK"

ReactantMsgTock = float(os.getenv(KERI_REACTANT_MSG_TOCK_KEY, "0.0"))
ReactantCueTock = float(os.getenv(KERI_REACTANT_CUE_TOCK_KEY, "0.25"))
ReactantEscrowTock = float(os.getenv(KERI_REACTANT_ESCROW_TOCK_KEY, "1.0"))

# Respondant component tocks (storing.py - Respondant)
KERI_RESPONDANT_CUE_TOCK_KEY = "KERI_RESPONDANT_CUE_TOCK"

RespondantCueTock = float(os.getenv(KERI_RESPONDANT_CUE_TOCK_KEY, "0.25"))

# WitnessReceiptor component tocks (agenting.py)
KERI_WITNESS_RECEIPTOR_TOCK_KEY = "KERI_WITNESS_RECEIPTOR_TOCK"

WitnessReceiptorTock = float(os.getenv(KERI_WITNESS_RECEIPTOR_TOCK_KEY, "0.0"))

# WitnessInquisitor component tocks (agenting.py)
KERI_WITNESS_INQUISITOR_TOCK_KEY = "KERI_WITNESS_INQUISITOR_TOCK"

WitnessInquisitorTock = float(os.getenv(KERI_WITNESS_INQUISITOR_TOCK_KEY, "1.0"))

# WitnessPublisher component tocks (agenting.py)
KERI_WITNESS_PUBLISHER_TOCK_KEY = "KERI_WITNESS_PUBLISHER_TOCK"

WitnessPublisherTock = float(os.getenv(KERI_WITNESS_PUBLISHER_TOCK_KEY, "0.25"))
