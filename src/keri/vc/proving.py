# -*- encoding: utf-8 -*-
"""
keri.vc.proving module

"""

from collections.abc import Iterable
from typing import Union

from .. import help
from ..core import coring, serdering
from ..core.coring import (Serials, versify)
from ..db import subing
from ..kering import Version
from ..help import helping

KERI_REGISTRY_TYPE = "KERICredentialRegistry"

logger = help.ogler.getLogger()


def credential(schema,
               issuer,
               data,
               recipient=None,
               private=False,
               salt=None,
               status=None,
               source=None,
               rules=None,
               version=Version,
               kind=Serials.json):
    """Utility function to create an ACDC. Creates dict SAD for credential from
    parameters and Saidifyies it before creation.

    Parameters:
        schema (SAID): of schema for this credential
        issuer (str): qb64 identifier prefix of the issuer
        status (str): qb64 said of the credential registry
        recipient (Option[str|None]): qb64 identifier prefix of the recipient
        data (dict): of the values being assigned to the subject of this credential
        private (bool): apply nonce used for privacy preserving ACDC
        salt (string): salt for nonce
        source (dict | list): of source credentials to which this credential is chained
        rules (dict | list): ACDC rules section for credential
        version (Version): version instance
        kind (Serials): serialization kind

    Returns:
        SerderACDC: credential instance

    """
    vs = versify(proto=coring.Protos.acdc, version=version, kind=kind, size=0)

    vc = dict(
        v=vs,
        d="",
    )

    subject = dict(
        d="",
    )

    if private:
        vc["u"] = salt if salt is not None else coring.Salter().qb64
        subject["u"] = salt if salt is not None else coring.Salter().qb64

    if recipient is not None:
        subject['i'] = recipient

    subject["dt"] = data["dt"] if "dt" in data else helping.nowIso8601()

    subject |= data

    vc |= dict(
        i=issuer,
    )

    if status is not None:
        vc["ri"] = status

    vc |= dict(
        s=schema,
        a={},
    )

    if source is not None:
        vc["e"] = source

    if rules is not None:
        vc["r"] = rules

    _, sad = coring.Saider.saidify(sad=subject, kind=kind, label=coring.Saids.d)
    vc["a"] = sad

    _, vc = coring.Saider.saidify(sad=vc)

    return serdering.SerderACDC(sad=vc)
