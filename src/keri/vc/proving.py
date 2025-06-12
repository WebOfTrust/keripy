# -*- encoding: utf-8 -*-
"""
keri.vc.proving module

"""

from typing import Optional, Union

from .. import core
from .. import help
from ..core import coring, serdering
from ..core.coring import (Kinds, versify)
from ..help import helping
from ..kering import Version

KERI_REGISTRY_TYPE = "KERICredentialRegistry"

logger = help.ogler.getLogger()


def credential(schema:str,
               issuer:str,
               data:dict,
               recipient:Optional[str]=None,
               private:bool=False,
               private_credential_nonce:Optional[str]=None,
               private_subject_nonce:Optional[str]=None,
               status:str=None,
               source:Union[dict, list]=None,
               rules:Union[dict, list]=None,
               version:Version=Version,
               kind:Kinds=Kinds.json):
    """Utility function to create an ACDC. Creates dict SAD for credential from
    parameters and Saidifyies it before creation.

    Parameters:
        schema (str): SAID of schema for this credential
        issuer (str): qb64 identifier prefix of the issuer
        data (dict): of the values being assigned to the subject of this credential
        recipient (Optional[str]): qb64 identifier prefix of the recipient
        private (bool): apply nonce used for privacy preserving ACDC
        private_credential_nonce (Optional[str]): nonce used for privacy vc
        private_subject_nonce (Optional[str]): nonce used for subject
        status (str): qb64 said of the credential registry
        source (Union[dict, list]): of source credentials to which this credential is chained
        rules (Union[dict, list]): ACDC rules section for credential
        version (Version): version instance
        kind (Kinds): serialization kind

    Returns:
        serdering.SerderACDC: credential instance

    """
    vs = versify(proto=coring.Protocols.acdc, pvrsn=version, kind=kind, size=0)

    vc = dict(
        v=vs,
        d="",
    )

    subject = dict(
        d="",
    )

    if private:
        vc["u"] = private_credential_nonce if private_credential_nonce is not None else core.Salter().qb64
        subject["u"] = private_subject_nonce if private_subject_nonce is not None else core.Salter().qb64

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

    #_, vc = coring.Saider.saidify(sad=vc)

    return serdering.SerderACDC(sad=vc, makify=True)



