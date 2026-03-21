# -*- encoding: utf-8 -*-
"""
keri.db.vdring module

Utility and support constants, functions, and classes

VIR  Verifiable Issuance(Revocation) Registry
VDR Verifiable Data Registry

"""

from dataclasses import dataclass, field

from ..recording import RawRecord

@dataclass
class RegistryRecord:
    """ Registry Key keyed by Registry name
    """
    registryKey: str
    prefix: str


@dataclass
class RegStateRecord(RawRecord):  # reger.state
    """
    Registry Event Log (REL) State information

    (see reger.state at 'stts' for database that holds these records  keyed by
    Registry SAID, i field)

    Attributes:
        vn (list[int]): version number [major, minor]
        i (str): registry SAID qb64 (registry inception event SAID)
        s (str): sequence number of latest event in KEL as hex str
        d (str): latest registry event digest qb64
        ii (str): registry issuer identifier aid qb64
        dt (str): datetime iso-8601 of registry state record update, usually now
        et (str): event packet type (ilk)
        bt (str): backer threshold hex num
        b (list[str]): backer aids qb64
        c (list[str]): config traits

    Note: the seal anchor dict 'a' field is not included in the state notice
    because it may be verbose and would impede the main purpose of a notice which
    is to trigger the download of the latest events, which would include the
    anchored seals.

    rsr = RegStateRecord(
            vn=list(version), # version number as list [major, minor]
            i=ri,  # qb64 registry SAID
            s="{:x}".format(sn),  # lowercase hex string no leading zeros
            d=said,
            ii=pre,
            dt=dts,
            et=eilk,
            bt="{:x}".format(toad),  # hex string no leading zeros lowercase
            b=wits,  # list of qb64 may be empty
            c=cnfg if cnfg is not None else [],
            )

    """
    vn: list[int] = field(default_factory=list)  # version number [major, minor] round trip serializable
    i: str = ''  # identifier prefix qb64
    s: str = '0'  # sequence number of latest event in KEL as hex str
    d: str = ''  # latest event digest qb64
    ii: str = ''  # issuer identifier of registry aid qb64
    dt: str = ''  # datetime of update of state record
    et: str = ''  # TEL evt packet type (ilk)
    bt: str = '0'  # backer threshold hex num str
    b: list = field(default_factory=list)  # backer AID list qb64
    c: list[str] = field(default_factory=list)  # config trait list


@dataclass
class VcStateRecord(RawRecord):
    vn: list[str] = field(default_factory=list)  # version number [major, minor] round trip serializable
    i: str = ''  # identifier prefix qb64
    s: str = '0'  # sequence number of latest event in KEL as hex str
    d: str = ''  # latest event digest qb64
    ri: str = ''  # registry identifier of registry aid qb64
    ra: dict = field(default_factory=dict)  # registry anchor for registry with backers
    a: dict = field(default_factory=dict)  # seal for anchor in KEL
    dt: str = ''  # datetime of update of state record
    et: str = ''  # TEL evt packet type (ilk)

