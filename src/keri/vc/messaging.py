# -*- encoding: utf-8 -*-
"""
keri.vc.messaging module

Utility functions for creating ACDC messages of all message types for v2

"""
from collections.abc import Mapping

from ..kering import versify, Protocols, Kinds, Ilks, Vrsn_2_0
from ..core import Number, Noncer, SerderACDC, Mapper
from ..help import nowIso8601

def regcept(issuer, *, uuid=None, stamp=None,
            pvrsn=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json):
    """Utility function to create registry inception message of type 'rip'
    for ACDC protocol v2.

    Returns:
        serder (SerderACDC): instance of ACDC 'rip' message

    Parameters:
        issuer  (str): qb64 of issuer AID
        uuid (str|None): qb64 of salty nonce (UUID) if any.
                         None means create random uuid on the fly
        stamp (str|None):  date-time-stamp RFC-3339 profile of ISO-8601 datetime of
                           creation of message. None means use

        pvrsn (Versionage): ACDC protocol version number
        gvrsn (Versionage): CESR Genus version number
        kind (str): serialization kind from Kinds

    alls (v='', t='', d='', u='', i='', n='', dt='')
    opts (,)
    """
    vs = versify(proto=Protocols.acdc, pvrsn=pvrsn, kind=kind, size=0, gvrsn=gvrsn)
    ilk = Ilks.rip
    uuid = uuid if uuid is not None else Noncer().qb64
    snh = Number(num=0).numh  # sn for registry incept must be 0
    stamp = stamp if stamp is not None else nowIso8601()
    sad = dict(v=vs, t=ilk, d='', u=uuid, i=issuer, n=snh, dt=stamp)
    return SerderACDC(sad=sad, makify=True)


def blindate(regid, prior, blid, *, sn=1, stamp=None,
            pvrsn=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json):
    """Utility function to create registry blindable update message of type 'bup'
    for ACDC protocol v2.

    Returns:
        serder (SerderACDC): instance of ACDC 'bup' message

    Parameters:
        regid  (str): qb64 registry SAID  (said, 'd' field of 'rip')
        prior  (str): qb64 prior message SAID  (said, 'd' field of 'rip' or 'bup')
        blid  (str): qb64 blindable state attribute block said (not its uuid)
        sn (int): sequence number of blindable update message
        stamp (str|None):  date-time-stamp RFC-3339 profile of ISO-8601 datetime of
                           creation of message. None means use

        pvrsn (Versionage): ACDC protocol version number
        gvrsn (Versionage): CESR Genus version number
        kind (str): serialization kind from Kinds

    alls (v='', t='', d='', rd='', n='', p='', dt='', b='')
    opts (,)
    """
    vs = versify(proto=Protocols.acdc, pvrsn=pvrsn, kind=kind, size=0, gvrsn=gvrsn)
    ilk = Ilks.bup
    snh = Number(num=sn).numh  # sn for registry incept must be 0
    stamp = stamp if stamp is not None else nowIso8601()
    sad = dict(v=vs, t=ilk, d='', rd=regid, n=snh, p=prior, dt=stamp, b=blid)
    return SerderACDC(sad=sad, makify=True)


def update(regid, prior, acdc, state, *, sn=1, stamp=None,
            pvrsn=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json):
    """Utility function to create registry update message of type 'upd'
    for ACDC protocol v2.

    Returns:
        serder (SerderACDC): instance of ACDC 'bup' message

    Parameters:
        regid  (str): qb64 registry SAID  (said, 'd' field of 'rip')
        prior  (str): qb64 prior message SAID  (said, 'd' field of 'rip' or 'upd')
        acdc  (str): transaction event ACDC SAID qb64
                        'd' field of associated acdc 'acm', 'ace', 'act', 'acg'
        state  (str): transaction event state string
        sn (int): sequence number of blindable update message
        stamp (str|None):  date-time-stamp RFC-3339 profile of ISO-8601 datetime of
                           creation of message. None means use

        pvrsn (Versionage): ACDC protocol version number
        gvrsn (Versionage): CESR Genus version number
        kind (str): serialization kind from Kinds

    alls (v='', t='', d='', rd='', n='', p='', dt='', td='', ts='')
    opts (,)
    """
    vs = versify(proto=Protocols.acdc, pvrsn=pvrsn, kind=kind, size=0, gvrsn=gvrsn)
    ilk = Ilks.upd
    snh = Number(num=sn).numh  # sn for registry incept must be 0
    stamp = stamp if stamp is not None else nowIso8601()
    sad = dict(v=vs, t=ilk, d='', rd=regid, n=snh, p=prior, dt=stamp, td=acdc, ts=state)
    return SerderACDC(sad=sad, makify=True)


def actSchemaDefault(kind=Kinds.json):
    """Utility function to create default schema dict for act message

    Returns:
        tuple(str, dict): of form (said[str], sad[dict]) where,
            said is computed on default schema with serialization of kind
            sad is defualt schema with substituted said


    Parameters:
        kind (str): serializaiton kind from Kinds used to compute said

    """
    mad = \
    {
        "$id": "",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "ACT Default Schema",
        "description": "Default JSON Schema for act ACDC.",
        "credentialType": "ACDC_act_message",
        "version": "2.0.0",
        "type": "object",
        "required":
        [
          "v",
          "d",
          "u",
          "i",
          "rd",
          "s",
          "a",
          "e",
          "r"
        ],
        "properties":
        {
            "v":
            {
                "description": "ACDC version string",
                "type": "string"
            },
            "d":
            {
                "description": "Message SAID",
                "type": "string"
            },
            "u":
            {
                "description": "Message UUID",
                "type": "string"
            },
            "i":
            {
                "description": "Issuer AID",
                "type": "string"
            },
            "rd":
            {
                "description": "Registry SAID",
                "type": "string"
            },
            "s":
            {
                "description": "Schema Section",
                "oneOf":
                [
                    {
                      "description": "Schema Section SAID",
                      "type": "string"
                    },
                    {
                      "description": "Uncompacted Schema Section",
                      "type": "object"
                    }
                ]
            },
            "a":
            {
                "description": "Attribute Section",
                "oneOf":
                [
                    {
                      "description": "Attribute Section SAID",
                      "type": "string"
                    },
                    {
                      "description": "Uncompacted Attribute Section",
                      "type": "object"
                    }
                ]
            },
            "e":
            {
                "description": "Edge Section",
                "oneOf":
                [
                    {
                      "description": "Edge Section SAID",
                      "type": "string"
                    },
                    {
                      "description": "Uncompacted Edge Section",
                      "type": "object"
                    }
                ]
            },
            "r":
            {
                "description": "Rule Section",
                "oneOf":
                [
                    {
                      "description": "Rule Section SAID",
                      "type": "string"
                    },
                    {
                      "description": "Uncompacted Rule Section",
                      "type": "object"
                    }
                ]
            }
        },
        "additionalProperties": False
    }

    mapper = Mapper(mad=mad, makify=True, strict=False, saids={"$id": 'E',},
                    saidive=True, kind=kind)
    return (mapper.said, mapper.mad)


def attribute(issuer, uuid=None, regid=None, schema=None, attrs=None,
              issuee=None, edges=None, rules=None,
            pvrsn=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json):
    """Utility function to create top-level fixed field ACDC message of type 'act'
    for ACDC protocol v2.

    Returns:
        serder (SerderACDC): instance of ACDC message

    Parameters:
        issuer  (str): qb64 of issuer AID
        uuid (str|None): qb64 of salty nonce (UUID) if any.
                         None means use empty string for value
        regid (str|None): qb64 of registry SAID if any.
                             None means use empty string for value
        schema (str|dict): SAID of schema section or schema section block
                           None means use default schema for value

        attrs (str|dict|None): SAID of attribute section block
                                    None means use empty dict for value
        issuee (str): qb64 of issuee AID if any to insert in attribute section
                      when attributes is a Mapping.
                      None means do not insert issuee
        edges (str|dict|None): SAID of edge section block.
                               None means use empty dict for value
        rules (str|dict|None): SAID of rule section block
                               None means use empty dict for value
        pvrsn (Versionage): ACDC protocol version number
        gvrsn (Versionage): CESR Genus version number.
        kind (str): serialization kind from Kinds

    all
    (v='', t='', d='', u='', i='', rd='', s='', a='', e='', r='')
    opts
    ()

    ACDC .sad and its serialization .raw. Is whatever in input to the serder. Its
    degree of compactification is whatever is input to the Serder. In the case of
    the .raw its the over the wire serialization to be deserialized.

    This is the same semantic as for KERI messages except that for ACDCs the
    SAIDS and nested SAIDs in ACDCs are calculated using the most compact algorithm.
    So if the serder gets an uncompacted sad or an uncompated raw, these become
    .sad and .raw.  These may be a received disclosure or a disclosure
    to be sent at any stage in a graduated disclosure.  The serialization of
    the uncompacted sad is special since its said is not literally the said of
    its  uncompact serialization but is the SAID of its most compact form.

    Essentially makify and verify for ACDCs is different because of most compact
    SAID computation.
    """
    vs = versify(proto=Protocols.acdc, pvrsn=pvrsn, kind=kind, size=0, gvrsn=gvrsn)
    ilk = Ilks.act
    uuid = uuid if uuid is not None else ""
    regid = regid if regid is not None else ""
    if schema is None:
        ssaid, ssad = actSchemaDefault(kind=kind)
        schema = ssad

    attrs = attrs if attrs is not None else {}
    if issuee is not None and isinstance(attrs, Mapping):
        attrs['i'] = issuee
    edges = edges if edges is not None else {}
    rules = rules if rules is not None else {}

    sad = dict(v=vs, t=ilk, d='', u=uuid, i=issuer, rd=regid,
               s=schema, a=attrs, e=edges, r=rules)
    return SerderACDC(sad=sad, makify=True)


def classic(issuer, schema, ilk=None, issuee=None, nonce=None, registry=None,
            attributes=None, aggregates=None, edges=None, rules=None,
            pvrsn=Vrsn_2_0, gvrsn=None, kind=Kinds.json):  #acedice
    """Utility function to create top-level field map ACDC message of type 'acm'
    for ACDC protocol v2.

    Returns:
        serder (SerderACDC): instance of ACDC message

    Parameters:
        issuer  (str): qb64 of issuer AID
        schema (str|dict): SAID of schema section or schema section block
        ilk (str|None): message type as 3 char str or None if not present
        issuee (str): qb64 of issuee AID if any. None means no issuee
        nonce (str|None): qb64 of salty nonce (UUID) if any. None means no UUID
        registry (str|None): qb64 of registry SAID if any. None means no registry
        attributes (str|dict|None): SAID of attribute section block or None if
                                    not present
        aggregates (str|dict|None): SAID of aggregate section list or None if
                                    not present
        edges (str|dict|None): SAID of edge section block or None if
                                    not present
        rules (str|dict|None): SAID of rule section block or None if
                                    not present
        pvrsn (Versionage): ACDC protocol version number
        gvrsn (Versionage|None): CESR Genus version number. None means default
                                 to pvrsn
        kind (str): serialization kind from Kinds



    all
    (v='', d='', u='', i='', rd='', s='', a={}, A=[], e={}, r={}),
    opts
    (u='', rd='', a='', A='', e='', r='')

    So check that Serder reorders fields so in right order so this function
    can conditionally add optional fields in other order or either way
    could follow order but put if conditions on optional fields


    ACDC .sad and its serialization .raw. Is whatever in input to the serder. Its
    degree of compactification is whatever is input to the Serder. In the case of
    the .raw its the over the wire serialization to be deserialized.
    This is the same semantic as for KERI messages except that for ACDCs the
    SAIDS and nested SAIDs in ACDCs are calculated using the most compact algorithm.
    So if the serder gets an uncompacted sad or an uncompated raw, these become
    .sad and .raw.  These may be a received disclosure or a disclosure
    to be sent at any stage in a graduated disclosure.  The serialization of
    the uncompacted sad is special since its said is not literally the said of
    its  uncompact serialization but is the SAID of its most compact form.

    ACDC .csad and its serialization .craw is the most compact sad and raw
    respectively. This must be generated in order to compute the SAID of the ACDC,
    as well the SAIDs of any nested parts of the uncompacted sad regardless of
    degree of compactness. The most compact SAID is the one that is anchored in
    its TEL. The most compact said is literally the said of .csad computed via
    the most compact serialization .craw

    So need to hoist serder SAID calculation code to own method so ACDC can
    override SAID calculation with most compact variant SAID calculation.
    For ACDC, its .sad SAID is the most compact SAID at result of most compact
    calculation. Therefor to generate .sad take given sad and then perform most
    compact algorithm and then assign to .sad

    so makify and verify for ACDCs is different because of most compact SAID


    """
    vs = versify(pvrsn=pvrsn, kind=kind, size=0, gvrsn=gvrsn)

    sad = dict()


    ilk = Ilks.acm


    tholder = Tholder(sith=isith)
    if tholder.num is not None and tholder.num < 1:
        raise ValueError(f"Invalid sith = {tholder.num} less than 1.")
    if tholder.size > len(keys):
        raise ValueError(f"Invalid sith = {tholder.num} for keys = {keys}")

    if ndigs is None:
        ndigs = []

    if nsith is None:
        nsith = max(0, ceil(len(ndigs) / 2))

    ntholder = Tholder(sith=nsith)
    if ntholder.num is not None and ntholder.num < 0:
        raise ValueError(f"Invalid nsith = {ntholder.num} less than 0.")
    if ntholder.size > len(ndigs):
        raise ValueError(f"Invalid nsith = {ntholder.num} for keys = {ndigs}")


    wits = wits if wits is not None else []
    if len(oset(wits)) != len(wits):
        raise ValueError(f"Invalid wits = {wits}, has duplicates.")

    if toad is None:
        if not wits:
            toad = 0
        else:  # compute default f and m for len(wits)
            toad = ample(len(wits))
    toader = Number(num=toad)

    if wits:
        if toader.num < 1 or toader.num > len(wits):  # out of bounds toad
            raise ValueError(f"Invalid toad = {toader.num} for wits = {wits}")
    else:
        if toader.num != 0:  # invalid toad
            raise ValueError(f"Invalid toad = {toader.num} for wits = {wits}")

    cnfg = cnfg if cnfg is not None else []

    data = data if data is not None else []
    if not isinstance(data, list):
        raise ValueError(f"Expected list got {data=}")

    ked = dict(v=vs,  # version string
               t=ilk,
               d="",   # qb64 SAID
               i="",  # qb64 prefix
               s=sner.numh,  # hex string no leading zeros lowercase
               kt=(tholder.num if intive and tholder.num is not None and
                   tholder.num <= MaxIntThold else tholder.sith),
               k=keys,  # list of qb64
               nt=(ntholder.num if intive and ntholder.num is not None and
                   ntholder.num <= MaxIntThold else ntholder.sith),
               n=ndigs,  # list of hashes qb64
               bt=toader.num if intive and toader.num <= MaxIntThold else toader.numh,
               b=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               a=data,  # list of seal dicts
               )

    pre = ""
    saids = None
    if delpre is not None:  # delegated inception with ilk = dip
        ked['di'] = delpre  # SerderKERI .verify will ensure valid prefix
    else:  # non delegated
        if (code is None or code not in DigDex) and len(keys) == 1:  # use key[0] as default
            ked["i"] = keys[0]  # SerderKERI .verify will ensure valid prefix

    if code is not None and code in PreDex:  # use code to override all else
        saids = {'i': code}

    serder = serdering.SerderKERI(sad=ked, makify=True, saids=saids)
    return serder
