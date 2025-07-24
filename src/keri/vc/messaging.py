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


def acdcmap(issuer, ilk=Ilks.acm, uuid=None, regid=None, schema=None,
            attribute=None, issuee=None, aggregate=None, edge=None, rule=None,
            pvrsn=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json, compactify=False):
    """Utility function to create top-level field map ACDC message of type 'acm'
    for ACDC protocol v2.

    Returns:
        serder (SerderACDC): instance of ACDC message

    Parameters:
        issuer  (str): qb64 of issuer AID
        ilk  (str|None): message type of Ilks. Default include field value 'acm'
                          None means do not include field
        uuid (str|None): qb64 of salty nonce (UUID) if any.
                         None means do not include field
        regid (str|None): qb64 of registry SAID if any.
                             None means do not include field
        schema (str|dict): SAID of schema section or schema section block
                           None means use default schema for value
        attribute (str|dict|None): SAID of attribute section or dict of
                                   attribute section block
                                    None means do not include field
                                    either attribute or aggregate is required
        issuee (str): qb64 of issuee AID if any to insert in attribute section
                      when attributes is a Mapping.
                      None means do not insert issuee
        aggregate (str|list|None): SAID of aggregate section or list of
                                   aggregate element blocks
                                   None means do not include field
                                   either attribute or aggregate is required
        edge (str|dict|None): SAID of edge section or dict of edge section block
                               None means do not include field
        rule (str|dict|None): SAID of rule section or dict of rule section block
                               None means do not include field
        pvrsn (Versionage): ACDC protocol version number
        gvrsn (Versionage): CESR Genus version number.
        kind (str): serialization kind from Kinds
        compactify (bool): True means make the most compact sad variant if any
                               False means do not make the most compact variant
                               Default is False

    alls= (v='', t='', d='', u='', i='', rd='', s='', a='', A='', e='', r=''),
    opts= (t='', u='', rd='', a='', A='', e='', r=''),
    alts= (a="A", A="a"),

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
    ilk = Ilks.acm if ilk is not None else None  # must be Ilk.acm or None
    if schema is None:
        ssaid, ssad = acmSchemaDefault(kind=kind)
        schema = ssad

    if issuee is not None and isinstance(attribute, Mapping):
        attribute['i'] = issuee

    if ((attribute is not None and aggregate is not None) or
            (attribute is None and aggregate is None)):
        raise ValueError(f"Either one or the other but not both of attribute "
                         f"and aggregate is required")

    sad = dict(v=vs)
    if ilk is not None:
        sad['t'] = ilk
    sad['d'] = ''
    if uuid is not None:
        sad['u'] = uuid
    sad['i'] = issuer
    if regid is not None:
        sad['rd'] = regid
    sad['s'] = schema
    if attribute is not None:
        sad['a'] = attribute
        if isinstance(attribute, Mapping):
            if issuee is not None:
                sad['a']['i'] = issuee
    if aggregate is not None:
        sad['A'] = aggregate
    if edge is not None:
        sad['e'] = edge
    if rule is not None:
        sad['r'] = rule

    return SerderACDC(sad=sad, makify=True, compactify=compactify)


def acdcatt(issuer, uuid=None, regid=None, schema=None, attribute=None,
              issuee=None, edge=None, rule=None,
            pvrsn=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json, compactify=False):
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

        attribute (str|dict|None): SAID of attribute section or dict of
                                   attribute section block
                                    None means use empty dict for value
        issuee (str): qb64 of issuee AID if any to insert in attribute section
                      when attributes is a Mapping.
                      None means do not insert issuee
        edge (str|dict|None): SAID of edge section or dict of edge section block
                               None means use empty dict for value
        rule (str|dict|None): SAID of rule section or dict of rule section block
                               None means use empty dict for value
        pvrsn (Versionage): ACDC protocol version number
        gvrsn (Versionage): CESR Genus version number.
        kind (str): serialization kind from Kinds
        compactify (bool): True means make the most compact sad variant if any
                               False means do not make the most compact variant
                               Default is False

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

    attribute = attribute if attribute is not None else {}
    if issuee is not None and isinstance(attribute, Mapping):
        attribute['i'] = issuee
    edge = edge if edge is not None else {}
    rule = rule if rule is not None else {}

    sad = dict(v=vs, t=ilk, d='', u=uuid, i=issuer, rd=regid,
               s=schema, a=attribute, e=edge, r=rule)
    return SerderACDC(sad=sad, makify=True, compactify=compactify)


def acdcagg(issuer, uuid=None, regid=None, schema=None, aggregate=None,
                    edge=None, rule=None,
            pvrsn=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json, compactify=False):
    """Utility function to create top-level fixed field ACDC message of type 'acg'
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

        aggregate (str|list|None): AGID of aggregate section or list of
                                   aggregate section block
                                   None means use empty list for value
        edge (str|dict|None): SAID of edge section or dict of edge section block
                               None means use empty dict for value
        rule (str|dict|None): SAID of rule section or dict of rule section block
                               None means use empty dict for value
        pvrsn (Versionage): ACDC protocol version number
        gvrsn (Versionage): CESR Genus version number.
        kind (str): serialization kind from Kinds
        compactify (bool): True means make the most compact sad variant if any
                               False means do not make the most compact variant
                               Default is False

    all
    (v='', t='', d='', u='', i='', rd='', s='', A='', e='', r='')
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
    ilk = Ilks.acg
    uuid = uuid if uuid is not None else ""
    regid = regid if regid is not None else ""
    if schema is None:
        ssaid, ssad = actSchemaDefault(kind=kind)
        schema = ssad

    aggregate = aggregate if aggregate is not None else []
    edge = edge if edge is not None else {}
    rule = rule if rule is not None else {}

    sad = dict(v=vs, t=ilk, d='', u=uuid, i=issuer, rd=regid,
               s=schema, A=aggregate, e=edge, r=rule)
    return SerderACDC(sad=sad, makify=True, compactify=compactify)


def sectschema(schema, pvrsn=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json):
    """Utility function to create top-level fixed field schema section message
    of type 'sch' for ACDC protocol v2.

    Returns:
        serder (SerderACDC): instance of ACDC message

    Parameters:
        schema (str|dict): SAID of schema section or schema section block
        pvrsn (Versionage): ACDC protocol version number
        gvrsn (Versionage): CESR Genus version number.
        kind (str): serialization kind from Kinds

    all
    (v='', t='', d='', s='')
    opts
    ()
    """
    vs = versify(proto=Protocols.acdc, pvrsn=pvrsn, kind=kind, size=0, gvrsn=gvrsn)
    ilk = Ilks.sch
    sad = dict(v=vs, t=ilk, d='', s=schema)
    return SerderACDC(sad=sad, makify=True)


def sectattr(attribute, pvrsn=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json):
    """Utility function to create top-level fixed field attribute section message
    of type 'att' for ACDC protocol v2.

    Returns:
        serder (SerderACDC): instance of ACDC message

    Parameters:
        attribute (str|dict): SAID of attribute section or attribute section block
        pvrsn (Versionage): ACDC protocol version number
        gvrsn (Versionage): CESR Genus version number.
        kind (str): serialization kind from Kinds

    all
    (v='', t='', d='', a='')
    opts
    ()
    """
    vs = versify(proto=Protocols.acdc, pvrsn=pvrsn, kind=kind, size=0, gvrsn=gvrsn)
    ilk = Ilks.att
    sad = dict(v=vs, t=ilk, d='', a=attribute)
    return SerderACDC(sad=sad, makify=True)


def sectaggr(aggregate, pvrsn=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json):
    """Utility function to create top-level fixed field aggregate section message
    of type 'agg' for ACDC protocol v2.

    Returns:
        serder (SerderACDC): instance of ACDC message

    Parameters:
        aggregate (str|dict): AGID of aggregate section or aggregate section list
        pvrsn (Versionage): ACDC protocol version number
        gvrsn (Versionage): CESR Genus version number.
        kind (str): serialization kind from Kinds

    all
    (v='', t='', d='', A='')
    opts
    ()
    """
    vs = versify(proto=Protocols.acdc, pvrsn=pvrsn, kind=kind, size=0, gvrsn=gvrsn)
    ilk = Ilks.agg
    sad = dict(v=vs, t=ilk, d='', A=aggregate)
    return SerderACDC(sad=sad, makify=True)


def sectedge(edge, pvrsn=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json):
    """Utility function to create top-level fixed field edge section message
    of type 'edg' for ACDC protocol v2.

    Returns:
        serder (SerderACDC): instance of ACDC message

    Parameters:
        edge (str|dict): SAID of edge section or edge section block
        pvrsn (Versionage): ACDC protocol version number
        gvrsn (Versionage): CESR Genus version number.
        kind (str): serialization kind from Kinds

    all
    (v='', t='', d='', e='')
    opts
    ()
    """
    vs = versify(proto=Protocols.acdc, pvrsn=pvrsn, kind=kind, size=0, gvrsn=gvrsn)
    ilk = Ilks.edg
    sad = dict(v=vs, t=ilk, d='', e=edge)
    return SerderACDC(sad=sad, makify=True)


def sectrule(rule, pvrsn=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json):
    """Utility function to create top-level fixed field rule section message
    of type 'rul' for ACDC protocol v2.

    Returns:
        serder (SerderACDC): instance of ACDC message

    Parameters:
        rule (str|dict): SAID of rule section or rule section block
        pvrsn (Versionage): ACDC protocol version number
        gvrsn (Versionage): CESR Genus version number.
        kind (str): serialization kind from Kinds

    all
    (v='', t='', d='', r='')
    opts
    ()
    """
    vs = versify(proto=Protocols.acdc, pvrsn=pvrsn, kind=kind, size=0, gvrsn=gvrsn)
    ilk = Ilks.rul
    sad = dict(v=vs, t=ilk, d='', r=rule)
    return SerderACDC(sad=sad, makify=True)


def sectionate(issuer, ilk=Ilks.acm, uuid=None, regid=None, schema=None,
            attribute=None, issuee=None, aggregate=None, edge=None, rule=None,
            pvrsn=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json, compactify=False):
    """Utility function to create top-level acdc message in most compact form and
    the associated section messages.

    Returns:
        msgs (tuple): of form (acdc, schema, attr, aggr, edge, rule) where:
            acdc (SerderACDC): instance of ilk of either 'acm', 'act', or 'acg'
            sch (SerderACDC): instance of ilk 'sch'
            att (SerderACDC|None): instance of ilk 'att' or None
            agg (SerderACDC|None): instance of ilk 'agg' or None
            edg (SerderACDC): instance of ilk 'edg'
            rul (SerderACDC): instance of ilk 'rul'

    Parameters:
        issuer  (str): qb64 of issuer AID
        ilk  (str|None): message type from Ilks for acdc in most compact form.
                        may be one of (None, 'acm','act','acg')
                        default is 'acm'
                        None means do not include ilk field so implicit 'acm'.
        uuid (str|None): qb64 of salty nonce (UUID) if any.
                         None means do not include field
        regid (str|None): qb64 of registry SAID if any.
                             None means do not include field
        schema (str|dict): SAID of schema section or schema section block
                           None means use default schema for value
        attribute (str|dict|None): SAID of attribute section or dict of
                                   attribute section block
                                    None means do not include field
                                    either attribute or aggregate is required
        issuee (str): qb64 of issuee AID if any to insert in attribute section
                      when attributes is a Mapping.
                      None means do not insert issuee
        aggregate (str|list|None): SAID of aggregate section or list of
                                   aggregate element blocks
                                   None means do not include field
                                   either attribute or aggregate is required
        edge (str|dict|None): SAID of edge section or dict of edge section block
                               None means do not include field
        rule (str|dict|None): SAID of rule section or dict of rule section block
                               None means do not include field
        pvrsn (Versionage): ACDC protocol version number
        gvrsn (Versionage): CESR Genus version number.
        kind (str): serialization kind from Kinds
        compactify (bool): True means make the most compact sad variant if any
                               False means do not make the most compact variant
                               Default is False


    """
    if ilk not in (None, Ilks.acm, Ilks.act, Ilks.acg):
        raise ValueError(f"Invalid {ilk=} must be one of ({None}, {Ilks.acm}, "
                         f"{Ilks.act}, {Ilks.acg})")

    if ((attribute is not None and aggregate is not None) or
            (attribute is None and aggregate is None)):
        raise ValueError(f"Either one or the other but not both of attribute "
                         f"and aggregate is required")

    if ilk == Ilks.act and attribute is None:
        raise ValueError(f"Invalid attribute=None for {ilk=}")

    if ilk == Ilks.acg and aggregate is None:
        raise ValueError(f"Invalid aggregate=None for {ilk=}")

    if issuee is not None and isinstance(attribute, Mapping):
        attribute['i'] = issuee

    if schema is None:
        if ilk == Ilks.act:
            ssaid, ssad = actSchemaDefault(kind=kind)

        elif ilk == Ilks.acg:
            ssaid, ssad = acgSchemaDefault(kind=kind)

        else:
            ssaid, ssad = acmSchemaDefault(kind=kind)
    elif isinstance(schema, str):
        ssaid = ssad = schema

    else:
        smapper = Mapper(mad=schema, makify=True, strict=False,
                         saids={'$id': 'E',}, saidive=True, kind=kind)
        ssaid = smapper.said
        ssad = smapper.mad

    sch = sectschema(schema=ssad, pvrsn=pvrsn, gvrsn=gvrsn, kind=kind)

    if ilk == Ilks.act:

        acdc = acdcatt(issuer, uuid=uuid, regid=regid, schema=ssaid,
                       attribute=attribute, issuee=issuee,
                       edge=edge, rule=rule,
                       pvrsn=pvrsn, gvrsn=gvrsn, kind=kind, compactify=True)
        att = sectattr(attribute, pvrsn=pvrsn, gvrsn=gvrsn, kind=kind)
        agg = None

    elif ilk == Ilks.acg:
        acdc = acdcagg(issuer, uuid=uuid, regid=regid, schema=ssaid,
                       aggregate=aggregate, edge=edge, rule=rule,
                       pvrsn=pvrsn, gvrsn=gvrsn, kind=kind, compactify=True)
        att = None
        agg = sectaggr(aggregate, pvrsn=pvrsn, gvrsn=gvrsn, kind=kind)


    else:
        acdc = acdcmap(issuer=issuer, ilk=ilk, uuid=uuid, regid=regid,
                       schema=ssaid, attribute=attribute, issuee=issuee,
                       aggregate=aggregate, edge=edge, rule=rule,
                       pvrsn=pvrsn, gvrsn=gvrsn, kind=kind, compactify=True)
        att = agg = None
        if attribute is not None:
            att = sectattr(attribute, pvrsn=pvrsn, gvrsn=gvrsn, kind=kind)
        elif aggregate is not None:
            agg = sectaggr(aggregate, pvrsn=pvrsn, gvrsn=gvrsn, kind=kind)


    edg = sectedge(edge, pvrsn=pvrsn, gvrsn=gvrsn, kind=kind)
    rul = sectrule(rule, pvrsn=pvrsn, gvrsn=gvrsn, kind=kind)

    return (acdc, sch, att, agg, edg, rul)


def acmSchemaDefault(kind=Kinds.json):
    """Utility function to create default schema dict for acm message

    Returns:
        tuple(str, dict): of form (said[str], sad[dict]) where,
            said is computed on default schema with serialization of kind
            sad is default schema with substituted said


    Parameters:
        kind (str): serializaiton kind from Kinds used to compute said

    alls= (v='', t='', d='', u='', i='', rd='', s='', a='', A='', e='', r=''),
    opts= (t='', u='', rd='', a='', A='', e='', r=''),
    alts= (a="A", A="a"),
    """
    mad = \
    {
        "$id": "",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "ACM Default Schema",
        "description": "Default JSON Schema for acm ACDC.",
        "credentialType": "ACDC_acm_message",
        "version": "2.0.0",
        "type": "object",
        "required":
        [
          "v",
          "d",
          "i",
          "s"
        ],
        "properties":
        {
            "v":
            {
                "description": "ACDC version string",
                "type": "string"
            },
            "t":
            {
                "description": "Message type",
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
            "A":
            {
                "description": "Aggregate Section",
                "oneOf":
                [
                    {
                      "description": "Aggregate Section AGID",
                      "type": "string"
                    },
                    {
                      "description": "Uncompacted Aggregate Section",
                      "type": "array"
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
          "t",
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
            "t":
            {
                "description": "Message type",
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



def acgSchemaDefault(kind=Kinds.json):
    """Utility function to create default schema dict for acg message

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
        "title": "ACG Default Schema",
        "description": "Default JSON Schema for acg ACDC.",
        "credentialType": "ACDC_acg_message",
        "version": "2.0.0",
        "type": "object",
        "required":
        [
          "v",
          "t",
          "d",
          "u",
          "i",
          "rd",
          "s",
          "A",
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
            "t":
            {
                "description": "Message type",
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
            "A":
            {
                "description": "Aggregate Section",
                "oneOf":
                [
                    {
                      "description": "Aggregate Section AGID",
                      "type": "string"
                    },
                    {
                      "description": "Uncompacted Aggregate Section",
                      "type": "array"
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
