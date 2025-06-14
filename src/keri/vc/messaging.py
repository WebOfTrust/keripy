# -*- encoding: utf-8 -*-
"""
keri.vc.messaging module

Utility functions for creating ACDC messages of all message types for v2

"""

from keri.kering import Vrsn_2_0




def mapACDC(issuer, schema, ilk=None, issuee=None, nonce=None, registry=None,
            attributes=None, aggregates=None, edges=None, rules=None,
            pvrsn=Vrsn_2_0, gvrsn=None):  #acedice
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



    all
    (v='', d='', u='', i='', rd='', s='', a={}, A=[], e={}, r={}),
    opts
    (u='', rd='', a='', A='', e='', r='')


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
