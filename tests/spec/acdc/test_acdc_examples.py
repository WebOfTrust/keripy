# -*- coding: utf-8 -*-
"""
tests.spec.acdc.test_acdc_examples module

"""
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64


import pytest

from keri import Vrsn_2_0, Kinds, Protocols, Ilks
from keri.core import (MtrDex, Salter, Labeler, Noncer, Mapper, Compactor, Aggor,
                       Blinder, BlindState, BoundState, GenDex)
from keri.core.eventing import incept
from keri.vc.messaging import regcept, blindate, update, acdcmap


def test_acdc_examples_setup():
    """Tests that setup AIDs for working examples in the ACDC specification"""
    # Create controller and witness AIDs for issuer and issuee

    # Create incepting key states
    # use same salter for all but different path
    # salt = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    salt = b'acdcspecworkexam'  # for example
    salter = Salter(raw=salt)
    assert salter.qb64 == '0ABhY2Rjc3BlY3dvcmtleGFt'  # CESR encoded for example

    # create set of signers each with private signing key and public verification key
    signers = salter.signers(count=8, transferable=True, temp=True)

    # create witness signers as nontransferable
    walt = b'acdcspecworkwits'
    walter = Salter(raw=walt)
    wigners = walter.signers(count=4,transferable=False, temp=True)

    # create issuer incepting key state, incepting signing key pair, Amy
    # rotating key pair, and  witness key pair, (witness aid is its public verification key)
    """
    Issuer incepting siging seed
    size=32
    path='0'
    salt=b'acdcspecworkexam'
    opslimit=1
    memlimit=8192
    seed = pysodium.crypto_pwhash(outlen=size,
                                      passwd=path,
                                      salt=self.raw,
                                      opslimit=opslimit,
                                      memlimit=memlimit,
                                      alg=pysodium.crypto_pwhash_ALG_ARGON2ID13)
    seed = (b'\xb7R\xfc+\xc2V\xd4\x03\xb6\xe79\x86$\xea~4\xcc\xe6\x83Z}3?\x16\xd4\xb8\x15\x97V>`_')

    verkey, sigkey = pysodium.crypto_sign_seed_keypair(seed)
    First 32 bytes of this internal sigkey is seed so we use seed externally as sigkey
    verkey =(b"\x0f>'A\x16\xf3\xc4Lb\xabT\x1d\x00\xeaO\x8a\xb6`}\xa2\x04YV\xf0z\x1b\x1c\xa5{\xe3(\xbf")

    verfer = Verfer(raw=verkey,
                    code=MtrDex.Ed25519 if transferable
                    else MtrDex.Ed25519N)
    """
    issuerSeedRaw = (b'\xb7R\xfc+\xc2V\xd4\x03\xb6\xe79\x86$\xea~4\xcc\xe6\x83Z}3?\x16\xd4\xb8\x15\x97V>`_')
    issuerSeedB64 = encodeB64(issuerSeedRaw)
    assert issuerSeedB64 == b't1L8K8JW1AO25zmGJOp-NMzmg1p9Mz8W1LgVl1Y-YF8='
    assert decodeB64(issuerSeedB64) == issuerSeedRaw


    issuerSigner = signers[0]
    issuerSigKey = issuerSigner.qb64  # issuer's private signing key seed
    issuerVerKey = issuerSigner.verfer.qb64  # issuer's public verification key
    assert issuerSigner.verfer.raw == (b"\x0f>'A\x16\xf3\xc4Lb\xabT\x1d\x00\xeaO\x8a\xb6`}\xa2\x04YV\xf0z\x1b\x1c\xa5{\xe3(\xbf")
    assert encodeB64(issuerSigner.verfer.raw) == b'Dz4nQRbzxExiq1QdAOpPirZgfaIEWVbwehscpXvjKL8='

    assert issuerSigKey == 'ALdS_CvCVtQDtuc5hiTqfjTM5oNafTM_FtS4FZdWPmBf'  # use in example
    assert issuerVerKey == 'DA8-J0EW88RMYqtUHQDqT4q2YH2iBFlW8HobHKV74yi_' # use in example

    # create issuer rotation key state Amy

    issuerRotSeedRaw = (b'\x82\xd7%\xd0\x9d\x95"u\x1d\x9c\x9d\x885ic\x86\x88\x84\xc7=Ps\x97\x88e\xf2\xab\xcc\x1e\xe2Q~')
    issuerRotSeedB64 = encodeB64(issuerRotSeedRaw)
    assert issuerRotSeedB64 == b'gtcl0J2VInUdnJ2INWljhoiExz1Qc5eIZfKrzB7iUX4='
    assert decodeB64(issuerRotSeedB64) == issuerRotSeedRaw

    issuerRotSigner = signers[1]
    issuerRotSigKey = issuerRotSigner.qb64  # issuer's private signing key seed
    issuerRotVerKey = issuerRotSigner.verfer.qb64  # issuer's public verification key
    assert issuerRotSigner.verfer.raw == (b'\xb7\xb8\xb9\xec2\xb6\xa7\xeak\x83A\xe0\t\xed4\xa0Y\xebR4M\x87 3?\x85K=U\xf6\xa7\x8c')
    assert encodeB64(issuerRotSigner.verfer.raw) == b't7i57DK2p-prg0HgCe00oFnrUjRNhyAzP4VLPVX2p4w='

    assert issuerRotSigKey == 'AILXJdCdlSJ1HZydiDVpY4aIhMc9UHOXiGXyq8we4lF-' # use in example
    assert issuerRotVerKey == 'DLe4uewytqfqa4NB4AntNKBZ61I0TYcgMz-FSz1V9qeM' # use in example


    # create issuer witness key state Amy

    issuerWitSeedRaw = (b'\x86\xa0&\x9b"B 5\\v\xe2\x11\xe5*\xc4\x80\x18\x8e\x17\xf9\x0f?\xee\x83\xb4\xe7f\xcaF\xf2\x11>')
    issuerWitSeedB64 = encodeB64(issuerWitSeedRaw)
    assert issuerWitSeedB64 == b'hqAmmyJCIDVcduIR5SrEgBiOF_kPP-6DtOdmykbyET4='
    assert decodeB64(issuerWitSeedB64) == issuerWitSeedRaw

    issuerWitSigner = wigners[0]
    issuerWitSigKey = issuerWitSigner.qb64  # issuer's private signing key seed
    issuerWitVerKey = issuerWitSigner.verfer.qb64  # issuer's public verification key
    assert issuerWitSigner.verfer.raw ==(b'\xa4Z\x0b\xa5,\x8a5\x18\xd4Tc\x13\x1a\x001\xcf\x168pC!\xf2\nbs\xa5\xc5a\xfcx\xe7\xbc')
    assert encodeB64(issuerWitSigner.verfer.raw) == b'pFoLpSyKNRjUVGMTGgAxzxY4cEMh8gpic6XFYfx457w='

    assert issuerWitSigKey == 'AIagJpsiQiA1XHbiEeUqxIAYjhf5Dz_ug7TnZspG8hE-'  # use in example
    assert issuerWitVerKey == 'BKRaC6UsijUY1FRjExoAMc8WOHBDIfIKYnOlxWH8eOe8' # use in example

    # create issuer AID with single sig simple inception event JSON
    keys = [issuerVerKey]  # initial signing keys
    nkeys = [issuerRotVerKey]  # next (rotation) keys
    wits = [issuerWitVerKey]  # witness aids (same as public verkey)
    serder = incept(keys, code=MtrDex.Blake3_256, ndigs=nkeys, wits=wits,
                    version=Vrsn_2_0, kind=Kinds.json)
    assert serder.pre == 'ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz'
    assert serder.said == 'ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz'
    assert serder.sad == \
    {
        'v': 'KERICAACAAJSONAAFb.',
        't': 'icp',
        'd': 'ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz',
        'i': 'ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz',
        's': '0',
        'kt': '1',
        'k': ['DA8-J0EW88RMYqtUHQDqT4q2YH2iBFlW8HobHKV74yi_'],
        'nt': '1',
        'n': ['DLe4uewytqfqa4NB4AntNKBZ61I0TYcgMz-FSz1V9qeM'],
        'bt': '1',
        'b': ['BKRaC6UsijUY1FRjExoAMc8WOHBDIfIKYnOlxWH8eOe8'],
        'c': [],
        'a': []
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAFb.","t":"icp","d":"ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtz'
                    b'Dn1meBVLAz","i":"ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz","s":"0","kt":'
                    b'"1","k":["DA8-J0EW88RMYqtUHQDqT4q2YH2iBFlW8HobHKV74yi_"],"nt":"1","n":["DLe4'
                    b'uewytqfqa4NB4AntNKBZ61I0TYcgMz-FSz1V9qeM"],"bt":"1","b":["BKRaC6UsijUY1FRjEx'
                    b'oAMc8WOHBDIfIKYnOlxWH8eOe8"],"c":[],"a":[]}')

    issuerAidJson = serder.pre
    assert issuerAidJson == 'ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz'
    # Amy AID = 'ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz'

    # create issuer AID with single sig simple inception event CESR
    keys = [issuerVerKey]  # initial signing keys
    nkeys = [issuerRotVerKey]  # next (rotation) keys
    wits = [issuerWitVerKey]  # witness aids (same as public verkey)
    serder = incept(keys, code=MtrDex.Blake3_256, ndigs=nkeys, wits=wits,
                    version=Vrsn_2_0, kind=Kinds.cesr)
    assert serder.pre == 'EJ8IT4pXhO1JgKxxm6kZyNbcUOVLXi95SQ2jDrEIuxhz'
    assert serder.said == 'EJ8IT4pXhO1JgKxxm6kZyNbcUOVLXi95SQ2jDrEIuxhz'
    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAAEU.',
        't': 'icp',
        'd': 'EJ8IT4pXhO1JgKxxm6kZyNbcUOVLXi95SQ2jDrEIuxhz',
        'i': 'EJ8IT4pXhO1JgKxxm6kZyNbcUOVLXi95SQ2jDrEIuxhz',
        's': '0',
        'kt': '1',
        'k': ['DA8-J0EW88RMYqtUHQDqT4q2YH2iBFlW8HobHKV74yi_'],
        'nt': '1',
        'n': ['DLe4uewytqfqa4NB4AntNKBZ61I0TYcgMz-FSz1V9qeM'],
        'bt': '1',
        'b': ['BKRaC6UsijUY1FRjExoAMc8WOHBDIfIKYnOlxWH8eOe8'],
        'c': [],
        'a': []
    }

    assert serder.raw == (b'-FBE0OKERICAACAAXicpEJ8IT4pXhO1JgKxxm6kZyNbcUOVLXi95SQ2jDrEIuxhzEJ8IT4pXhO1J'
                        b'gKxxm6kZyNbcUOVLXi95SQ2jDrEIuxhzMAAAMAAB-JALDA8-J0EW88RMYqtUHQDqT4q2YH2iBFlW'
                        b'8HobHKV74yi_MAAB-JALDLe4uewytqfqa4NB4AntNKBZ61I0TYcgMz-FSz1V9qeMMAAB-JALBKRa'
                        b'C6UsijUY1FRjExoAMc8WOHBDIfIKYnOlxWH8eOe8-JAA-JAA')

    issuerAidCesr = serder.pre
    assert issuerAidCesr == 'EJ8IT4pXhO1JgKxxm6kZyNbcUOVLXi95SQ2jDrEIuxhz'

    # create issuee incepting key state  Bob
    issueeSeedRaw = (b'vE}\xa1\xb5\xed<Zv\x1a\xf4\xaa#\xd8+$\x96\x1d\xc0\x14,>\xdb\xa6\xade\xa6\xb9{\xb4n[')
    issueeSeedB64 = encodeB64(issueeSeedRaw)
    assert issueeSeedB64 ==b'dkV9obXtPFp2GvSqI9grJJYdwBQsPtumrWWmuXu0bls='
    assert decodeB64(issueeSeedB64) == issueeSeedRaw

    issueeSigner = signers[2]
    issueeSigKey = issueeSigner.qb64  # issuee's private signing key
    issueeVerKey = issueeSigner.verfer.qb64  # issuee's public verification key
    assert issueeSigner.verfer.raw == b'\xb7:\xbb\xbe\x8d"\xbd\x15\xaa*\xd0</d\xe1iN\x1f\r\xa6 o{CpU\xd1C7\x121\xf9'
    assert encodeB64(issueeSigner.verfer.raw) == b'tzq7vo0ivRWqKtA8L2ThaU4fDaYgb3tDcFXRQzcSMfk='

    assert issueeSigKey == 'AHZFfaG17Txadhr0qiPYKySWHcAULD7bpq1lprl7tG5b'  # use in example
    assert issueeVerKey == 'DLc6u76NIr0VqirQPC9k4WlOHw2mIG97Q3BV0UM3EjH5' # use in example

    # create issuee rotation key state  Bob

    issueeRotSeedRaw = (b'\x1b\xd7o*A\xec^\xfb}\xa0 j`\\+\xb6MZ\xe8\xb5\xa31\xb1\xf0a\x1bD6\xcb\x0e_\x00')
    issueeRotSeedB64 = encodeB64(issueeRotSeedRaw)
    assert issueeRotSeedB64 ==b'G9dvKkHsXvt9oCBqYFwrtk1a6LWjMbHwYRtENssOXwA='
    assert decodeB64(issueeRotSeedB64) == issueeRotSeedRaw

    issueeRotSigner = signers[3]
    issueeRotSigKey = issueeRotSigner.qb64  # issuer's private signing key seed
    issueeRotVerKey = issueeRotSigner.verfer.qb64  # issuer's public verification key
    assert issueeRotSigner.verfer.raw == (b"/\x90\x0f\xea%\t'\x1e\xe1'\xfa\xa9\xaaU\xd2\xfa\x8f\xd2[\xd1:\xdeCZ\xa3\x1cQ\x8cX\xeaaP")
    assert encodeB64(issueeRotSigner.verfer.raw) == b'L5AP6iUJJx7hJ_qpqlXS-o_SW9E63kNaoxxRjFjqYVA='

    assert issueeRotSigKey == 'ABvXbypB7F77faAgamBcK7ZNWui1ozGx8GEbRDbLDl8A' # use in example
    assert issueeRotVerKey == 'DC-QD-olCSce4Sf6qapV0vqP0lvROt5DWqMcUYxY6mFQ' # use in example

    # create issuee witness key state Bob
    issueeWitSeedRaw = (b"\xee\xf2%'\x0c\x83FnF\x83\x07I<g\x18h\xa9\xa0V`@r0\x86\xd2\x1c\xc7\x9d$\xd8%\xde")
    issueeWitSeedB64 = encodeB64(issueeWitSeedRaw)
    assert issueeWitSeedB64 == b'7vIlJwyDRm5GgwdJPGcYaKmgVmBAcjCG0hzHnSTYJd4='
    assert decodeB64(issueeWitSeedB64) == issueeWitSeedRaw

    issueeWitSigner = wigners[1]
    issueeWitSigKey = issueeWitSigner.qb64  # issuer's private signing key seed
    issueeWitVerKey = issueeWitSigner.verfer.qb64  # issuer's public verification key
    assert issueeWitSigner.verfer.raw == (b"\xe7\xd5\xa5hnNV\xf9K`\x899R\xd2yI\xbd\x03E\xea\xee\x1d'\xe9\xefP\x9e\r\xe0\xe0}\xa9")
    assert encodeB64(issueeWitSigner.verfer.raw) == b'59WlaG5OVvlLYIk5UtJ5Sb0DReruHSfp71CeDeDgfak='

    assert issueeWitSigKey == 'AO7yJScMg0ZuRoMHSTxnGGipoFZgQHIwhtIcx50k2CXe'  # use in example
    assert issueeWitVerKey == 'BOfVpWhuTlb5S2CJOVLSeUm9A0Xq7h0n6e9Qng3g4H2p' # use in example

    # create issuee AID with single sig simple inception event JSON
    keys = [issueeVerKey]  # initial signing keys
    nkeys = [issueeRotVerKey]  # next (rotation) keys
    wits = [issueeWitVerKey]  # witness aids (same as public verkey)
    serder = incept(keys, code=MtrDex.Blake3_256, ndigs=nkeys, wits=wits,
                    version=Vrsn_2_0, kind=Kinds.json)
    assert serder.pre == 'ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf'
    assert serder.said == 'ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf'
    assert serder.sad == \
    {
        'v': 'KERICAACAAJSONAAFb.',
        't': 'icp',
        'd': 'ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf',
        'i': 'ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf',
        's': '0',
        'kt': '1',
        'k': ['DLc6u76NIr0VqirQPC9k4WlOHw2mIG97Q3BV0UM3EjH5'],
        'nt': '1',
        'n': ['DC-QD-olCSce4Sf6qapV0vqP0lvROt5DWqMcUYxY6mFQ'],
        'bt': '1',
        'b': ['BOfVpWhuTlb5S2CJOVLSeUm9A0Xq7h0n6e9Qng3g4H2p'],
        'c': [],
        'a': []
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAFb.","t":"icp","d":"ECWJZFBtllh99fESUOrBvT3EtBujWtDKCm'
                        b'yzDAXWhYmf","i":"ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf","s":"0","kt":'
                        b'"1","k":["DLc6u76NIr0VqirQPC9k4WlOHw2mIG97Q3BV0UM3EjH5"],"nt":"1","n":["DC-Q'
                        b'D-olCSce4Sf6qapV0vqP0lvROt5DWqMcUYxY6mFQ"],"bt":"1","b":["BOfVpWhuTlb5S2CJOV'
                        b'LSeUm9A0Xq7h0n6e9Qng3g4H2p"],"c":[],"a":[]}')

    issueeAidJson = serder.pre
    assert issueeAidJson == 'ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf'
    # Bob AID = 'ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf'

    # create issuee AID with single sig simple inception event CESR
    keys = [issueeVerKey]  # initial signing keys
    nkeys = [issueeRotVerKey]  # next (rotation) keys
    wits = [issueeWitVerKey]  # witness aids (same as public verkey)
    serder = incept(keys, code=MtrDex.Blake3_256, ndigs=nkeys, wits=wits,
                    version=Vrsn_2_0, kind=Kinds.cesr)
    assert serder.pre == 'EFUJ7F5fnQYCCbAnyLxrpgeBmkmUCFOIm0I3reQj8ro-'
    assert serder.said == 'EFUJ7F5fnQYCCbAnyLxrpgeBmkmUCFOIm0I3reQj8ro-'
    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAAEU.',
        't': 'icp',
        'd': 'EFUJ7F5fnQYCCbAnyLxrpgeBmkmUCFOIm0I3reQj8ro-',
        'i': 'EFUJ7F5fnQYCCbAnyLxrpgeBmkmUCFOIm0I3reQj8ro-',
        's': '0',
        'kt': '1',
        'k': ['DLc6u76NIr0VqirQPC9k4WlOHw2mIG97Q3BV0UM3EjH5'],
        'nt': '1',
        'n': ['DC-QD-olCSce4Sf6qapV0vqP0lvROt5DWqMcUYxY6mFQ'],
        'bt': '1',
        'b': ['BOfVpWhuTlb5S2CJOVLSeUm9A0Xq7h0n6e9Qng3g4H2p'],
        'c': [],
        'a': []
    }

    assert serder.raw == (b'-FBE0OKERICAACAAXicpEFUJ7F5fnQYCCbAnyLxrpgeBmkmUCFOIm0I3reQj8ro-EFUJ7F5fnQYC'
                        b'CbAnyLxrpgeBmkmUCFOIm0I3reQj8ro-MAAAMAAB-JALDLc6u76NIr0VqirQPC9k4WlOHw2mIG97'
                        b'Q3BV0UM3EjH5MAAB-JALDC-QD-olCSce4Sf6qapV0vqP0lvROt5DWqMcUYxY6mFQMAAB-JALBOfV'
                        b'pWhuTlb5S2CJOVLSeUm9A0Xq7h0n6e9Qng3g4H2p-JAA-JAA')

    issueeAidCesr = serder.pre
    assert issueeAidCesr == 'EFUJ7F5fnQYCCbAnyLxrpgeBmkmUCFOIm0I3reQj8ro-'


    # create Cal AID
    calSigner = signers[4]
    calVerKey = calSigner.verfer.qb64  # public verification key
    assert calVerKey == 'DA18V-ejmy10RzbQJsk2EgmW3alJ_GgG6tG0pOs7CPmC' # use in example

    calRotSigner = signers[5]
    calRotVerKey = calRotSigner.verfer.qb64  # public verification key
    assert calRotVerKey == 'DB7etpbzc9GvqzlM_6X-pT34rguzJ2xBLcyRS6KOIKuD' # use in example

    calWitSigner = wigners[2]
    calWitVerKey = calWitSigner.verfer.qb64  # issuer's public verification key
    assert calWitVerKey == 'BCE2LoxrPOijy3lF9RDyd4VIPLC9qfZIlkbk59pytYhv' # use in example

    keys = [calVerKey]  # initial signing keys
    nkeys = [calRotVerKey]  # next (rotation) keys
    wits = [calWitVerKey]  # witness aids (same as public verkey)
    serder = incept(keys, code=MtrDex.Blake3_256, ndigs=nkeys, wits=wits,
                    version=Vrsn_2_0, kind=Kinds.json)
    assert serder.sad == \
    {
        'v': 'KERICAACAAJSONAAFb.',
        't': 'icp',
        'd': 'ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT',
        'i': 'ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT',
        's': '0',
        'kt': '1',
        'k': ['DA18V-ejmy10RzbQJsk2EgmW3alJ_GgG6tG0pOs7CPmC'],
        'nt': '1',
        'n': ['DB7etpbzc9GvqzlM_6X-pT34rguzJ2xBLcyRS6KOIKuD'],
        'bt': '1',
        'b': ['BCE2LoxrPOijy3lF9RDyd4VIPLC9qfZIlkbk59pytYhv'],
        'c': [],
        'a': []
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAFb.","t":"icp","d":"ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3b'
                b'LUsRP4yVdT","i":"ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT","s":"0","kt":'
                b'"1","k":["DA18V-ejmy10RzbQJsk2EgmW3alJ_GgG6tG0pOs7CPmC"],"nt":"1","n":["DB7e'
                b'tpbzc9GvqzlM_6X-pT34rguzJ2xBLcyRS6KOIKuD"],"bt":"1","b":["BCE2LoxrPOijy3lF9R'
                b'Dyd4VIPLC9qfZIlkbk59pytYhv"],"c":[],"a":[]}')

    calAidJson = serder.pre
    assert calAidJson == 'ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT'

    # create Deb AID
    debSigner = signers[6]
    debVerKey = debSigner.verfer.qb64  # public verification key
    assert debVerKey == 'DD-bLXb5uDZZUFA26HMwgtCA8S3FvFDT8fp1QGRNpHxl' # use in example

    debRotSigner = signers[7]
    debRotVerKey = debRotSigner.verfer.qb64  # public verification key
    assert debRotVerKey == 'DDmDGfklFByWbnsVaCndkABPOttEOeENt4Swly6Q1al6' # use in example

    debWitSigner = wigners[3]
    debWitVerKey = debWitSigner.verfer.qb64  # issuer's public verification key
    assert debWitVerKey == 'BMxAdDFzKgD8VVvmbjJgA0B93S6U2rzIvQdHCVJ7MCBP' # use in example

    keys = [debVerKey]  # initial signing keys
    nkeys = [debRotVerKey]  # next (rotation) keys
    wits = [debWitVerKey]  # witness aids (same as public verkey)
    serder = incept(keys, code=MtrDex.Blake3_256, ndigs=nkeys, wits=wits,
                    version=Vrsn_2_0, kind=Kinds.json)
    assert serder.sad == \
    {
        'v': 'KERICAACAAJSONAAFb.',
        't': 'icp',
        'd': 'EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW',
        'i': 'EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW',
        's': '0',
        'kt': '1',
        'k': ['DD-bLXb5uDZZUFA26HMwgtCA8S3FvFDT8fp1QGRNpHxl'],
        'nt': '1',
        'n': ['DDmDGfklFByWbnsVaCndkABPOttEOeENt4Swly6Q1al6'],
        'bt': '1',
        'b': ['BMxAdDFzKgD8VVvmbjJgA0B93S6U2rzIvQdHCVJ7MCBP'],
        'c': [],
        'a': []
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAFb.","t":"icp","d":"EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYV'
                        b'Xe9isaP5SW","i":"EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW","s":"0","kt":'
                        b'"1","k":["DD-bLXb5uDZZUFA26HMwgtCA8S3FvFDT8fp1QGRNpHxl"],"nt":"1","n":["DDmD'
                        b'GfklFByWbnsVaCndkABPOttEOeENt4Swly6Q1al6"],"bt":"1","b":["BMxAdDFzKgD8VVvmbj'
                        b'JgA0B93S6U2rzIvQdHCVJ7MCBP"],"c":[],"a":[]}')

    debAidJson = serder.pre
    assert debAidJson == 'EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW'


    # UUIDs for the examples

    raws = [b'acdcspecworkraw' + b'%0x'%(i, ) for i in range(16)]
    assert raws == \
    [
        b'acdcspecworkraw0',
        b'acdcspecworkraw1',
        b'acdcspecworkraw2',
        b'acdcspecworkraw3',
        b'acdcspecworkraw4',
        b'acdcspecworkraw5',
        b'acdcspecworkraw6',
        b'acdcspecworkraw7',
        b'acdcspecworkraw8',
        b'acdcspecworkraw9',
        b'acdcspecworkrawa',
        b'acdcspecworkrawb',
        b'acdcspecworkrawc',
        b'acdcspecworkrawd',
        b'acdcspecworkrawe',
        b'acdcspecworkrawf'
    ]

    uuids = [Noncer(raw=raw).qb64 for raw in raws]
    assert uuids == \
    [
     '0ABhY2Rjc3BlY3dvcmtyYXcw',
     '0ABhY2Rjc3BlY3dvcmtyYXcx',
     '0ABhY2Rjc3BlY3dvcmtyYXcy',
     '0ABhY2Rjc3BlY3dvcmtyYXcz',
     '0ABhY2Rjc3BlY3dvcmtyYXc0',
     '0ABhY2Rjc3BlY3dvcmtyYXc1',
     '0ABhY2Rjc3BlY3dvcmtyYXc2',
     '0ABhY2Rjc3BlY3dvcmtyYXc3',
     '0ABhY2Rjc3BlY3dvcmtyYXc4',
     '0ABhY2Rjc3BlY3dvcmtyYXc5',
     '0ABhY2Rjc3BlY3dvcmtyYXdh',
     '0ABhY2Rjc3BlY3dvcmtyYXdi',
     '0ABhY2Rjc3BlY3dvcmtyYXdj',
     '0ABhY2Rjc3BlY3dvcmtyYXdk',
     '0ABhY2Rjc3BlY3dvcmtyYXdl',
     '0ABhY2Rjc3BlY3dvcmtyYXdm'
    ]

    """Done Test"""


def test_acdc_registry_examples_JSON():
    """Basic Examples using JSON serializaton to create Registries"""

    amy = issuer = "ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz"
    bob = issuee = "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf"
    cal = "ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT"
    deb = "EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW"

    raws = [b'acdcspecworkraw' + b'%0x'%(i, ) for i in range(16)]
    uuids = [Noncer(raw=raw).qb64 for raw in raws]

    # Registry0  test default kind JSON uuid0 stamp0
    stamp0 = '2025-07-04T17:50:00.000000+00:00'
    serder = regcept(issuer=amy, uuid=uuids[0], stamp=stamp0)
    assert serder.sad == \
    {
        "v": "ACDCCAACAAJSONAADa.",
        "t": "rip",
        "d": "EOMMCyztOvg970W0dZVJT2JIwlQ22DSeY7wtxNBBtpmX",
        "u": "0ABhY2Rjc3BlY3dvcmtyYXcw",
        "i": "ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz",
        "n": "0",
        "dt": "2025-07-04T17:50:00.000000+00:00"
    }
    regAmy = rd0 = serder.said
    assert rd0 == "EOMMCyztOvg970W0dZVJT2JIwlQ22DSeY7wtxNBBtpmX"

    # Registry1 test default kind JSON uuid1 Stamp1
    stamp1 = '2025-07-04T17:51:00.000000+00:00'
    serder = regcept(issuer=bob, uuid=uuids[1], stamp=stamp1)
    assert serder.sad == \
    {
        "v": "ACDCCAACAAJSONAADa.",
        "t": "rip",
        "d": "ECOWJI9kAjpCFYJ7RenpJx2w66-GsGlhyKLO-Or3qOIQ",
        "u": "0ABhY2Rjc3BlY3dvcmtyYXcx",
        "i": "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf",
        "n": "0",
        "dt": "2025-07-04T17:51:00.000000+00:00"
    }
    regBob = rd1 = serder.said
    assert rd1 == "ECOWJI9kAjpCFYJ7RenpJx2w66-GsGlhyKLO-Or3qOIQ"

    # Registry2 test default kind JSON uuid2 Stamp2
    stamp2 = '2025-07-04T17:52:00.000000+00:00'
    serder = regcept(issuer=cal, uuid=uuids[2], stamp=stamp2)
    assert serder.sad == \
    {
        "v": "ACDCCAACAAJSONAADa.",
        "t": "rip",
        "d": "EPtolmh_NE2vC02oFc7FOiWkPcEiKUPWm5uu_Gv1JZDw",
        "u": "0ABhY2Rjc3BlY3dvcmtyYXcy",
        "i": "ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT",
        "n": "0",
        "dt": "2025-07-04T17:52:00.000000+00:00"
    }
    regCal = rd2 = serder.said
    assert rd2 == "EPtolmh_NE2vC02oFc7FOiWkPcEiKUPWm5uu_Gv1JZDw"

    # Registry3 test default kind JSON uuid3 Stamp3
    stamp3 = '2025-07-04T17:53:00.000000+00:00'
    serder = regcept(issuer=deb, uuid=uuids[3], stamp=stamp3)
    assert serder.sad == \
    {
        "v": "ACDCCAACAAJSONAADa.",
        "t": "rip",
        "d": "EJl5EUxL23p_pqgN3IyM-pzru89Nb7NzOM8ijH644xSU",
        "u": "0ABhY2Rjc3BlY3dvcmtyYXcz",
        "i": "EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW",
        "n": "0",
        "dt": "2025-07-04T17:53:00.000000+00:00"
    }
    regDeb = rd3 = serder.said
    assert rd3 == "EJl5EUxL23p_pqgN3IyM-pzru89Nb7NzOM8ijH644xSU"


def test_blindable_state_tel_examples_JSON():
    """Basic Examples using JSON serializaton to create Registries"""

    amy = issuer = "ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz"
    bob = issuee = "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf"
    cal = "ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT"
    deb = "EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW"

    raws = [b'acdcspecworkraw' + b'%0x'%(i, ) for i in range(16)]
    uuids = [Noncer(raw=raw).qb64 for raw in raws]

    labeler = Labeler(label="revoked")
    assert labeler.label == 'revoked'
    assert labeler.qb64 == 'Yrevoked'

    labeler = Labeler(label="issued")
    assert labeler.label == 'issued'
    assert labeler.qb64 == '0Missued'

    labeler = Labeler(text="")
    assert labeler.text == ''
    assert labeler.qb64 == '1AAP'

    # Registry1 test default kind JSON uuid1 Stamp1
    stamp1 = '2025-07-04T17:51:00.000000+00:00'
    serder = regcept(issuer=bob, uuid=uuids[1], stamp=stamp1)
    assert serder.sad == \
    {
        "v": "ACDCCAACAAJSONAADa.",
        "t": "rip",
        "d": "ECOWJI9kAjpCFYJ7RenpJx2w66-GsGlhyKLO-Or3qOIQ",
        "u": "0ABhY2Rjc3BlY3dvcmtyYXcx",
        "i": "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf",
        "n": "0",
        "dt": "2025-07-04T17:51:00.000000+00:00"
    }
    regBob = serder.said
    assert regBob == "ECOWJI9kAjpCFYJ7RenpJx2w66-GsGlhyKLO-Or3qOIQ"

    # create placeholder blind from 128 bit salt for sn=1
    salt = uuids[15]
    assert salt == '0ABhY2Rjc3BlY3dvcmtyYXdm'

    qb64 = "ECVr7QWEp_aqVQuz4yprRFXVxJ-9uWLx_d6oDinlHU6JaG1lSjdJSNl7TiroPl67Uqzd5eFvzmr6bPlL7Lh4ukv81AAP1AAP"
    eqb64 = "-aAYECVr7QWEp_aqVQuz4yprRFXVxJ-9uWLx_d6oDinlHU6JaG1lSjdJSNl7TiroPl67Uqzd5eFvzmr6bPlL7Lh4ukv81AAP1AAP"
    blid = 'ECVr7QWEp_aqVQuz4yprRFXVxJ-9uWLx_d6oDinlHU6J'
    uuid = 'aG1lSjdJSNl7TiroPl67Uqzd5eFvzmr6bPlL7Lh4ukv8'
    state = ''
    acdc = ''
    sn = 1
    dummied = '############################################aG1lSjdJSNl7TiroPl67Uqzd5eFvzmr6bPlL7Lh4ukv81AAP1AAP'
    assert len(dummied) == 96
    blinder = Blinder.blind(acdc=acdc, state=state, salt=salt, sn=sn)
    assert blinder.crew ==  BlindState(d='ECVr7QWEp_aqVQuz4yprRFXVxJ-9uWLx_d6oDinlHU6J',
                                       u='aG1lSjdJSNl7TiroPl67Uqzd5eFvzmr6bPlL7Lh4ukv8',
                                       td='',
                                       ts='')
    assert blinder.qb64 == qb64
    assert blinder.said == blid
    assert blinder.uuid == uuid
    assert blinder.acdc == acdc
    assert blinder.state == state
    assert Blinder.enclose([blinder]).decode() == eqb64

    regid = regBob
    prior = regBob
    stamp = '2025-08-01T18:06:10.988921+00:00'

    said = 'EPNwyvHp2XJsz9pSpXtHtcCmzw6bKSFc-nhGKTbso0Yg'

    # test  use default sn=1  default kind=JSON
    serder = blindate(regid=regid, prior=prior, blid=blid, stamp=stamp)
    assert serder.proto == Protocols.acdc
    assert serder.pvrsn == Vrsn_2_0
    assert serder.genus == GenDex.KERI
    assert serder.gvrsn == Vrsn_2_0
    assert serder.kind == Kinds.json
    assert serder.ilk == Ilks.bup
    assert serder.said == said
    assert serder.stamp == stamp
    assert serder.sad['rd'] == regid
    assert serder.sad['b'] == blid
    assert serder.sad == \
    {
        "v": "ACDCCAACAAJSONAAEi.",
        "t": "bup",
        "d": "EPNwyvHp2XJsz9pSpXtHtcCmzw6bKSFc-nhGKTbso0Yg",
        "rd": "ECOWJI9kAjpCFYJ7RenpJx2w66-GsGlhyKLO-Or3qOIQ",
        "n": "1",
        "p": "ECOWJI9kAjpCFYJ7RenpJx2w66-GsGlhyKLO-Or3qOIQ",
        "dt": "2025-08-01T18:06:10.988921+00:00",
        "b": "ECVr7QWEp_aqVQuz4yprRFXVxJ-9uWLx_d6oDinlHU6J"
    }
    prior = serder.said

    # Change state to issued
    acdc = 'EMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M'  # bob project report ACDC
    state = 'issued'
    sn = 2
    blid = 'EOtWw6X_aoOJlkzNaLj23IC6MXHl7ZSYSWVulFW_Hr_t'
    uuid = 'aLfCdNAnc-0P2SiruarZSajXiUWu5iU2VfQahvpNCyzB'
    qb64 = 'EOtWw6X_aoOJlkzNaLj23IC6MXHl7ZSYSWVulFW_Hr_taLfCdNAnc-0P2SiruarZSajXiUWu5iU2VfQahvpNCyzBEMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M0Missued'
    eqb64 = '-aAjEOtWw6X_aoOJlkzNaLj23IC6MXHl7ZSYSWVulFW_Hr_taLfCdNAnc-0P2SiruarZSajXiUWu5iU2VfQahvpNCyzBEMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M0Missued'
    dummied = '############################################aLfCdNAnc-0P2SiruarZSajXiUWu5iU2VfQahvpNCyzBEMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M0Missued'
    assert len(dummied) == 140
    blinder = Blinder.blind(acdc=acdc, state=state, salt=salt, sn=sn)
    assert blinder.qb64 == qb64
    assert blinder.said == blid
    assert blinder.uuid == uuid
    assert blinder.acdc == acdc
    assert blinder.state == state
    assert Blinder.enclose([blinder]).decode() == eqb64

    stamp = '2020-08-02T12:00:20.000000+00:00'
    said = 'EBdytzDC4dnatn-6mrCWLSGuM62LM0BgS31YnAg5NTeW'

    serder = blindate(regid=regid, prior=prior, blid=blid, stamp=stamp, sn=sn)
    assert serder.proto == Protocols.acdc
    assert serder.pvrsn == Vrsn_2_0
    assert serder.genus == GenDex.KERI
    assert serder.gvrsn == Vrsn_2_0
    assert serder.kind == Kinds.json
    assert serder.ilk == Ilks.bup
    assert serder.said == said
    assert serder.stamp == stamp
    assert serder.sad['rd'] == regid
    assert serder.sad['b'] == blid
    assert serder.sad == \
    {
        "v": "ACDCCAACAAJSONAAEi.",
        "t": "bup",
        "d": "EBdytzDC4dnatn-6mrCWLSGuM62LM0BgS31YnAg5NTeW",
        "rd": "ECOWJI9kAjpCFYJ7RenpJx2w66-GsGlhyKLO-Or3qOIQ",
        "n": "2",
        "p": "EPNwyvHp2XJsz9pSpXtHtcCmzw6bKSFc-nhGKTbso0Yg",
        "dt": "2020-08-02T12:00:20.000000+00:00",
        "b": "EOtWw6X_aoOJlkzNaLj23IC6MXHl7ZSYSWVulFW_Hr_t"
    }
    prior = serder.said

    # Change state to revoked
    state = 'revoked'
    sn = 3

    blid = 'EPj3sZj8OOWTkTgAN5vzVYdANeoj3zxgEn5APb8fCRRN'
    uuid = 'aGx7b16vGHVPT56tX30kYOEzTwiVY4aabc4k9AawYyZG'

    blinder = Blinder.blind(acdc=acdc, state=state, salt=salt, sn=sn)
    assert blinder.said == blid
    assert blinder.uuid == uuid
    assert blinder.acdc == acdc
    assert blinder.state == state

    qb64 = 'EPj3sZj8OOWTkTgAN5vzVYdANeoj3zxgEn5APb8fCRRNaGx7b16vGHVPT56tX30kYOEzTwiVY4aabc4k9AawYyZGEMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4MYrevoked'
    assert blinder.qb64 == qb64

    eqb64 = '-aAjEPj3sZj8OOWTkTgAN5vzVYdANeoj3zxgEn5APb8fCRRNaGx7b16vGHVPT56tX30kYOEzTwiVY4aabc4k9AawYyZGEMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4MYrevoked'
    assert Blinder.enclose([blinder]).decode() == eqb64

    stamp = '2020-08-03T12:00:20.000000+00:00'
    said = 'EM8B1uDhWaJLfpIiEqgp-3EurGUcbfe7u2k5AarDl2XD'

    serder = blindate(regid=regid, prior=prior, blid=blid, stamp=stamp, sn=sn)
    assert serder.said == said
    assert serder.proto == Protocols.acdc
    assert serder.pvrsn == Vrsn_2_0
    assert serder.genus == GenDex.KERI
    assert serder.gvrsn == Vrsn_2_0
    assert serder.kind == Kinds.json
    assert serder.ilk == Ilks.bup
    assert serder.stamp == stamp
    assert serder.sad['rd'] == regid
    assert serder.sad == \
    {
        "v": "ACDCCAACAAJSONAAEi.",
        "t": "bup",
        "d": "EM8B1uDhWaJLfpIiEqgp-3EurGUcbfe7u2k5AarDl2XD",
        "rd": "ECOWJI9kAjpCFYJ7RenpJx2w66-GsGlhyKLO-Or3qOIQ",
        "n": "3",
        "p": "EBdytzDC4dnatn-6mrCWLSGuM62LM0BgS31YnAg5NTeW",
        "dt": "2020-08-03T12:00:20.000000+00:00",
        "b": "EPj3sZj8OOWTkTgAN5vzVYdANeoj3zxgEn5APb8fCRRN"
    }


    # alternate unblindable update
    said = 'ENR6tbkJCJXQTiu5TP-RBxkS2_ZSZBgbJmpjKucDe07h'
    serder = update(regid=regid, prior=prior, acdc=acdc, state=state, stamp=stamp, sn=sn)
    assert serder.proto == Protocols.acdc
    assert serder.pvrsn == Vrsn_2_0
    assert serder.genus == GenDex.KERI
    assert serder.gvrsn == Vrsn_2_0
    assert serder.kind == Kinds.json
    assert serder.ilk == Ilks.upd
    assert serder.said == said
    assert serder.stamp == stamp
    assert serder.sad['rd'] == regid
    assert serder.sad == \
    {
        "v": "ACDCCAACAAJSONAAEy.",
        "t": "upd",
        "d": "ENR6tbkJCJXQTiu5TP-RBxkS2_ZSZBgbJmpjKucDe07h",
        "rd": "ECOWJI9kAjpCFYJ7RenpJx2w66-GsGlhyKLO-Or3qOIQ",
        "n": "3",
        "p": "EBdytzDC4dnatn-6mrCWLSGuM62LM0BgS31YnAg5NTeW",
        "dt": "2020-08-03T12:00:20.000000+00:00",
        "td": "EMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M",
        "ts": "revoked"
    }



    # Test Blind Bound Example
    # create placeholder blind from 128 bit salt for sn=1
    salt = uuids[14]
    assert salt == '0ABhY2Rjc3BlY3dvcmtyYXdl'

    blid = 'EFaQ00QW-ZeoMxE9baWcpJbAFXrs5h0ya-wpKnHvMQ0c'
    uuid = 'aJxtoz6qVeJxPCZvP-qBJifRfIxP3itQBVAAu7JJHxMa'
    acdc = ''
    state = ''
    sn = 1
    bsn = 0
    bd = ""

    blinder = Blinder.blind(acdc=acdc, state=state, salt=salt, sn=sn,
                            bound=True, bsn=bsn, bd=bd)
    assert blinder.crew == BoundState(d='EFaQ00QW-ZeoMxE9baWcpJbAFXrs5h0ya-wpKnHvMQ0c',
                                      u='aJxtoz6qVeJxPCZvP-qBJifRfIxP3itQBVAAu7JJHxMa',
                                      td='',
                                      ts='',
                                      bn='0',
                                      bd='')


    assert blinder.said == blid
    assert blinder.uuid == uuid
    assert blinder.acdc == acdc
    assert blinder.state == state
    assert blinder.bsn == bsn
    assert blinder.bd == bd

    dummied = '############################################aJxtoz6qVeJxPCZvP-qBJifRfIxP3itQBVAAu7JJHxMa1AAP1AAPMAAA1AAP'
    assert len(dummied) == 104

    qb64 = 'EFaQ00QW-ZeoMxE9baWcpJbAFXrs5h0ya-wpKnHvMQ0caJxtoz6qVeJxPCZvP-qBJifRfIxP3itQBVAAu7JJHxMa1AAP1AAPMAAA1AAP'
    assert blinder.qb64 == qb64

    eqb64 = '-bAaEFaQ00QW-ZeoMxE9baWcpJbAFXrs5h0ya-wpKnHvMQ0caJxtoz6qVeJxPCZvP-qBJifRfIxP3itQBVAAu7JJHxMa1AAP1AAPMAAA1AAP'
    assert Blinder.enclose([blinder]).decode() == eqb64

    regid = regBob
    prior = regBob
    stamp = '2025-08-01T18:06:10.988921+00:00'

    said = 'EOBVdcIL2rVEzBDpQvmBpsp3R52DsoKhTAAdvHqAz9yc'

    # test  use default sn=1  default kind=JSON
    serder = blindate(regid=regid, prior=prior, blid=blid, stamp=stamp)
    assert serder.said == said
    assert serder.proto == Protocols.acdc
    assert serder.pvrsn == Vrsn_2_0
    assert serder.genus == GenDex.KERI
    assert serder.gvrsn == Vrsn_2_0
    assert serder.kind == Kinds.json
    assert serder.ilk == Ilks.bup
    assert serder.stamp == stamp
    assert serder.sad['rd'] == regid
    assert serder.sad['b'] == blid
    assert serder.sad == \
    {
        "v": "ACDCCAACAAJSONAAEi.",
        "t": "bup",
        "d": "EOBVdcIL2rVEzBDpQvmBpsp3R52DsoKhTAAdvHqAz9yc",
        "rd": "ECOWJI9kAjpCFYJ7RenpJx2w66-GsGlhyKLO-Or3qOIQ",
        "n": "1",
        "p": "ECOWJI9kAjpCFYJ7RenpJx2w66-GsGlhyKLO-Or3qOIQ",
        "dt": "2025-08-01T18:06:10.988921+00:00",
        "b": "EFaQ00QW-ZeoMxE9baWcpJbAFXrs5h0ya-wpKnHvMQ0c"
    }
    prior = serder.said

    acdc = 'EMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M'  # bob project report ACDC
    state = 'issued'
    sn = 2
    bsn = 1
    bd = 'EJOnAKXGaSyJ_43kit0V806NNeGWS07lfjybB1UcfWsv'

    blid = 'EJAeKLEtVtMtt28IdAKJShyZHodEIZTHJHzaP21A_ZU4'
    uuid = 'aKNPEY4_60x6vUx2g5_5kAoJTn0RDspR04Ql8ecNyTkO'

    blinder = Blinder.blind(acdc=acdc, state=state, salt=salt, sn=sn,
                            bound=True, bsn=bsn, bd=bd)
    assert blinder.said == blid
    assert blinder.uuid == uuid

    assert blinder.acdc == acdc
    assert blinder.state == state
    assert blinder.bsn == bsn
    assert blinder.bd == bd

    dummied = '############################################aKNPEY4_60x6vUx2g5_5kAoJTn0RDspR04Ql8ecNyTkOEMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M0MissuedMAABEJOnAKXGaSyJ_43kit0V806NNeGWS07lfjybB1UcfWsv'
    assert len(dummied) == 188

    qb64 = 'EJAeKLEtVtMtt28IdAKJShyZHodEIZTHJHzaP21A_ZU4aKNPEY4_60x6vUx2g5_5kAoJTn0RDspR04Ql8ecNyTkOEMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M0MissuedMAABEJOnAKXGaSyJ_43kit0V806NNeGWS07lfjybB1UcfWsv'
    assert blinder.qb64 == qb64

    eqb64 = '-bAvEJAeKLEtVtMtt28IdAKJShyZHodEIZTHJHzaP21A_ZU4aKNPEY4_60x6vUx2g5_5kAoJTn0RDspR04Ql8ecNyTkOEMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M0MissuedMAABEJOnAKXGaSyJ_43kit0V806NNeGWS07lfjybB1UcfWsv'
    assert Blinder.enclose([blinder]).decode() == eqb64

    stamp = '2020-08-02T12:00:20.000000+00:00'
    said = 'EGu4B78s6G_GVrzaoBw2a1vkFpB5tVo-wZ1OGsC9D_pK'

    serder = blindate(regid=regid, prior=prior, blid=blid, stamp=stamp, sn=sn)
    assert serder.said == said
    assert serder.proto == Protocols.acdc
    assert serder.pvrsn == Vrsn_2_0
    assert serder.genus == GenDex.KERI
    assert serder.gvrsn == Vrsn_2_0
    assert serder.kind == Kinds.json
    assert serder.ilk == Ilks.bup
    assert serder.stamp == stamp
    assert serder.sad['rd'] == regid
    assert serder.sad['b'] == blid
    assert serder.sad == \
    {
        "v": "ACDCCAACAAJSONAAEi.",
        "t": "bup",
        "d": "EGu4B78s6G_GVrzaoBw2a1vkFpB5tVo-wZ1OGsC9D_pK",
        "rd": "ECOWJI9kAjpCFYJ7RenpJx2w66-GsGlhyKLO-Or3qOIQ",
        "n": "2",
        "p": "EOBVdcIL2rVEzBDpQvmBpsp3R52DsoKhTAAdvHqAz9yc",
        "dt": "2020-08-02T12:00:20.000000+00:00",
        "b": "EJAeKLEtVtMtt28IdAKJShyZHodEIZTHJHzaP21A_ZU4"
    }

    state = 'revoked'
    sn = 3
    bsn = 8
    bd = "EDeCPBTHAt75Acgi9PfEciHFnc1r2DKAno3s9_QIYrXk"

    blid = 'EIBNZ3t5rA_-PbBNmhtvtf0VgHBjVrE0fc-DO67f-wGv'
    uuid = 'aFudXE-d0b2owzZNBjd78sx4kCTJx-RTP_Zd19HRUcVD'

    blinder = Blinder.blind(acdc=acdc, state=state, salt=salt, sn=sn,
                            bound=True, bsn=bsn, bd=bd)
    assert blinder.said == blid
    assert blinder.uuid == uuid
    assert blinder.acdc == acdc
    assert blinder.state == state
    assert blinder.bsn == bsn
    assert blinder.bd == bd

    dummied = '############################################aFudXE-d0b2owzZNBjd78sx4kCTJx-RTP_Zd19HRUcVDEMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4MYrevokedMAAIEDeCPBTHAt75Acgi9PfEciHFnc1r2DKAno3s9_QIYrXk'
    assert len(dummied) == 188

    qb64 = 'EIBNZ3t5rA_-PbBNmhtvtf0VgHBjVrE0fc-DO67f-wGvaFudXE-d0b2owzZNBjd78sx4kCTJx-RTP_Zd19HRUcVDEMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4MYrevokedMAAIEDeCPBTHAt75Acgi9PfEciHFnc1r2DKAno3s9_QIYrXk'
    assert blinder.qb64 == qb64

    eqb64 = '-bAvEIBNZ3t5rA_-PbBNmhtvtf0VgHBjVrE0fc-DO67f-wGvaFudXE-d0b2owzZNBjd78sx4kCTJx-RTP_Zd19HRUcVDEMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4MYrevokedMAAIEDeCPBTHAt75Acgi9PfEciHFnc1r2DKAno3s9_QIYrXk'
    assert Blinder.enclose([blinder]).decode() == eqb64

    prior = serder.said
    stamp = '2020-08-03T12:00:20.000000+00:00'
    said = 'EDXGqM-V_sfj65Dk-lgMnpOZ9DYziqMaYkrju7NRKpFn'

    serder = blindate(regid=regid, prior=prior, blid=blid, stamp=stamp, sn=sn)
    assert serder.said == said
    assert serder.proto == Protocols.acdc
    assert serder.pvrsn == Vrsn_2_0
    assert serder.genus == GenDex.KERI
    assert serder.gvrsn == Vrsn_2_0
    assert serder.kind == Kinds.json
    assert serder.ilk == Ilks.bup
    assert serder.stamp == stamp
    assert serder.sad['rd'] == regid
    assert serder.sad['b'] == blid
    assert serder.sad == \
    {
        "v": "ACDCCAACAAJSONAAEi.",
        "t": "bup",
        "d": "EDXGqM-V_sfj65Dk-lgMnpOZ9DYziqMaYkrju7NRKpFn",
        "rd": "ECOWJI9kAjpCFYJ7RenpJx2w66-GsGlhyKLO-Or3qOIQ",
        "n": "3",
        "p": "EGu4B78s6G_GVrzaoBw2a1vkFpB5tVo-wZ1OGsC9D_pK",
        "dt": "2020-08-03T12:00:20.000000+00:00",
        "b": "EIBNZ3t5rA_-PbBNmhtvtf0VgHBjVrE0fc-DO67f-wGv"
    }


    # NonBlindable Update `upd` example
    # Registry3 RegDeb test default kind JSON uuid3 Stamp3
    stamp3 = '2025-07-04T17:53:00.000000+00:00'
    serder = regcept(issuer=deb, uuid=uuids[3], stamp=stamp3)
    assert serder.sad == \
    {
        "v": "ACDCCAACAAJSONAADa.",
        "t": "rip",
        "d": "EJl5EUxL23p_pqgN3IyM-pzru89Nb7NzOM8ijH644xSU",
        "u": "0ABhY2Rjc3BlY3dvcmtyYXcz",
        "i": "EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW",
        "n": "0",
        "dt": "2025-07-04T17:53:00.000000+00:00"
    }
    regDeb = serder.said
    assert regDeb == "EJl5EUxL23p_pqgN3IyM-pzru89Nb7NzOM8ijH644xSU"
    prior = serder.said

    regid = regDeb
    acdc = 'EAU5dUws4ffM9jZjWs0QfXTnhJ1qk2u3IUhBwFVbFnt5'  # deb research report
    stamp = '2020-08-03T12:00:20.000000+00:00'
    state = 'issued'
    sn = 1
    said = 'EJFxtbr9WioIkzTfVX4iC6Axxyg8jjKSX0ZrJgoNHiB-'
    serder = update(regid=regid, prior=prior, acdc=acdc, state=state, stamp=stamp, sn=sn)
    assert serder.said == said
    assert serder.sad == \
    {
        "v": "ACDCCAACAAJSONAAEx.",
        "t": "upd",
        "d": "EJFxtbr9WioIkzTfVX4iC6Axxyg8jjKSX0ZrJgoNHiB-",
        "rd": "EJl5EUxL23p_pqgN3IyM-pzru89Nb7NzOM8ijH644xSU",
        "n": "1",
        "p": "EJl5EUxL23p_pqgN3IyM-pzru89Nb7NzOM8ijH644xSU",
        "dt": "2020-08-03T12:00:20.000000+00:00",
        "td": "EAU5dUws4ffM9jZjWs0QfXTnhJ1qk2u3IUhBwFVbFnt5",
        "ts": "issued"
    }
    prior = serder.said

    stamp = '2020-08-04T12:00:20.000000+00:00'
    state = 'revoked'
    sn = 2
    said = 'EJQ-ezS6h0Oa0BIN_w4KjstdapfOfrwmVluxn1DR5Gja'
    serder = update(regid=regid, prior=prior, acdc=acdc, state=state, stamp=stamp, sn=sn)
    assert serder.said == said
    assert serder.sad == \
    {
        "v": "ACDCCAACAAJSONAAEy.",
        "t": "upd",
        "d": "EJQ-ezS6h0Oa0BIN_w4KjstdapfOfrwmVluxn1DR5Gja",
        "rd": "EJl5EUxL23p_pqgN3IyM-pzru89Nb7NzOM8ijH644xSU",
        "n": "2",
        "p": "EJFxtbr9WioIkzTfVX4iC6Axxyg8jjKSX0ZrJgoNHiB-",
        "dt": "2020-08-04T12:00:20.000000+00:00",
        "td": "EAU5dUws4ffM9jZjWs0QfXTnhJ1qk2u3IUhBwFVbFnt5",
        "ts": "revoked"
    }
    prior = serder.said


    """Done Test"""

def test_acdc_attribute_section_JSON():
    """Attribute section examples using JSON"""

    issuer = "ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz"
    issuee = "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf"

    amy = "ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz"
    bob = "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf"
    cal = "ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT"
    deb = "EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW"

    raws = [b'acdcspecworkraw' + b'%0x'%(i, ) for i in range(16)]
    uuids = [Noncer(raw=raw).qb64 for raw in raws]

    rd0 = "EOMMCyztOvg970W0dZVJT2JIwlQ22DSeY7wtxNBBtpmX"
    rd1 = "ECOWJI9kAjpCFYJ7RenpJx2w66-GsGlhyKLO-Or3qOIQ"
    rd2 = "EPtolmh_NE2vC02oFc7FOiWkPcEiKUPWm5uu_Gv1JZDw"
    rd3 = "EJl5EUxL23p_pqgN3IyM-pzru89Nb7NzOM8ijH644xSU"

    #Basic attribute section example

    privateSchema = \
    {
        "description": "Attribute Section",
        "oneOf":
        [
            {
                "description": "Attribute Section SAID",
                "type": "string"
              },
              {
                "description": "Attribute Section Detail",
                "type": "object",
                "required":
                [
                  "d",
                  "u",
                  "i",
                  "score",
                  "name"
                ],
                "properties":
                {
                  "d":
                  {
                    "description": "Attribute Section SAID",
                    "type": "string"
                  },
                  "u":
                  {
                    "description": "Attribute Section UUID",
                    "type": "string"
                  },
                  "i":
                  {
                    "description": "Issuee AID",
                    "type": "string"
                  },
                  "score":
                  {
                    "description": "Test Score",
                    "type": "integer"
                  },
                  "name":
                  {
                    "description": "Test Taker Full Name",
                    "type": "string"
                  }
                },
                "additionalProperties": False
              }
        ]
    }

    publicSchema = \
    {
      "description": "Attribute Section",
      "oneOf":
      [
        {
          "description": "Sttribute Section SAID",
          "type": "string"
        },
        {
          "description": "Attribute Section Detail",
          "type": "object",
          "required":
          [
            "d",
            "i",
            "score",
            "name"
          ],
          "properties":
          {
            "d":
            {
              "description": "Attribute Section SAID",
              "type": "string"
            },
            "i":
            {
              "description": "Issuee AID",
              "type": "string"
            },
            "score":
            {
              "description": "Test Score",
              "type": "integer"
            },
            "name":
            {
              "description": "Test Taker Full Name",
              "type": "string"
            }
          },
          "additionalProperties": False
        }
      ]
    }

    # private targeted attribute section
    mad = \
    {
    "d": "",
    "u": uuids[0],
    "i": issuee,
    "score": 96,
    "name": "Zoe Doe"
    }

    mapper = Mapper(mad=mad, saidive=True, makify=True, kind=Kinds.json)
    assert mapper.mad == \
    {
        "d": "EIMMcLl1w2KW2J3AD3twaESJO4u_fDFCdlMHjouojU8C",
        "u": "0ABhY2Rjc3BlY3dvcmtyYXcw",
        "i": "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf",
        "score": 96,
        "name": "Zoe Doe"
    }

    # public targeted attribute section
    mad = \
    {
    "d": "",
    "i": issuee,
    "score": 96,
    "name": "Zoe Doe"
    }

    mapper = Mapper(mad=mad, saidive=True, makify=True, kind=Kinds.json)
    assert mapper.mad == \
    {
        "d": "ELNJxIInWN4WAih9MQ4vVDrMRYnmhToS9a0gqjLfctOO",
        "i": "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf",
        "score": 96,
        "name": "Zoe Doe"
    }

    # partially disclosable attribute section

    partialSchema = \
    {
        "description": "Attribute Section",
        "oneOf":
        [
          {
            "description": "Attribute Section SAID",
            "type": "string"
          },
          {
            "description": "Attribute Section Detail",
            "type": "object",
            "required":
            [
              "d",
              "u",
              "i",
              "name"
              "gpa",
              "grades"
            ],
            "properties":
            {
              "d":
              {
                "description": "Attribute Section SAID",
                "type": "string"
              },
              "i":
              {
                "description": "Issuee AID",
                "type": "string"
              },
              "name":
              {
                "description": "Student Full Name",
                "type": "string"
              },
              "gpa":
              {
                "description": "Grade Point Average",
                "type": "number"
              },
              "grades":
              {
                "description": "Grades Block",
                "oneOf":
                [
                  {
                    "description": "Block SAID",
                    "type": "string"
                  },
                  {
                    "description": "Block detail",
                    "type": "object",
                    "required":
                    [
                      "d",
                      "u",
                      "history"
                      "english",
                      "math"
                    ],
                    "properties":
                    {
                      "d":
                      {
                        "description": "Block SAID",
                        "type": "string"
                      },
                      "u":
                      {
                        "description": "Block UUID",
                        "type": "string"
                      },
                      "history":
                      {
                        "description": "History Grade",
                        "type": "number"
                      },
                      "english":
                      {
                        "description": "English Grade",
                        "type": "number"
                      },
                      "math":
                      {
                        "description": "Math Grade",
                        "type": "number"
                      }
                    },
                    "additionalProperties": False
                  }
                ]
              },
              "additionalProperties": False
            }
          }
        ]
    }


    mad = \
    {
        "d": "",
        "u": uuids[0],
        "i": issuee,
        "name": "Zoe Doe",
        "gpa": 3.5,
        "grades":
        {
          "d": "",
          "u": uuids[1],
          "history": 3.5,
          "english": 4.0,
          "math": 3.0
        }
    }

    compactor = Compactor(mad=mad, makify=True, compactify=True, kind=Kinds.json)
    assert compactor.said == 'ELI2TuO6mLF0cR_0iU57EjYK4dExHIHdHxlRcAdO6x-U'
    assert compactor.iscompact
    assert compactor.mad == \
    {
        'd': 'ELI2TuO6mLF0cR_0iU57EjYK4dExHIHdHxlRcAdO6x-U',
        'u': '0ABhY2Rjc3BlY3dvcmtyYXcw',
        'i': 'ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf',
        'name': 'Zoe Doe',
        'gpa': 3.5,
        'grades': 'EFQnBFeKAeS4DAWYoKDwWXOT4h2-XaGk7-w4-2N4ktXy'
    }

    assert compactor.partials[('.grades',)].mad == \
    {
        'd': 'ELI2TuO6mLF0cR_0iU57EjYK4dExHIHdHxlRcAdO6x-U',
        'u': '0ABhY2Rjc3BlY3dvcmtyYXcw',
        'i': 'ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf',
        'name': 'Zoe Doe',
        'gpa': 3.5,
        'grades':
        {
            'd': 'EFQnBFeKAeS4DAWYoKDwWXOT4h2-XaGk7-w4-2N4ktXy',
            'u': '0ABhY2Rjc3BlY3dvcmtyYXcx',
            'history': 3.5,
            'english': 4.0,
            'math': 3.0
        }
    }

    assert compactor.partials[('',)].mad == \
    {
        'd': 'ELI2TuO6mLF0cR_0iU57EjYK4dExHIHdHxlRcAdO6x-U',
        'u': '0ABhY2Rjc3BlY3dvcmtyYXcw',
        'i': 'ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf',
        'name': 'Zoe Doe',
        'gpa': 3.5,
        'grades': 'EFQnBFeKAeS4DAWYoKDwWXOT4h2-XaGk7-w4-2N4ktXy'
    }


def test_acdc_aggregate_section_JSON():
    """Aggregate section using JSON"""

    amy = issuer = "ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz"
    bob = issuee = "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf"
    cal = "ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT"
    deb = "EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW"

    raws = [b'acdcspecworkraw' + b'%0x'%(i, ) for i in range(16)]
    uuids = [Noncer(raw=raw).qb64 for raw in raws]

    rd0 = "EOMMCyztOvg970W0dZVJT2JIwlQ22DSeY7wtxNBBtpmX"
    rd1 = "ECOWJI9kAjpCFYJ7RenpJx2w66-GsGlhyKLO-Or3qOIQ"
    rd2 = "EPtolmh_NE2vC02oFc7FOiWkPcEiKUPWm5uu_Gv1JZDw"
    rd3 = "EJl5EUxL23p_pqgN3IyM-pzru89Nb7NzOM8ijH644xSU"


    schema = \
    {
      "description": "Selectively disclosable attribute aggregate section",
      "oneOf":
      [
        {
          "description": "Aggregate Section AGID",
          "type": "string"
        },
        {
          "description": "Selectively disclosable attribute details",
          "type": "array",
          "uniqueItems": True,
          "items":
          {
            "anyOf":
            [
              {
                  "description": "Issue Block",
                  "oneOf":
                  [
                      {
                          "description": "Issuee Block SAID",
                          "type": "string"
                      },
                      {
                        "description": "Issuee Block Detail",
                        "type": "object",
                        "required":
                        [
                          "d",
                          "u",
                          "i"
                        ],
                        "properties":
                        {
                          "d":
                          {
                            "description": "Block SAID",
                            "type": "string"
                          },
                          "u":
                          {
                            "description": "Block UUID",
                            "type": "string"
                          },
                          "i":
                          {
                            "description": "Issuee SAID",
                            "type": "string"
                          }
                        },
                        "additionalProperties": False
                      }
                  ]
              },
              {
                  "description": "Score Block",
                  "oneOf":
                  [
                      {
                          "description": "Score Block SAID",
                          "type": "string"
                      },
                      {
                        "description": "Score Block Detail",
                        "type": "object",
                        "required":
                        [
                          "d",
                          "u",
                          "score"
                        ],
                        "properties":
                        {
                          "d":
                          {
                            "description": "Block SAID",
                            "type": "string"
                          },
                          "u":
                          {
                            "description": "Block UUID",
                            "type": "string"
                          },
                          "score":
                          {
                            "description": "Score Value",
                            "type": "integer"
                          }
                        },
                        "additionalProperties": False
                      }
                  ]
              },
              {
                  "description": "Name Block",
                  "oneOf":
                  [
                      {
                          "description": "Name Block SAID",
                          "type": "string"
                      },
                      {
                        "description": "Name Block Detail",
                        "type": "object",
                        "required":
                        [
                          "d",
                          "u",
                          "name"
                        ],
                        "properties":
                        {
                          "d":
                          {
                            "description": "Block SAID",
                            "type": "string"
                          },
                          "u":
                          {
                            "description": "Block UUID",
                            "type": "string"
                          },
                          "name":
                          {
                            "description": "Name Value",
                            "type": "string"
                          }
                        },
                        "additionalProperties": False
                      }
                  ]
              }
            ]
          }
        }
      ],
      "additionalProperties": False
    }


    iael = \
    [
      "",
      {
        "d": "",
        "u": uuids[0],
        "i": issuee
      },
      {
        "d": "",
        "u": uuids[1],
        "score": 96
      },
      {
        "d": "",
        "u": uuids[2],
        "name": "Zoe Doe"
      }
    ]

    kind = Kinds.json

    oael = \
    [
        "EN5d44fTNM0M4kmMMVrsH0HwMLRLyb6SoJEV0ogkLdXx",
        {
            "d": "EI2lwi1ZKrs-bDwgEreOhEh-W2O5xrOm5T-QCyMuX5V4",
            "u": "0ABhY2Rjc3BlY3dvcmtyYXcw",
            "i": "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf"
        },
        {
            "d": "EC-vU19URXX8ztfWdp_j2HHr1lJsqtGa1YHtZrg6-GMR",
            "u": "0ABhY2Rjc3BlY3dvcmtyYXcx",
            "score": 96
        },
        {
            "d": "EKYLUIpDXNT0ujSdoNOT5pLp0okOKW3mAbg-M7K5OO_C",
            "u": "0ABhY2Rjc3BlY3dvcmtyYXcy",
            "name": "Zoe Doe"
        }
    ]
    agid = "EN5d44fTNM0M4kmMMVrsH0HwMLRLyb6SoJEV0ogkLdXx"

    cael = \
    [
        "EN5d44fTNM0M4kmMMVrsH0HwMLRLyb6SoJEV0ogkLdXx",
        "EI2lwi1ZKrs-bDwgEreOhEh-W2O5xrOm5T-QCyMuX5V4",
        "EC-vU19URXX8ztfWdp_j2HHr1lJsqtGa1YHtZrg6-GMR",
        "EKYLUIpDXNT0ujSdoNOT5pLp0okOKW3mAbg-M7K5OO_C"
    ]

    craw = (b'["############################################","EI2lwi1ZKrs-bDwgEreOhEh-W2O'
            b'5xrOm5T-QCyMuX5V4","EC-vU19URXX8ztfWdp_j2HHr1lJsqtGa1YHtZrg6-GMR","EKYLUIpDX'
            b'NT0ujSdoNOT5pLp0okOKW3mAbg-M7K5OO_C"]')

    dael = \
    [
        "EN5d44fTNM0M4kmMMVrsH0HwMLRLyb6SoJEV0ogkLdXx",
        {
            "d": "EI2lwi1ZKrs-bDwgEreOhEh-W2O5xrOm5T-QCyMuX5V4",
            "u": "0ABhY2Rjc3BlY3dvcmtyYXcw",
            "i": "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf"
        },
        {
            "d": "EC-vU19URXX8ztfWdp_j2HHr1lJsqtGa1YHtZrg6-GMR",
            "u": "0ABhY2Rjc3BlY3dvcmtyYXcx",
            "score": 96
        },
        "EKYLUIpDXNT0ujSdoNOT5pLp0okOKW3mAbg-M7K5OO_C"
    ]

    aggor = Aggor(ael=iael, makify=True, kind=kind)
    assert aggor.agid == agid
    assert aggor.ael == oael
    assert aggor.disclose() == (cael, kind)
    assert aggor.disclose([1, 2]) == (dael, kind)

    """Done Test"""


def test_acdc_aggregate_section_CESR():
    """Aggregate section using CESR

    Note:  The aids and rds here were derived using json serializations of
    the assocted kel and rip messages. Its fine to have ACDC issuer's kel use a
    different serialization from an ACDC issued by that issuer
    """

    amy = issuer = "ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz"
    bob = issuee = "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf"
    cal = "ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT"
    deb = "EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW"

    raws = [b'acdcspecworkraw' + b'%0x'%(i, ) for i in range(16)]
    uuids = [Noncer(raw=raw).qb64 for raw in raws]

    rd0 = "EOMMCyztOvg970W0dZVJT2JIwlQ22DSeY7wtxNBBtpmX"
    rd1 = "ECOWJI9kAjpCFYJ7RenpJx2w66-GsGlhyKLO-Or3qOIQ"
    rd2 = "EPtolmh_NE2vC02oFc7FOiWkPcEiKUPWm5uu_Gv1JZDw"
    rd3 = "EJl5EUxL23p_pqgN3IyM-pzru89Nb7NzOM8ijH644xSU"

    iael = \
    [
      "",
      {
        "d": "",
        "u": uuids[0],
        "i": issuee
      },
      {
        "d": "",
        "u": uuids[1],
        "score": 96
      },
      {
        "d": "",
        "u": uuids[2],
        "name": "Zoe Doe"
      }
    ]

    kind = Kinds.cesr

    oael = \
    [
        "EEL7OTDzXjYoaDE8g8064thOpKdxsJWaG8DhRyOB58qW",
        {
            "d": "EPss9hsx7P5iYjWXNYJM5NiEu5EtPQHdGZ5K-qXK2p5E",
            "u": "0ABhY2Rjc3BlY3dvcmtyYXcw",
            "i": "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf"
        },
        {
            "d": "EGoIcPap1swfLGRQzTaxf38HsLFuHehBCY5kUSDK8XGs",
            "u": "0ABhY2Rjc3BlY3dvcmtyYXcx",
            "score": 96
        },
        {
            "d": "ED50KTrvT5n20JFTsyZFvBJfH-bOAVP9xHFhtbI5nCN6",
            "u": "0ABhY2Rjc3BlY3dvcmtyYXcy",
            "name": "Zoe Doe"
        }
    ]

    agid = 'EEL7OTDzXjYoaDE8g8064thOpKdxsJWaG8DhRyOB58qW'

    cael = \
    [
        "EEL7OTDzXjYoaDE8g8064thOpKdxsJWaG8DhRyOB58qW",
        "EPss9hsx7P5iYjWXNYJM5NiEu5EtPQHdGZ5K-qXK2p5E",
        "EGoIcPap1swfLGRQzTaxf38HsLFuHehBCY5kUSDK8XGs",
        "ED50KTrvT5n20JFTsyZFvBJfH-bOAVP9xHFhtbI5nCN6"
    ]

    craw = (b'-JAs############################################EPss9hsx7P5iYjWXNYJM5NiEu5Et'
            b'PQHdGZ5K-qXK2p5EEGoIcPap1swfLGRQzTaxf38HsLFuHehBCY5kUSDK8XGsED50KTrvT5n20JFT'
            b'syZFvBJfH-bOAVP9xHFhtbI5nCN6')

    dael = \
    [
        "EEL7OTDzXjYoaDE8g8064thOpKdxsJWaG8DhRyOB58qW",
        {
            "d": "EPss9hsx7P5iYjWXNYJM5NiEu5EtPQHdGZ5K-qXK2p5E",
            "u": "0ABhY2Rjc3BlY3dvcmtyYXcw",
            "i": "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf"
        },
        {
            "d": "EGoIcPap1swfLGRQzTaxf38HsLFuHehBCY5kUSDK8XGs",
            "u": "0ABhY2Rjc3BlY3dvcmtyYXcx",
            "score": 96
        },
        "ED50KTrvT5n20JFTsyZFvBJfH-bOAVP9xHFhtbI5nCN6"
    ]

    aggor = Aggor(ael=iael, makify=True, kind=kind)
    assert aggor.agid == agid
    assert aggor.ael == oael
    assert aggor.disclose() == (cael, kind)
    assert aggor.disclose([1, 2]) == (dael, kind)


    """Done Test"""

def test_acdc_rule_section_JSON():
    """Rule section using JSON"""

    amy = issuer = "ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz"
    bob = issuee = "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf"
    cal = "ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT"
    deb = "EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW"

    raws = [b'acdcspecworkraw' + b'%0x'%(i, ) for i in range(16)]
    uuids = [Noncer(raw=raw).qb64 for raw in raws]

    rd0 = "EOMMCyztOvg970W0dZVJT2JIwlQ22DSeY7wtxNBBtpmX"
    rd1 = "ECOWJI9kAjpCFYJ7RenpJx2w66-GsGlhyKLO-Or3qOIQ"
    rd2 = "EPtolmh_NE2vC02oFc7FOiWkPcEiKUPWm5uu_Gv1JZDw"
    rd3 = "EJl5EUxL23p_pqgN3IyM-pzru89Nb7NzOM8ijH644xSU"

    schema = \
    {
        "description": "Rule Section",
        "oneOf":
        [
            {
                "description": "Rule Section SAID",
                "type": "string"
            },
            {
                "description": "Rule Section Detail",
                "type": "object",
                "required":
                [
                    "d",
                    "u",
                    "disclaimers",
                    "permittedUse"
                ],
                "properties":
                {
                    "d":
                    {
                        "description": "Rule Section SAID",
                        "type": "string"
                    },
                    "u":
                    {
                        "description": "Rule Section UUID",
                        "type": "string"
                    },
                    "disclaimers":
                    {
                        "description": "Rule Group",
                        "oneOf":
                        [
                            {
                                "description": "Rule Group SAID",
                                "type": "string"
                            },
                            {
                                "description": "Rule Group Detail",
                                "type": "object",
                                "required":
                                [
                                    "d",
                                    "u",
                                    "l",
                                    "warrantyDisclaimer",
                                    "liabilityDisclaimer"
                                ],
                                "properties":
                                {
                                    "warrantyDisclaimer":
                                    {
                                        "oneOf":
                                        [
                                            {
                                                "description": "Rule SAID",
                                                "type": "string"
                                            },
                                            {
                                                "description": "Rule Detail",
                                                "type": "object",
                                                "required":
                                                [
                                                    "d",
                                                    "u",
                                                    "l"
                                                ],
                                                "properties":
                                                {
                                                    "d":
                                                    {
                                                        "description": "Rule SAID",
                                                        "type": "string"
                                                    },
                                                    "u":
                                                    {
                                                        "description": "Rule UUID",
                                                        "type": "string"
                                                    },
                                                    "l":
                                                    {
                                                        "description": "Legal Language",
                                                        "type": "string"
                                                    }
                                                },
                                                "additionalProperties": False
                                            }
                                        ],
                                    },
                                    "liabilityDisclaimer":
                                    {
                                        "oneOf":
                                        [
                                            {
                                                "description": "Rule SAID",
                                                "type": "string"
                                            },
                                            {
                                                "description": "Rule Detail",
                                                "type": "object",
                                                "required":
                                                [
                                                    "d",
                                                    "u",
                                                    "l"
                                                ],
                                                "properties":
                                                {
                                                    "d":
                                                    {
                                                        "description": "Rule SAID",
                                                        "type": "string"
                                                    },
                                                    "u":
                                                    {
                                                        "description": "Rule UUID",
                                                        "type": "string"
                                                    },
                                                    "l":
                                                    {
                                                        "description": "Legal Language",
                                                        "type": "string"
                                                    }
                                                },
                                                "additionalProperties": False
                                            }
                                        ]
                                    }
                                }
                            }
                        ],
                    },
                    "permittedUse":
                    {
                        "oneOf":
                        [
                            {
                                "description": "Rule SAID",
                                "type": "string"
                            },
                            {
                                "description": "Rule Detail",
                                "type": "object",
                                "required":
                                [
                                    "d",
                                    "u",
                                    "l"
                                ],
                                "properties":
                                {
                                    "d":
                                    {
                                        "description": "Clause SAID",
                                        "type": "string"
                                    },
                                    "u":
                                    {
                                        "description": "Clause UUID",
                                        "type": "string"
                                    },
                                    "l":
                                    {
                                        "description": "Legal Language",
                                        "type": "string"
                                    }
                                },
                                "additionalProperties": False
                            }
                        ]
                    }
                },
                "additionalProperties": False
            }
        ]
    }

    rimad = \
    {
      "d": "",
      "u": uuids[0],
      "disclaimers":
      {
        "d": "",
        "u": uuids[1],
        "l": "The person or legal entity identified by this ACDC's Issuer AID (Issuer) makes the following disclaimers:",
        "warrantyDisclaimer":
        {
          "d": "",
          "u": uuids[2],
          "l": "Issuer provides this ACDC on an AS IS basis."
        },
        "liabilityDisclaimer":
        {
          "d": "",
          "u": uuids[3],
          "l": "The Issuer SHALL NOT be liable for ANY damages arising as a result of this credential."
        }
      },
      "permittedUse":
      {
        "d": "",
        "u": uuids[4],
        "l": "The Issuee (controller of the Issuee AID) MAY only use this ACDC for non-commercial purposes."
      }
    }

    # JSON
    kind = Kinds.json
    said = 'EL7oXtsH1t7YqOOCS0fMhWfUKx1fHwiQ2u47fVba4lAA'
    rcmad = \
    {
        "d": "EL7oXtsH1t7YqOOCS0fMhWfUKx1fHwiQ2u47fVba4lAA",
        "u": "0ABhY2Rjc3BlY3dvcmtyYXcw",
        "disclaimers": "EIRP8ZLuMNb1I_Uk1GgnD3qZ_MAh6GaXV1JmzFKLebb3",
        "permittedUse": "EIn94r7ax0PmalGUddjP3ElnU2Lzz92UFE1uIinoVeVs"
    }

    compactor = Compactor(mad=rimad, makify=True, kind=kind, compactify=True)
    assert compactor.said == said
    assert compactor.mad == rcmad
    assert compactor.kind == kind

    epath = ('.disclaimers.warrantyDisclaimer', '.disclaimers.liabilityDisclaimer', '.permittedUse')
    assert compactor.partials[epath].mad == \
    {
        "d": "EL7oXtsH1t7YqOOCS0fMhWfUKx1fHwiQ2u47fVba4lAA",
        "u": "0ABhY2Rjc3BlY3dvcmtyYXcw",
        "disclaimers":
        {
            "d": "EIRP8ZLuMNb1I_Uk1GgnD3qZ_MAh6GaXV1JmzFKLebb3",
            "u": "0ABhY2Rjc3BlY3dvcmtyYXcx",
            "l": "The person or legal entity identified by this ACDC's Issuer AID (Issuer) makes the following disclaimers:",
            "warrantyDisclaimer":
            {
                "d": "EA84ClmyIMrSl5XaAWENAxTVZH25_YZGmu0WQm_VBBeV",
                "u": "0ABhY2Rjc3BlY3dvcmtyYXcy",
                "l": "Issuer provides this ACDC on an AS IS basis."
            },
            "liabilityDisclaimer":
            {
                "d": "ECENp0nXYDm_bLgr7TlJ8ns8I1QI2qzyqxoXnYG8B-ac",
                "u": "0ABhY2Rjc3BlY3dvcmtyYXcz",
                "l": "The Issuer SHALL NOT be liable for ANY damages arising as a result of this credential."
            }
        },
        "permittedUse":
        {
            "d": "EIn94r7ax0PmalGUddjP3ElnU2Lzz92UFE1uIinoVeVs",
            "u": "0ABhY2Rjc3BlY3dvcmtyYXc0",
            "l": "The Issuee (controller of the Issuee AID) MAY only use this ACDC for non-commercial purposes."
        }
    }

    # Non partially disclosable rule section

    schema = \
    {
      "description": "Rule Section",
      "oneOf":
      [
        {
          "description": "Rule Section SAID",
          "type": "string"
        },
        {
          "description": "Rule Section Detail",
          "type": "object",
          "required":
          [
            "d",
            "disclaimers",
            "permittedUse"
          ],
          "properties":
          {
            "d":
            {
              "description": "Rule Section SAID",
              "type": "string"
            },
            "disclaimers":
            {
              "description": "Rule Group",
              "type": "object",
              "required":
              [
                "l",
                "warrantyDisclaimer",
                "liabilityDisclaimer"
              ],
              "properties":
              {
                "l":
                {
                    "description": "Legal Language",
                    "type": "string"
                },
                "warrantyDisclaimer":
                {
                    "description": "Rule in Simple Compact Form",
                    "type": "string"
                },
                "liabilityDisclaimer":
                {
                    "description": "Rule in Simple Compact Form",
                    "type": "string"
                }
              },
              "additionalProperties": False
            },
            "permittedUse":
            {
              "description": "Rule in Simple Compact Form",
              "type": "string"
            },
          },
          "additionalProperties": False
        }
      ]
    }


    rimad = \
    {
      "d": "",
      "disclaimers":
      {
        "l": "The person or legal entity identified by this ACDC's Issuer AID (Issuer) makes the following disclaimers:",
        "warrantyDisclaimer": "Issuer provides this ACDC on an AS IS basis.",
        "liabilityDisclaimer": "The Issuer SHALL NOT be liable for ANY damages arising as a result of this credential."
      },
      "permittedUse":  "The Issuee (controller of the Issuee AID) MAY only use this ACDC for non-commercial purposes."
    }

    said = "EF9f-pCPJcgQclUu1OzzAfgyURW7iLPF2nwhuKYHFBlV"
    rcmad = \
    {
        "d": "EF9f-pCPJcgQclUu1OzzAfgyURW7iLPF2nwhuKYHFBlV",
        "disclaimers":
        {
            "l": "The person or legal entity identified by this ACDC's Issuer AID (Issuer) makes the following disclaimers:",
            "warrantyDisclaimer": "Issuer provides this ACDC on an AS IS basis.",
            "liabilityDisclaimer": "The Issuer SHALL NOT be liable for ANY damages arising as a result of this credential."
        },
        "permittedUse": "The Issuee (controller of the Issuee AID) MAY only use this ACDC for non-commercial purposes."
    }

    compactor = Compactor(mad=rimad, makify=True, kind=kind, compactify=True)
    assert compactor.said == said
    assert compactor.mad == rcmad
    assert compactor.kind == kind

    epath = ('',)
    assert compactor.partials[epath].mad == rcmad

    """Done Test"""




def test_acdc_examples_JSON():
    """Basic Examples using JSON serializaton"""
    amy = issuer = "ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz"
    bob = issuee = "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf"
    cal = "ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT"
    deb = "EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW"

    raws = [b'acdcspecworkraw' + b'%0x'%(i, ) for i in range(16)]
    uuids = [Noncer(raw=raw).qb64 for raw in raws]

    regAmy = "EOMMCyztOvg970W0dZVJT2JIwlQ22DSeY7wtxNBBtpmX"
    regBob = "ECOWJI9kAjpCFYJ7RenpJx2w66-GsGlhyKLO-Or3qOIQ"
    regCal = "EPtolmh_NE2vC02oFc7FOiWkPcEiKUPWm5uu_Gv1JZDw"
    regDeb = "EJl5EUxL23p_pqgN3IyM-pzru89Nb7NzOM8ijH644xSU"

    kind = Kinds.json

    # Example
    # Amy as school issues transcript credential to Bob as student
    # cal as accredidation agency issues auth credential to Amy as school
    # Amy prooves accredidation by linking via edge I2I with amy as issuee
    # Deb as department issues research report skill sample that names Bob as co-author
    # Amy endorses research paper by linking via edge NI2I
    # Bob as student issues poject report skill sample to whom it may concern
    # Amy endorses project report with Bob as issuer by linking via edge NI2I

    # Rule for the ACDCs
    ruleSchema = \
    {
      "description": "Rule Section",
      "oneOf":
      [
        {
          "description": "Rule Section SAID",
          "type": "string"
        },
        {
          "description": "Rule Section Detail",
          "type": "object",
          "required":
          [
            "d",
            "l"
          ],
          "properties":
          {
            "d":
            {
              "description": "Rule Section SAID",
              "type": "string"
            },
            "l":
            {
              "description": "Legal Language",
              "type": "string",
            },
          },
          "additionalProperties": False
        }
      ]
    }


    iRuleMad = \
    {
      "d": "",
      "l": "Issuer provides this ACDC on an AS IS basis. This ACDC in whole or in part MUST NOT be shared with any other entity besides the intended recipient."
    }

    ruleSaid = "EMZf9m0XYwqo4L8tnIDMZuX7YCZnMswS7Ta9j0CuYfjU"
    ruleMad = \
    {
        "d": "EMZf9m0XYwqo4L8tnIDMZuX7YCZnMswS7Ta9j0CuYfjU",
        "l": "Issuer provides this ACDC on an AS IS basis. This ACDC in whole or in part MUST NOT be shared with any other entity besides the intended recipient."
    }

    compactor = Compactor(mad=iRuleMad, makify=True, compactify=True, kind=kind)
    assert compactor.said == ruleSaid
    assert compactor.mad == ruleMad

    # Edge ACDCs
    # Accredidation ACDC
    # Accred attr section
    accrAttrSchema = \
    {
        "description": "Attribute Section",
        "oneOf":
        [
            {
                "description": "Attribute Section SAID",
                "type": "string"
              },
              {
                "description": "Attribute Section Detail",
                "type": "object",
                "required":
                [
                  "d",
                  "u",
                  "i",
                  "score",
                  "name"
                ],
                "properties":
                {
                  "d":
                  {
                    "description": "Attribute Section SAID",
                    "type": "string"
                  },
                  "u":
                  {
                    "description": "Attribute Section UUID",
                    "type": "string"
                  },
                  "i":
                  {
                    "description": "Issuee AID",
                    "type": "string"
                  },
                  "name":
                  {
                    "description": "Institution Name",
                    "type": "string"
                  },
                  "level":
                  {
                    "description": "Accreditation Level",
                    "type": "string"
                  }
                },
                "additionalProperties": False
              }
        ]
    }

    iAccrAttrMad = \
    {
        "d": "",
        "u": uuids[7],
        "i": amy,
        "name": "Sunspot College",
        "level": "gold"
    }

    accrAttrSaid = 'EK799owRYyk8UPFWUmfsm5AJfJmU7jZGtZXJFbg2I0KL'
    accrAttrMad = \
    {
        'd': 'EK799owRYyk8UPFWUmfsm5AJfJmU7jZGtZXJFbg2I0KL',
        'u': '0ABhY2Rjc3BlY3dvcmtyYXc3',
        'i': 'ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz',
        'name': 'Sunspot College',
        'level': 'gold'
    }

    compactor = Compactor(mad=iAccrAttrMad, makify=True, compactify=True, kind=kind)
    assert compactor.said == accrAttrSaid
    assert compactor.mad ==accrAttrMad

    #accreditation acdc schema
    iAccredSMad = \
    {
        "$id": "",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Accreditation Schema",
        "description": "Accreditation JSON Schema for acm ACDC.",
        "credentialType": "Accreditation_ACDC_acm_message",
        "version": "2.0.0",
        "type": "object",
        "required": [ "v", "d", "i", "s", "a", "r"],
        "properties":
        {
            "v": { "description": "ACDC version string", "type": "string"},
            "t": { "description": "Message type", "type": "string"},
            "d": { "description": "Message SAID", "type": "string"},
            "u": { "description": "Message UUID", "type": "string"},
            "i": { "description": "Issuer AID", "type": "string"},
            "rd": { "description": "Registry SAID", "type": "string"},
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
                      "description": "Schema Section Detail",
                      "type": "object"
                    }
                ]
            },
            "a":accrAttrSchema,
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
                      "description": "Edge Section Detail",
                      "type": "object"
                    }
                ]
            },
            "r": ruleSchema
        },
        "additionalProperties": False
    }

    accredSchemaSaid = 'EK_iGlfdc7Q-qIGL-kqbDSD2z4fesT4dAQLEHGgH4lLG'
    accredSchemaMad = \
    {
        "$id": "EK_iGlfdc7Q-qIGL-kqbDSD2z4fesT4dAQLEHGgH4lLG",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Accreditation Schema",
        "description": "Accreditation JSON Schema for acm ACDC.",
        "credentialType": "Accreditation_ACDC_acm_message",
        "version": "2.0.0",
        "type": "object",
        "required": ["v", "d", "i", "s", "a", "r"],
        "properties":
        {
            "v": {"description": "ACDC version string", "type": "string"},
            "t": {"description": "Message type", "type": "string"},
            "d": {"description": "Message SAID", "type": "string"},
            "u": {"description": "Message UUID", "type": "string"},
            "i": {"description": "Issuer AID", "type": "string"},
            "rd": {"description": "Registry SAID", "type": "string"},
            "s":
            {
                "description": "Schema Section",
                "oneOf":
                [
                    {"description": "Schema Section SAID", "type": "string"},
                    {"description": "Schema Section Detail", "type": "object"}
                ]
            },
            "a":
            {
                "description": "Attribute Section",
                "oneOf":
                [
                    {"description": "Attribute Section SAID", "type": "string"},
                    {
                        "description": "Attribute Section Detail",
                        "type": "object",
                        "required": ["d", "u", "i", "score", "name"],
                        "properties":
                        {
                            "d": {"description": "Attribute Section SAID", "type": "string"},
                            "u": {"description": "Attribute Section UUID", "type": "string"},
                            "i": {"description": "Issuee AID", "type": "string"},
                            "name": {"description": "Institution Name", "type": "string"},
                            "level": {"description": "Accreditation Level", "type": "string"}
                        },
                        "additionalProperties": False
                    }
                ]
            },
            "e":
            {
                "description": "Edge Section",
                "oneOf":
                [
                    {"description": "Edge Section SAID", "type": "string"},
                    {"description": "Edge Section Detail", "type": "object"}
                ]
            },
            "r":
            {
                "description": "Rule Section",
                "oneOf":
                [
                    {"description": "Rule Section SAID", "type": "string"},
                    {
                        "description": "Rule Section Detail",
                        "type": "object",
                        "required": ["d", "l"],
                        "properties":
                        {
                            "d": {"description": "Rule Section SAID", "type": "string"},
                            "l": {"description": "Legal Language", "type": "string"}
                        },
                        "additionalProperties": False
                    }
                ]
            }
        },
        "additionalProperties": False
    }

    mapper = Mapper(mad=iAccredSMad, makify=True, strict=False, saids={"$id": 'E',},
                    saidive=True, kind=kind)
    assert mapper.said == accredSchemaSaid
    assert mapper.mad == accredSchemaMad

    accredSaid = 'EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi'
    accredSad = \
    {
        "v": "ACDCCAACAAJSONAAKX.",
        "t": "acm",
        "d": "EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi",
        "u": "0ABhY2Rjc3BlY3dvcmtyYXdh",
        "i": "ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT",
        "rd": "EPtolmh_NE2vC02oFc7FOiWkPcEiKUPWm5uu_Gv1JZDw",
        "s": "EK_iGlfdc7Q-qIGL-kqbDSD2z4fesT4dAQLEHGgH4lLG",
        "a":
        {
            "d": "EK799owRYyk8UPFWUmfsm5AJfJmU7jZGtZXJFbg2I0KL",
            "u": "0ABhY2Rjc3BlY3dvcmtyYXc3",
            "i": "ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz",
            "name": "Sunspot College",
            "level": "gold"
        },
        "r":
        {
            "d": "EMZf9m0XYwqo4L8tnIDMZuX7YCZnMswS7Ta9j0CuYfjU",
            "l": "Issuer provides this ACDC on an AS IS basis. This ACDC in whole or in part MUST NOT be shared with any other entity besides the intended recipient."
        }
    }

    serder = acdcmap(issuer=cal, uuid=uuids[10], regid=regCal, schema=accredSchemaSaid,
                     attribute=accrAttrMad, issuee=amy, rule=ruleMad)
    assert serder.said == accredSaid
    assert serder.sad == accredSad

    accredCSad = \
    {
        "v": "ACDCCAACAAJSONAAF3.",
        "t": "acm",
        "d": "EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi",
        "u": "0ABhY2Rjc3BlY3dvcmtyYXdh",
        "i": "ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT",
        "rd": "EPtolmh_NE2vC02oFc7FOiWkPcEiKUPWm5uu_Gv1JZDw",
        "s": "EK_iGlfdc7Q-qIGL-kqbDSD2z4fesT4dAQLEHGgH4lLG",
        "a": "EK799owRYyk8UPFWUmfsm5AJfJmU7jZGtZXJFbg2I0KL",
        "r": "EMZf9m0XYwqo4L8tnIDMZuX7YCZnMswS7Ta9j0CuYfjU"
    }

    serder = acdcmap(issuer=cal, uuid=uuids[10], regid=regCal, schema=accredSchemaSaid,
                     attribute=accrAttrMad, issuee=amy, rule=ruleMad, compactify=True)
    assert serder.said == accredSaid
    assert serder.sad == accredCSad


    # Reports
    reportAttrSchema = \
    {
        "description": "Attribute Section",
        "oneOf":
        [
            { "description": "Attribute Section SAID", "type": "string"},
            {
                "description": "Attribute Section Detail",
                "type": "object",
                "required": [ "d", "u", "i", "title", "author", "report"],
                "properties":
                {
                  "d": {"description": "Attribute Section SAID", "type": "string"},
                  "u": {"description": "Attribute Section UUID", "type": "string"},
                  "title": {"description": "Report Title", "type": "string"},
                  "author": {"description": "Author Full Name", "type": "string"},
                  "report": { "description": "Report Body", "type": "string"}
                },
                "additionalProperties": False
              }
        ]
    }

    iReportSMad = \
    {
        "$id": "",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Report Schema",
        "description": "Report JSON Schema for acm ACDC.",
        "credentialType": "Report_ACDC_acm_message",
        "version": "2.0.0",
        "type": "object",
        "required": [ "v", "d", "i", "s", "a", "r"],
        "properties":
        {
            "v": { "description": "ACDC version string", "type": "string"},
            "t": { "description": "Message type", "type": "string"},
            "d": { "description": "Message SAID", "type": "string"},
            "u": { "description": "Message UUID", "type": "string"},
            "i": { "description": "Issuer AID", "type": "string"},
            "rd": { "description": "Registry SAID", "type": "string"},
            "s":
            {
                "description": "Schema Section",
                "oneOf":
                [
                    { "description": "Schema Section SAID", "type": "string"},
                    { "description": "Schema Section Detail", "type": "object"}
                ]
            },
            "a":reportAttrSchema,
            "e":
            {
                "description": "Edge Section",
                "oneOf":
                [
                    { "description": "Edge Section SAID", "type": "string"},
                    { "description": "Edge Section Detail", "type": "object"}
                ]
            },
            "r": ruleSchema
        },
        "additionalProperties": False
    }

    reportSchemaSaid = 'EKMXqyMQmOy0RuEj1VgOK9aD4GYR0D8Dcj0kssQtcY4-'
    reportSchemaMad = \
    {
        "$id": "EKMXqyMQmOy0RuEj1VgOK9aD4GYR0D8Dcj0kssQtcY4-",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Report Schema",
        "description": "Report JSON Schema for acm ACDC.",
        "credentialType": "Report_ACDC_acm_message",
        "version": "2.0.0",
        "type": "object",
        "required": ["v", "d", "i", "s", "a", "r"],
        "properties":
        {
            "v": {"description": "ACDC version string", "type": "string"},
            "t": {"description": "Message type", "type": "string"},
            "d": {"description": "Message SAID", "type": "string"},
            "u": {"description": "Message UUID", "type": "string"},
            "i": {"description": "Issuer AID", "type": "string"},
            "rd": {"description": "Registry SAID", "type": "string"},
            "s":
            {
                "description": "Schema Section",
                "oneOf":
                [
                    {"description": "Schema Section SAID", "type": "string"},
                    {"description": "Schema Section Detail", "type": "object"}
                ]
            },
            "a":
             {
                "description": "Attribute Section",
                "oneOf":
                [
                    { "description": "Attribute Section SAID", "type": "string"},
                    {
                        "description": "Attribute Section Detail",
                        "type": "object",
                        "required": [ "d", "u", "i", "title", "author", "report"],
                        "properties":
                        {
                          "d": {"description": "Attribute Section SAID", "type": "string"},
                          "u": {"description": "Attribute Section UUID", "type": "string"},
                          "title": {"description": "Report Title", "type": "string"},
                          "author": {"description": "Author Full Name", "type": "string"},
                          "report": { "description": "Report Body", "type": "string"}
                        },
                        "additionalProperties": False
                      }
                ]
            },
            "e":
            {
                "description": "Edge Section",
                "oneOf":
                [
                    {"description": "Edge Section SAID", "type": "string"},
                    {"description": "Edge Section Detail", "type": "object"}
                ]
            },
            "r":
            {
                "description": "Rule Section",
                "oneOf":
                [
                    {"description": "Rule Section SAID", "type": "string"},
                    {
                        "description": "Rule Section Detail",
                        "type": "object",
                        "required": ["d", "l"],
                        "properties":
                        {
                            "d": {"description": "Rule Section SAID", "type": "string"},
                            "l": {"description": "Legal Language", "type": "string"}
                        },
                        "additionalProperties": False
                    }
                ]
            }
        },
        "additionalProperties": False
    }

    mapper = Mapper(mad=iReportSMad, makify=True, strict=False, saids={"$id": 'E',},
                    saidive=True, kind=kind)
    assert mapper.said == reportSchemaSaid
    assert mapper.mad == reportSchemaMad

    # Research Report
    iRrptMad = \
    {
        "d": "",
        "u": uuids[8],
        "title": "Post Quantum Security",
        "name": "Zoe Doe",
        "report": "Imprementation should prioritize cryptographic agility over PQ.",
    }

    rrptSaid = 'EFTqnoiGSf-D76W3geNxEudBI_wz81FIkIXjzsjFztI-'
    rrptMad = \
    {
        'd': 'EFTqnoiGSf-D76W3geNxEudBI_wz81FIkIXjzsjFztI-',
        'u': '0ABhY2Rjc3BlY3dvcmtyYXc4',
        'title': 'Post Quantum Security',
        'name': 'Zoe Doe',
        'report': 'Imprementation should prioritize cryptographic agility over PQ.'
    }

    compactor = Compactor(mad=iRrptMad, makify=True, compactify=True, kind=kind)
    assert compactor.said == rrptSaid
    assert compactor.mad == rrptMad

    rReportSaid = 'EAU5dUws4ffM9jZjWs0QfXTnhJ1qk2u3IUhBwFVbFnt5'
    rReportSad = \
    {
        "v": "ACDCCAACAAJSONAAK4.",
        "t": "acm",
        "d": "EAU5dUws4ffM9jZjWs0QfXTnhJ1qk2u3IUhBwFVbFnt5",
        "u": "0ABhY2Rjc3BlY3dvcmtyYXdi",
        "i": "EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW",
        "rd": "EJl5EUxL23p_pqgN3IyM-pzru89Nb7NzOM8ijH644xSU",
        "s": "EKMXqyMQmOy0RuEj1VgOK9aD4GYR0D8Dcj0kssQtcY4-",
        "a":
        {
            "d": "EFTqnoiGSf-D76W3geNxEudBI_wz81FIkIXjzsjFztI-",
            "u": "0ABhY2Rjc3BlY3dvcmtyYXc4",
            "title": "Post Quantum Security",
            "name": "Zoe Doe",
            "report": "Imprementation should prioritize cryptographic agility over PQ."
        },
        "r":
        {
            "d": "EMZf9m0XYwqo4L8tnIDMZuX7YCZnMswS7Ta9j0CuYfjU",
            "l": "Issuer provides this ACDC on an AS IS basis. This ACDC in whole or in part MUST NOT be shared with any other entity besides the intended recipient."
        }
    }

    serder = acdcmap(issuer=deb, uuid=uuids[11], regid=regDeb, schema=reportSchemaSaid,
                     attribute=rrptMad, rule=ruleMad)
    assert serder.said == rReportSaid
    assert serder.sad == rReportSad

    rReportCSad = \
    {
        "v": "ACDCCAACAAJSONAAF3.",
        "t": "acm",
        "d": "EAU5dUws4ffM9jZjWs0QfXTnhJ1qk2u3IUhBwFVbFnt5",
        "u": "0ABhY2Rjc3BlY3dvcmtyYXdi",
        "i": "EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW",
        "rd": "EJl5EUxL23p_pqgN3IyM-pzru89Nb7NzOM8ijH644xSU",
        "s": "EKMXqyMQmOy0RuEj1VgOK9aD4GYR0D8Dcj0kssQtcY4-",
        "a": "EFTqnoiGSf-D76W3geNxEudBI_wz81FIkIXjzsjFztI-",
        "r": "EMZf9m0XYwqo4L8tnIDMZuX7YCZnMswS7Ta9j0CuYfjU"
    }

    serder = acdcmap(issuer=deb, uuid=uuids[11], regid=regDeb, schema=reportSchemaSaid,
                     attribute=rrptMad, rule=ruleMad, compactify=True)
    assert serder.said == rReportSaid
    assert serder.sad == rReportCSad


    # Project Report
    iPrptMad = \
    {
        "d": "",
        "u": uuids[9],
        "title": "PQ Proof of Concept",
        "name": "Zoe Doe",
        "report": "Demonstration of recovery from surprise quantum attack",
    }

    prptSaid = 'EIg1zAS3FfMMbQtLqARSwS3uGMttVbAPhKB71bjIPTs_'
    prptMad = \
    {
        'd': 'EIg1zAS3FfMMbQtLqARSwS3uGMttVbAPhKB71bjIPTs_',
        'u': '0ABhY2Rjc3BlY3dvcmtyYXc5',
        'title': 'PQ Proof of Concept',
        'name': 'Zoe Doe',
        'report': 'Demonstration of recovery from surprise quantum attack'
    }

    compactor = Compactor(mad=iPrptMad, makify=True, compactify=True, kind=kind)
    assert compactor.said == prptSaid
    assert compactor.mad == prptMad

    pReportSaid = 'EMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M'
    pReportSad = \
    {
        "v": "ACDCCAACAAJSONAAKt.",
        "t": "acm",
        "d": "EMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M",
        "u": "0ABhY2Rjc3BlY3dvcmtyYXdj",
        "i": "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf",
        "rd": "ECOWJI9kAjpCFYJ7RenpJx2w66-GsGlhyKLO-Or3qOIQ",
        "s": "EKMXqyMQmOy0RuEj1VgOK9aD4GYR0D8Dcj0kssQtcY4-",
        "a":
        {
            "d": "EIg1zAS3FfMMbQtLqARSwS3uGMttVbAPhKB71bjIPTs_",
            "u": "0ABhY2Rjc3BlY3dvcmtyYXc5",
            "title": "PQ Proof of Concept",
            "name": "Zoe Doe",
            "report": "Demonstration of recovery from surprise quantum attack"
        },
        "r":
        {
            "d": "EMZf9m0XYwqo4L8tnIDMZuX7YCZnMswS7Ta9j0CuYfjU",
            "l": "Issuer provides this ACDC on an AS IS basis. This ACDC in whole or in part MUST NOT be shared with any other entity besides the intended recipient."
        }
    }

    serder = acdcmap(issuer=bob, uuid=uuids[12], regid=regBob, schema=reportSchemaSaid,
                     attribute=prptMad, rule=ruleMad)
    assert serder.said == pReportSaid
    assert serder.sad == pReportSad

    pReportCSad = \
    {
        "v": "ACDCCAACAAJSONAAF3.",
        "t": "acm",
        "d": "EMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M",
        "u": "0ABhY2Rjc3BlY3dvcmtyYXdj",
        "i": "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf",
        "rd": "ECOWJI9kAjpCFYJ7RenpJx2w66-GsGlhyKLO-Or3qOIQ",
        "s": "EKMXqyMQmOy0RuEj1VgOK9aD4GYR0D8Dcj0kssQtcY4-",
        "a": "EIg1zAS3FfMMbQtLqARSwS3uGMttVbAPhKB71bjIPTs_",
        "r": "EMZf9m0XYwqo4L8tnIDMZuX7YCZnMswS7Ta9j0CuYfjU"
    }

    serder = acdcmap(issuer=bob, uuid=uuids[12], regid=regBob, schema=reportSchemaSaid,
                     attribute=prptMad, rule=ruleMad, compactify=True)
    assert serder.said == pReportSaid
    assert serder.sad == pReportCSad


    # main ACDC

    mainAttrSchema = \
    {
        "description": "Attribute Section",
        "oneOf":
        [
          { "description": "Attribute Section SAID", "type": "string"},
          {
            "description": "Attribute Section Detail",
            "type": "object",
            "required": ["d", "u", "i", "name" "gpa", "grades"],
            "properties":
            {
              "d": {"description": "Attribute Section SAID", "type": "string"},
              "i": {"description": "Issuee AID", "type": "string"},
              "name": {"description": "Student Full Name", "type": "string"},
              "gpa": {"description": "Grade Point Average", "type": "number"},
              "grades":
              {
                "description": "Grades Block",
                "oneOf":
                [
                  {"description": "Block SAID", "type": "string"},
                  {
                    "description": "Block detail",
                    "type": "object",
                    "required": ["d", "u", "history" "english", "math"],
                    "properties":
                    {
                      "d": {"description": "Block SAID", "type": "string"},
                      "u": {"description": "Block UUID", "type": "string"},
                      "history": {"description": "History Grade", "type": "number"},
                      "english": {"description": "English Grade", "type": "number"},
                      "math": {"description": "Math Grade", "type": "number"}
                    },
                    "additionalProperties": False
                  }
                ]
              },
              "additionalProperties": False
            }
          }
        ]
    }

    iAttrMad = \
    {
        "d": "",
        "u": uuids[0],
        "i": bob,
        "name": "Zoe Doe",
        "gpa": 3.5,
        "grades":
        {
          "d": "",
          "u": uuids[1],
          "history": 3.5,
          "english": 4.0,
          "math": 3.0
        }
    }

    mainAttrSaid = 'ELI2TuO6mLF0cR_0iU57EjYK4dExHIHdHxlRcAdO6x-U'
    mainAttrCMad = \
    {
        'd': 'ELI2TuO6mLF0cR_0iU57EjYK4dExHIHdHxlRcAdO6x-U',
        'u': '0ABhY2Rjc3BlY3dvcmtyYXcw',
        'i': 'ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf',
        'name': 'Zoe Doe',
        'gpa': 3.5,
        'grades': 'EFQnBFeKAeS4DAWYoKDwWXOT4h2-XaGk7-w4-2N4ktXy'
    }

    mainAttrMad = \
    {
        'd': 'ELI2TuO6mLF0cR_0iU57EjYK4dExHIHdHxlRcAdO6x-U',
        'u': '0ABhY2Rjc3BlY3dvcmtyYXcw',
        'i': 'ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf',
        'name': 'Zoe Doe',
        'gpa': 3.5,
        'grades':
        {
            'd': 'EFQnBFeKAeS4DAWYoKDwWXOT4h2-XaGk7-w4-2N4ktXy',
            'u': '0ABhY2Rjc3BlY3dvcmtyYXcx',
            'history': 3.5,
            'english': 4.0,
            'math': 3.0
        }
    }

    compactor = Compactor(mad=iAttrMad, makify=True, compactify=True, kind=kind)
    assert compactor.said == mainAttrSaid
    assert compactor.mad == mainAttrCMad
    assert compactor.partials[('.grades',)].mad == mainAttrMad


    mainEdgeSchema = \
    {
        "description": "Edge Section",
        "oneOf":
        [
          { "description": "Edge Section SAID", "type": "string"},
          {
            "description": "Edge Section Detail",
            "type": "object",
            "required": ["d", "u", "accreditation" "reports"],
            "properties":
            {
              "d": {"description": "Edge Section SAID", "type": "string"},
              "u": {"description": "Edge Section UUID", "type": "string"},
              "o": {"description": "Edge Section M-ary Operator", "type": "string"},
              "w": {"description": "Edge Section Weight", "type": "number"},
              "accreditation":
              {
                "description": "Accreditation Edge",
                "oneOf":
                [
                  {"description": "Edge SAID", "type": "string"},
                  {
                    "description": "Edge Detail",
                    "type": "object",
                    "required": ["n"],
                    "properties":
                    {
                      "d": {"description": "Edge SAID", "type": "string"},
                      "u": {"description": "Edge UUID", "type": "string"},
                      "n": {"description": "Far Node SAID", "type": "string"},
                      "s": {"description": "Far Node Schema SAID", "type": "string"},
                      "o": {"description": "Edge Unary Operator", "type": "string"},
                      "w": {"description": "Edge Weight", "type": "number"},
                    },
                    "additionalProperties": False
                  }
                ]
              },
              "reports":
              {
                "description": "Reports Edge Group",
                "oneOf":
                [
                  {"description": "Edge Group SAID", "type": "string"},
                  {
                    "description": "Edge Group detail",
                    "type": "object",
                    "required": ["research", "project"],
                    "properties":
                    {
                      "d": {"description": "Block SAID", "type": "string"},
                      "u": {"description": "Block UUID", "type": "string"},
                      "s": {"description": "Far Node Schema SAID", "type": "string"},
                      "o": {"description": "Edge Group M-ary Operator", "type": "string"},
                      "w": {"description": "Edge Group Weight", "type": "number"},
                      "research":
                      {
                        "description": "Research Edge",
                        "oneOf":
                        [
                          {"description": "Edge SAID", "type": "string"},
                          {
                            "description": "Edge Detail",
                            "type": "object",
                            "required": ["n"],
                            "properties":
                            {
                              "d": {"description": "Edge SAID", "type": "string"},
                              "u": {"description": "Edge UUID", "type": "string"},
                              "n": {"description": "Far Node SAID", "type": "string"},
                              "s": {"description": "Far Node Schema SAID", "type": "string"},
                              "o": {"description": "Edge Unary Operator", "type": "string"},
                              "w": {"description": "Edge Weight", "type": "number"},
                            },
                            "additionalProperties": False
                          }
                        ]
                      },
                      "project":
                      {
                        "description": "Project Edge",
                        "oneOf":
                        [
                          {"description": "Edge SAID", "type": "string"},
                          {
                            "description": "Edge Detail",
                            "type": "object",
                            "required": ["n"],
                            "properties":
                            {
                              "d": {"description": "Edge SAID", "type": "string"},
                              "u": {"description": "Edge UUID", "type": "string"},
                              "n": {"description": "Far Node SAID", "type": "string"},
                              "s": {"description": "Far Node Schema SAID", "type": "string"},
                              "o": {"description": "Edge Unary Operator", "type": "string"},
                              "w": {"description": "Edge Weight", "type": "number"},
                            },
                            "additionalProperties": False
                          }
                        ]
                      }
                    },
                    "additionalProperties": False
                  }
                ]
              },
              "additionalProperties": False
            }
          }
        ]
    }


    iEdgeMad = \
    {
        'd': '',
        'u': uuids[2],
        "accreditation":
        {
          "d": "",
          "u": uuids[3],
          "n": accredSaid,
          "s": accredSchemaSaid
        },
        "reports":
        {
            "d": "",
            "u": uuids[4],
            "o": "OR",
            "research":
            {
              "d": "",
              "u": uuids[6],
              "n": rReportSaid,
              "o": "NI2I"
            },
            "project":
            {
              "d": "",
              "u": uuids[5],
              "n": pReportSaid,
              "o": "NI2I"
            }
        }
    }

    mainEdgeSaid = 'ECpmTyIIc1duvCeIceK19Sbd0uymklmwNTtwtmfjQnX0'
    mainEdgeCMad = \
    {
        'd': 'ECpmTyIIc1duvCeIceK19Sbd0uymklmwNTtwtmfjQnX0',
        'u': '0ABhY2Rjc3BlY3dvcmtyYXcy',
        'accreditation': 'EAFj8JaNEC3mdFNJKrXW8E03_k9qqb_xM9NjAPVHw-xJ',
        'reports': 'EOObmbCppe1S-7vtLuy766_4-RcfrC7p4ciFtBxdexuz'
    }
    mainEdgeMad = \
    {
        'd': 'ECpmTyIIc1duvCeIceK19Sbd0uymklmwNTtwtmfjQnX0',
        'u': '0ABhY2Rjc3BlY3dvcmtyYXcy',
        'accreditation':
        {
            'd': 'EAFj8JaNEC3mdFNJKrXW8E03_k9qqb_xM9NjAPVHw-xJ',
            'u': '0ABhY2Rjc3BlY3dvcmtyYXcz',
            'n': 'EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi',
            's': 'EK_iGlfdc7Q-qIGL-kqbDSD2z4fesT4dAQLEHGgH4lLG'
        },
        'reports':
        {
            'd': 'EOObmbCppe1S-7vtLuy766_4-RcfrC7p4ciFtBxdexuz',
            'u': '0ABhY2Rjc3BlY3dvcmtyYXc0',
            'o': 'OR',
            'research':
            {
                'd': 'EN9ngstOcFHqsjqf75JZFKtCRmW76NkeRrUSxTLoqqkI',
                'u': '0ABhY2Rjc3BlY3dvcmtyYXc2',
                'n': 'EAU5dUws4ffM9jZjWs0QfXTnhJ1qk2u3IUhBwFVbFnt5',
                'o': 'NI2I'
            },
            'project':
            {
                'd': 'EFwHz5qJ4_8c7IefP7_zugX2eIgtoyY8Up_WZ3osXwkI',
                'u': '0ABhY2Rjc3BlY3dvcmtyYXc1',
                'n': 'EMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M',
                'o': 'NI2I'
            }
        }
    }

    compactor = Compactor(mad=iEdgeMad, makify=True, compactify=True, kind=kind)
    assert compactor.said == mainEdgeSaid
    assert compactor.mad == mainEdgeCMad
    path = ('.accreditation', '.reports.research', '.reports.project')
    assert compactor.partials[path].mad == mainEdgeMad

    iMainSMad = \
    {
        "$id": "",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Transcript Schema",
        "description": "Transcript JSON Schema for acm ACDC.",
        "credentialType": "Transcript_ACDC_acm_message",
        "version": "2.0.0",
        "type": "object",
        "required": [ "v", "d", "i", "s", "a", "r"],
        "properties":
        {
            "v": { "description": "ACDC version string", "type": "string"},
            "t": { "description": "Message type", "type": "string"},
            "d": { "description": "Message SAID", "type": "string"},
            "u": { "description": "Message UUID", "type": "string"},
            "i": { "description": "Issuer AID", "type": "string"},
            "rd": { "description": "Registry SAID", "type": "string"},
            "s":
            {
                "description": "Schema Section",
                "oneOf":
                [
                    { "description": "Schema Section SAID", "type": "string"},
                    { "description": "Schema Section Detail", "type": "object"}
                ]
            },
            "a": mainAttrSchema,
            "e": mainEdgeSchema,
            "r": ruleSchema
        },
        "additionalProperties": False
    }

    mainSchemaSaid = 'EABGAia_vH_zHCRLOK3Bm2xxujV5A8sYIJbypfSM_2Fh'
    mainSchemaMad = \
    {
        "$id": "EABGAia_vH_zHCRLOK3Bm2xxujV5A8sYIJbypfSM_2Fh",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Transcript Schema",
        "description": "Transcript JSON Schema for acm ACDC.",
        "credentialType": "Transcript_ACDC_acm_message",
        "version": "2.0.0",
        "type": "object",
        "required": ["v", "d", "i", "s", "a", "r"],
        "properties":
        {
            "v": {"description": "ACDC version string", "type": "string"},
            "t": {"description": "Message type", "type": "string"},
            "d": {"description": "Message SAID", "type": "string"},
            "u": {"description": "Message UUID", "type": "string"},
            "i": {"description": "Issuer AID", "type": "string"},
            "rd": {"description": "Registry SAID", "type": "string"},
            "s":
            {
                "description": "Schema Section",
                "oneOf":
                [
                    {"description": "Schema Section SAID", "type": "string"},
                    {"description": "Schema Section Detail", "type": "object"}
                ]
            },
            "a":
             {
                "description": "Attribute Section",
                "oneOf":
                [
                    { "description": "Attribute Section SAID", "type": "string"},
                    {
                      "description": "Attribute Section Detail",
                      "type": "object",
                      "required": ["d", "u", "i", "name" "gpa", "grades"],
                      "properties":
                      {
                        "d": {"description": "Attribute Section SAID", "type": "string"},
                        "i": {"description": "Issuee AID", "type": "string"},
                        "name": {"description": "Student Full Name", "type": "string"},
                        "gpa": {"description": "Grade Point Average", "type": "number"},
                        "grades":
                        {
                          "description": "Grades Block",
                          "oneOf":
                          [
                            {"description": "Block SAID", "type": "string"},
                            {
                              "description": "Block detail",
                              "type": "object",
                              "required": ["d", "u", "history" "english", "math"],
                              "properties":
                              {
                                "d": {"description": "Block SAID", "type": "string"},
                                "u": {"description": "Block UUID", "type": "string"},
                                "history": {"description": "History Grade", "type": "number"},
                                "english": {"description": "English Grade", "type": "number"},
                                "math": {"description": "Math Grade", "type": "number"}
                              },
                              "additionalProperties": False
                            }
                          ]
                        },
                        "additionalProperties": False
                      }
                    }
                ]
            },
            "e":
            {
                "description": "Edge Section",
                "oneOf":
                [
                  { "description": "Edge Section SAID", "type": "string"},
                  {
                    "description": "Edge Section Detail",
                    "type": "object",
                    "required": ["d", "u", "accreditation" "reports"],
                    "properties":
                    {
                      "d": {"description": "Edge Section SAID", "type": "string"},
                      "u": {"description": "Edge Section UUID", "type": "string"},
                      "o": {"description": "Edge Section M-ary Operator", "type": "string"},
                      "w": {"description": "Edge Section Weight", "type": "number"},
                      "accreditation":
                      {
                        "description": "Accreditation Edge",
                        "oneOf":
                        [
                          {"description": "Edge SAID", "type": "string"},
                          {
                            "description": "Edge Detail",
                            "type": "object",
                            "required": ["n"],
                            "properties":
                            {
                              "d": {"description": "Edge SAID", "type": "string"},
                              "u": {"description": "Edge UUID", "type": "string"},
                              "n": {"description": "Far Node SAID", "type": "string"},
                              "s": {"description": "Far Node Schema SAID", "type": "string"},
                              "o": {"description": "Edge Unary Operator", "type": "string"},
                              "w": {"description": "Edge Weight", "type": "number"},
                            },
                            "additionalProperties": False
                          }
                        ]
                      },
                      "reports":
                      {
                        "description": "Reports Edge Group",
                        "oneOf":
                        [
                          {"description": "Edge Group SAID", "type": "string"},
                          {
                            "description": "Edge Group detail",
                            "type": "object",
                            "required": ["research", "project"],
                            "properties":
                            {
                              "d": {"description": "Block SAID", "type": "string"},
                              "u": {"description": "Block UUID", "type": "string"},
                              "s": {"description": "Far Node Schema SAID", "type": "string"},
                              "o": {"description": "Edge Group M-ary Operator", "type": "string"},
                              "w": {"description": "Edge Group Weight", "type": "number"},
                              "research":
                              {
                                "description": "Research Edge",
                                "oneOf":
                                [
                                  {"description": "Edge SAID", "type": "string"},
                                  {
                                    "description": "Edge Detail",
                                    "type": "object",
                                    "required": ["n"],
                                    "properties":
                                    {
                                      "d": {"description": "Edge SAID", "type": "string"},
                                      "u": {"description": "Edge UUID", "type": "string"},
                                      "n": {"description": "Far Node SAID", "type": "string"},
                                      "s": {"description": "Far Node Schema SAID", "type": "string"},
                                      "o": {"description": "Edge Unary Operator", "type": "string"},
                                      "w": {"description": "Edge Weight", "type": "number"},
                                    },
                                    "additionalProperties": False
                                  }
                                ]
                              },
                              "project":
                              {
                                "description": "Project Edge",
                                "oneOf":
                                [
                                  {"description": "Edge SAID", "type": "string"},
                                  {
                                    "description": "Edge Detail",
                                    "type": "object",
                                    "required": ["n"],
                                    "properties":
                                    {
                                      "d": {"description": "Edge SAID", "type": "string"},
                                      "u": {"description": "Edge UUID", "type": "string"},
                                      "n": {"description": "Far Node SAID", "type": "string"},
                                      "s": {"description": "Far Node Schema SAID", "type": "string"},
                                      "o": {"description": "Edge Unary Operator", "type": "string"},
                                      "w": {"description": "Edge Weight", "type": "number"},
                                    },
                                    "additionalProperties": False
                                  }
                                ]
                              }
                            },
                            "additionalProperties": False
                          }
                        ]
                      },
                      "additionalProperties": False
                    }
                  }
                ]
            },
            "r":
            {
                "description": "Rule Section",
                "oneOf":
                [
                    {"description": "Rule Section SAID", "type": "string"},
                    {
                        "description": "Rule Section Detail",
                        "type": "object",
                        "required": ["d", "l"],
                        "properties":
                        {
                            "d": {"description": "Rule Section SAID", "type": "string"},
                            "l": {"description": "Legal Language", "type": "string"}
                        },
                        "additionalProperties": False
                    }
                ]
            }
        },
        "additionalProperties": False
    }

    mapper = Mapper(mad=iMainSMad, makify=True, strict=False, saids={"$id": 'E',},
                    saidive=True, kind=kind)
    assert mapper.said == mainSchemaSaid
    assert mapper.mad == mainSchemaMad

    mainSaid = 'ENeNWgCCNcOf1JbgKxUzREKpyK5kABYFd2QYUzEfwz9H'
    mainSad = \
    {
        "v": "ACDCCAACAAJSONAAXG.",
        "d": "ENeNWgCCNcOf1JbgKxUzREKpyK5kABYFd2QYUzEfwz9H",
        "u": "0ABhY2Rjc3BlY3dvcmtyYXdk",
        "i": "ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz",
        "rd": "EOMMCyztOvg970W0dZVJT2JIwlQ22DSeY7wtxNBBtpmX",
        "s": "EABGAia_vH_zHCRLOK3Bm2xxujV5A8sYIJbypfSM_2Fh",
        "a":
        {
            "d": "ELI2TuO6mLF0cR_0iU57EjYK4dExHIHdHxlRcAdO6x-U",
            "u": "0ABhY2Rjc3BlY3dvcmtyYXcw",
            "i": "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf",
            "name": "Zoe Doe",
            "gpa": 3.5,
            "grades":
            {
                "d": "EFQnBFeKAeS4DAWYoKDwWXOT4h2-XaGk7-w4-2N4ktXy",
                "u": "0ABhY2Rjc3BlY3dvcmtyYXcx",
                "history": 3.5,
                "english": 4.0,
                "math": 3.0
            }
        },
        "e":
        {
            "d": "ECpmTyIIc1duvCeIceK19Sbd0uymklmwNTtwtmfjQnX0",
            "u": "0ABhY2Rjc3BlY3dvcmtyYXcy",
            "accreditation":
            {
                "d": "EAFj8JaNEC3mdFNJKrXW8E03_k9qqb_xM9NjAPVHw-xJ",
                "u": "0ABhY2Rjc3BlY3dvcmtyYXcz",
                "n": "EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi",
                "s": "EK_iGlfdc7Q-qIGL-kqbDSD2z4fesT4dAQLEHGgH4lLG"
            },
            "reports":
            {
                "d": "EOObmbCppe1S-7vtLuy766_4-RcfrC7p4ciFtBxdexuz",
                "u": "0ABhY2Rjc3BlY3dvcmtyYXc0",
                "o": "OR",
                "research":
                {
                    "d": "EN9ngstOcFHqsjqf75JZFKtCRmW76NkeRrUSxTLoqqkI",
                    "u": "0ABhY2Rjc3BlY3dvcmtyYXc2",
                    "n": "EAU5dUws4ffM9jZjWs0QfXTnhJ1qk2u3IUhBwFVbFnt5",
                    "o": "NI2I"
                },
                "project":
                {
                    "d": "EFwHz5qJ4_8c7IefP7_zugX2eIgtoyY8Up_WZ3osXwkI",
                    "u": "0ABhY2Rjc3BlY3dvcmtyYXc1",
                    "n": "EMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M",
                    "o": "NI2I"
                }
            }
        },
        "r":
        {
            "d": "EMZf9m0XYwqo4L8tnIDMZuX7YCZnMswS7Ta9j0CuYfjU",
            "l": "Issuer provides this ACDC on an AS IS basis. This ACDC in whole or in part MUST NOT be shared with any other entity besides the intended recipient."
        }
    }

    serder = acdcmap(issuer=amy, ilk=None, uuid=uuids[13], regid=regAmy, schema=mainSchemaSaid,
                     attribute=mainAttrMad, edge=mainEdgeMad, rule=ruleMad)
    assert serder.said == mainSaid
    assert serder.sad == mainSad

    mainCSad = \
    {
        "v": "ACDCCAACAAJSONAAGg.",
        "d": "ENeNWgCCNcOf1JbgKxUzREKpyK5kABYFd2QYUzEfwz9H",
        "u": "0ABhY2Rjc3BlY3dvcmtyYXdk",
        "i": "ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz",
        "rd": "EOMMCyztOvg970W0dZVJT2JIwlQ22DSeY7wtxNBBtpmX",
        "s": "EABGAia_vH_zHCRLOK3Bm2xxujV5A8sYIJbypfSM_2Fh",
        "a": "ELI2TuO6mLF0cR_0iU57EjYK4dExHIHdHxlRcAdO6x-U",
        "e": "ECpmTyIIc1duvCeIceK19Sbd0uymklmwNTtwtmfjQnX0",
        "r": "EMZf9m0XYwqo4L8tnIDMZuX7YCZnMswS7Ta9j0CuYfjU"
    }

    serder = acdcmap(issuer=amy, ilk=None, uuid=uuids[13], regid=regAmy, schema=mainSchemaSaid,
                     attribute=mainAttrMad, edge=mainEdgeMad, rule=ruleMad, compactify=True)
    assert serder.said == mainSaid
    assert serder.sad == mainCSad

    # Simple Main Edge Schema Example

    simpleEdgeSchema = \
    {
        "description": "Edge Section",
        "oneOf":
        [
            { "description": "Edge Section SAID", "type": "string"},
            {
                "description": "Edge Section Detail",
                "type": "object",
                "required": ["d", "u", "accreditation" "reports"],
                "properties":
                {
                    "d": {"description": "Edge Section SAID", "type": "string"},
                    "u": {"description": "Edge Section UUID", "type": "string"},
                    "o": {"description": "Edge Section M-ary Operator", "type": "string"},
                    "w": {"description": "Edge Section Weight", "type": "number"},
                    "accreditation": {"description": "Far Node SAID", "type": "string"},
                    "reports":
                    {
                        "description": "Edge Group detail",
                        "type": "object",
                        "required": ["research", "project"],
                        "properties":
                        {
                            "d": {"description": "Block SAID", "type": "string"},
                            "u": {"description": "Block UUID", "type": "string"},
                            "s": {"description": "Far Node Schema SAID", "type": "string"},
                            "o": {"description": "Edge Group M-ary Operator", "type": "string"},
                            "w": {"description": "Edge Group Weight", "type": "number"},
                            "research": {"description": "Far Node SAID", "type": "string"},
                            "project": {"description": "Far Node SAID", "type": "string"},
                        },
                        "additionalProperties": False
                    }
                },
                "additionalProperties": False
            }
        ]
    }

    iSimpleEdgeMainSMad = \
    {
        "$id": "",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Transcript Schema",
        "description": "Transcript JSON Schema for acm ACDC.",
        "credentialType": "Transcript_ACDC_acm_message",
        "version": "2.0.0",
        "type": "object",
        "required": [ "v", "d", "i", "s", "a", "r"],
        "properties":
        {
            "v": { "description": "ACDC version string", "type": "string"},
            "t": { "description": "Message type", "type": "string"},
            "d": { "description": "Message SAID", "type": "string"},
            "u": { "description": "Message UUID", "type": "string"},
            "i": { "description": "Issuer AID", "type": "string"},
            "rd": { "description": "Registry SAID", "type": "string"},
            "s":
            {
                "description": "Schema Section",
                "oneOf":
                [
                    { "description": "Schema Section SAID", "type": "string"},
                    { "description": "Schema Section Detail", "type": "object"}
                ]
            },
            "a": mainAttrSchema,
            "e": simpleEdgeSchema,
            "r": ruleSchema
        },
        "additionalProperties": False
    }

    simpleMainSchemaSaid = 'ECVhGE4yeuHZ8KEqWK-lx5O9xrfUg6wiDPkkxxQSjgfk'
    simpleMainSchemaMad = \
    {
        "$id": "ECVhGE4yeuHZ8KEqWK-lx5O9xrfUg6wiDPkkxxQSjgfk",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Transcript Schema",
        "description": "Transcript JSON Schema for acm ACDC.",
        "credentialType": "Transcript_ACDC_acm_message",
        "version": "2.0.0",
        "type": "object",
        "required": ["v", "d", "i", "s", "a", "r"],
        "properties":
        {
            "v": {"description": "ACDC version string", "type": "string"},
            "t": {"description": "Message type", "type": "string"},
            "d": {"description": "Message SAID", "type": "string"},
            "u": {"description": "Message UUID", "type": "string"},
            "i": {"description": "Issuer AID", "type": "string"},
            "rd": {"description": "Registry SAID", "type": "string"},
            "s":
            {
                "description": "Schema Section",
                "oneOf":
                [
                    {"description": "Schema Section SAID", "type": "string"},
                    {"description": "Schema Section Detail", "type": "object"}
                ]
            },
            "a":
             {
                "description": "Attribute Section",
                "oneOf":
                [
                    { "description": "Attribute Section SAID", "type": "string"},
                    {
                      "description": "Attribute Section Detail",
                      "type": "object",
                      "required": ["d", "u", "i", "name" "gpa", "grades"],
                      "properties":
                      {
                        "d": {"description": "Attribute Section SAID", "type": "string"},
                        "i": {"description": "Issuee AID", "type": "string"},
                        "name": {"description": "Student Full Name", "type": "string"},
                        "gpa": {"description": "Grade Point Average", "type": "number"},
                        "grades":
                        {
                          "description": "Grades Block",
                          "oneOf":
                          [
                            {"description": "Block SAID", "type": "string"},
                            {
                              "description": "Block detail",
                              "type": "object",
                              "required": ["d", "u", "history" "english", "math"],
                              "properties":
                              {
                                "d": {"description": "Block SAID", "type": "string"},
                                "u": {"description": "Block UUID", "type": "string"},
                                "history": {"description": "History Grade", "type": "number"},
                                "english": {"description": "English Grade", "type": "number"},
                                "math": {"description": "Math Grade", "type": "number"}
                              },
                              "additionalProperties": False
                            }
                          ]
                        },
                        "additionalProperties": False
                      }
                    }
                ]
            },
            "e":
            {
                "description": "Edge Section",
                "oneOf":
                [
                    { "description": "Edge Section SAID", "type": "string"},
                    {
                        "description": "Edge Section Detail",
                        "type": "object",
                        "required": ["d", "u", "accreditation" "reports"],
                        "properties":
                        {
                            "d": {"description": "Edge Section SAID", "type": "string"},
                            "u": {"description": "Edge Section UUID", "type": "string"},
                            "o": {"description": "Edge Section M-ary Operator", "type": "string"},
                            "w": {"description": "Edge Section Weight", "type": "number"},
                            "accreditation": {"description": "Far Node SAID", "type": "string"},
                            "reports":
                            {
                                "description": "Edge Group detail",
                                "type": "object",
                                "required": ["research", "project"],
                                "properties":
                                {
                                    "d": {"description": "Block SAID", "type": "string"},
                                    "u": {"description": "Block UUID", "type": "string"},
                                    "s": {"description": "Far Node Schema SAID", "type": "string"},
                                    "o": {"description": "Edge Group M-ary Operator", "type": "string"},
                                    "w": {"description": "Edge Group Weight", "type": "number"},
                                    "research": {"description": "Far Node SAID", "type": "string"},
                                    "project": {"description": "Far Node SAID", "type": "string"},
                                },
                                "additionalProperties": False
                            }
                        },
                        "additionalProperties": False
                    }
                ]
            },
            "r":
            {
                "description": "Rule Section",
                "oneOf":
                [
                    {"description": "Rule Section SAID", "type": "string"},
                    {
                        "description": "Rule Section Detail",
                        "type": "object",
                        "required": ["d", "l"],
                        "properties":
                        {
                            "d": {"description": "Rule Section SAID", "type": "string"},
                            "l": {"description": "Legal Language", "type": "string"}
                        },
                        "additionalProperties": False
                    }
                ]
            }
        },
        "additionalProperties": False
    }

    mapper = Mapper(mad=iSimpleEdgeMainSMad, makify=True, strict=False, saids={"$id": 'E',},
                    saidive=True, kind=kind)
    assert mapper.said == simpleMainSchemaSaid
    assert mapper.mad == simpleMainSchemaMad

    iSimpleEdgeMad = \
    {
        'd': '',
        'u': uuids[2],
        "accreditation": accredSaid,
        "reports":
        {
            "o": "OR",
            "research": rReportSaid,
            "project": pReportSaid
        }
    }

    simpleEdgeSaid = 'EEWx-E6Rexj3eORT-e2kLcAWVgviTqxwWvxS2LbNKuCh'
    simpleEdgeCMad = \
    {
        'd': 'EEWx-E6Rexj3eORT-e2kLcAWVgviTqxwWvxS2LbNKuCh',
        'u': '0ABhY2Rjc3BlY3dvcmtyYXcy',
        'accreditation': 'EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi',
        'reports':
        {
            'o': 'OR',
            'research': 'EAU5dUws4ffM9jZjWs0QfXTnhJ1qk2u3IUhBwFVbFnt5',
            'project': 'EMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M'
        }
    }

    compactor = Compactor(mad=iSimpleEdgeMad, makify=True, compactify=True, kind=kind)
    assert compactor.said == simpleEdgeSaid
    assert compactor.mad == simpleEdgeCMad


    simpleMainSaid = 'EBaEMTKi6ZtHXmkhxHUoGEEtG8JKelw3b0gv6cFTg6BN'
    simpleMainSad = \
    {
        "v": "ACDCCAACAAJSONAAOD.",
        "d": "EBaEMTKi6ZtHXmkhxHUoGEEtG8JKelw3b0gv6cFTg6BN",
        "u": "0ABhY2Rjc3BlY3dvcmtyYXdl",
        "i": "ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz",
        "rd": "EOMMCyztOvg970W0dZVJT2JIwlQ22DSeY7wtxNBBtpmX",
        "s": "ECVhGE4yeuHZ8KEqWK-lx5O9xrfUg6wiDPkkxxQSjgfk",
        "a":
        {
            "d": "ELI2TuO6mLF0cR_0iU57EjYK4dExHIHdHxlRcAdO6x-U",
            "u": "0ABhY2Rjc3BlY3dvcmtyYXcw",
            "i": "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf",
            "name": "Zoe Doe",
            "gpa": 3.5,
            "grades":
            {
                "d": "EFQnBFeKAeS4DAWYoKDwWXOT4h2-XaGk7-w4-2N4ktXy",
                "u": "0ABhY2Rjc3BlY3dvcmtyYXcx",
                "history": 3.5,
                "english": 4.0,
                "math": 3.0
            }
        },
        "e":
        {
            "d": "EEWx-E6Rexj3eORT-e2kLcAWVgviTqxwWvxS2LbNKuCh",
            "u": "0ABhY2Rjc3BlY3dvcmtyYXcy",
            "accreditation": "EIF7egPvC8ITbGRdM9G0kd6aPELDg-azMkAqT-7cMuAi",
            "reports":
            {
                "o": "OR",
                "research": "EAU5dUws4ffM9jZjWs0QfXTnhJ1qk2u3IUhBwFVbFnt5",
                "project": "EMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M"
            }
        },
        "r": "EMZf9m0XYwqo4L8tnIDMZuX7YCZnMswS7Ta9j0CuYfjU"
    }

    serder = acdcmap(issuer=amy, ilk=None, uuid=uuids[14], regid=regAmy,
                     schema=simpleMainSchemaSaid, attribute=mainAttrMad,
                     edge=simpleEdgeCMad, rule=ruleSaid)
    assert serder.said == simpleMainSaid
    assert serder.sad == simpleMainSad

    simpleMainCSad = \
    {
        "v": "ACDCCAACAAJSONAAGg.",
        "d": "EBaEMTKi6ZtHXmkhxHUoGEEtG8JKelw3b0gv6cFTg6BN",
        "u": "0ABhY2Rjc3BlY3dvcmtyYXdl",
        "i": "ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz",
        "rd": "EOMMCyztOvg970W0dZVJT2JIwlQ22DSeY7wtxNBBtpmX",
        "s": "ECVhGE4yeuHZ8KEqWK-lx5O9xrfUg6wiDPkkxxQSjgfk",
        "a": "ELI2TuO6mLF0cR_0iU57EjYK4dExHIHdHxlRcAdO6x-U",
        "e": "EEWx-E6Rexj3eORT-e2kLcAWVgviTqxwWvxS2LbNKuCh",
        "r": "EMZf9m0XYwqo4L8tnIDMZuX7YCZnMswS7Ta9j0CuYfjU"
    }

    serder = acdcmap(issuer=amy, ilk=None, uuid=uuids[14], regid=regAmy,
                     schema=simpleMainSchemaSaid, attribute=mainAttrMad,
                     edge=simpleEdgeCMad, rule=ruleSaid, compactify=True)
    assert serder.said == simpleMainSaid
    assert serder.sad == simpleMainCSad


if __name__ == "__main__":
    test_acdc_examples_setup()
    test_acdc_registry_examples_JSON()
    test_blindable_state_tel_examples_JSON()
    test_acdc_attribute_section_JSON()
    test_acdc_aggregate_section_JSON()
    test_acdc_aggregate_section_CESR()
    test_acdc_rule_section_JSON()
    test_acdc_examples_JSON()


