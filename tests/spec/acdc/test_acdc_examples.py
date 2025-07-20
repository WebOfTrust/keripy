# -*- coding: utf-8 -*-
"""
tests.spec.acdc.test_acdc_examples module

"""
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64


import pytest

from keri import Vrsn_2_0, Kinds
from keri.core import MtrDex, Salter, Noncer, Mapper, Compactor
from keri.core.eventing import incept

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
    signers = salter.signers(count=4, transferable=True, temp=True)

    # create witness signers as nontransferable
    walt = b'acdcspecworkwits'
    walter = Salter(raw=walt)
    wigners = walter.signers(count=2,transferable=False, temp=True)

    # create issuer incepting key state, incepting signing key pair,
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

    # create issuer rotation key state
    """
    Issuer rotating seed
    size=32
    path='1'
    salt=b'acdcspecworkexam'
    opslimit=1
    memlimit=8192
    seed = pysodium.crypto_pwhash(outlen=size,
                                      passwd=path,
                                      salt=self.raw,
                                      opslimit=opslimit,
                                      memlimit=memlimit,
                                      alg=pysodium.crypto_pwhash_ALG_ARGON2ID13)
    seed = (b'\x82\xd7%\xd0\x9d\x95"u\x1d\x9c\x9d\x885ic\x86\x88\x84\xc7=Ps\x97\x88e\xf2\xab\xcc\x1e\xe2Q~')

    verkey, sigkey = pysodium.crypto_sign_seed_keypair(seed)
    verkey = (b'\xb7\xb8\xb9\xec2\xb6\xa7\xeak\x83A\xe0\t\xed4\xa0Y\xebR4M\x87 3?\x85K=U\xf6\xa7\x8c')
    First 32 bytes of this internal sigkey is seed so we use seed externally as sigkey
    verfer = Verfer(raw=verkey,
                    code=MtrDex.Ed25519 if transferable
                    else MtrDex.Ed25519N)
    """
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


    # create issuer witness key state

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

    # create issuee incepting key state
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

    # create issuee rotation key state

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

    # create issuee witness key state
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


def test_acdc_examples_JSON():
    """Basic Examples using JSON serializaton"""
    issuer = "ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz"
    issuee = "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf"

    raws = [b'acdcspecworkraw' + b'%0x'%(i, ) for i in range(16)]
    uuids = [Noncer(raw=raw).qb64 for raw in raws]

    uuid0 = '0ABhY2Rjc3BlY3dvcmtyYXcw'
    uuid1 = '0ABhY2Rjc3BlY3dvcmtyYXcx'

    #Basic attribute section example
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

    assert compactor.partials[('',)].mad == compactor.mad



if __name__ == "__main__":
    test_acdc_examples_setup()
    test_acdc_examples_JSON()
