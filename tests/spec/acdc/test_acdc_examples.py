# -*- coding: utf-8 -*-
"""
tests.spec.acdc.test_acdc_examples module

"""
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64


import pytest

from keri import Vrsn_2_0, Kinds
from keri.core import MtrDex, Salter
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
    signers = salter.signers(count=6, transferable=True, temp=True)

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
    """
    Issuer Witness seed
    size=32
    path='2'
    salt=b'acdcspecworkexam'
    opslimit=1
    memlimit=8192
    seed = pysodium.crypto_pwhash(outlen=size,
                                      passwd=path,
                                      salt=self.raw,
                                      opslimit=opslimit,
                                      memlimit=memlimit,
                                      alg=pysodium.crypto_pwhash_ALG_ARGON2ID13)
    seed = (b'vE}\xa1\xb5\xed<Zv\x1a\xf4\xaa#\xd8+$\x96\x1d\xc0\x14,>\xdb\xa6\xade\xa6\xb9{\xb4n[')

    verkey, sigkey = pysodium.crypto_sign_seed_keypair(seed)

    First 32 bytes of this internal sigkey is seed so we use seed externally as sigkey
    verkey = b'\xb7:\xbb\xbe\x8d"\xbd\x15\xaa*\xd0</d\xe1iN\x1f\r\xa6 o{CpU\xd1C7\x121\xf9'

    verfer = Verfer(raw=verkey,
                    code=MtrDex.Ed25519 if transferable
                    else MtrDex.Ed25519N)
    """
    issuerWitSeedRaw = (b'vE}\xa1\xb5\xed<Zv\x1a\xf4\xaa#\xd8+$\x96\x1d\xc0\x14,>\xdb\xa6\xade\xa6\xb9{\xb4n[')
    issuerWitSeedB64 = encodeB64(issuerWitSeedRaw)
    assert issuerWitSeedB64 == b'dkV9obXtPFp2GvSqI9grJJYdwBQsPtumrWWmuXu0bls='
    assert decodeB64(issuerWitSeedB64) == issuerWitSeedRaw

    issuerWitSigner = signers[2]
    issuerWitSigKey = issuerWitSigner.qb64  # issuer's private signing key seed
    issuerWitVerKey = issuerWitSigner.verfer.qb64  # issuer's public verification key
    assert issuerWitSigner.verfer.raw == b'\xb7:\xbb\xbe\x8d"\xbd\x15\xaa*\xd0</d\xe1iN\x1f\r\xa6 o{CpU\xd1C7\x121\xf9'
    assert encodeB64(issuerWitSigner.verfer.raw) == b'tzq7vo0ivRWqKtA8L2ThaU4fDaYgb3tDcFXRQzcSMfk='

    assert issuerWitSigKey == 'AHZFfaG17Txadhr0qiPYKySWHcAULD7bpq1lprl7tG5b'  # use in example
    assert issuerWitVerKey == 'DLc6u76NIr0VqirQPC9k4WlOHw2mIG97Q3BV0UM3EjH5' # use in example

    # create issuer AID with single sig simple inception event JSON
    keys = [issuerVerKey]  # initial signing keys
    nkeys = [issuerRotVerKey]  # next (rotation) keys
    wits = [issuerWitVerKey]  # witness aids (same as public verkey)
    serder = incept(keys, code=MtrDex.Blake3_256, ndigs=nkeys, wits=wits,
                    version=Vrsn_2_0, kind=Kinds.json)
    assert serder.pre == 'EIveOd-P96dx5KT5oA2hyI52SIG2V7XNIoo3QTmbs51T'
    assert serder.said == 'EIveOd-P96dx5KT5oA2hyI52SIG2V7XNIoo3QTmbs51T'
    assert serder.sad == \
    {
        'v': 'KERICAACAAJSONAAFb.',
        't': 'icp',
        'd': 'EIveOd-P96dx5KT5oA2hyI52SIG2V7XNIoo3QTmbs51T',
        'i': 'EIveOd-P96dx5KT5oA2hyI52SIG2V7XNIoo3QTmbs51T',
        's': '0',
        'kt': '1',
        'k': ['DA8-J0EW88RMYqtUHQDqT4q2YH2iBFlW8HobHKV74yi_'],
        'nt': '1',
        'n': ['DLe4uewytqfqa4NB4AntNKBZ61I0TYcgMz-FSz1V9qeM'],
        'bt': '1',
        'b': ['DLc6u76NIr0VqirQPC9k4WlOHw2mIG97Q3BV0UM3EjH5'],
        'c': [],
        'a': []
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAFb.","t":"icp","d":"EIveOd-P96dx5KT5oA2hyI52SIG2V7XNIo'
                        b'o3QTmbs51T","i":"EIveOd-P96dx5KT5oA2hyI52SIG2V7XNIoo3QTmbs51T","s":"0","kt":'
                        b'"1","k":["DA8-J0EW88RMYqtUHQDqT4q2YH2iBFlW8HobHKV74yi_"],"nt":"1","n":["DLe4'
                        b'uewytqfqa4NB4AntNKBZ61I0TYcgMz-FSz1V9qeM"],"bt":"1","b":["DLc6u76NIr0VqirQPC'
                        b'9k4WlOHw2mIG97Q3BV0UM3EjH5"],"c":[],"a":[]}')

    issuerAidJson = serder.pre
    assert issuerAidJson == 'EIveOd-P96dx5KT5oA2hyI52SIG2V7XNIoo3QTmbs51T'

    # create issuer AID with single sig simple inception event CESR
    keys = [issuerVerKey]  # initial signing keys
    nkeys = [issuerRotVerKey]  # next (rotation) keys
    wits = [issuerWitVerKey]  # witness aids (same as public verkey)
    serder = incept(keys, code=MtrDex.Blake3_256, ndigs=nkeys, wits=wits,
                    version=Vrsn_2_0, kind=Kinds.cesr)
    assert serder.pre == 'EF9ksTMfcHgFjXLV-uiklpuglxGmKh5n15r4Al7-sHq6'
    assert serder.said == 'EF9ksTMfcHgFjXLV-uiklpuglxGmKh5n15r4Al7-sHq6'
    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAAEU.',
        't': 'icp',
        'd': 'EF9ksTMfcHgFjXLV-uiklpuglxGmKh5n15r4Al7-sHq6',
        'i': 'EF9ksTMfcHgFjXLV-uiklpuglxGmKh5n15r4Al7-sHq6',
        's': '0',
        'kt': '1',
        'k': ['DA8-J0EW88RMYqtUHQDqT4q2YH2iBFlW8HobHKV74yi_'],
        'nt': '1',
        'n': ['DLe4uewytqfqa4NB4AntNKBZ61I0TYcgMz-FSz1V9qeM'],
        'bt': '1',
        'b': ['DLc6u76NIr0VqirQPC9k4WlOHw2mIG97Q3BV0UM3EjH5'],
        'c': [],
        'a': []
    }

    assert serder.raw == (b'-FBE0OKERICAACAAXicpEF9ksTMfcHgFjXLV-uiklpuglxGmKh5n15r4Al7-sHq6EF9ksTMfcHgF'
                        b'jXLV-uiklpuglxGmKh5n15r4Al7-sHq6MAAAMAAB-JALDA8-J0EW88RMYqtUHQDqT4q2YH2iBFlW'
                        b'8HobHKV74yi_MAAB-JALDLe4uewytqfqa4NB4AntNKBZ61I0TYcgMz-FSz1V9qeMMAAB-JALDLc6'
                        b'u76NIr0VqirQPC9k4WlOHw2mIG97Q3BV0UM3EjH5-JAA-JAA')

    issuerAidCesr = serder.pre
    assert issuerAidCesr == 'EF9ksTMfcHgFjXLV-uiklpuglxGmKh5n15r4Al7-sHq6'

    # create issuee incepting key state

    """
    Issuee seed
    size=32
    path='3'
    salt=b'acdcspecworkexam'
    opslimit=1
    memlimit=8192
    seed = pysodium.crypto_pwhash(outlen=size,
                                      passwd=path,
                                      salt=self.raw,
                                      opslimit=opslimit,
                                      memlimit=memlimit,
                                      alg=pysodium.crypto_pwhash_ALG_ARGON2ID13)
    seed = (b'\x1b\xd7o*A\xec^\xfb}\xa0 j`\\+\xb6MZ\xe8\xb5\xa31\xb1\xf0a\x1bD6\xcb\x0e_\x00')

    verkey, sigkey = pysodium.crypto_sign_seed_keypair(seed)
    verkey = (b"/\x90\x0f\xea%\t'\x1e\xe1'\xfa\xa9\xaaU\xd2\xfa\x8f\xd2[\xd1:\xdeCZ\xa3\x1cQ\x8cX\xeaaP")
    First 32 bytes of this internal sigkey is seed so we use seed externally as sigkey
    verfer = Verfer(raw=verkey,
                    code=MtrDex.Ed25519 if transferable
                    else MtrDex.Ed25519N)
    """
    issueeSeedRaw = (b'\x1b\xd7o*A\xec^\xfb}\xa0 j`\\+\xb6MZ\xe8\xb5\xa31\xb1\xf0a\x1bD6\xcb\x0e_\x00')
    issueeSeedB64 = encodeB64(issueeSeedRaw)
    assert issueeSeedB64 == b'G9dvKkHsXvt9oCBqYFwrtk1a6LWjMbHwYRtENssOXwA='
    assert decodeB64(issueeSeedB64) == issueeSeedRaw

    issueeSigner = signers[3]
    issueeSigKey = issueeSigner.qb64  # issuee's private signing key
    issueeVerKey = issueeSigner.verfer.qb64  # issuee's public verification key
    assert issueeSigner.verfer.raw ==(b"/\x90\x0f\xea%\t'\x1e\xe1'\xfa\xa9\xaaU\xd2\xfa\x8f\xd2[\xd1:\xdeCZ\xa3\x1cQ\x8cX\xeaaP")
    assert encodeB64(issueeSigner.verfer.raw) == b'L5AP6iUJJx7hJ_qpqlXS-o_SW9E63kNaoxxRjFjqYVA='

    assert issueeSigKey == 'ABvXbypB7F77faAgamBcK7ZNWui1ozGx8GEbRDbLDl8A'  # use in example
    assert issueeVerKey == 'DC-QD-olCSce4Sf6qapV0vqP0lvROt5DWqMcUYxY6mFQ' # use in example

    # create issuee rotation key state
    """
    Issuee rotating seed
    size=32
    path='4'
    salt=b'acdcspecworkexam'
    opslimit=1
    memlimit=8192
    seed = pysodium.crypto_pwhash(outlen=size,
                                      passwd=path,
                                      salt=self.raw,
                                      opslimit=opslimit,
                                      memlimit=memlimit,
                                      alg=pysodium.crypto_pwhash_ALG_ARGON2ID13)
    seed = (b'm*\xc5\x9ej\xb15gc\x94?\x89E\x86\xa3\x97Rx\x10\xe6\x8ez\xb7\x8a\x86\xa4ic\x80\x1bU\xd5')

    verkey, sigkey = pysodium.crypto_sign_seed_keypair(seed)
    verkey = (b'\r|W\xe7\xa3\x9b-tG6\xd0&\xc96\x12\t\x96\xdd\xa9I\xfch\x06\xea\xd1\xb4\xa4\xeb;\x08\xf9\x82')

    First 32 bytes of this internal sigkey is seed so we use seed externally as sigkey
    verfer = Verfer(raw=verkey,
                    code=MtrDex.Ed25519 if transferable
                    else MtrDex.Ed25519N)
    """
    issueeRotSeedRaw = (b'm*\xc5\x9ej\xb15gc\x94?\x89E\x86\xa3\x97Rx\x10\xe6\x8ez\xb7\x8a\x86\xa4ic\x80\x1bU\xd5')
    issueeRotSeedB64 = encodeB64(issueeRotSeedRaw)
    assert issueeRotSeedB64 == b'bSrFnmqxNWdjlD-JRYajl1J4EOaOereKhqRpY4AbVdU='
    assert decodeB64(issueeRotSeedB64) == issueeRotSeedRaw

    issueeRotSigner = signers[4]
    issueeRotSigKey = issueeRotSigner.qb64  # issuer's private signing key seed
    issueeRotVerKey = issueeRotSigner.verfer.qb64  # issuer's public verification key
    assert issueeRotSigner.verfer.raw == (b'\r|W\xe7\xa3\x9b-tG6\xd0&\xc96\x12\t\x96\xdd\xa9I\xfch\x06\xea\xd1\xb4\xa4\xeb;\x08\xf9\x82')
    assert encodeB64(issueeRotSigner.verfer.raw) == b'DXxX56ObLXRHNtAmyTYSCZbdqUn8aAbq0bSk6zsI-YI='

    assert issueeRotSigKey == 'AG0qxZ5qsTVnY5Q_iUWGo5dSeBDmjnq3ioakaWOAG1XV' # use in example
    assert issueeRotVerKey == 'DA18V-ejmy10RzbQJsk2EgmW3alJ_GgG6tG0pOs7CPmC' # use in example


    # create issuee witness key state
    """
    Issuee Witness seed
    size=32
    path='5'
    salt=b'acdcspecworkexam'
    opslimit=1
    memlimit=8192
    seed = pysodium.crypto_pwhash(outlen=size,
                                      passwd=path,
                                      salt=self.raw,
                                      opslimit=opslimit,
                                      memlimit=memlimit,
                                      alg=pysodium.crypto_pwhash_ALG_ARGON2ID13)
    seed = (b'\x16\xd0\xc2t\xff\xbc\x95$Z\x02\x80\xee\x81_Mq\x05\xa9\x01j\xa6\xa5,\x80\x9a\xe4\x8e\x91fn\x8a0')

    verkey, sigkey = pysodium.crypto_sign_seed_keypair(seed)

    First 32 bytes of this internal sigkey is seed so we use seed externally as sigkey
    verkey = (b"\x1e\xde\xb6\x96\xf3s\xd1\xaf\xab9L\xff\xa5\xfe\xa5=\xf8\xae\x0b\xb3'lA-\xcc\x91K\xa2\x8e \xab\x83")

    verfer = Verfer(raw=verkey,
                    code=MtrDex.Ed25519 if transferable
                    else MtrDex.Ed25519N)
    """
    issueeWitSeedRaw = (b'\x16\xd0\xc2t\xff\xbc\x95$Z\x02\x80\xee\x81_Mq\x05\xa9\x01j\xa6\xa5,\x80\x9a\xe4\x8e\x91fn\x8a0')
    issueeWitSeedB64 = encodeB64(issueeWitSeedRaw)
    assert issueeWitSeedB64 ==b'FtDCdP-8lSRaAoDugV9NcQWpAWqmpSyAmuSOkWZuijA='
    assert decodeB64(issueeWitSeedB64) == issueeWitSeedRaw

    issueeWitSigner = signers[5]
    issueeWitSigKey = issueeWitSigner.qb64  # issuer's private signing key seed
    issueeWitVerKey = issueeWitSigner.verfer.qb64  # issuer's public verification key
    assert issueeWitSigner.verfer.raw == (b"\x1e\xde\xb6\x96\xf3s\xd1\xaf\xab9L\xff\xa5\xfe\xa5=\xf8\xae\x0b\xb3'lA-\xcc\x91K\xa2\x8e \xab\x83")
    assert encodeB64(issueeWitSigner.verfer.raw) == b'Ht62lvNz0a-rOUz_pf6lPfiuC7MnbEEtzJFLoo4gq4M='

    assert issueeWitSigKey == 'ABbQwnT_vJUkWgKA7oFfTXEFqQFqpqUsgJrkjpFmboow'  # use in example
    assert issueeWitVerKey == 'DB7etpbzc9GvqzlM_6X-pT34rguzJ2xBLcyRS6KOIKuD' # use in example

    # create issuee AID with single sig simple inception event JSON
    keys = [issueeVerKey]  # initial signing keys
    nkeys = [issueeRotVerKey]  # next (rotation) keys
    wits = [issueeWitVerKey]  # witness aids (same as public verkey)
    serder = incept(keys, code=MtrDex.Blake3_256, ndigs=nkeys, wits=wits,
                    version=Vrsn_2_0, kind=Kinds.json)
    assert serder.pre == 'EALsBaF8k7ww-B1KwQcQ6581Z0PpKBPJa-dmyBCJ9ytH'
    assert serder.said == 'EALsBaF8k7ww-B1KwQcQ6581Z0PpKBPJa-dmyBCJ9ytH'
    assert serder.sad == \
    {
        'v': 'KERICAACAAJSONAAFb.',
        't': 'icp',
        'd': 'EALsBaF8k7ww-B1KwQcQ6581Z0PpKBPJa-dmyBCJ9ytH',
        'i': 'EALsBaF8k7ww-B1KwQcQ6581Z0PpKBPJa-dmyBCJ9ytH',
        's': '0',
        'kt': '1',
        'k': ['DC-QD-olCSce4Sf6qapV0vqP0lvROt5DWqMcUYxY6mFQ'],
        'nt': '1',
        'n': ['DA18V-ejmy10RzbQJsk2EgmW3alJ_GgG6tG0pOs7CPmC'],
        'bt': '1',
        'b': ['DB7etpbzc9GvqzlM_6X-pT34rguzJ2xBLcyRS6KOIKuD'],
        'c': [],
        'a': []
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAFb.","t":"icp","d":"EALsBaF8k7ww-B1KwQcQ6581Z0PpKBPJa-'
                        b'dmyBCJ9ytH","i":"EALsBaF8k7ww-B1KwQcQ6581Z0PpKBPJa-dmyBCJ9ytH","s":"0","kt":'
                        b'"1","k":["DC-QD-olCSce4Sf6qapV0vqP0lvROt5DWqMcUYxY6mFQ"],"nt":"1","n":["DA18'
                        b'V-ejmy10RzbQJsk2EgmW3alJ_GgG6tG0pOs7CPmC"],"bt":"1","b":["DB7etpbzc9GvqzlM_6'
                        b'X-pT34rguzJ2xBLcyRS6KOIKuD"],"c":[],"a":[]}')

    issueeAidJson = serder.pre
    assert issueeAidJson == 'EALsBaF8k7ww-B1KwQcQ6581Z0PpKBPJa-dmyBCJ9ytH'

    # create issuee AID with single sig simple inception event CESR
    keys = [issueeVerKey]  # initial signing keys
    nkeys = [issueeRotVerKey]  # next (rotation) keys
    wits = [issueeWitVerKey]  # witness aids (same as public verkey)
    serder = incept(keys, code=MtrDex.Blake3_256, ndigs=nkeys, wits=wits,
                    version=Vrsn_2_0, kind=Kinds.cesr)
    assert serder.pre == 'EGfaNGX8SuHp90RN_W6YCxpVVyt6zezNv9XgSF9AF20P'
    assert serder.said == 'EGfaNGX8SuHp90RN_W6YCxpVVyt6zezNv9XgSF9AF20P'
    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAAEU.',
        't': 'icp',
        'd': 'EGfaNGX8SuHp90RN_W6YCxpVVyt6zezNv9XgSF9AF20P',
        'i': 'EGfaNGX8SuHp90RN_W6YCxpVVyt6zezNv9XgSF9AF20P',
        's': '0',
        'kt': '1',
        'k': ['DC-QD-olCSce4Sf6qapV0vqP0lvROt5DWqMcUYxY6mFQ'],
        'nt': '1',
        'n': ['DA18V-ejmy10RzbQJsk2EgmW3alJ_GgG6tG0pOs7CPmC'],
        'bt': '1',
        'b': ['DB7etpbzc9GvqzlM_6X-pT34rguzJ2xBLcyRS6KOIKuD'],
        'c': [],
        'a': []
    }

    assert serder.raw == (b'-FBE0OKERICAACAAXicpEGfaNGX8SuHp90RN_W6YCxpVVyt6zezNv9XgSF9AF20PEGfaNGX8SuHp'
                        b'90RN_W6YCxpVVyt6zezNv9XgSF9AF20PMAAAMAAB-JALDC-QD-olCSce4Sf6qapV0vqP0lvROt5D'
                        b'WqMcUYxY6mFQMAAB-JALDA18V-ejmy10RzbQJsk2EgmW3alJ_GgG6tG0pOs7CPmCMAAB-JALDB7e'
                        b'tpbzc9GvqzlM_6X-pT34rguzJ2xBLcyRS6KOIKuD-JAA-JAA')

    issueeAidCesr = serder.pre
    assert issueeAidCesr == 'EGfaNGX8SuHp90RN_W6YCxpVVyt6zezNv9XgSF9AF20P'

    """Done Test"""

if __name__ == "__main__":
    test_acdc_examples_setup()
