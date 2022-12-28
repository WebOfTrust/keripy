# -*- encoding: utf-8 -*-
"""
tests.core.test_bare module

Test bare message
routes:

"""
from keri import kering

from keri.core import eventing
from keri.core.coring import MtrDex, Salter, Diger

from keri.core.eventing import (SealEvent, messagize)

from keri import help

logger = help.ogler.getLogger()


def test_bare():
    """
    Test bare message 'bre'

    {
      "v" : "KERI10JSON00011c_",
      "t" : "bar",
      "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
      "r" : "logs/processor",
      "a" :
      {
         "cid": "D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0",
         "role": "watcher",
         "eid": "EAoTNZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM",
         "name": "John Jones",
      }
    }

    """
    # use same salter for all but different path
    # raw = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    salter = Salter(raw=raw)

    # create transferable key pair for controller of service endpoint designation
    signerC = salter.signer(path="C", temp=True)
    assert signerC.code == MtrDex.Ed25519_Seed
    assert signerC.verfer.code == MtrDex.Ed25519  # transferable
    preC = signerC.verfer.qb64  # use public key verfer.qb64 trans pre
    assert preC == 'DN6WBhWqp6wC08no2iWhgFYTaUgrasnqz6llSvWQTWZN'
    sith = '1'
    keys = [signerC.verfer.qb64]
    digers = [Diger(ser=signerC.verfer.qb64b)]
    nxt = [diger.qb64 for diger in digers]
    assert nxt == ['EDDOarj1lzr8pqG5a-SSnM2cc_3JgstRRjmzrrA_Bibg']

    # create key pairs for witnesses of KEL
    signerW0 = salter.signer(path="W0", transferable=False, temp=True)
    assert signerW0.verfer.code == MtrDex.Ed25519N  # non-transferable
    preW0 = signerW0.verfer.qb64  # use public key verfer.qb64 as pre
    assert preW0 == 'BDU5LLVHxQSb9EdSKDTYyqViusxGT8Y4DHOyktkOv5Rt'

    signerW1 = salter.signer(path="W1", transferable=False, temp=True)
    assert signerW1.verfer.code == MtrDex.Ed25519N  # non-transferable
    preW1 = signerW1.verfer.qb64  # use public key verfer.qb64 as pre
    assert preW1 == 'BGhCNcrRBR6mlBduhbuCYL7Bwc3gbuyaGo9opZsd0D8F'

    signerW2 = salter.signer(path="W2", transferable=False, temp=True)
    assert signerW2.verfer.code == MtrDex.Ed25519N  # non-transferable
    preW2 = signerW2.verfer.qb64  # use public key verfer.qb64 as pre
    assert preW2 == 'BO7x6ctSA7FllJx39hlObnetizGFjuZT1jq0geno0NRK'

    signerW3 = salter.signer(path="W3", transferable=False, temp=True)
    assert signerW3.verfer.code == MtrDex.Ed25519N  # non-transferable
    preW3 = signerW3.verfer.qb64  # use public key verfer.qb64 as pre
    assert preW3 == 'BK7isi_2-A-RE6Pbtdg7S1NSeinNQkJ4oCFASqwRc_9W'

    wits = [preW1, preW2, preW3]
    toad = 2

    role = kering.Roles.watcher

    data = dict( cid=preC,
                 role=role,
                 eid="EAoTNZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM",
                 name="besty",
               )


    serderE = eventing.bare(route="/to/the/moon",
                             data=data,
                            )

    assert serderE.raw == (b'{"v":"KERI10JSON0000f9_","t":"bar","d":"EOBOm9NDlTey2VyDGhMZ-wKqOoS5FnJEPwdp'
                           b'IMVH7Oll","r":"/to/the/moon","a":{"cid":"DN6WBhWqp6wC08no2iWhgFYTaUgrasnqz6l'
                           b'lSvWQTWZN","role":"watcher","eid":"EAoTNZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ'
                           b'5CM","name":"besty"}}')

    assert serderE.ked["d"] == 'EOBOm9NDlTey2VyDGhMZ-wKqOoS5FnJEPwdpIMVH7Oll'

    # create SealEvent for endorsers est evt whose keys use to sign

    # These are all  wrong below need to do anchor attachment and lookup anchor
    # to verify not attached signatures

    # Sign reply
    sigerC = signerC.sign(ser=serderE.raw, index=0)
    assert signerC.verfer.verify(sig=sigerC.raw, ser=serderE.raw)
    seal = SealEvent(i=preC,
                     s='0',
                     d='EAuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
    msg = messagize(serderE, sigers=[sigerC], seal=seal)
    assert msg == (b'{"v":"KERI10JSON0000f9_","t":"bar","d":"EOBOm9NDlTey2VyDGhMZ-wKq'
                   b'OoS5FnJEPwdpIMVH7Oll","r":"/to/the/moon","a":{"cid":"DN6WBhWqp6w'
                   b'C08no2iWhgFYTaUgrasnqz6llSvWQTWZN","role":"watcher","eid":"EAoTN'
                   b'ZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM","name":"besty"}}-FABDN6'
                   b'WBhWqp6wC08no2iWhgFYTaUgrasnqz6llSvWQTWZN0AAAAAAAAAAAAAAAAAAAAAA'
                   b'AEAuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAACKOcmfrZtRsW_'
                   b'PKmt_gDXFiAsepoKl85WFTr_XaVGh2qkh_JQ7eN-nEFFgyPv-8a51jrOGRX_tY2M'
                   b'6DPQqQHUJ')

    # create endorsed bar with trans endorser
    # create trans key pair for endorser
    signerE = salter.signer(path="E", temp=True)
    assert signerE.verfer.code == MtrDex.Ed25519  # transferable
    preE = signerE.verfer.qb64  # use public key verfer.qb64 as pre
    assert preE == 'DMrwi0a-Zblpqe5Hg7w7iz9JCKnMgWKu_W9w4aNUL64y'

    # create endorsed ksn
    sigerE = signerE.sign(ser=serderE.raw, index=0)
    assert signerE.verfer.verify(sig=sigerE.raw, ser=serderE.raw)
    # create SealEvent for endorsers est evt whose keys use to sign
    seal = SealEvent(i=preE,
                     s='0',
                     d='EAuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
    msg = messagize(serderE, sigers=[sigerE], seal=seal)
    assert msg == (b'{"v":"KERI10JSON0000f9_","t":"bar","d":"EOBOm9NDlTey2VyDGhMZ-wKq'
                   b'OoS5FnJEPwdpIMVH7Oll","r":"/to/the/moon","a":{"cid":"DN6WBhWqp6w'
                   b'C08no2iWhgFYTaUgrasnqz6llSvWQTWZN","role":"watcher","eid":"EAoTN'
                   b'ZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM","name":"besty"}}-FABDMr'
                   b'wi0a-Zblpqe5Hg7w7iz9JCKnMgWKu_W9w4aNUL64y0AAAAAAAAAAAAAAAAAAAAAA'
                   b'AEAuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAABABWeacQ_nHgu'
                   b'Ugw6scJCUIbs5_vczaXxtKTYaryN15e_9Y7GT-korkJc4sHGpkmekr7w2XFhr1Da'
                   b'OTfVsyNUI')


    # create endorsed bar with nontrans endorser
    # create nontrans key pair for endorder
    signerE = salter.signer(path="E", transferable=False, temp=True)
    assert signerE.verfer.code == MtrDex.Ed25519N  # non-transferable
    preE = signerE.verfer.qb64  # use public key verfer.qb64 as pre
    assert preE == 'BMrwi0a-Zblpqe5Hg7w7iz9JCKnMgWKu_W9w4aNUL64y'

    cigarE = signerE.sign(ser=serderE.raw)  # no index so Cigar
    assert signerE.verfer.verify(sig=cigarE.raw, ser=serderE.raw)
    msg = messagize(serderE, cigars=[cigarE])
    assert msg == (b'{"v":"KERI10JSON0000f9_","t":"bar","d":"EOBOm9NDlTey2VyDGhMZ-wKq'
          b'OoS5FnJEPwdpIMVH7Oll","r":"/to/the/moon","a":{"cid":"DN6WBhWqp6w'
          b'C08no2iWhgFYTaUgrasnqz6llSvWQTWZN","role":"watcher","eid":"EAoTN'
          b'ZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM","name":"besty"}}-CABBMr'
          b'wi0a-Zblpqe5Hg7w7iz9JCKnMgWKu_W9w4aNUL64y0BBABWeacQ_nHguUgw6scJC'
          b'UIbs5_vczaXxtKTYaryN15e_9Y7GT-korkJc4sHGpkmekr7w2XFhr1DaOTfVsyNUI')


    """Done Test"""



if __name__ == "__main__":
    test_bare()
    # pytest.main(['-vv', 'test_reply.py::test_reply'])



