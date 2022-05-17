# -*- encoding: utf-8 -*-
"""
tests.core.test_bare module

Test bare message
routes:

"""
from keri import kering

from keri.core import eventing
from keri.core.coring import MtrDex, Nexter, Salter

from keri.core.eventing import (SealEvent, messagize)

from keri import help

logger = help.ogler.getLogger()


def test_bare():
    """
    Test bare message 'bre'

    {
      "v" : "KERI10JSON00011c_",
      "t" : "bre",
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
    # salt = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    salt = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    salter = Salter(raw=salt)

    # create transferable key pair for controller of service endpoint designation
    signerC = salter.signer(path="C", temp=True)
    assert signerC.code == MtrDex.Ed25519_Seed
    assert signerC.verfer.code == MtrDex.Ed25519  # transferable
    preC = signerC.verfer.qb64  # use public key verfer.qb64 trans pre
    assert preC == 'D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0'
    sith = '1'
    keys = [signerC.verfer.qb64]
    nexter = Nexter(keys=keys)  # compute nxt digest (dummy reuse keys)
    nxt = nexter.digs
    assert nxt == ['EIlyVEHnE9F6QYkl82ERnHSj5iv9punbGhS2dwMAKpiM']

    # create key pairs for witnesses of KEL
    signerW0 = salter.signer(path="W0", transferable=False, temp=True)
    assert signerW0.verfer.code == MtrDex.Ed25519N  # non-transferable
    preW0 = signerW0.verfer.qb64  # use public key verfer.qb64 as pre
    assert preW0 == 'BNTkstUfFBJv0R1IoNNjKpWK6zEZPxjgMc7KS2Q6_lG0'

    signerW1 = salter.signer(path="W1", transferable=False, temp=True)
    assert signerW1.verfer.code == MtrDex.Ed25519N  # non-transferable
    preW1 = signerW1.verfer.qb64  # use public key verfer.qb64 as pre
    assert preW1 == 'BaEI1ytEFHqaUF26Fu4JgvsHBzeBu7Joaj2ilmx3QPwU'

    signerW2 = salter.signer(path="W2", transferable=False, temp=True)
    assert signerW2.verfer.code == MtrDex.Ed25519N  # non-transferable
    preW2 = signerW2.verfer.qb64  # use public key verfer.qb64 as pre
    assert preW2 == 'B7vHpy1IDsWWUnHf2GU5ud62LMYWO5lPWOrSB6ejQ1Eo'

    signerW3 = salter.signer(path="W3", transferable=False, temp=True)
    assert signerW3.verfer.code == MtrDex.Ed25519N  # non-transferable
    preW3 = signerW3.verfer.qb64  # use public key verfer.qb64 as pre
    assert preW3 == 'BruKyL_b4D5ETo9u12DtLU1J6Kc1CQnigIUBKrBFz_1Y'

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

    assert serderE.raw == (b'{"v":"KERI10JSON0000f9_","t":"bre","d":"EB_Xo7dILS8QB5Y1-KeB3qHUwbpVW2-gEe9D'
                           b'jd-OG-cw","r":"/to/the/moon","a":{"cid":"D3pYGFaqnrALTyejaJaGAVhNpSCtqyerPqW'
                           b'VK9ZBNZk0","role":"watcher","eid":"EAoTNZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ'
                           b'5CM","name":"besty"}}')



    assert serderE.ked["d"] == "EB_Xo7dILS8QB5Y1-KeB3qHUwbpVW2-gEe9Djd-OG-cw"

    # create SealEvent for endorsers est evt whose keys use to sign

    # These are all  wrong below need to do anchor attachment and lookup anchor
    # to verify not attached signatures

    # Sign reply
    sigerC = signerC.sign(ser=serderE.raw, index=0)
    assert signerC.verfer.verify(sig=sigerC.raw, ser=serderE.raw)
    seal = SealEvent(i=preC,
                     s='0',
                     d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
    msg = messagize(serderE, sigers=[sigerC], seal=seal)
    assert msg == (b'{"v":"KERI10JSON0000f9_","t":"bre","d":"EB_Xo7dILS8QB5Y1-KeB3qHU'
                   b'wbpVW2-gEe9Djd-OG-cw","r":"/to/the/moon","a":{"cid":"D3pYGFaqnrA'
                   b'LTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0","role":"watcher","eid":"EAoTN'
                   b'ZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM","name":"besty"}}-FABD3p'
                   b'YGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk00AAAAAAAAAAAAAAAAAAAAAA'
                   b'AEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAARJ66zuChkViyH'
                   b'IghE_ODT5NXyhWHXH7kfo23q85BnjT8tJ9RSOErXifLY6RHRiv3yYf7ooX5eENPy'
                   b'Ut5luaeCA')

    # create endorsed bre with trans endorser
    # create trans key pair for endorser
    signerE = salter.signer(path="E", temp=True)
    assert signerE.verfer.code == MtrDex.Ed25519  # transferable
    preE = signerE.verfer.qb64  # use public key verfer.qb64 as pre
    assert preE == 'DyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI'

    # create endorsed ksn
    sigerE = signerE.sign(ser=serderE.raw, index=0)
    assert signerE.verfer.verify(sig=sigerE.raw, ser=serderE.raw)
    # create SealEvent for endorsers est evt whose keys use to sign
    seal = SealEvent(i=preE,
                     s='0',
                     d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
    msg = messagize(serderE, sigers=[sigerE], seal=seal)
    assert msg == (b'{"v":"KERI10JSON0000f9_","t":"bre","d":"EB_Xo7dILS8QB5Y1-KeB3qHU'
                   b'wbpVW2-gEe9Djd-OG-cw","r":"/to/the/moon","a":{"cid":"D3pYGFaqnrA'
                   b'LTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0","role":"watcher","eid":"EAoTN'
                   b'ZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM","name":"besty"}}-FABDyv'
                   b'CLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI0AAAAAAAAAAAAAAAAAAAAAA'
                   b'AEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAAYsvGuxuEjx8uy'
                   b'-QtgZrwXMrkdcix7nUdx_qCXM-Oy23D44m_xHbtTGdHXtNJAKZ1H-jnaNDnYNmjk'
                   b'c8NOd4ZAA')


    # create endorsed bre with nontrans endorser
    # create nontrans key pair for endorder
    signerE = salter.signer(path="E", transferable=False, temp=True)
    assert signerE.verfer.code == MtrDex.Ed25519N  # non-transferable
    preE = signerE.verfer.qb64  # use public key verfer.qb64 as pre
    assert preE == 'ByvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI'

    cigarE = signerE.sign(ser=serderE.raw)  # no index so Cigar
    assert signerE.verfer.verify(sig=cigarE.raw, ser=serderE.raw)
    msg = messagize(serderE, cigars=[cigarE])
    assert msg == (b'{"v":"KERI10JSON0000f9_","t":"bre","d":"EB_Xo7dILS8QB5Y1-KeB3qHU'
                   b'wbpVW2-gEe9Djd-OG-cw","r":"/to/the/moon","a":{"cid":"D3pYGFaqnrA'
                   b'LTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0","role":"watcher","eid":"EAoTN'
                   b'ZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM","name":"besty"}}-CABByv'
                   b'CLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI0BYsvGuxuEjx8uy-QtgZrwX'
                   b'Mrkdcix7nUdx_qCXM-Oy23D44m_xHbtTGdHXtNJAKZ1H-jnaNDnYNmjkc8NOd4ZAA')


    """Done Test"""



if __name__ == "__main__":
    test_bare()
    # pytest.main(['-vv', 'test_reply.py::test_reply'])



