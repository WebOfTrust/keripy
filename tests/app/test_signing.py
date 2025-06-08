# -*- encoding: utf-8 -*-
"""
tests.app.signing module

"""
from keri import kering, core
from keri.core import coring, parsing, eventing
from keri.core.eventing import SealEvent

from keri.app import habbing, configing, keeping
from keri.app import signing

from keri.db import basing
from keri.vc import proving
from keri.vdr import verifying, credentialing



def test_signatory():
    salt = core.Salter(raw=b'0123456789abcdef')  # init sig Salter

    with basing.openDB(name="sig") as db, keeping.openKS(name="sig") as ks, \
            habbing.openHab(name="sig", salt=salt.raw) as (sigHby, sigHab):
        # Init signatory
        signer = sigHby.signator

        assert signer.pre == 'BN5Lu0RqptmJC-iXEldMMrlEew7Q01te2fLgqlbqW9zR'
        assert signer._hab.kever.verfers[0].qb64b == b'BN5Lu0RqptmJC-iXEldMMrlEew7Q01te2fLgqlbqW9zR'
        spre = signer.db.hbys.get(habbing.SIGNER)
        assert spre == signer.pre

        raw = b'this is the raw data'
        cig = signer.sign(ser=raw)
        assert cig.qb64b == (b'0BBcREN6U3eyPXDnRaDrRBgA7JECxr8fAqTHvbLY8RzMBIQr1'
                             b'Qoz9H5d0aPM1EbKFP1DcT1zadxb'
                             b'eEQciT0lkysL')

        assert signer.verify(ser=raw, cigar=cig) is True

        bad = b'0BAh1y8Dq7Pj7xbEj6Ja-ew9nzu-bX5_wQKu5Yw3472-ghptsrEFDyD6o4Lk0L7Ym9oWCuGj_UAc-ltI9p7F9999'
        badcig = coring.Cigar(qb64b=bad)
        assert signer.verify(ser=raw, cigar=badcig) is False

        verfer = coring.Verfer(qb64=spre)
        assert verfer.verify(cig.raw, raw) is True

        # Create a second, should have the same key
        mgr = keeping.Manager(ks=ks, salt=salt.qb64)
        kvy = eventing.Kevery(db=db)
        sig2 = habbing.Signator(db=db, temp=True, ks=ks, mgr=mgr, cf=sigHab.cf, rtr=None,
                                rvy=None, kvy=kvy, psr=None)
        assert sig2._hab.pre == spre
        assert sig2._hab.kever.verfers[0].qb64b == spre.encode("utf-8")
        assert sig2.verify(ser=raw, cigar=cig) is True
        cig2 = sig2.sign(ser=raw)
        assert cig2.qb64b == cig2.qb64b
        assert signer.verify(ser=raw, cigar=cig2) is True

        raw2 = b'second text to sign that is a little longer'
        cig3 = sig2.sign(ser=raw2)
        assert cig3.qb64b == (b'0BD9VxJWhKcaTxMwKMFmtXPwf-ABW8bpqiCjBozfrBBm637'
                              b'dk81yqgr_kvD7aaKmi4Dw7wgmmLXx'
                              b'i0nhP08Jpo0B')
        assert signer.verify(ser=raw2, cigar=cig3) is True
