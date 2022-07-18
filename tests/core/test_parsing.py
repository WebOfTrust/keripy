# -*- encoding: utf-8 -*-
"""
tests.core.test_eventing module

"""
import os

import pytest
from hio.help import decking

from keri.app import habbing
from keri.kering import ValidationError
from keri.core import parsing, coring
from keri.core.coring import (CtrDex, Counter, Signer)
from keri.core.eventing import (Kever, Kevery, incept, rotate, interact)
from keri.db.basing import openDB

from keri import help
from keri.peer import exchanging

logger = help.ogler.getLogger()


def test_parser():
    """
    Test the support functionality for Parser stream processor
    """
    logger.setLevel("ERROR")

    # Test sequence of events given set of secrets
    secrets = [
        'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
        'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
        'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
        'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
        'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
        'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
        'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
        'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
    ]

    with openDB(name="controller") as conDB, openDB(name="validator") as valDB:
        event_digs = []  # list of event digs in sequence

        # create event stream
        msgs = bytearray()
        #  create signers
        signers = [Signer(qb64=secret) for secret in secrets]  # faster
        assert [signer.qb64 for signer in signers] == secrets

        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[signers[0].verfer.qb64],
                        nkeys=[coring.Diger(ser=signers[1].verfer.qb64b).qb64])
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[0].sign(serder.raw, index=0)  # return siger
        # create key event verifier state
        kever = Kever(serder=serder, sigers=[siger], db=conDB)
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        assert msgs == bytearray(b'{"v":"KERI10JSON00012b_","t":"icp","d":"ELeMG3OOxWi5n1Zud603_Bn6'
                                 b'Hzm3hIRZXlQnSgC5lU7A","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKt'
                                 b'WTOunRA","s":"0","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_Z'
                                 b'OoeKtWTOunRA"],"nt":"1","n":["E67B6WkwQrEfSA2MylxmF28HJc_HxfHRyK'
                                 b'1kRXSYeMiI"],"bt":"0","b":[],"c":[],"a":[]}-AABAAw6czYydWCMpfs-X'
                                 b'pUPi-h2OuBHP6ji5IU7YbK0pnsQt237sI4jaALv7Guc30y1zh8j5hrou-zOoUrVI'
                                 b'NlhSICw')

        # Event 1 Rotation Transferable
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[1].verfer.qb64],
                        dig=kever.serder.saider.qb64,
                        nkeys=[coring.Diger(ser=signers[2].verfer.qb64b).qb64],
                        sn=1)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[1].sign(serder.raw, index=0)  # returns siger
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 2 Rotation Transferable
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[2].verfer.qb64],
                        dig=kever.serder.saider.qb64,
                        nkeys=[coring.Diger(ser=signers[3].verfer.qb64b).qb64],
                        sn=2)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[2].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 3 Interaction
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.saider.qb64,
                          sn=3)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[2].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 4 Interaction
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.saider.qb64,
                          sn=4)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[2].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 5 Rotation Transferable
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[3].verfer.qb64],
                        dig=kever.serder.saider.qb64,
                        nkeys=[coring.Diger(ser=signers[4].verfer.qb64b).qb64],
                        sn=5)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[3].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 6 Interaction
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.saider.qb64,
                          sn=6)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[3].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 7 Rotation to null NonTransferable Abandon
        # nxt digest is empty
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[4].verfer.qb64],
                        dig=kever.serder.saider.qb64,
                        sn=7)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[4].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 8 Interaction
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.saider.qb64,
                          sn=8)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[4].sign(serder.raw, index=0)
        # update key event verifier state
        with pytest.raises(ValidationError):  # nulled so reject any more events
            kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 8 Rotation
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[4].verfer.qb64],
                        dig=kever.serder.saider.qb64,
                        nkeys=[coring.Diger(ser=signers[5].verfer.qb64b).qb64],
                        sn=8)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[4].sign(serder.raw, index=0)
        # update key event verifier state
        with pytest.raises(ValidationError):  # nontransferable so reject update
            kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        assert len(msgs) == 3745

        pre = kever.prefixer.qb64

        db_digs = [bytes(val).decode("utf-8") for val in kever.db.getKelIter(pre)]
        assert db_digs == event_digs

        kevery = Kevery(db=valDB)

        parser = parsing.Parser(kvy=kevery)

        parser.parse(ims=bytearray(msgs))  # make copy
        assert parser.ims == bytearray(b'')  # emptied
        assert pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == kever.sn
        assert vkever.verfers[0].qb64 == kever.verfers[0].qb64
        assert vkever.verfers[0].qb64 == signers[4].verfer.qb64

        db_digs = [bytes(val).decode("utf-8") for val in kevery.db.getKelIter(pre)]
        assert db_digs == event_digs

        parser = parsing.Parser()  # no kevery
        parser.parse(ims=msgs)
        assert parser.ims == bytearray(b'')

    assert not os.path.exists(kevery.db.path)
    assert not os.path.exists(kever.db.path)

    """ Done Test """


def test_pathed_material(mockHelpingNowUTC):
    fwd = (
        b'{"v":"KERI10JSON00044d_","t":"exn","d":"EZwbLsmCpxBf9l2tfzvf1kg5ezQZ9i6FyDmBHHwVFQGk","dt":"2022-02-27T18:02:'
        b'22.044703+00:00","r":"/fwd","q":{"pre":"EoUntUikciNJYKQEFtBaa3qAgn99ffJ316xWi3ejy6BU","topic":"replay"},"a":'
        b'[{"v":"KERI10JSON0001ac_","t":"icp","d":"EL1L56LyoKrIofnn0oPChS4EyzMHEEk75INJohDS_Bug","i":"EL1L56LyoKrIofnn0'
        b'oPChS4EyzMHEEk75INJohDS_Bug","s":"0","kt":"1","k":["DsYDaph2oHNoY4a1JxGCiSR4DRVG4E-cd4-Xhmj8wP2E"],"n":'
        b'"E_qGxQnFfRbfW2SnvYgZiczVeGIXTPGRMqGzPR5x_JPE","bt":"2","b":["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo",'
        b'"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"],"c":[],"a":[]}'
        b',{"v":"KERI10JSON0001c4_","t":"rot","d":"Em8CcAaukAXUo9OH20v7rGekRBQbai78keT9NloPb04c","i":"EL1L56LyoKrIofnn0'
        b'oPChS4EyzMHEEk75INJohDS_Bug","s":"1","p":"EL1L56LyoKrIofnn0oPChS4EyzMHEEk75INJohDS_Bug","kt":"1","k":["D-i5e1'
        b'zY9_ic6mddsG-lC_qLyW5wxLS8GBdIETx-m9eA"],"n":"Egtz7luAa9zYv__wE1Y1NuuJgFrzfdKoFS0dl0m1OrYc","bt":"3","br":[],'
        b'"ba":[],"a":[{"i":"EdUB40PiRIGD5KK12ixqtg-iOzdB53mvquFxEMY95Sjc","s":"0","d":"EdUB40PiRIGD5KK12ixqtg-iOzdB53m'
        b'vquFxEMY95Sjc"}]}]}-CABBgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c0BYb31eFKSIfTxztT6-ft9xmH4ozf9T4OcXK3L'
        b'T-qINq0tgxFDrftGt5WCRIPNhFes3bbZt3I1HpMh0IftvGh4Bw-LBt4AAB-a-0-VBq-AABAA57gKX2fuFDQueMfjVZP2t8TKxyR8GrUkQV9yk'
        b'At0UAdQzk24E2c4g4X4pJmu9z8Ab6iolHfxYYqWXubUDA7LCQ-BADAAakx_iP6JIlUg8gb45IdMJI9IXU1F3OrUCSG0RYXPt_-vcFTJ7f_MOT'
        b'nC8fwc4kLO_57z_kZFwnjpw_zJNY83BwABOQbSEplzc_AK76CK18GVcy4NeNMh3FMAd19nO3oQYiW2_v6BTRDKuSAvTA7JaeoT9sq28U3umfd'
        b'iuxEnuqphAgAC-YGArB4QGi9JxuduvzThCALaA7WWdDVeW4aNCUe_k45Ur6-U9MAWH0epAHx5Pu9BBmoM0i53tGBXWRkYAe-yBA-EAB0AAAAA'
        b'AAAAAAAAAAAAAAAAAA1AAG2022-02-27T18c02c09d640135p00c00-LBt4AAB-a-1-VBq-AABAAh8GcgHc4gvZzNOHxcjGMDxQZkuHeR9H4w'
        b'7MKWlIyeg-4Cx815rya5RBTpsjlg0DhYcacQutrJHI4jzS5tj7UBQ-BADAAPZd8UNgjPNGE0mLWhF81jQW10KtKwPwn0A18jnSZekoiC3meFq'
        b'ZFObZphYDsI8PGJY9j7Xv7klG7jTdL0DkjDgABNMO7i7vjVfi7G-AbeDbnu1zl86Ia_BSWVLt6ykylfGRZaIIaWBC-YrsX1bQCNIzkaf2WEj3'
        b'-7KvwtNaAxXnxCQACgztaYp19Ho6nTgBDB2Ytfp5POVRedbwtD1u9JhRBt8filMay6K65IbspoPK-MYv3t2UNvBqK8Qt1piiFT_lNCQ-EAB0A'
        b'AAAAAAAAAAAAAAAAAAAAAQ1AAG2022-02-27T18c02c21d952358p00c00')

    class MockHandler:
        resource = "/fwd"

        def __init__(self):
            self.msgs = decking.Deck()

    with habbing.openHby(name="pal", salt=coring.Salter(raw=b'0123456789abcdef').qb64) as hby:
        handler = MockHandler()
        exc = exchanging.Exchanger(hby=hby, handlers=[handler])
        parser = parsing.Parser(exc=exc)

        parser.parseOne(ims=fwd)
        assert len(handler.msgs) == 1
        msg = handler.msgs.popleft()

        payload = msg["payload"]
        assert len(payload) == 2
        assert payload[0]["t"] == coring.Ilks.icp
        assert payload[1]["t"] == coring.Ilks.rot
        attachments = msg["attachments"]
        assert len(attachments) == 2
        (path1, attachment1) = attachments[0]
        assert path1.bext == "-0"
        assert attachment1 == (b'-VBq-AABAA57gKX2fuFDQueMfjVZP2t8TKxyR8GrUkQV9ykAt0UAdQzk24E2c4g4X4pJmu9z8Ab6iolHfxY'
                               b'YqWXubUDA7LCQ-BADAAakx_iP6JIlUg8gb45IdMJI9IXU1F3OrUCSG0RYXPt_-vcFTJ7f_MOTnC8fwc4kLO'
                               b'_57z_kZFwnjpw_zJNY83BwABOQbSEplzc_AK76CK18GVcy4NeNMh3FMAd19nO3oQYiW2_v6BTRDKuSAvTA7'
                               b'JaeoT9sq28U3umfdiuxEnuqphAgAC-YGArB4QGi9JxuduvzThCALaA7WWdDVeW4aNCUe_k45Ur6-U9MAWH0'
                               b'epAHx5Pu9BBmoM0i53tGBXWRkYAe-yBA-EAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2022-02-27T18c02c09'
                               b'd640135p00c00')
        (path2, attachment2) = attachments[1]
        assert path2.bext == "-1"
        assert attachment2 == (b'-VBq-AABAAh8GcgHc4gvZzNOHxcjGMDxQZkuHeR9H4w7MKWlIyeg-4Cx815rya5RBTpsjlg0DhYcacQutrJ'
                               b'HI4jzS5tj7UBQ-BADAAPZd8UNgjPNGE0mLWhF81jQW10KtKwPwn0A18jnSZekoiC3meFqZFObZphYDsI8PG'
                               b'JY9j7Xv7klG7jTdL0DkjDgABNMO7i7vjVfi7G-AbeDbnu1zl86Ia_BSWVLt6ykylfGRZaIIaWBC-YrsX1bQ'
                               b'CNIzkaf2WEj3-7KvwtNaAxXnxCQACgztaYp19Ho6nTgBDB2Ytfp5POVRedbwtD1u9JhRBt8filMay6K65Ib'
                               b'spoPK-MYv3t2UNvBqK8Qt1piiFT_lNCQ-EAB0AAAAAAAAAAAAAAAAAAAAAAQ1AAG2022-02-27T18c02c21'
                               b'd952358p00c00')


if __name__ == "__main__":
    test_parser()
