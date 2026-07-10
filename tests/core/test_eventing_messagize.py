# -*- encoding: utf-8 -*-
"""
tests.core.test_eventing_messagize module

"""
import os

import blake3
import pysodium
import pytest

from keri import (ValidationError, UnverifiedReceiptError, InvalidCodeError,
                         Ilks, TraitDex, Vrsn_1_0, Vrsn_2_0, Ilks, Kinds,
                         versify)

from keri.app import habbing, openKS, Manager
from keri.core import (Noncer, Signer, Counter, Codens, Kever, Parser,
                       SerderKERI, Salter, Diger, Matter, Cigar, Seqner,
                       Verfer, Prefixer, Number, Saider, Seqner,
                       DigDex, MtrDex, PreDex, NumDex, IdrDex, IdxSigDex,
                       Siger, SealDigest, SealRoot, SealBack, SealEvent,
                       SealSource, SealLast, BlindState, BoundState, TypeMedia,
                       StateEvent, StateEstEvent,
                       Kever, Kevery,
                       LastEstLoc, simple, ample, deWitnessCouple,
                       deReceiptCouple, deSourceCouple, deReceiptTriple,
                       deTransReceiptQuadruple, deTransReceiptQuintuple,
                       incept, rotate, interact, receipt, query, delcept,
                       deltate, exchept, state, messagize, loadEvent)

from keri.db import openDB, dgKey, snKey
from keri.help import helping, ogler

logger = ogler.getLogger()


def test_messagize_v1():
    """Test messagize utility function with version 1 messages and v1 attachments
    """
    salter = Salter(raw=b'0123456789abcdef')
    with openDB(name="edy") as db, openKS(name="edy") as ks:
        # Init key pair manager
        mgr = Manager(ks=ks, salt=salter.qb64)
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=True, stem="C")

        # Test with inception message
        serder = incept(keys=[verfers[0].qb64], code=MtrDex.Blake3_256,
                        kind=Kinds.json, pvrsn=Vrsn_1_0, version=Vrsn_1_0)

        ked = serder.ked
        pre = serder.pre

        sigers = mgr.sign(ser=serder.raw, verfers=verfers)  # default indexed True
        assert isinstance(sigers[0], Siger)

        # test framed
        msg = messagize(serder, sigers=sigers, framed=True, gvrsn=Vrsn_1_0)
        assert isinstance(msg, bytearray)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-AA'
                    b'BAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfP'
                    b'QQkQkxI862_XjyZLHyClVTLoD')

        # test framed and genusify
        msg = messagize(serder, sigers=sigers, framed=True, gvrsn=Vrsn_1_0, genusify=True)
        assert isinstance(msg, bytearray)
        assert msg == (b'-_AAABAA{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecCh'
                    b'c6AhSLTQssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZA'
                    b'mNvPnGxjJyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57s'
                    b'nMRIuX0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a'
                    b'":[]}-AABAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1'
                    b'rSc5lPfPQQkQkxI862_XjyZLHyClVTLoD')

        # Test not framed
        msg = messagize(serder, sigers=sigers, framed=False, gvrsn=Vrsn_1_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA'
                    b'X-AABAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5'
                    b'lPfPQQkQkxI862_XjyZLHyClVTLoD')

        # Test not framed and genuisfy
        msg = messagize(serder, sigers=sigers, framed=False, gvrsn=Vrsn_1_0, genusify=True)
        assert msg == (b'-_AAABAA{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecCh'
                    b'c6AhSLTQssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZA'
                    b'mNvPnGxjJyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57s'
                    b'nMRIuX0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a'
                    b'":[]}-VAX-AABAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x'
                    b'_NA1rSc5lPfPQQkQkxI862_XjyZLHyClVTLoD')

        # Test with source SealEvent and sigers
        # create SealEvent for endorsers est evt whose keys use to sign
        source = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        msg = messagize(serder, sigers=sigers, source=source, framed=True, gvrsn=Vrsn_1_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-FA'
                    b'BDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_kH4c'
                    b'G7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE'
                    b'-QzdORp-DbxdDN_GG84x_NA1rSc5lPfPQQkQkxI862_XjyZLHyClVTLoD')

        # Test with not framed
        msg = messagize(serder, sigers=sigers, source=source, framed=False, gvrsn=Vrsn_1_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA'
                    b'v-FABDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_'
                    b'kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAAB1DuEfnZZ6juMZDYiodcWiIqd'
                    b'juEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfPQQkQkxI862_XjyZLHyClVTLoD')

         # Test with seal SealEvent Only
        msg = messagize(serder, bonds=seal, framed=True, gvrsn=Vrsn_1_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-IA'
                    b'BDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_kH4c'
                    b'G7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        # Test with not framed
        msg = messagize(serder, bonds=seal, framed=False, gvrsn=Vrsn_1_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA'
                    b'Y-IABDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_'
                    b'kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        # Test with SealLast and Sigers
        # create SealLast for endorsers est evt whose keys use to sign
        source = SealLast(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI')
        seal = SealLast(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI')

        msg = messagize(serder, sigers=sigers, source=source, framed=True, gvrsn=Vrsn_1_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-HA'
                    b'BDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI-AABAAB1DuEfnZZ6juM'
                    b'ZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfPQQkQkxI862_XjyZL'
                    b'HyClVTLoD')

        # Test with not framed
        msg = messagize(serder, sigers=sigers, source=source, framed=False, gvrsn=Vrsn_1_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA'
                    b'j-HABDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI-AABAAB1DuEfnZZ'
                    b'6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfPQQkQkxI862_X'
                    b'jyZLHyClVTLoD')

        # Test with seal only SealLast only raises error since not supported in v1

        with pytest.raises(InvalidCodeError):
            msg = messagize(serder, bonds=seal, framed=True, gvrsn=Vrsn_1_0)

        # test with seal SealSource only
        seal = SealSource(s='0',
                          d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        msg = messagize(serder, bonds=seal, framed=False, gvrsn=Vrsn_1_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA'
                    b'N-GABMAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        # test with multiple seals so collated
        seal0 = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal1 = SealSource(s='1',
                           d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal2 = SealSource(s='2',
                           d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal3 = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='3',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seals = [seal0, seal1, seal2, seal3]

        msg = messagize(serder, bonds=seals, framed=False, gvrsn=Vrsn_1_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VB'
                    b'I-IACDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_'
                    b'kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2zDAvCLRr5luWmp7keDvDuLP0kIqcyBYq'
                    b'79b3Dho1QvrjIMAADEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-GA'
                    b'CMAABEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2zMAACEMuNWHss_H_'
                    b'kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        # Test with wigers
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=False, stem="W")
        wigers = mgr.sign(ser=serder.raw, verfers=verfers)  # default indexed True
        assert isinstance(wigers[0], Siger)
        msg = messagize(serder, wigers=wigers, framed=True, gvrsn=Vrsn_1_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-BA'
                    b'BAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs7_JuO4RioH1NUTtzTuV1bbuB7eoNhEj'
                    b'20VJYa4947ZMVrOxKhzI6EqUH')

        # Test with wigers and not framed
        msg = messagize(serder, wigers=wigers,framed=False, gvrsn=Vrsn_1_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA'
                    b'X-BABAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs7_JuO4RioH1NUTtzTuV1bbuB7eo'
                    b'NhEj20VJYa4947ZMVrOxKhzI6EqUH')

        # Test with cigars
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=False, stem="R")
        cigars = mgr.sign(ser=serder.raw, verfers=verfers, indexed=False)
        assert isinstance(cigars[0], Cigar)
        msg = messagize(serder, cigars=cigars, framed=True, gvrsn=Vrsn_1_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-CA'
                    b'BBJjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDwWrxO8RItpgGFtFi'
                    b'DF7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVw'
                    b'g_TwF')

        # Test with cigars and not framed
        msg = messagize(serder, cigars=cigars, framed=False, gvrsn=Vrsn_1_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA'
                    b'i-CABBJjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDwWrxO8RItpgG'
                    b'FtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko'
                    b'5EVwg_TwF')


        # Test with wigers and cigars
        msg = messagize(serder, wigers=wigers, cigars=cigars, framed=True, gvrsn=Vrsn_1_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-BA'
                    b'BAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs7_JuO4RioH1NUTtzTuV1bbuB7eoNhEj'
                    b'20VJYa4947ZMVrOxKhzI6EqUH-CABBJjH1MCDssEZMnORskF34AwOFDgDL47513G'
                    b'ivRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUV'
                    b'X2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')


        # Test with wigers and cigars and not framed
        msg = messagize(serder, cigars=cigars, wigers=wigers, framed=False, gvrsn=Vrsn_1_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA'
                    b'5-BABAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs7_JuO4RioH1NUTtzTuV1bbuB7eo'
                    b'NhEj20VJYa4947ZMVrOxKhzI6EqUH-CABBJjH1MCDssEZMnORskF34AwOFDgDL47'
                    b'513GivRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa'
                    b'0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')


        # Test with sigers and wigers and cigars
        msg = messagize(serder, sigers=sigers, cigars=cigars, wigers=wigers,
                        framed=True, gvrsn=Vrsn_1_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-AA'
                    b'BAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfP'
                    b'QQkQkxI862_XjyZLHyClVTLoD-BABAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs7_J'
                    b'uO4RioH1NUTtzTuV1bbuB7eoNhEj20VJYa4947ZMVrOxKhzI6EqUH-CABBJjH1MC'
                    b'DssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas'
                    b'-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with sigers and wigers and cigars and pipelines
        msg = messagize(serder, sigers=sigers, cigars=cigars, wigers=wigers,
                        framed=False, gvrsn=Vrsn_1_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VB'
                    b'Q-AABAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5'
                    b'lPfPQQkQkxI862_XjyZLHyClVTLoD-BABAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyx'
                    b's7_JuO4RioH1NUTtzTuV1bbuB7eoNhEj20VJYa4947ZMVrOxKhzI6EqUH-CABBJj'
                    b'H1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDwWrxO8RItpgGFtFiDF7Q'
                    b'oVas-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with sigers and source and seal and wigers and cigars and not framed
        source = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        msg = messagize(serder, sigers=sigers, source=source, bonds=seal,
                        wigers=wigers, cigars=cigars, framed=False, gvrsn=Vrsn_1_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VC'
                    b'A-FABDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_'
                    b'kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAAB1DuEfnZZ6juMZDYiodcWiIqd'
                    b'juEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfPQQkQkxI862_XjyZLHyClVTLoD-BA'
                    b'BAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs7_JuO4RioH1NUTtzTuV1bbuB7eoNhEj'
                    b'20VJYa4947ZMVrOxKhzI6EqUH-CABBJjH1MCDssEZMnORskF34AwOFDgDL47513G'
                    b'ivRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUV'
                    b'X2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF-IABDAvCLRr5luWmp7keDvDuLP0kIqc'
                    b'yBYq79b3Dho1QvrjIMAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        # Test receipt message with wigers and/or cigars on prior message
        wigers = mgr.sign(ser=serder.raw, verfers=verfers, indexed=True)
        assert isinstance(wigers[0], Siger)
        cigars = mgr.sign(ser=serder.raw, verfers=verfers, indexed=False)  # sign event not receipt

        serder = receipt(pre=pre,
                           sn=int(ked["s"], 16),
                           said=serder.said,
                           kind=Kinds.json,
                           pvrsn=Vrsn_1_0, version=Vrsn_1_0)

        # test with wigers
        msg = messagize(serder, wigers=wigers, framed=True, gvrsn=Vrsn_1_0)
        assert msg == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
          b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
          b'JyHxl4F","s":"0"}-BABAADwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31'
          b'jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with cigars
        msg = messagize(serder, cigars=cigars, framed=True, gvrsn=Vrsn_1_0)
        assert msg == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0"}-CABBJjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QK'
                    b'z0BDwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xsyyH1'
                    b'US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with wigers and cigars
        msg = messagize(serder, wigers=wigers, cigars=cigars, framed=True, gvrsn=Vrsn_1_0)
        assert msg == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0"}-BABAADwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31'
                    b'jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF-CABBJjH1MCDssEZMnO'
                    b'RskF34AwOFDgDL47513GivRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0x'
                    b'tOfbsh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with wigers and cigars and not framed
        msg = messagize(serder, wigers=wigers, cigars=cigars, framed=False, gvrsn=Vrsn_1_0)
        assert msg == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0"}-VA5-BABAADwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfb'
                    b'sh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF-CABBJjH1MCDssE'
                    b'ZMnORskF34AwOFDgDL47513GivRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas-6Bz'
                    b'vj0xtOfbsh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with query message
        serder = query(route="log",
                        query=dict(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI'),
                        stamp=helping.DTS_BASE_0,
                        kind=Kinds.json,
                        pvrsn=Vrsn_1_0)

        # Test with SealLast and framed for endorsers est evt whose keys use to sign
        source = SealLast(i=pre)
        msg = messagize(serder, sigers=sigers, source=source, framed=True, gvrsn=Vrsn_1_0)
        assert msg == (b'{"v":"KERI10JSON0000c9_","t":"qry","d":"EGN68_seecuzXQO15FFGJLVw'
                    b'ZCBCPYW-hy29fjWWPQbp","dt":"2021-01-01T00:00:00.000000+00:00","r'
                    b'":"log","rr":"","q":{"i":"DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho'
                    b'1QvrjI"}}-HABEFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxjJyHxl4F-AABAAB'
                    b'1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfPQQkQ'
                    b'kxI862_XjyZLHyClVTLoD')

        # Not framed SealLast
        msg = messagize(serder, sigers=sigers, source=source, framed=False, gvrsn=Vrsn_1_0)
        assert msg == (b'{"v":"KERI10JSON0000c9_","t":"qry","d":"EGN68_seecuzXQO15FFGJLVw'
                    b'ZCBCPYW-hy29fjWWPQbp","dt":"2021-01-01T00:00:00.000000+00:00","r'
                    b'":"log","rr":"","q":{"i":"DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho'
                    b'1QvrjI"}}-VAj-HABEFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxjJyHxl4F-AA'
                    b'BAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfP'
                    b'QQkQkxI862_XjyZLHyClVTLoD')

        """ Done Test """


def test_messagize_v1_mix_v2():
    """Test messagize for v1 messages mixed with v2 attachments
    """
    salter = Salter(raw=b'0123456789abcdef')
    with openDB(name="edy") as db, openKS(name="edy") as ks:
        # Init key pair manager
        mgr = Manager(ks=ks, salt=salter.qb64)
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=True, stem="C")

        # Test with inception message
        serder = incept(keys=[verfers[0].qb64], code=MtrDex.Blake3_256,
                        kind=Kinds.json, pvrsn=Vrsn_1_0, version=Vrsn_1_0)

        ked = serder.ked
        pre = serder.pre

        sigers = mgr.sign(ser=serder.raw, verfers=verfers)  # default indexed True
        assert isinstance(sigers[0], Siger)

        # test framed
        msg = messagize(serder, sigers=sigers, framed=True, gvrsn=Vrsn_2_0)
        assert isinstance(msg, bytearray)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-KA'
                    b'WAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfP'
                    b'QQkQkxI862_XjyZLHyClVTLoD')

        # test framed and genusify
        msg = messagize(serder, sigers=sigers, framed=True, gvrsn=Vrsn_2_0, genusify=True)
        assert isinstance(msg, bytearray)
        assert msg == (b'-_AAACAA{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecCh'
                b'c6AhSLTQssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZA'
                b'mNvPnGxjJyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57s'
                b'nMRIuX0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a'
                b'":[]}-KAWAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1'
                b'rSc5lPfPQQkQkxI862_XjyZLHyClVTLoD')

        # Test not framed
        msg = messagize(serder, sigers=sigers, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-CA'
                    b'X-KAWAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5'
                    b'lPfPQQkQkxI862_XjyZLHyClVTLoD')

        # Test not framed and genuisfy
        msg = messagize(serder, sigers=sigers, framed=False, gvrsn=Vrsn_2_0, genusify=True)
        assert msg == (b'-_AAACAA{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecCh'
                    b'c6AhSLTQssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZA'
                    b'mNvPnGxjJyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57s'
                    b'nMRIuX0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a'
                    b'":[]}-CAX-KAWAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x'
                    b'_NA1rSc5lPfPQQkQkxI862_XjyZLHyClVTLoD')

        # Test with source SealEvent and Sigers
        # create SealEvent for endorsers est evt whose keys use to sign
        source = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        msg = messagize(serder, sigers=sigers, source=source, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-XA'
                    b'uDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_kH4c'
                    b'G7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-KAWAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE'
                    b'-QzdORp-DbxdDN_GG84x_NA1rSc5lPfPQQkQkxI862_XjyZLHyClVTLoD')

        # Test with not framed
        msg = messagize(serder, sigers=sigers, source=source, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-CA'
                    b'v-XAuDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_'
                    b'kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-KAWAAB1DuEfnZZ6juMZDYiodcWiIqd'
                    b'juEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfPQQkQkxI862_XjyZLHyClVTLoD')

         # Test with seal SealEvent Only
        msg = messagize(serder, bonds=seal, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-TA'
                    b'XDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_kH4c'
                    b'G7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        # Test with not framed
        msg = messagize(serder, bonds=seal, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-CA'
                    b'Y-TAXDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_'
                    b'kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        # Test with source SealLast and Sigers
        # create SealLast for endorsers est evt whose keys use to sign
        source = SealLast(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI')
        seal = SealLast(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI')

        msg = messagize(serder, sigers=sigers, source=source, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-YA'
                    b'iDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI-KAWAAB1DuEfnZZ6juM'
                    b'ZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfPQQkQkxI862_XjyZL'
                    b'HyClVTLoD')

        # Test with not framed
        msg = messagize(serder, sigers=sigers, source=source, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-CA'
                    b'j-YAiDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI-KAWAAB1DuEfnZZ'
                    b'6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfPQQkQkxI862_X'
                    b'jyZLHyClVTLoD')

        # Test with seal SealLast only
        msg = messagize(serder, bonds=seal, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-UA'
                    b'LDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI')

        # Test with not framed
        msg = messagize(serder, bonds=seal, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-CA'
                    b'M-UALDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI')

        # test with seal SealSource only
        seal = SealSource(s='0',
                          d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        msg = messagize(serder, bonds=seal, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-CA'
                    b'N-SAMMAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        # test with multiple seals so collated
        seal0 = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal1 = SealSource(s='1',
                           d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal2 = SealSource(s='2',
                           d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal3 = BlindState(d='EGhjWjnjDTBTQ5uZ-17_nipeMzaCaADNeMBXa8QmmBev',
                                      u='aB3RS8CZP2ds_ZgUyJBuJyim8P8qLRG9wMANIkWPGzev',
                                      td='EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ',
                                      ts='revoked')
        seal4 = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='3',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal5 = BlindState(d='ECVr7QWEp_aqVQuz4yprRFXVxJ-9uWLx_d6oDinlHU6J',
                            u='aG1lSjdJSNl7TiroPl67Uqzd5eFvzmr6bPlL7Lh4ukv8',
                            td='',
                            ts='')
        seal6 = BoundState(d='EFaQ00QW-ZeoMxE9baWcpJbAFXrs5h0ya-wpKnHvMQ0c',
                                      u='aJxtoz6qVeJxPCZvP-qBJifRfIxP3itQBVAAu7JJHxMa',
                                      td='',
                                      ts='',
                                      bn='0',
                                      bd='')
        seal7 = TypeMedia(d='EHYFmR_QWCLz8gZyhc4BQ8xJ-ftZ6OA4fNmuu1ZAvyTE',
                         u='0ABtZWRpYXJyYXdub25jZV8w',
                         mt='application/json',
                         mv='{"name":"Sue","food":"Pizza"}')
        seals = [seal0, seal1, seal2, seal3, seal4, seal5, seal6, seal7]

        msg = messagize(serder, bonds=seals, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-CD'
                    b'D-TAuDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_'
                    b'kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2zDAvCLRr5luWmp7keDvDuLP0kIqcyBYq'
                    b'79b3Dho1QvrjIMAADEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-SA'
                    b'YMAABEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2zMAACEMuNWHss_H_'
                    b'kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-aA7EGhjWjnjDTBTQ5uZ-17_nipeMza'
                    b'CaADNeMBXa8QmmBevaB3RS8CZP2ds_ZgUyJBuJyim8P8qLRG9wMANIkWPGzevEBj'
                    b'u1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQYrevokedECVr7QWEp_aqVQu'
                    b'z4yprRFXVxJ-9uWLx_d6oDinlHU6JaG1lSjdJSNl7TiroPl67Uqzd5eFvzmr6bPl'
                    b'L7Lh4ukv81AAP1AAP-bAaEFaQ00QW-ZeoMxE9baWcpJbAFXrs5h0ya-wpKnHvMQ0'
                    b'caJxtoz6qVeJxPCZvP-qBJifRfIxP3itQBVAAu7JJHxMa1AAP1AAPMAAA1AAP-cA'
                    b'jEHYFmR_QWCLz8gZyhc4BQ8xJ-ftZ6OA4fNmuu1ZAvyTE0ABtZWRpYXJyYXdub25'
                    b'jZV8w6BAGAABhcHBsaWNhdGlvbi9qc29u5BAKAHsibmFtZSI6IlN1ZSIsImZvb2Q'
                    b'iOiJQaXp6YSJ9')

        # Test with wigers
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=False, stem="W")
        wigers = mgr.sign(ser=serder.raw, verfers=verfers)  # default indexed True
        assert isinstance(wigers[0], Siger)
        msg = messagize(serder, wigers=wigers, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-LA'
                    b'WAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs7_JuO4RioH1NUTtzTuV1bbuB7eoNhEj'
                    b'20VJYa4947ZMVrOxKhzI6EqUH')

        # Test with wigers and not framed
        msg = messagize(serder, wigers=wigers,framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-CA'
                    b'X-LAWAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs7_JuO4RioH1NUTtzTuV1bbuB7eo'
                    b'NhEj20VJYa4947ZMVrOxKhzI6EqUH')

        # Test with cigars
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=False, stem="R")
        cigars = mgr.sign(ser=serder.raw, verfers=verfers, indexed=False)
        assert isinstance(cigars[0], Cigar)
        msg = messagize(serder, cigars=cigars, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-MA'
                    b'hBJjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDwWrxO8RItpgGFtFi'
                    b'DF7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVw'
                    b'g_TwF')

        # Test with cigars and not framed
        msg = messagize(serder, cigars=cigars, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-CA'
                    b'i-MAhBJjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDwWrxO8RItpgG'
                    b'FtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko'
                    b'5EVwg_TwF')

        # Test with wigers and cigars
        msg = messagize(serder, wigers=wigers, cigars=cigars, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-LA'
                    b'WAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs7_JuO4RioH1NUTtzTuV1bbuB7eoNhEj'
                    b'20VJYa4947ZMVrOxKhzI6EqUH-MAhBJjH1MCDssEZMnORskF34AwOFDgDL47513G'
                    b'ivRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUV'
                    b'X2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with wigers and cigars and not framed
        msg = messagize(serder, cigars=cigars, wigers=wigers, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-CA'
                    b'5-LAWAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs7_JuO4RioH1NUTtzTuV1bbuB7eo'
                    b'NhEj20VJYa4947ZMVrOxKhzI6EqUH-MAhBJjH1MCDssEZMnORskF34AwOFDgDL47'
                    b'513GivRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa'
                    b'0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with sigers and wigers and cigars
        msg = messagize(serder, sigers=sigers, cigars=cigars, wigers=wigers,
                        framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-KA'
                    b'WAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfP'
                    b'QQkQkxI862_XjyZLHyClVTLoD-LAWAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs7_J'
                    b'uO4RioH1NUTtzTuV1bbuB7eoNhEj20VJYa4947ZMVrOxKhzI6EqUH-MAhBJjH1MC'
                    b'DssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas'
                    b'-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with sigers and wigers and cigars and framed
        msg = messagize(serder, sigers=sigers, cigars=cigars, wigers=wigers,
                        framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-CB'
                    b'Q-KAWAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5'
                    b'lPfPQQkQkxI862_XjyZLHyClVTLoD-LAWAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyx'
                    b's7_JuO4RioH1NUTtzTuV1bbuB7eoNhEj20VJYa4947ZMVrOxKhzI6EqUH-MAhBJj'
                    b'H1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDwWrxO8RItpgGFtFiDF7Q'
                    b'oVas-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with sigers and seal and wigers and cigars and not framed
        source = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        msg = messagize(serder, sigers=sigers, source=source, bonds=seal, wigers=wigers,
                        cigars=cigars, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b'
                    b'qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-CC'
                    b'A-XAuDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_'
                    b'kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-KAWAAB1DuEfnZZ6juMZDYiodcWiIqd'
                    b'juEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfPQQkQkxI862_XjyZLHyClVTLoD-LA'
                    b'WAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs7_JuO4RioH1NUTtzTuV1bbuB7eoNhEj'
                    b'20VJYa4947ZMVrOxKhzI6EqUH-MAhBJjH1MCDssEZMnORskF34AwOFDgDL47513G'
                    b'ivRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUV'
                    b'X2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF-TAXDAvCLRr5luWmp7keDvDuLP0kIqc'
                    b'yBYq79b3Dho1QvrjIMAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        # Test receipt message with wigers and or cigars signing prior event
        wigers = mgr.sign(ser=serder.raw, verfers=verfers, indexed=True)
        assert isinstance(wigers[0], Siger)
        cigars = mgr.sign(ser=serder.raw, verfers=verfers, indexed=False)

        serder = receipt(pre=pre,
                           sn=int(ked["s"], 16),
                           said=serder.said,
                           kind=Kinds.json,
                           pvrsn=Vrsn_1_0, version=Vrsn_1_0)

        # create receipt with wigers
        msg = messagize(serder, wigers=wigers, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0"}-LAWAADwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31'
                    b'jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')

        # Create receipt with cigars
        msg = messagize(serder, cigars=cigars, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0"}-MAhBJjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QK'
                    b'z0BDwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xsyyH1'
                    b'US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with wigers and cigars
        msg = messagize(serder, wigers=wigers, cigars=cigars, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0"}-LAWAADwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31'
                    b'jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF-MAhBJjH1MCDssEZMnO'
                    b'RskF34AwOFDgDL47513GivRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0x'
                    b'tOfbsh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with wigers and cigars and not framed
        msg = messagize(serder, wigers=wigers, cigars=cigars, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EFyzzg2Mp5A3ecChc6AhSLTQ'
                    b'ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj'
                    b'JyHxl4F","s":"0"}-CA5-LAWAADwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfb'
                    b'sh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF-MAhBJjH1MCDssE'
                    b'ZMnORskF34AwOFDgDL47513GivRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas-6Bz'
                    b'vj0xtOfbsh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with query message
        serder = query(route="log",
                        query=dict(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI'),
                        stamp=helping.DTS_BASE_0,
                        kind=Kinds.json,
                        pvrsn=Vrsn_1_0)

        # Test with SealLast and framed for endorsers est evt whose keys use to sign
        source = SealLast(i=pre)
        msg = messagize(serder, sigers=sigers, source=source, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON0000c9_","t":"qry","d":"EGN68_seecuzXQO15FFGJLVw'
                    b'ZCBCPYW-hy29fjWWPQbp","dt":"2021-01-01T00:00:00.000000+00:00","r'
                    b'":"log","rr":"","q":{"i":"DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho'
                    b'1QvrjI"}}-YAiEFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxjJyHxl4F-KAWAAB'
                    b'1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfPQQkQ'
                    b'kxI862_XjyZLHyClVTLoD')

        # Not framed SealLast
        msg = messagize(serder, sigers=sigers, source=source, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERI10JSON0000c9_","t":"qry","d":"EGN68_seecuzXQO15FFGJLVw'
                    b'ZCBCPYW-hy29fjWWPQbp","dt":"2021-01-01T00:00:00.000000+00:00","r'
                    b'":"log","rr":"","q":{"i":"DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho'
                    b'1QvrjI"}}-CAj-YAiEFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxjJyHxl4F-KA'
                    b'WAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfP'
                    b'QQkQkxI862_XjyZLHyClVTLoD')


        """ Done Test """

def test_messagize_v2():
    """Test messagize for v2 messages and v2 attachments
    """
    salter = Salter(raw=b'0123456789abcdef')
    with openDB(name="edy") as db, openKS(name="edy") as ks:
        # Init key pair manager
        mgr = Manager(ks=ks, salt=salter.qb64)
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=True, stem="C")

        # Test with inception message
        serder = incept(keys=[verfers[0].qb64], code=MtrDex.Blake3_256,
                        kind=Kinds.json, pvrsn=Vrsn_2_0, version=Vrsn_1_0)
        ked = serder.ked
        pre = serder.pre

        sigers = mgr.sign(ser=serder.raw, verfers=verfers)  # default indexed True
        assert isinstance(sigers[0], Siger)

        # test framed
        msg = messagize(serder, sigers=sigers, framed=True, gvrsn=Vrsn_2_0)
        assert isinstance(msg, bytearray)
        assert msg == (b'{"v":"KERICAACAAJSONAAD_.","t":"icp","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX'
                    b'0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-'
                    b'KAWAADdpYFg2ecIl0O7FeUnHN2P_aK-9U_31Hsvt57_duHbLVlG50kep74k6uFcc'
                    b'MbXLqxMI0dAMAPDisFFvBcb6qEC')

        # test framed and genusify
        msg = messagize(serder, sigers=sigers, framed=True, gvrsn=Vrsn_2_0, genusify=True)
        assert isinstance(msg, bytearray)
        assert msg == (b'-_AAACAA{"v":"KERICAACAAJSONAAD_.","t":"icp","d":"ECtGzXBDhYAOdK'
                    b'eQcTgBr4agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy0'
                    b'6IN7jaKc3OIQLyLWU","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz5'
                    b'7snMRIuX0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],'
                    b'"a":[]}-KAWAADdpYFg2ecIl0O7FeUnHN2P_aK-9U_31Hsvt57_duHbLVlG50kep'
                    b'74k6uFccMbXLqxMI0dAMAPDisFFvBcb6qEC')

        # Test not framed
        msg = messagize(serder, sigers=sigers, framed=False, gvrsn=Vrsn_2_0)
        assert msg ==(b'{"v":"KERICAACAAJSONAAD_.","t":"icp","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX'
                    b'0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-'
                    b'CAX-KAWAADdpYFg2ecIl0O7FeUnHN2P_aK-9U_31Hsvt57_duHbLVlG50kep74k6'
                    b'uFccMbXLqxMI0dAMAPDisFFvBcb6qEC')

        # Test not framed and genuisfy
        msg = messagize(serder, sigers=sigers, framed=False, gvrsn=Vrsn_2_0, genusify=True)
        assert msg == (b'-_AAACAA{"v":"KERICAACAAJSONAAD_.","t":"icp","d":"ECtGzXBDhYAOdK'
                    b'eQcTgBr4agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy0'
                    b'6IN7jaKc3OIQLyLWU","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz5'
                    b'7snMRIuX0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],'
                    b'"a":[]}-CAX-KAWAADdpYFg2ecIl0O7FeUnHN2P_aK-9U_31Hsvt57_duHbLVlG5'
                    b'0kep74k6uFccMbXLqxMI0dAMAPDisFFvBcb6qEC')

        # Test with source SealEvent and Sigers
        # create SealEvent for endorsers est evt whose keys use to sign
        source = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        msg = messagize(serder, sigers=sigers, source=source, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAAD_.","t":"icp","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX'
                    b'0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-'
                    b'XAuDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_kH'
                    b'4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-KAWAADdpYFg2ecIl0O7FeUnHN2P_aK-9'
                    b'U_31Hsvt57_duHbLVlG50kep74k6uFccMbXLqxMI0dAMAPDisFFvBcb6qEC')

        # Test with not framed
        msg = messagize(serder, sigers=sigers, source=source, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAAD_.","t":"icp","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX'
                    b'0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-'
                    b'CAv-XAuDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_'
                    b'H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-KAWAADdpYFg2ecIl0O7FeUnHN2P_'
                    b'aK-9U_31Hsvt57_duHbLVlG50kep74k6uFccMbXLqxMI0dAMAPDisFFvBcb6qEC')

         # Test with seal SealEvent Only
        msg = messagize(serder, bonds=seal, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAAD_.","t":"icp","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX'
                    b'0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-'
                    b'TAXDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_kH'
                    b'4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        # Test with not framed
        msg = messagize(serder, bonds=seal, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAAD_.","t":"icp","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX'
                    b'0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-'
                    b'CAY-TAXDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_'
                    b'H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        # Test with source SealLast and Sigers
        # create SealLast for endorsers est evt whose keys use to sign
        source = SealLast(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI')
        seal = SealLast(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI')

        msg = messagize(serder, sigers=sigers, source=source, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAAD_.","t":"icp","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX'
                    b'0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-'
                    b'YAiDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI-KAWAADdpYFg2ecIl'
                    b'0O7FeUnHN2P_aK-9U_31Hsvt57_duHbLVlG50kep74k6uFccMbXLqxMI0dAMAPDi'
                    b'sFFvBcb6qEC')

        # Test with not framed
        msg = messagize(serder, sigers=sigers, source=source, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAAD_.","t":"icp","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX'
                    b'0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-'
                    b'CAj-YAiDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI-KAWAADdpYFg2'
                    b'ecIl0O7FeUnHN2P_aK-9U_31Hsvt57_duHbLVlG50kep74k6uFccMbXLqxMI0dAM'
                    b'APDisFFvBcb6qEC')

        # Test with seal SealLast only
        msg = messagize(serder, bonds=seal, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAAD_.","t":"icp","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX'
                    b'0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-'
                    b'UALDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI')

        # Test with not framed
        msg = messagize(serder, bonds=seal, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAAD_.","t":"icp","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX'
                    b'0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-'
                    b'CAM-UALDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI')

        # test with seal SealSource only
        seal = SealSource(s='0',
                          d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        msg = messagize(serder, bonds=seal, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAAD_.","t":"icp","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX'
                    b'0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-'
                    b'CAN-SAMMAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        # Test with wigers
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=False, stem="W")
        wigers = mgr.sign(ser=serder.raw, verfers=verfers)  # default indexed True
        assert isinstance(wigers[0], Siger)
        msg = messagize(serder, wigers=wigers, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAAD_.","t":"icp","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX'
                    b'0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-'
                    b'LAWAACXlTpe-ZODGKZmovS9GZKkf8k-OsvdBpyVz-YvqIIVrxSH1UjWDaWDlGUWr'
                    b'LBdCJFrCkHGNGseQYrrVYc59BwL')

        # Test with wigers and not framed
        msg = messagize(serder, wigers=wigers,framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAAD_.","t":"icp","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX'
                    b'0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-'
                    b'CAX-LAWAACXlTpe-ZODGKZmovS9GZKkf8k-OsvdBpyVz-YvqIIVrxSH1UjWDaWDl'
                    b'GUWrLBdCJFrCkHGNGseQYrrVYc59BwL')

        # Test with cigars
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=False, stem="R")
        cigars = mgr.sign(ser=serder.raw, verfers=verfers, indexed=False)
        assert isinstance(cigars[0], Cigar)
        msg = messagize(serder, cigars=cigars, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAAD_.","t":"icp","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX'
                    b'0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-'
                    b'MAhBJjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BBnxvPGzvJf8d6hz'
                    b'fDR62RMk0aX0T-MhgqJqgvO4z672OO2RDC3t_b__1HuqAIG1kTGrkhpBDyuOpknk'
                    b'W-xYkcG')

        # Test with cigars and not framed
        msg = messagize(serder, cigars=cigars, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAAD_.","t":"icp","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX'
                    b'0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-'
                    b'CAi-MAhBJjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BBnxvPGzvJf8'
                    b'd6hzfDR62RMk0aX0T-MhgqJqgvO4z672OO2RDC3t_b__1HuqAIG1kTGrkhpBDyuO'
                    b'pknkW-xYkcG')

        # Test with wigers and cigars
        msg = messagize(serder, wigers=wigers, cigars=cigars, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAAD_.","t":"icp","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX'
                    b'0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-'
                    b'LAWAACXlTpe-ZODGKZmovS9GZKkf8k-OsvdBpyVz-YvqIIVrxSH1UjWDaWDlGUWr'
                    b'LBdCJFrCkHGNGseQYrrVYc59BwL-MAhBJjH1MCDssEZMnORskF34AwOFDgDL4751'
                    b'3GivRvd_QKz0BBnxvPGzvJf8d6hzfDR62RMk0aX0T-MhgqJqgvO4z672OO2RDC3t'
                    b'_b__1HuqAIG1kTGrkhpBDyuOpknkW-xYkcG')

        # Test with wigers and cigars and not framed
        msg = messagize(serder, cigars=cigars, wigers=wigers, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAAD_.","t":"icp","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX'
                    b'0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-'
                    b'CA5-LAWAACXlTpe-ZODGKZmovS9GZKkf8k-OsvdBpyVz-YvqIIVrxSH1UjWDaWDl'
                    b'GUWrLBdCJFrCkHGNGseQYrrVYc59BwL-MAhBJjH1MCDssEZMnORskF34AwOFDgDL'
                    b'47513GivRvd_QKz0BBnxvPGzvJf8d6hzfDR62RMk0aX0T-MhgqJqgvO4z672OO2R'
                    b'DC3t_b__1HuqAIG1kTGrkhpBDyuOpknkW-xYkcG')

        # Test with sigers and wigers and cigars and framed
        msg = messagize(serder, sigers=sigers, cigars=cigars, wigers=wigers,
                        framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAAD_.","t":"icp","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX'
                    b'0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-'
                    b'KAWAADdpYFg2ecIl0O7FeUnHN2P_aK-9U_31Hsvt57_duHbLVlG50kep74k6uFcc'
                    b'MbXLqxMI0dAMAPDisFFvBcb6qEC-LAWAACXlTpe-ZODGKZmovS9GZKkf8k-OsvdB'
                    b'pyVz-YvqIIVrxSH1UjWDaWDlGUWrLBdCJFrCkHGNGseQYrrVYc59BwL-MAhBJjH1'
                    b'MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BBnxvPGzvJf8d6hzfDR62RMk'
                    b'0aX0T-MhgqJqgvO4z672OO2RDC3t_b__1HuqAIG1kTGrkhpBDyuOpknkW-xYkcG')

        # Test with sigers and wigers and cigars and not framed
        msg = messagize(serder, sigers=sigers, cigars=cigars, wigers=wigers,
                        framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAAD_.","t":"icp","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX'
                    b'0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-'
                    b'CBQ-KAWAADdpYFg2ecIl0O7FeUnHN2P_aK-9U_31Hsvt57_duHbLVlG50kep74k6'
                    b'uFccMbXLqxMI0dAMAPDisFFvBcb6qEC-LAWAACXlTpe-ZODGKZmovS9GZKkf8k-O'
                    b'svdBpyVz-YvqIIVrxSH1UjWDaWDlGUWrLBdCJFrCkHGNGseQYrrVYc59BwL-MAhB'
                    b'JjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BBnxvPGzvJf8d6hzfDR6'
                    b'2RMk0aX0T-MhgqJqgvO4z672OO2RDC3t_b__1HuqAIG1kTGrkhpBDyuOpknkW-xY'
                    b'kcG')

        # Test with sigers and seal and wigers and cigars and not framed
        source = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        msg = messagize(serder, sigers=sigers, source=source, bonds=seal,
                        wigers=wigers, cigars=cigars, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAAD_.","t":"icp","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX'
                    b'0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-'
                    b'CCA-XAuDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_'
                    b'H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-KAWAADdpYFg2ecIl0O7FeUnHN2P_'
                    b'aK-9U_31Hsvt57_duHbLVlG50kep74k6uFccMbXLqxMI0dAMAPDisFFvBcb6qEC-'
                    b'LAWAACXlTpe-ZODGKZmovS9GZKkf8k-OsvdBpyVz-YvqIIVrxSH1UjWDaWDlGUWr'
                    b'LBdCJFrCkHGNGseQYrrVYc59BwL-MAhBJjH1MCDssEZMnORskF34AwOFDgDL4751'
                    b'3GivRvd_QKz0BBnxvPGzvJf8d6hzfDR62RMk0aX0T-MhgqJqgvO4z672OO2RDC3t'
                    b'_b__1HuqAIG1kTGrkhpBDyuOpknkW-xYkcG-TAXDAvCLRr5luWmp7keDvDuLP0kI'
                    b'qcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeD'
                    b'Z2z')

        # test with multiple seals so collated
        seal0 = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal1 = SealSource(s='1',
                           d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal2 = SealSource(s='2',
                           d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal3 = BlindState(d='EGhjWjnjDTBTQ5uZ-17_nipeMzaCaADNeMBXa8QmmBev',
                                      u='aB3RS8CZP2ds_ZgUyJBuJyim8P8qLRG9wMANIkWPGzev',
                                      td='EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ',
                                      ts='revoked')
        seal4 = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='3',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal5 = BlindState(d='ECVr7QWEp_aqVQuz4yprRFXVxJ-9uWLx_d6oDinlHU6J',
                            u='aG1lSjdJSNl7TiroPl67Uqzd5eFvzmr6bPlL7Lh4ukv8',
                            td='',
                            ts='')
        seal6 = BoundState(d='EFaQ00QW-ZeoMxE9baWcpJbAFXrs5h0ya-wpKnHvMQ0c',
                                      u='aJxtoz6qVeJxPCZvP-qBJifRfIxP3itQBVAAu7JJHxMa',
                                      td='',
                                      ts='',
                                      bn='0',
                                      bd='')
        seal7 = TypeMedia(d='EHYFmR_QWCLz8gZyhc4BQ8xJ-ftZ6OA4fNmuu1ZAvyTE',
                         u='0ABtZWRpYXJyYXdub25jZV8w',
                         mt='application/json',
                         mv='{"name":"Sue","food":"Pizza"}')
        seals = [seal0, seal1, seal2, seal3, seal4, seal5, seal6, seal7]

        msg = messagize(serder, bonds=seals, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAAD_.","t":"icp","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX'
                    b'0bqN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-'
                    b'CDD-TAuDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_'
                    b'H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2zDAvCLRr5luWmp7keDvDuLP0kIqcyB'
                    b'Yq79b3Dho1QvrjIMAADEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-'
                    b'SAYMAABEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2zMAACEMuNWHss_'
                    b'H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-aA7EGhjWjnjDTBTQ5uZ-17_nipeM'
                    b'zaCaADNeMBXa8QmmBevaB3RS8CZP2ds_ZgUyJBuJyim8P8qLRG9wMANIkWPGzevE'
                    b'Bju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQYrevokedECVr7QWEp_aqV'
                    b'Quz4yprRFXVxJ-9uWLx_d6oDinlHU6JaG1lSjdJSNl7TiroPl67Uqzd5eFvzmr6b'
                    b'PlL7Lh4ukv81AAP1AAP-bAaEFaQ00QW-ZeoMxE9baWcpJbAFXrs5h0ya-wpKnHvM'
                    b'Q0caJxtoz6qVeJxPCZvP-qBJifRfIxP3itQBVAAu7JJHxMa1AAP1AAPMAAA1AAP-'
                    b'cAjEHYFmR_QWCLz8gZyhc4BQ8xJ-ftZ6OA4fNmuu1ZAvyTE0ABtZWRpYXJyYXdub'
                    b'25jZV8w6BAGAABhcHBsaWNhdGlvbi9qc29u5BAKAHsibmFtZSI6IlN1ZSIsImZvb'
                    b'2QiOiJQaXp6YSJ9')


        # Test with receipt message with wigers and or cigars on prior message
        wigers = mgr.sign(ser=serder.raw, verfers=verfers, indexed=True)
        assert isinstance(wigers[0], Siger)
        cigars = mgr.sign(ser=serder.raw, verfers=verfers, indexed=False)  # sign event not receipt

        serder = receipt(pre=pre,
                           sn=int(ked["s"], 16),
                           said=serder.said,
                           kind=Kinds.json,
                           pvrsn=Vrsn_2_0, version=Vrsn_1_0)

        # Test with wigers
        msg = messagize(serder, wigers=wigers, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAACT.","t":"rct","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0"}-LAWAABnxvPGzvJf8d6hzfDR62RMk0aX0T-MhgqJqgvO4'
                    b'z672OO2RDC3t_b__1HuqAIG1kTGrkhpBDyuOpknkW-xYkcG')

        # Test with cigars
        msg = messagize(serder, cigars=cigars, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAACT.","t":"rct","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0"}-MAhBJjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_'
                    b'QKz0BBnxvPGzvJf8d6hzfDR62RMk0aX0T-MhgqJqgvO4z672OO2RDC3t_b__1Huq'
                    b'AIG1kTGrkhpBDyuOpknkW-xYkcG')

        # Test with wigers and cigars
        msg = messagize(serder, wigers=wigers, cigars=cigars, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAACT.","t":"rct","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0"}-LAWAABnxvPGzvJf8d6hzfDR62RMk0aX0T-MhgqJqgvO4'
                    b'z672OO2RDC3t_b__1HuqAIG1kTGrkhpBDyuOpknkW-xYkcG-MAhBJjH1MCDssEZM'
                    b'nORskF34AwOFDgDL47513GivRvd_QKz0BBnxvPGzvJf8d6hzfDR62RMk0aX0T-Mh'
                    b'gqJqgvO4z672OO2RDC3t_b__1HuqAIG1kTGrkhpBDyuOpknkW-xYkcG')

        # Test with wigers and cigars and not framed
        msg = messagize(serder, wigers=wigers, cigars=cigars, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAACT.","t":"rct","d":"ECtGzXBDhYAOdKeQcTgBr4'
                    b'agqy06IN7jaKc3OIQLyLWU","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","s":"0"}-CA5-LAWAABnxvPGzvJf8d6hzfDR62RMk0aX0T-MhgqJq'
                    b'gvO4z672OO2RDC3t_b__1HuqAIG1kTGrkhpBDyuOpknkW-xYkcG-MAhBJjH1MCDs'
                    b'sEZMnORskF34AwOFDgDL47513GivRvd_QKz0BBnxvPGzvJf8d6hzfDR62RMk0aX0'
                    b'T-MhgqJqgvO4z672OO2RDC3t_b__1HuqAIG1kTGrkhpBDyuOpknkW-xYkcG')

        # Test with query message
        serder = query(pre=pre,
                       route="log",
                        query=dict(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI'),
                        stamp=helping.DTS_BASE_0,
                        kind=Kinds.json,
                        pvrsn=Vrsn_2_0)

        # Test with SealLast and framed for endorsers est evt whose keys use to sign
        source = SealLast(i=pre)
        msg = messagize(serder, sigers=sigers, source=source, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAAD-.","t":"qry","d":"EJhb5rCAKt5x_KUuhZVfle'
                    b'7nDN7Bv0ZExzez63lHZu3y","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","dt":"2021-01-01T00:00:00.000000+00:00","r":"log","rr'
                    b'":"","q":{"i":"DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI"}}-Y'
                    b'AiECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc3OIQLyLWU-KAWAADdpYFg2ecIl0'
                    b'O7FeUnHN2P_aK-9U_31Hsvt57_duHbLVlG50kep74k6uFccMbXLqxMI0dAMAPDis'
                    b'FFvBcb6qEC')

        # Not framed SealLast
        msg = messagize(serder, sigers=sigers, source=source, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'{"v":"KERICAACAAJSONAAD-.","t":"qry","d":"EJhb5rCAKt5x_KUuhZVfle'
                    b'7nDN7Bv0ZExzez63lHZu3y","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                    b'3OIQLyLWU","dt":"2021-01-01T00:00:00.000000+00:00","r":"log","rr'
                    b'":"","q":{"i":"DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI"}}-C'
                    b'Aj-YAiECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc3OIQLyLWU-KAWAADdpYFg2e'
                    b'cIl0O7FeUnHN2P_aK-9U_31Hsvt57_duHbLVlG50kep74k6uFccMbXLqxMI0dAMA'
                    b'PDisFFvBcb6qEC')


        """ Done Test """


def test_messagize_v2_native():
    """Test messagize for v2 native messages and v2 attachments
    """
    salter = Salter(raw=b'0123456789abcdef')
    with openDB(name="edy") as db, openKS(name="edy") as ks:
        # Init key pair manager
        mgr = Manager(ks=ks, salt=salter.qb64)
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=True, stem="C")

        # Test with inception message
        serder = incept(keys=[verfers[0].qb64], code=MtrDex.Blake3_256,
                        kind=Kinds.cesr, pvrsn=Vrsn_2_0, version=Vrsn_1_0)
        ked = serder.ked
        pre = serder.pre

        sigers = mgr.sign(ser=serder.raw, verfers=verfers)  # default indexed True
        assert isinstance(sigers[0], Siger)

        # test framed
        msg = messagize(serder, sigers=sigers, framed=True, gvrsn=Vrsn_2_0)
        assert isinstance(msg, bytearray)
        assert msg == (b'-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif48wh'
                    b'Ampb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA-KAW'
                    b'AABfKnU9VdFRGI2pQ2gMotaAB3Q8BxNhLRnrXTrKiyi5qhjQ5YKU4SbDFjVdGoUo'
                    b'N3u5gfn6dHBVwvnBkr96OPwM')

        # test framed and genusify
        msg = messagize(serder, sigers=sigers, framed=True, gvrsn=Vrsn_2_0, genusify=True)
        assert isinstance(msg, bytearray)
        assert msg == (b'-_AAACAA-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9Pap'
                    b'Q2A2NfHnEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JAL'
                    b'DOif48whAmpb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA'
                    b'-JAA-KAWAABfKnU9VdFRGI2pQ2gMotaAB3Q8BxNhLRnrXTrKiyi5qhjQ5YKU4SbD'
                    b'FjVdGoUoN3u5gfn6dHBVwvnBkr96OPwM')

        # Test not framed
        msg = messagize(serder, sigers=sigers, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif48wh'
                    b'Ampb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA-CAX'
                    b'-KAWAABfKnU9VdFRGI2pQ2gMotaAB3Q8BxNhLRnrXTrKiyi5qhjQ5YKU4SbDFjVd'
                    b'GoUoN3u5gfn6dHBVwvnBkr96OPwM')

        # Test not framed and genuisfy
        msg = messagize(serder, sigers=sigers, framed=False, gvrsn=Vrsn_2_0, genusify=True)
        assert msg == (b'-_AAACAA-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9Pap'
                    b'Q2A2NfHnEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JAL'
                    b'DOif48whAmpb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA'
                    b'-JAA-CAX-KAWAABfKnU9VdFRGI2pQ2gMotaAB3Q8BxNhLRnrXTrKiyi5qhjQ5YKU'
                    b'4SbDFjVdGoUoN3u5gfn6dHBVwvnBkr96OPwM')

        # Test with source SealEvent and Sigers
        # create SealEvent for endorsers est evt whose keys use to sign
        source = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        msg = messagize(serder, sigers=sigers, source=source, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif48wh'
                    b'Ampb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA-XAu'
                    b'DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_kH4cG'
                    b'7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-KAWAABfKnU9VdFRGI2pQ2gMotaAB3Q8BxNh'
                    b'LRnrXTrKiyi5qhjQ5YKU4SbDFjVdGoUoN3u5gfn6dHBVwvnBkr96OPwM')

        # Test with not framed
        msg = messagize(serder, sigers=sigers, source=source, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif48wh'
                    b'Ampb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA-CAv'
                    b'-XAuDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_k'
                    b'H4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-KAWAABfKnU9VdFRGI2pQ2gMotaAB3Q8'
                    b'BxNhLRnrXTrKiyi5qhjQ5YKU4SbDFjVdGoUoN3u5gfn6dHBVwvnBkr96OPwM')

         # Test with seal SealEvent Only
        msg = messagize(serder, bonds=seal, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif48wh'
                    b'Ampb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA-TAX'
                    b'DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_kH4cG'
                    b'7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        # Test with not framed
        msg = messagize(serder, bonds=seal, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif48wh'
                    b'Ampb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA-CAY'
                    b'-TAXDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_k'
                    b'H4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        # Test with source SealLast and Sigers
        # create SealLast for endorsers est evt whose keys use to sign
        source = SealLast(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI')
        seal = SealLast(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI')

        msg = messagize(serder, sigers=sigers, source=source, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif48wh'
                    b'Ampb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA-YAi'
                    b'DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI-KAWAABfKnU9VdFRGI2p'
                    b'Q2gMotaAB3Q8BxNhLRnrXTrKiyi5qhjQ5YKU4SbDFjVdGoUoN3u5gfn6dHBVwvnB'
                    b'kr96OPwM')

        # Test with not framed
        msg = messagize(serder, sigers=sigers, source=source, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif48wh'
                    b'Ampb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA-CAj'
                    b'-YAiDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI-KAWAABfKnU9VdFR'
                    b'GI2pQ2gMotaAB3Q8BxNhLRnrXTrKiyi5qhjQ5YKU4SbDFjVdGoUoN3u5gfn6dHBV'
                    b'wvnBkr96OPwM')

        # Test with seal SealLast only
        msg = messagize(serder, bonds=seal, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif48wh'
                    b'Ampb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA-UAL'
                    b'DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI')

        # Test with not framed
        msg = messagize(serder, bonds=seal, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif48wh'
                    b'Ampb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA-CAM'
                    b'-UALDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI')

        # test with seal SealSource only
        seal = SealSource(s='0',
                          d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        msg = messagize(serder, bonds=seal, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif48wh'
                    b'Ampb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA-CAN'
                    b'-SAMMAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        # Test with wigers
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=False, stem="W")
        wigers = mgr.sign(ser=serder.raw, verfers=verfers)  # default indexed True
        assert isinstance(wigers[0], Siger)
        msg = messagize(serder, wigers=wigers, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif48wh'
                    b'Ampb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA-LAW'
                    b'AAA704jdZETqR_LNm1gf82PAXEa7qFxza_SEP4Q97wL32P1oItaECL2m9egSKBGe'
                    b'LofMC1tL22Mvz2RICLDUvbsA')

        # Test with wigers and not framed
        msg = messagize(serder, wigers=wigers,framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif48wh'
                    b'Ampb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA-CAX'
                    b'-LAWAAA704jdZETqR_LNm1gf82PAXEa7qFxza_SEP4Q97wL32P1oItaECL2m9egS'
                    b'KBGeLofMC1tL22Mvz2RICLDUvbsA')

        # Test with cigars
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=False, stem="R")
        cigars = mgr.sign(ser=serder.raw, verfers=verfers, indexed=False)
        assert isinstance(cigars[0], Cigar)
        msg = messagize(serder, cigars=cigars, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif48wh'
                    b'Ampb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA-MAh'
                    b'BJjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDB0Tz52RRyT-CFE6zb'
                    b'oIEkrJI87RfIltfOiYBZLcrdK2Sk3aCRrg3185PzzR1XGd9asEEG6l3zejhFHaA9'
                    b'1O8M')

        # Test with cigars and not framed
        msg = messagize(serder, cigars=cigars, framed=False, gvrsn=Vrsn_2_0)
        assert msg ==(b'-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif48wh'
                    b'Ampb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA-CAi'
                    b'-MAhBJjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDB0Tz52RRyT-CF'
                    b'E6zboIEkrJI87RfIltfOiYBZLcrdK2Sk3aCRrg3185PzzR1XGd9asEEG6l3zejhF'
                    b'HaA91O8M')

        # Test with wigers and cigars
        msg = messagize(serder, wigers=wigers, cigars=cigars, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif48wh'
                    b'Ampb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA-LAW'
                    b'AAA704jdZETqR_LNm1gf82PAXEa7qFxza_SEP4Q97wL32P1oItaECL2m9egSKBGe'
                    b'LofMC1tL22Mvz2RICLDUvbsA-MAhBJjH1MCDssEZMnORskF34AwOFDgDL47513Gi'
                    b'vRvd_QKz0BDB0Tz52RRyT-CFE6zboIEkrJI87RfIltfOiYBZLcrdK2Sk3aCRrg31'
                    b'85PzzR1XGd9asEEG6l3zejhFHaA91O8M')

        # Test with wigers and cigars and not framed
        msg = messagize(serder, cigars=cigars, wigers=wigers, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif48wh'
                    b'Ampb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA-CA5'
                    b'-LAWAAA704jdZETqR_LNm1gf82PAXEa7qFxza_SEP4Q97wL32P1oItaECL2m9egS'
                    b'KBGeLofMC1tL22Mvz2RICLDUvbsA-MAhBJjH1MCDssEZMnORskF34AwOFDgDL475'
                    b'13GivRvd_QKz0BDB0Tz52RRyT-CFE6zboIEkrJI87RfIltfOiYBZLcrdK2Sk3aCR'
                    b'rg3185PzzR1XGd9asEEG6l3zejhFHaA91O8M')

        # Test with sigers and wigers and cigars and framed
        msg = messagize(serder, sigers=sigers, cigars=cigars, wigers=wigers,
                        framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif48wh'
                    b'Ampb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA-KAW'
                    b'AABfKnU9VdFRGI2pQ2gMotaAB3Q8BxNhLRnrXTrKiyi5qhjQ5YKU4SbDFjVdGoUo'
                    b'N3u5gfn6dHBVwvnBkr96OPwM-LAWAAA704jdZETqR_LNm1gf82PAXEa7qFxza_SE'
                    b'P4Q97wL32P1oItaECL2m9egSKBGeLofMC1tL22Mvz2RICLDUvbsA-MAhBJjH1MCD'
                    b'ssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDB0Tz52RRyT-CFE6zboIEkrJI8'
                    b'7RfIltfOiYBZLcrdK2Sk3aCRrg3185PzzR1XGd9asEEG6l3zejhFHaA91O8M')

        # Test with sigers and wigers and cigars and not framed
        msg = messagize(serder, sigers=sigers, cigars=cigars, wigers=wigers,
                        framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif48wh'
                    b'Ampb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA-CBQ'
                    b'-KAWAABfKnU9VdFRGI2pQ2gMotaAB3Q8BxNhLRnrXTrKiyi5qhjQ5YKU4SbDFjVd'
                    b'GoUoN3u5gfn6dHBVwvnBkr96OPwM-LAWAAA704jdZETqR_LNm1gf82PAXEa7qFxz'
                    b'a_SEP4Q97wL32P1oItaECL2m9egSKBGeLofMC1tL22Mvz2RICLDUvbsA-MAhBJjH'
                    b'1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDB0Tz52RRyT-CFE6zboIEk'
                    b'rJI87RfIltfOiYBZLcrdK2Sk3aCRrg3185PzzR1XGd9asEEG6l3zejhFHaA91O8M')

        # Test with sigers and seal and wigers and cigars and not framed
        source = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                                 s='0',
                                 d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        msg = messagize(serder, sigers=sigers, source=source, bonds=seal, wigers=wigers,
                        cigars=cigars, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif48wh'
                    b'Ampb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA-CCA'
                    b'-XAuDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_k'
                    b'H4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-KAWAABfKnU9VdFRGI2pQ2gMotaAB3Q8'
                    b'BxNhLRnrXTrKiyi5qhjQ5YKU4SbDFjVdGoUoN3u5gfn6dHBVwvnBkr96OPwM-LAW'
                    b'AAA704jdZETqR_LNm1gf82PAXEa7qFxza_SEP4Q97wL32P1oItaECL2m9egSKBGe'
                    b'LofMC1tL22Mvz2RICLDUvbsA-MAhBJjH1MCDssEZMnORskF34AwOFDgDL47513Gi'
                    b'vRvd_QKz0BDB0Tz52RRyT-CFE6zboIEkrJI87RfIltfOiYBZLcrdK2Sk3aCRrg31'
                    b'85PzzR1XGd9asEEG6l3zejhFHaA91O8M-TAXDAvCLRr5luWmp7keDvDuLP0kIqcy'
                    b'BYq79b3Dho1QvrjIMAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        # test with multiple seals so collated
        seal0 = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal1 = SealSource(s='1',
                           d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal2 = SealSource(s='2',
                           d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal3 = BlindState(d='EGhjWjnjDTBTQ5uZ-17_nipeMzaCaADNeMBXa8QmmBev',
                                      u='aB3RS8CZP2ds_ZgUyJBuJyim8P8qLRG9wMANIkWPGzev',
                                      td='EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ',
                                      ts='revoked')
        seal4 = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='3',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal5 = BlindState(d='ECVr7QWEp_aqVQuz4yprRFXVxJ-9uWLx_d6oDinlHU6J',
                            u='aG1lSjdJSNl7TiroPl67Uqzd5eFvzmr6bPlL7Lh4ukv8',
                            td='',
                            ts='')
        seal6 = BoundState(d='EFaQ00QW-ZeoMxE9baWcpJbAFXrs5h0ya-wpKnHvMQ0c',
                                      u='aJxtoz6qVeJxPCZvP-qBJifRfIxP3itQBVAAu7JJHxMa',
                                      td='',
                                      ts='',
                                      bn='0',
                                      bd='')
        seal7 = TypeMedia(d='EHYFmR_QWCLz8gZyhc4BQ8xJ-ftZ6OA4fNmuu1ZAvyTE',
                         u='0ABtZWRpYXJyYXdub25jZV8w',
                         mt='application/json',
                         mv='{"name":"Sue","food":"Pizza"}')
        seals = [seal0, seal1, seal2, seal3, seal4, seal5, seal6, seal7]

        msg = messagize(serder, bonds=seals, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif48wh'
                    b'Ampb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA-CDD'
                    b'-TAuDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_k'
                    b'H4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2zDAvCLRr5luWmp7keDvDuLP0kIqcyBYq7'
                    b'9b3Dho1QvrjIMAADEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-SAY'
                    b'MAABEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2zMAACEMuNWHss_H_k'
                    b'H4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-aA7EGhjWjnjDTBTQ5uZ-17_nipeMzaC'
                    b'aADNeMBXa8QmmBevaB3RS8CZP2ds_ZgUyJBuJyim8P8qLRG9wMANIkWPGzevEBju'
                    b'1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQYrevokedECVr7QWEp_aqVQuz'
                    b'4yprRFXVxJ-9uWLx_d6oDinlHU6JaG1lSjdJSNl7TiroPl67Uqzd5eFvzmr6bPlL'
                    b'7Lh4ukv81AAP1AAP-bAaEFaQ00QW-ZeoMxE9baWcpJbAFXrs5h0ya-wpKnHvMQ0c'
                    b'aJxtoz6qVeJxPCZvP-qBJifRfIxP3itQBVAAu7JJHxMa1AAP1AAPMAAA1AAP-cAj'
                    b'EHYFmR_QWCLz8gZyhc4BQ8xJ-ftZ6OA4fNmuu1ZAvyTE0ABtZWRpYXJyYXdub25j'
                    b'ZV8w6BAGAABhcHBsaWNhdGlvbi9qc29u5BAKAHsibmFtZSI6IlN1ZSIsImZvb2Qi'
                    b'OiJQaXp6YSJ9')

        # Test with receipt message with wigers and or cigars on prior message
        wigers = mgr.sign(ser=serder.raw, verfers=verfers, indexed=True)
        assert isinstance(wigers[0], Siger)
        cigars = mgr.sign(ser=serder.raw, verfers=verfers, indexed=False)  # sign event not receipt

        serder = receipt(pre=pre,
                           sn=int(ked["s"], 16),
                           said=serder.said,
                           kind=Kinds.cesr,
                           pvrsn=Vrsn_2_0, version=Vrsn_1_0)

        # Test with wigers
        msg = messagize(serder, wigers=wigers, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAb0OKERICAACAAXrctEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAA-LAWAADB0Tz52RRy'
                    b'T-CFE6zboIEkrJI87RfIltfOiYBZLcrdK2Sk3aCRrg3185PzzR1XGd9asEEG6l3z'
                    b'ejhFHaA91O8M')

        # Test with cigars
        msg = messagize(serder, cigars=cigars, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAb0OKERICAACAAXrctEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAA-MAhBJjH1MCDssEZ'
                    b'MnORskF34AwOFDgDL47513GivRvd_QKz0BDB0Tz52RRyT-CFE6zboIEkrJI87RfI'
                    b'ltfOiYBZLcrdK2Sk3aCRrg3185PzzR1XGd9asEEG6l3zejhFHaA91O8M')

        # Test with wigers and cigars
        msg = messagize(serder, wigers=wigers, cigars=cigars, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAb0OKERICAACAAXrctEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAA-LAWAADB0Tz52RRy'
                    b'T-CFE6zboIEkrJI87RfIltfOiYBZLcrdK2Sk3aCRrg3185PzzR1XGd9asEEG6l3z'
                    b'ejhFHaA91O8M-MAhBJjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDB'
                    b'0Tz52RRyT-CFE6zboIEkrJI87RfIltfOiYBZLcrdK2Sk3aCRrg3185PzzR1XGd9a'
                    b'sEEG6l3zejhFHaA91O8M')

        # Test with wigers and cigars and not framed
        msg = messagize(serder, wigers=wigers, cigars=cigars, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAb0OKERICAACAAXrctEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAA-CA5-LAWAADB0Tz5'
                    b'2RRyT-CFE6zboIEkrJI87RfIltfOiYBZLcrdK2Sk3aCRrg3185PzzR1XGd9asEEG'
                    b'6l3zejhFHaA91O8M-MAhBJjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz'
                    b'0BDB0Tz52RRyT-CFE6zboIEkrJI87RfIltfOiYBZLcrdK2Sk3aCRrg3185PzzR1X'
                    b'Gd9asEEG6l3zejhFHaA91O8M')

        # Test with query message
        serder = query(pre=pre,
                       route="log",
                        query=dict(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI'),
                        stamp=helping.DTS_BASE_0,
                        kind=Kinds.cesr,
                        pvrsn=Vrsn_2_0)

        # Test with SealLast and framed for endorsers est evt whose keys use to sign
        source = SealLast(i=pre)
        msg = messagize(serder, sigers=sigers, source=source, framed=True, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAz0OKERICAACAAXqryEOtc_pUXyVNOyRDMJXTBpFrfEn9e-v56A6RIRVhv4tDE'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn1AAG2021-01-01T00c00'
                    b'c00d000000p00c004AABAlog4AAA-IAM0J_iDAvCLRr5luWmp7keDvDuLP0kIqcy'
                    b'BYq79b3Dho1QvrjI-YAiEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn'
                    b'-KAWAABfKnU9VdFRGI2pQ2gMotaAB3Q8BxNhLRnrXTrKiyi5qhjQ5YKU4SbDFjVd'
                    b'GoUoN3u5gfn6dHBVwvnBkr96OPwM')

        # Not framed SealLast
        msg = messagize(serder, sigers=sigers, source=source, framed=False, gvrsn=Vrsn_2_0)
        assert msg == (b'-FAz0OKERICAACAAXqryEOtc_pUXyVNOyRDMJXTBpFrfEn9e-v56A6RIRVhv4tDE'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn1AAG2021-01-01T00c00'
                    b'c00d000000p00c004AABAlog4AAA-IAM0J_iDAvCLRr5luWmp7keDvDuLP0kIqcy'
                    b'BYq79b3Dho1QvrjI-CAj-YAiEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2'
                    b'NfHn-KAWAABfKnU9VdFRGI2pQ2gMotaAB3Q8BxNhLRnrXTrKiyi5qhjQ5YKU4SbD'
                    b'FjVdGoUoN3u5gfn6dHBVwvnBkr96OPwM')

        """ Done Test """


def test_messagize_v1_nested():
    """Test messagize utility function with version 1 messages nested in body
    +attach group

    """
    salter = Salter(raw=b'0123456789abcdef')
    with openDB(name="edy") as db, openKS(name="edy") as ks:
        # Init key pair manager
        mgr = Manager(ks=ks, salt=salter.qb64)
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=True, stem="C")

        # Test with inception message
        serder = incept(keys=[verfers[0].qb64], code=MtrDex.Blake3_256,
                        kind=Kinds.json, pvrsn=Vrsn_1_0, version=Vrsn_1_0)

        ked = serder.ked
        pre = serder.pre

        sigers = mgr.sign(ser=serder.raw, verfers=verfers)  # default indexed True
        assert isinstance(sigers[0], Siger)

        # test nested ignores framed and gvrsn
        msg = messagize(serder, sigers=sigers, framed=True, nested=True, gvrsn=Vrsn_1_0)
        assert isinstance(msg, bytearray)
        assert msg == (b'-BBu-HBW6BBVAAB7InYiOiJLRVJJMTBKU09OMDAwMGZkXyIsInQiOiJpY3AiLCJk'
                    b'IjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhsNEYi'
                    b'LCJpIjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhs'
                    b'NEYiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-KAWAAB1DuEfnZZ6juMZDYiodcWiIqdj'
                    b'uEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfPQQkQkxI862_XjyZLHyClVTLoD')

        # test nested and genusify
        msg = messagize(serder, sigers=sigers, nested=True, genusify=True, gvrsn=Vrsn_1_0)
        assert isinstance(msg, bytearray)
        assert msg == (b'-_AAACAA-BBu-HBW6BBVAAB7InYiOiJLRVJJMTBKU09OMDAwMGZkXyIsInQiOiJp'
                    b'Y3AiLCJkIjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5'
                    b'SHhsNEYiLCJpIjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4'
                    b'akp5SHhsNEYiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRr'
                    b'eWtzTWN6NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10s'
                    b'ImJ0IjoiMCIsImIiOltdLCJjIjpbXSwiYSI6W119-KAWAAB1DuEfnZZ6juMZDYio'
                    b'dcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfPQQkQkxI862_XjyZLHyClV'
                    b'TLoD')

        # Test with source SealEvent and Sigers
        # create SealEvent for endorsers est evt whose keys use to sign
        source = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        msg = messagize(serder, sigers=sigers, source=source, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BCG-HBW6BBVAAB7InYiOiJLRVJJMTBKU09OMDAwMGZkXyIsInQiOiJpY3AiLCJk'
                    b'IjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhsNEYi'
                    b'LCJpIjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhs'
                    b'NEYiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-XAuDAvCLRr5luWmp7keDvDuLP0kIqcy'
                    b'BYq79b3Dho1QvrjIMAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z'
                    b'-KAWAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5l'
                    b'PfPQQkQkxI862_XjyZLHyClVTLoD')

         # Test with seal SealEvent Only
        msg = messagize(serder, bonds=seal, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BBv-HBW6BBVAAB7InYiOiJLRVJJMTBKU09OMDAwMGZkXyIsInQiOiJpY3AiLCJk'
                    b'IjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhsNEYi'
                    b'LCJpIjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhs'
                    b'NEYiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-TAXDAvCLRr5luWmp7keDvDuLP0kIqcy'
                    b'BYq79b3Dho1QvrjIMAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        # Test with SealLast and Sigers
        # create SealLast for endorsers est evt whose keys use to sign
        source = SealLast(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI')
        seal = SealLast(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI')

        msg = messagize(serder, sigers=sigers, source=source, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BB6-HBW6BBVAAB7InYiOiJLRVJJMTBKU09OMDAwMGZkXyIsInQiOiJpY3AiLCJk'
                    b'IjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhsNEYi'
                    b'LCJpIjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhs'
                    b'NEYiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-YAiDAvCLRr5luWmp7keDvDuLP0kIqcy'
                    b'BYq79b3Dho1QvrjI-KAWAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdD'
                    b'N_GG84x_NA1rSc5lPfPQQkQkxI862_XjyZLHyClVTLoD')

        # Test with seal SealLast only
        msg = messagize(serder, bonds=seal, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BBj-HBW6BBVAAB7InYiOiJLRVJJMTBKU09OMDAwMGZkXyIsInQiOiJpY3AiLCJk'
                    b'IjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhsNEYi'
                    b'LCJpIjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhs'
                    b'NEYiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-UALDAvCLRr5luWmp7keDvDuLP0kIqcy'
                    b'BYq79b3Dho1QvrjI')

        # test with seal SealSource only
        seal = SealSource(s='0',
                          d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        msg = messagize(serder, bonds=seal, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BBk-HBW6BBVAAB7InYiOiJLRVJJMTBKU09OMDAwMGZkXyIsInQiOiJpY3AiLCJk'
                    b'IjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhsNEYi'
                    b'LCJpIjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhs'
                    b'NEYiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-SAMMAAAEMuNWHss_H_kH4cG7Li1jn2D'
                    b'XfrEaqN7zhqTEhkeDZ2z')

        # Test with wigers
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=False, stem="W")
        wigers = mgr.sign(ser=serder.raw, verfers=verfers)  # default indexed True
        assert isinstance(wigers[0], Siger)
        msg = messagize(serder, wigers=wigers, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BBu-HBW6BBVAAB7InYiOiJLRVJJMTBKU09OMDAwMGZkXyIsInQiOiJpY3AiLCJk'
                    b'IjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhsNEYi'
                    b'LCJpIjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhs'
                    b'NEYiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-LAWAABtOhjlKo8WhJQ3EXMIMaQ_IH6y'
                    b'eyxs7_JuO4RioH1NUTtzTuV1bbuB7eoNhEj20VJYa4947ZMVrOxKhzI6EqUH')

        # Test with cigars
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=False, stem="R")
        cigars = mgr.sign(ser=serder.raw, verfers=verfers, indexed=False)
        assert isinstance(cigars[0], Cigar)
        msg = messagize(serder, cigars=cigars, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BB5-HBW6BBVAAB7InYiOiJLRVJJMTBKU09OMDAwMGZkXyIsInQiOiJpY3AiLCJk'
                    b'IjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhsNEYi'
                    b'LCJpIjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhs'
                    b'NEYiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-MAhBJjH1MCDssEZMnORskF34AwOFDgD'
                    b'L47513GivRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31jjtsh'
                    b'cEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with wigers and cigars
        msg = messagize(serder, wigers=wigers, cigars=cigars, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BCQ-HBW6BBVAAB7InYiOiJLRVJJMTBKU09OMDAwMGZkXyIsInQiOiJpY3AiLCJk'
                    b'IjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhsNEYi'
                    b'LCJpIjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhs'
                    b'NEYiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-LAWAABtOhjlKo8WhJQ3EXMIMaQ_IH6y'
                    b'eyxs7_JuO4RioH1NUTtzTuV1bbuB7eoNhEj20VJYa4947ZMVrOxKhzI6EqUH-MAh'
                    b'BJjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDwWrxO8RItpgGFtFiD'
                    b'F7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg'
                    b'_TwF')

        # Test with sigers and wigers and cigars
        msg = messagize(serder, sigers=sigers, cigars=cigars, wigers=wigers,
                        nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BCn-HBW6BBVAAB7InYiOiJLRVJJMTBKU09OMDAwMGZkXyIsInQiOiJpY3AiLCJk'
                    b'IjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhsNEYi'
                    b'LCJpIjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhs'
                    b'NEYiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-KAWAAB1DuEfnZZ6juMZDYiodcWiIqdj'
                    b'uEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfPQQkQkxI862_XjyZLHyClVTLoD-LAW'
                    b'AABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs7_JuO4RioH1NUTtzTuV1bbuB7eoNhEj2'
                    b'0VJYa4947ZMVrOxKhzI6EqUH-MAhBJjH1MCDssEZMnORskF34AwOFDgDL47513Gi'
                    b'vRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUVX'
                    b'2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with sigers and wigers and cigars
        msg = messagize(serder, sigers=sigers, cigars=cigars, wigers=wigers,
                        nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BCn-HBW6BBVAAB7InYiOiJLRVJJMTBKU09OMDAwMGZkXyIsInQiOiJpY3AiLCJk'
                    b'IjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhsNEYi'
                    b'LCJpIjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhs'
                    b'NEYiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-KAWAAB1DuEfnZZ6juMZDYiodcWiIqdj'
                    b'uEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfPQQkQkxI862_XjyZLHyClVTLoD-LAW'
                    b'AABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs7_JuO4RioH1NUTtzTuV1bbuB7eoNhEj2'
                    b'0VJYa4947ZMVrOxKhzI6EqUH-MAhBJjH1MCDssEZMnORskF34AwOFDgDL47513Gi'
                    b'vRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUVX'
                    b'2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with sigers and seal and wigers and cigars
        source = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        msg = messagize(serder, sigers=sigers, source=source, bonds=seal, wigers=wigers,
                        cigars=cigars, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BDX-HBW6BBVAAB7InYiOiJLRVJJMTBKU09OMDAwMGZkXyIsInQiOiJpY3AiLCJk'
                    b'IjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhsNEYi'
                    b'LCJpIjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhs'
                    b'NEYiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-XAuDAvCLRr5luWmp7keDvDuLP0kIqcy'
                    b'BYq79b3Dho1QvrjIMAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z'
                    b'-KAWAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5l'
                    b'PfPQQkQkxI862_XjyZLHyClVTLoD-LAWAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs'
                    b'7_JuO4RioH1NUTtzTuV1bbuB7eoNhEj20VJYa4947ZMVrOxKhzI6EqUH-MAhBJjH'
                    b'1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDwWrxO8RItpgGFtFiDF7Qo'
                    b'Vas-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF'
                    b'-TAXDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_k'
                    b'H4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        # test with multiple seals so collated
        seal0 = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal1 = SealSource(s='1',
                           d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal2 = SealSource(s='2',
                           d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal3 = BlindState(d='EGhjWjnjDTBTQ5uZ-17_nipeMzaCaADNeMBXa8QmmBev',
                                      u='aB3RS8CZP2ds_ZgUyJBuJyim8P8qLRG9wMANIkWPGzev',
                                      td='EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ',
                                      ts='revoked')
        seal4 = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='3',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal5 = BlindState(d='ECVr7QWEp_aqVQuz4yprRFXVxJ-9uWLx_d6oDinlHU6J',
                            u='aG1lSjdJSNl7TiroPl67Uqzd5eFvzmr6bPlL7Lh4ukv8',
                            td='',
                            ts='')
        seal6 = BoundState(d='EFaQ00QW-ZeoMxE9baWcpJbAFXrs5h0ya-wpKnHvMQ0c',
                                      u='aJxtoz6qVeJxPCZvP-qBJifRfIxP3itQBVAAu7JJHxMa',
                                      td='',
                                      ts='',
                                      bn='0',
                                      bd='')
        seal7 = TypeMedia(d='EHYFmR_QWCLz8gZyhc4BQ8xJ-ftZ6OA4fNmuu1ZAvyTE',
                         u='0ABtZWRpYXJyYXdub25jZV8w',
                         mt='application/json',
                         mv='{"name":"Sue","food":"Pizza"}')
        seals = [seal0, seal1, seal2, seal3, seal4, seal5, seal6, seal7]

        msg = messagize(serder, bonds=seals, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BEa-HBW6BBVAAB7InYiOiJLRVJJMTBKU09OMDAwMGZkXyIsInQiOiJpY3AiLCJk'
                    b'IjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhsNEYi'
                    b'LCJpIjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhs'
                    b'NEYiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-TAuDAvCLRr5luWmp7keDvDuLP0kIqcy'
                    b'BYq79b3Dho1QvrjIMAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z'
                    b'DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAADEMuNWHss_H_kH4cG'
                    b'7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-SAYMAABEMuNWHss_H_kH4cG7Li1jn2DXfrE'
                    b'aqN7zhqTEhkeDZ2zMAACEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z'
                    b'-aA7EGhjWjnjDTBTQ5uZ-17_nipeMzaCaADNeMBXa8QmmBevaB3RS8CZP2ds_ZgU'
                    b'yJBuJyim8P8qLRG9wMANIkWPGzevEBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbY'
                    b'GGCUQgqQYrevokedECVr7QWEp_aqVQuz4yprRFXVxJ-9uWLx_d6oDinlHU6JaG1l'
                    b'SjdJSNl7TiroPl67Uqzd5eFvzmr6bPlL7Lh4ukv81AAP1AAP-bAaEFaQ00QW-Zeo'
                    b'MxE9baWcpJbAFXrs5h0ya-wpKnHvMQ0caJxtoz6qVeJxPCZvP-qBJifRfIxP3itQ'
                    b'BVAAu7JJHxMa1AAP1AAPMAAA1AAP-cAjEHYFmR_QWCLz8gZyhc4BQ8xJ-ftZ6OA4'
                    b'fNmuu1ZAvyTE0ABtZWRpYXJyYXdub25jZV8w6BAGAABhcHBsaWNhdGlvbi9qc29u'
                    b'5BAKAHsibmFtZSI6IlN1ZSIsImZvb2QiOiJQaXp6YSJ9')

        # Test receipt message with wigers and/or cigars on prior message
        wigers = mgr.sign(ser=serder.raw, verfers=verfers, indexed=True)
        assert isinstance(wigers[0], Siger)
        cigars = mgr.sign(ser=serder.raw, verfers=verfers, indexed=False)  # sign event not receipt

        serder = receipt(pre=pre,
                           sn=int(ked["s"], 16),
                           said=serder.said,
                           kind=Kinds.json,
                           pvrsn=Vrsn_1_0, version=Vrsn_1_0)

        # test with wigers
        msg = messagize(serder, wigers=wigers, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BBK-HAy6BAxAAB7InYiOiJLRVJJMTBKU09OMDAwMDkxXyIsInQiOiJyY3QiLCJk'
                    b'IjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhsNEYi'
                    b'LCJpIjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhs'
                    b'NEYiLCJzIjoiMCJ9-LAWAADwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31j'
                    b'jtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with cigars
        msg = messagize(serder, cigars=cigars, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BBV-HAy6BAxAAB7InYiOiJLRVJJMTBKU09OMDAwMDkxXyIsInQiOiJyY3QiLCJk'
                    b'IjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhsNEYi'
                    b'LCJpIjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhs'
                    b'NEYiLCJzIjoiMCJ9-MAhBJjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz'
                    b'0BDwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xsyyH1U'
                    b'S2fBWe7FNpn6xko5EVwg_TwF')


        # Test with wigers and cigars
        msg = messagize(serder, wigers=wigers, cigars=cigars, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BBs-HAy6BAxAAB7InYiOiJLRVJJMTBKU09OMDAwMDkxXyIsInQiOiJyY3QiLCJk'
                    b'IjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhsNEYi'
                    b'LCJpIjoiRUZ5enpnMk1wNUEzZWNDaGM2QWhTTFRRc3NCWkFtTnZQbkd4akp5SHhs'
                    b'NEYiLCJzIjoiMCJ9-LAWAADwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31j'
                    b'jtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF-MAhBJjH1MCDssEZMnOR'
                    b'skF34AwOFDgDL47513GivRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xt'
                    b'Ofbsh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF')

        # Test with query message
        serder = query(route="log",
                        query=dict(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI'),
                        stamp=helping.DTS_BASE_0,
                        kind=Kinds.json,
                        pvrsn=Vrsn_1_0)

        # Test with SealLast and framed for endorsers est evt whose keys use to sign
        source = SealLast(i=pre)
        msg = messagize(serder, sigers=sigers, source=source, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BBo-HBE4BBDeyJ2IjoiS0VSSTEwSlNPTjAwMDBjOV8iLCJ0IjoicXJ5IiwiZCI6'
                    b'IkVHTjY4X3NlZWN1elhRTzE1RkZHSkxWd1pDQkNQWVctaHkyOWZqV1dQUWJwIiwi'
                    b'ZHQiOiIyMDIxLTAxLTAxVDAwOjAwOjAwLjAwMDAwMCswMDowMCIsInIiOiJsb2ci'
                    b'LCJyciI6IiIsInEiOnsiaSI6IkRBdkNMUnI1bHVXbXA3a2VEdkR1TFAwa0lxY3lC'
                    b'WXE3OWIzRGhvMVF2cmpJIn19-YAiEFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGx'
                    b'jJyHxl4F-KAWAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_'
                    b'NA1rSc5lPfPQQkQkxI862_XjyZLHyClVTLoD')

        """ Done Test """


def test_messagize_v2_nested():
    """Test messagize utility function with version 2 messages nested in body
    +attach group

    """
    salter = Salter(raw=b'0123456789abcdef')
    with openDB(name="edy") as db, openKS(name="edy") as ks:
        # Init key pair manager
        mgr = Manager(ks=ks, salt=salter.qb64)
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=True, stem="C")

        # Test with inception message
        serder = incept(keys=[verfers[0].qb64], code=MtrDex.Blake3_256,
                        kind=Kinds.json, pvrsn=Vrsn_2_0, version=Vrsn_1_0)

        ked = serder.ked
        pre = serder.pre

        sigers = mgr.sign(ser=serder.raw, verfers=verfers)  # default indexed True
        assert isinstance(sigers[0], Siger)

        # test nested ignores framed and gvrsn
        msg = messagize(serder, sigers=sigers, framed=True, nested=True, gvrsn=Vrsn_1_0)
        assert isinstance(msg, bytearray)
        assert msg == (b'-BBu-HBW4BBVeyJ2IjoiS0VSSUNBQUNBQUpTT05BQURfLiIsInQiOiJpY3AiLCJk'
                    b'IjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlMV1Ui'
                    b'LCJpIjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlM'
                    b'V1UiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-KAWAADdpYFg2ecIl0O7FeUnHN2P_aK-'
                    b'9U_31Hsvt57_duHbLVlG50kep74k6uFccMbXLqxMI0dAMAPDisFFvBcb6qEC')

        # test nested and genusify
        msg = messagize(serder, sigers=sigers, nested=True, genusify=True, gvrsn=Vrsn_1_0)
        assert isinstance(msg, bytearray)
        assert msg == (b'-_AAACAA-BBu-HBW4BBVeyJ2IjoiS0VSSUNBQUNBQUpTT05BQURfLiIsInQiOiJp'
                    b'Y3AiLCJkIjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lR'
                    b'THlMV1UiLCJpIjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2Mz'
                    b'T0lRTHlMV1UiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRr'
                    b'eWtzTWN6NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10s'
                    b'ImJ0IjoiMCIsImIiOltdLCJjIjpbXSwiYSI6W119-KAWAADdpYFg2ecIl0O7FeUn'
                    b'HN2P_aK-9U_31Hsvt57_duHbLVlG50kep74k6uFccMbXLqxMI0dAMAPDisFFvBcb'
                    b'6qEC')

        # Test with source SealEvent and Sigers
        # create SealEvent for endorsers est evt whose keys use to sign
        source = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        msg = messagize(serder, sigers=sigers, source=source, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BCG-HBW4BBVeyJ2IjoiS0VSSUNBQUNBQUpTT05BQURfLiIsInQiOiJpY3AiLCJk'
                    b'IjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlMV1Ui'
                    b'LCJpIjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlM'
                    b'V1UiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-XAuDAvCLRr5luWmp7keDvDuLP0kIqcy'
                    b'BYq79b3Dho1QvrjIMAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z'
                    b'-KAWAADdpYFg2ecIl0O7FeUnHN2P_aK-9U_31Hsvt57_duHbLVlG50kep74k6uFc'
                    b'cMbXLqxMI0dAMAPDisFFvBcb6qEC')

         # Test with seal SealEvent Only
        msg = messagize(serder, bonds=seal, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BBv-HBW4BBVeyJ2IjoiS0VSSUNBQUNBQUpTT05BQURfLiIsInQiOiJpY3AiLCJk'
                    b'IjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlMV1Ui'
                    b'LCJpIjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlM'
                    b'V1UiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-TAXDAvCLRr5luWmp7keDvDuLP0kIqcy'
                    b'BYq79b3Dho1QvrjIMAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        # Test with SealLast and Sigers
        # create SealLast for endorsers est evt whose keys use to sign
        source = SealLast(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI')
        seal = SealLast(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI')

        msg = messagize(serder, sigers=sigers, source=source, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BB6-HBW4BBVeyJ2IjoiS0VSSUNBQUNBQUpTT05BQURfLiIsInQiOiJpY3AiLCJk'
                    b'IjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlMV1Ui'
                    b'LCJpIjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlM'
                    b'V1UiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-YAiDAvCLRr5luWmp7keDvDuLP0kIqcy'
                    b'BYq79b3Dho1QvrjI-KAWAADdpYFg2ecIl0O7FeUnHN2P_aK-9U_31Hsvt57_duHb'
                    b'LVlG50kep74k6uFccMbXLqxMI0dAMAPDisFFvBcb6qEC')

        # Test with SealLast only
        msg = messagize(serder, bonds=seal, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BBj-HBW4BBVeyJ2IjoiS0VSSUNBQUNBQUpTT05BQURfLiIsInQiOiJpY3AiLCJk'
                    b'IjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlMV1Ui'
                    b'LCJpIjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlM'
                    b'V1UiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-UALDAvCLRr5luWmp7keDvDuLP0kIqcy'
                    b'BYq79b3Dho1QvrjI')

        # test with seal SealSource only
        seal = SealSource(s='0',
                          d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        msg = messagize(serder, bonds=seal, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BBk-HBW4BBVeyJ2IjoiS0VSSUNBQUNBQUpTT05BQURfLiIsInQiOiJpY3AiLCJk'
                    b'IjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlMV1Ui'
                    b'LCJpIjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlM'
                    b'V1UiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-SAMMAAAEMuNWHss_H_kH4cG7Li1jn2D'
                    b'XfrEaqN7zhqTEhkeDZ2z')

        # Test with wigers
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=False, stem="W")
        wigers = mgr.sign(ser=serder.raw, verfers=verfers)  # default indexed True
        assert isinstance(wigers[0], Siger)
        msg = messagize(serder, wigers=wigers, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BBu-HBW4BBVeyJ2IjoiS0VSSUNBQUNBQUpTT05BQURfLiIsInQiOiJpY3AiLCJk'
                    b'IjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlMV1Ui'
                    b'LCJpIjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlM'
                    b'V1UiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-LAWAACXlTpe-ZODGKZmovS9GZKkf8k-'
                    b'OsvdBpyVz-YvqIIVrxSH1UjWDaWDlGUWrLBdCJFrCkHGNGseQYrrVYc59BwL')

        # Test with cigars
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=False, stem="R")
        cigars = mgr.sign(ser=serder.raw, verfers=verfers, indexed=False)
        assert isinstance(cigars[0], Cigar)
        msg = messagize(serder, cigars=cigars, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BB5-HBW4BBVeyJ2IjoiS0VSSUNBQUNBQUpTT05BQURfLiIsInQiOiJpY3AiLCJk'
                    b'IjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlMV1Ui'
                    b'LCJpIjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlM'
                    b'V1UiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-MAhBJjH1MCDssEZMnORskF34AwOFDgD'
                    b'L47513GivRvd_QKz0BBnxvPGzvJf8d6hzfDR62RMk0aX0T-MhgqJqgvO4z672OO2'
                    b'RDC3t_b__1HuqAIG1kTGrkhpBDyuOpknkW-xYkcG')

        # Test with wigers and cigars
        msg = messagize(serder, wigers=wigers, cigars=cigars, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BCQ-HBW4BBVeyJ2IjoiS0VSSUNBQUNBQUpTT05BQURfLiIsInQiOiJpY3AiLCJk'
                    b'IjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlMV1Ui'
                    b'LCJpIjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlM'
                    b'V1UiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-LAWAACXlTpe-ZODGKZmovS9GZKkf8k-'
                    b'OsvdBpyVz-YvqIIVrxSH1UjWDaWDlGUWrLBdCJFrCkHGNGseQYrrVYc59BwL-MAh'
                    b'BJjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BBnxvPGzvJf8d6hzfDR'
                    b'62RMk0aX0T-MhgqJqgvO4z672OO2RDC3t_b__1HuqAIG1kTGrkhpBDyuOpknkW-x'
                    b'YkcG')

        # Test with sigers and wigers and cigars
        msg = messagize(serder, sigers=sigers, cigars=cigars, wigers=wigers,
                        nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BCn-HBW4BBVeyJ2IjoiS0VSSUNBQUNBQUpTT05BQURfLiIsInQiOiJpY3AiLCJk'
                    b'IjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlMV1Ui'
                    b'LCJpIjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlM'
                    b'V1UiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-KAWAADdpYFg2ecIl0O7FeUnHN2P_aK-'
                    b'9U_31Hsvt57_duHbLVlG50kep74k6uFccMbXLqxMI0dAMAPDisFFvBcb6qEC-LAW'
                    b'AACXlTpe-ZODGKZmovS9GZKkf8k-OsvdBpyVz-YvqIIVrxSH1UjWDaWDlGUWrLBd'
                    b'CJFrCkHGNGseQYrrVYc59BwL-MAhBJjH1MCDssEZMnORskF34AwOFDgDL47513Gi'
                    b'vRvd_QKz0BBnxvPGzvJf8d6hzfDR62RMk0aX0T-MhgqJqgvO4z672OO2RDC3t_b_'
                    b'_1HuqAIG1kTGrkhpBDyuOpknkW-xYkcG')

        # Test with sigers and wigers and cigars
        msg = messagize(serder, sigers=sigers, cigars=cigars, wigers=wigers,
                        nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BCn-HBW4BBVeyJ2IjoiS0VSSUNBQUNBQUpTT05BQURfLiIsInQiOiJpY3AiLCJk'
                    b'IjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlMV1Ui'
                    b'LCJpIjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlM'
                    b'V1UiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-KAWAADdpYFg2ecIl0O7FeUnHN2P_aK-'
                    b'9U_31Hsvt57_duHbLVlG50kep74k6uFccMbXLqxMI0dAMAPDisFFvBcb6qEC-LAW'
                    b'AACXlTpe-ZODGKZmovS9GZKkf8k-OsvdBpyVz-YvqIIVrxSH1UjWDaWDlGUWrLBd'
                    b'CJFrCkHGNGseQYrrVYc59BwL-MAhBJjH1MCDssEZMnORskF34AwOFDgDL47513Gi'
                    b'vRvd_QKz0BBnxvPGzvJf8d6hzfDR62RMk0aX0T-MhgqJqgvO4z672OO2RDC3t_b_'
                    b'_1HuqAIG1kTGrkhpBDyuOpknkW-xYkcG')

        # Test with sigers and seal and wigers and cigars
        source = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        msg = messagize(serder, sigers=sigers, source=source, bonds=seal, wigers=wigers,
                        cigars=cigars, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BDX-HBW4BBVeyJ2IjoiS0VSSUNBQUNBQUpTT05BQURfLiIsInQiOiJpY3AiLCJk'
                    b'IjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlMV1Ui'
                    b'LCJpIjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlM'
                    b'V1UiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-XAuDAvCLRr5luWmp7keDvDuLP0kIqcy'
                    b'BYq79b3Dho1QvrjIMAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z'
                    b'-KAWAADdpYFg2ecIl0O7FeUnHN2P_aK-9U_31Hsvt57_duHbLVlG50kep74k6uFc'
                    b'cMbXLqxMI0dAMAPDisFFvBcb6qEC-LAWAACXlTpe-ZODGKZmovS9GZKkf8k-Osvd'
                    b'BpyVz-YvqIIVrxSH1UjWDaWDlGUWrLBdCJFrCkHGNGseQYrrVYc59BwL-MAhBJjH'
                    b'1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BBnxvPGzvJf8d6hzfDR62RM'
                    b'k0aX0T-MhgqJqgvO4z672OO2RDC3t_b__1HuqAIG1kTGrkhpBDyuOpknkW-xYkcG'
                    b'-TAXDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_k'
                    b'H4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        # test with multiple seals so collated
        seal0 = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal1 = SealSource(s='1',
                           d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal2 = SealSource(s='2',
                           d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal3 = BlindState(d='EGhjWjnjDTBTQ5uZ-17_nipeMzaCaADNeMBXa8QmmBev',
                                      u='aB3RS8CZP2ds_ZgUyJBuJyim8P8qLRG9wMANIkWPGzev',
                                      td='EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ',
                                      ts='revoked')
        seal4 = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='3',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal5 = BlindState(d='ECVr7QWEp_aqVQuz4yprRFXVxJ-9uWLx_d6oDinlHU6J',
                            u='aG1lSjdJSNl7TiroPl67Uqzd5eFvzmr6bPlL7Lh4ukv8',
                            td='',
                            ts='')
        seal6 = BoundState(d='EFaQ00QW-ZeoMxE9baWcpJbAFXrs5h0ya-wpKnHvMQ0c',
                                      u='aJxtoz6qVeJxPCZvP-qBJifRfIxP3itQBVAAu7JJHxMa',
                                      td='',
                                      ts='',
                                      bn='0',
                                      bd='')
        seal7 = TypeMedia(d='EHYFmR_QWCLz8gZyhc4BQ8xJ-ftZ6OA4fNmuu1ZAvyTE',
                         u='0ABtZWRpYXJyYXdub25jZV8w',
                         mt='application/json',
                         mv='{"name":"Sue","food":"Pizza"}')
        seals = [seal0, seal1, seal2, seal3, seal4, seal5, seal6, seal7]

        msg = messagize(serder, bonds=seals, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BEa-HBW4BBVeyJ2IjoiS0VSSUNBQUNBQUpTT05BQURfLiIsInQiOiJpY3AiLCJk'
                    b'IjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlMV1Ui'
                    b'LCJpIjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlM'
                    b'V1UiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-TAuDAvCLRr5luWmp7keDvDuLP0kIqcy'
                    b'BYq79b3Dho1QvrjIMAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z'
                    b'DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAADEMuNWHss_H_kH4cG'
                    b'7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-SAYMAABEMuNWHss_H_kH4cG7Li1jn2DXfrE'
                    b'aqN7zhqTEhkeDZ2zMAACEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z'
                    b'-aA7EGhjWjnjDTBTQ5uZ-17_nipeMzaCaADNeMBXa8QmmBevaB3RS8CZP2ds_ZgU'
                    b'yJBuJyim8P8qLRG9wMANIkWPGzevEBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbY'
                    b'GGCUQgqQYrevokedECVr7QWEp_aqVQuz4yprRFXVxJ-9uWLx_d6oDinlHU6JaG1l'
                    b'SjdJSNl7TiroPl67Uqzd5eFvzmr6bPlL7Lh4ukv81AAP1AAP-bAaEFaQ00QW-Zeo'
                    b'MxE9baWcpJbAFXrs5h0ya-wpKnHvMQ0caJxtoz6qVeJxPCZvP-qBJifRfIxP3itQ'
                    b'BVAAu7JJHxMa1AAP1AAPMAAA1AAP-cAjEHYFmR_QWCLz8gZyhc4BQ8xJ-ftZ6OA4'
                    b'fNmuu1ZAvyTE0ABtZWRpYXJyYXdub25jZV8w6BAGAABhcHBsaWNhdGlvbi9qc29u'
                    b'5BAKAHsibmFtZSI6IlN1ZSIsImZvb2QiOiJQaXp6YSJ9')

        # Test receipt message with wigers and/or cigars on prior message
        wigers = mgr.sign(ser=serder.raw, verfers=verfers, indexed=True)
        assert isinstance(wigers[0], Siger)
        cigars = mgr.sign(ser=serder.raw, verfers=verfers, indexed=False)  # sign event not receipt

        serder = receipt(pre=pre,
                           sn=int(ked["s"], 16),
                           said=serder.said,
                           kind=Kinds.json,
                           pvrsn=Vrsn_2_0, version=Vrsn_1_0)

        # test with wigers
        msg = messagize(serder, wigers=wigers, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BBK-HAy4BAxeyJ2IjoiS0VSSUNBQUNBQUpTT05BQUNULiIsInQiOiJyY3QiLCJk'
                    b'IjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlMV1Ui'
                    b'LCJpIjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlM'
                    b'V1UiLCJzIjoiMCJ9-LAWAABnxvPGzvJf8d6hzfDR62RMk0aX0T-MhgqJqgvO4z67'
                    b'2OO2RDC3t_b__1HuqAIG1kTGrkhpBDyuOpknkW-xYkcG')

        # Test with cigars
        msg = messagize(serder, cigars=cigars, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BBV-HAy4BAxeyJ2IjoiS0VSSUNBQUNBQUpTT05BQUNULiIsInQiOiJyY3QiLCJk'
                    b'IjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlMV1Ui'
                    b'LCJpIjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlM'
                    b'V1UiLCJzIjoiMCJ9-MAhBJjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz'
                    b'0BBnxvPGzvJf8d6hzfDR62RMk0aX0T-MhgqJqgvO4z672OO2RDC3t_b__1HuqAIG'
                    b'1kTGrkhpBDyuOpknkW-xYkcG')

        # Test with wigers and cigars
        msg = messagize(serder, wigers=wigers, cigars=cigars, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BBs-HAy4BAxeyJ2IjoiS0VSSUNBQUNBQUpTT05BQUNULiIsInQiOiJyY3QiLCJk'
                    b'IjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlMV1Ui'
                    b'LCJpIjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlM'
                    b'V1UiLCJzIjoiMCJ9-LAWAABnxvPGzvJf8d6hzfDR62RMk0aX0T-MhgqJqgvO4z67'
                    b'2OO2RDC3t_b__1HuqAIG1kTGrkhpBDyuOpknkW-xYkcG-MAhBJjH1MCDssEZMnOR'
                    b'skF34AwOFDgDL47513GivRvd_QKz0BBnxvPGzvJf8d6hzfDR62RMk0aX0T-MhgqJ'
                    b'qgvO4z672OO2RDC3t_b__1HuqAIG1kTGrkhpBDyuOpknkW-xYkcG')

        # Test with query message
        serder = query(pre=pre,
                       route="log",
                        query=dict(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI'),
                        stamp=helping.DTS_BASE_0,
                        kind=Kinds.json,
                        pvrsn=Vrsn_2_0)

        # Test with SealLast and framed for endorsers est evt whose keys use to sign
        source = SealLast(i=pre)
        msg = messagize(serder, sigers=sigers, source=source, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BB6-HBW5BBVAHsidiI6IktFUklDQUFDQUFKU09OQUFELS4iLCJ0IjoicXJ5Iiwi'
                    b'ZCI6IkVKaGI1ckNBS3Q1eF9LVXVoWlZmbGU3bkRON0J2MFpFeHplejYzbEhadTN5'
                    b'IiwiaSI6IkVDdEd6WEJEaFlBT2RLZVFjVGdCcjRhZ3F5MDZJTjdqYUtjM09JUUx5'
                    b'TFdVIiwiZHQiOiIyMDIxLTAxLTAxVDAwOjAwOjAwLjAwMDAwMCswMDowMCIsInIi'
                    b'OiJsb2ciLCJyciI6IiIsInEiOnsiaSI6IkRBdkNMUnI1bHVXbXA3a2VEdkR1TFAw'
                    b'a0lxY3lCWXE3OWIzRGhvMVF2cmpJIn19-YAiECtGzXBDhYAOdKeQcTgBr4agqy06'
                    b'IN7jaKc3OIQLyLWU-KAWAADdpYFg2ecIl0O7FeUnHN2P_aK-9U_31Hsvt57_duHb'
                    b'LVlG50kep74k6uFccMbXLqxMI0dAMAPDisFFvBcb6qEC')

        """ Done Test """


def test_messagize_v2_native_nested():
    """Test messagize utility function with version 2 messages in native CESR
    nested in body+attach group

    """
    salter = Salter(raw=b'0123456789abcdef')
    with openDB(name="edy") as db, openKS(name="edy") as ks:
        # Init key pair manager
        mgr = Manager(ks=ks, salt=salter.qb64)
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=True, stem="C")

        # Test with inception message
        serder = incept(keys=[verfers[0].qb64], code=MtrDex.Blake3_256,
                        kind=Kinds.cesr, pvrsn=Vrsn_2_0, version=Vrsn_1_0)

        ked = serder.ked
        pre = serder.pre

        sigers = mgr.sign(ser=serder.raw, verfers=verfers)  # default indexed True
        assert isinstance(sigers[0], Siger)

        # test nested ignores framed and gvrsn
        msg = messagize(serder, sigers=sigers, framed=True, nested=True, gvrsn=Vrsn_1_0)
        assert isinstance(msg, bytearray)
        assert msg == (b'-BBG-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2'
                    b'NfHnEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif'
                    b'48whAmpb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA'
                    b'-KAWAABfKnU9VdFRGI2pQ2gMotaAB3Q8BxNhLRnrXTrKiyi5qhjQ5YKU4SbDFjVd'
                    b'GoUoN3u5gfn6dHBVwvnBkr96OPwM')

        # test nested and genusify
        msg = messagize(serder, sigers=sigers, nested=True, genusify=True, gvrsn=Vrsn_1_0)
        assert isinstance(msg, bytearray)
        assert msg == (b'-_AAACAA-BBG-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o'
                    b'9PapQ2A2NfHnEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB'
                    b'-JALDOif48whAmpb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA'
                    b'-JAA-JAA-KAWAABfKnU9VdFRGI2pQ2gMotaAB3Q8BxNhLRnrXTrKiyi5qhjQ5YKU'
                    b'4SbDFjVdGoUoN3u5gfn6dHBVwvnBkr96OPwM')

        # Test with source SealEvent and Sigers
        # create SealEvent for endorsers est evt whose keys use to sign
        source = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        msg = messagize(serder, sigers=sigers, source=source, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BBe-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2'
                    b'NfHnEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif'
                    b'48whAmpb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA'
                    b'-XAuDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_k'
                    b'H4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-KAWAABfKnU9VdFRGI2pQ2gMotaAB3Q8'
                    b'BxNhLRnrXTrKiyi5qhjQ5YKU4SbDFjVdGoUoN3u5gfn6dHBVwvnBkr96OPwM')

         # Test with seal SealEvent Only
        msg = messagize(serder, bonds=seal, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BBH-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2'
                    b'NfHnEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif'
                    b'48whAmpb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA'
                    b'-TAXDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_k'
                    b'H4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        # Test with SealLast and Sigers
        # create SealLast for endorsers est evt whose keys use to sign
        source = SealLast(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI')
        seal = SealLast(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI')

        msg = messagize(serder, sigers=sigers, source=source, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BBS-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2'
                    b'NfHnEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif'
                    b'48whAmpb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA'
                    b'-YAiDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI-KAWAABfKnU9VdFR'
                    b'GI2pQ2gMotaAB3Q8BxNhLRnrXTrKiyi5qhjQ5YKU4SbDFjVdGoUoN3u5gfn6dHBV'
                    b'wvnBkr96OPwM')

        # Test with SealLast only
        msg = messagize(serder, bonds=seal, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BA7-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2'
                    b'NfHnEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif'
                    b'48whAmpb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA'
                    b'-UALDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI')

        # test with seal SealSource only
        seal = SealSource(s='0',
                          d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        msg = messagize(serder, bonds=seal, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BA8-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2'
                    b'NfHnEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif'
                    b'48whAmpb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA'
                    b'-SAMMAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        # Test with wigers
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=False, stem="W")
        wigers = mgr.sign(ser=serder.raw, verfers=verfers)  # default indexed True
        assert isinstance(wigers[0], Siger)
        msg = messagize(serder, wigers=wigers, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BBG-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2'
                    b'NfHnEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif'
                    b'48whAmpb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA'
                    b'-LAWAAA704jdZETqR_LNm1gf82PAXEa7qFxza_SEP4Q97wL32P1oItaECL2m9egS'
                    b'KBGeLofMC1tL22Mvz2RICLDUvbsA')

        # Test with cigars
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=False, stem="R")
        cigars = mgr.sign(ser=serder.raw, verfers=verfers, indexed=False)
        assert isinstance(cigars[0], Cigar)
        msg = messagize(serder, cigars=cigars, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BBR-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2'
                    b'NfHnEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif'
                    b'48whAmpb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA'
                    b'-MAhBJjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDB0Tz52RRyT-CF'
                    b'E6zboIEkrJI87RfIltfOiYBZLcrdK2Sk3aCRrg3185PzzR1XGd9asEEG6l3zejhF'
                    b'HaA91O8M')

        # Test with wigers and cigars
        msg = messagize(serder, wigers=wigers, cigars=cigars, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BBo-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2'
                    b'NfHnEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif'
                    b'48whAmpb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA'
                    b'-LAWAAA704jdZETqR_LNm1gf82PAXEa7qFxza_SEP4Q97wL32P1oItaECL2m9egS'
                    b'KBGeLofMC1tL22Mvz2RICLDUvbsA-MAhBJjH1MCDssEZMnORskF34AwOFDgDL475'
                    b'13GivRvd_QKz0BDB0Tz52RRyT-CFE6zboIEkrJI87RfIltfOiYBZLcrdK2Sk3aCR'
                    b'rg3185PzzR1XGd9asEEG6l3zejhFHaA91O8M')

        # Test with sigers and wigers and cigars
        msg = messagize(serder, sigers=sigers, cigars=cigars, wigers=wigers,
                        nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BB_-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2'
                    b'NfHnEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif'
                    b'48whAmpb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA'
                    b'-KAWAABfKnU9VdFRGI2pQ2gMotaAB3Q8BxNhLRnrXTrKiyi5qhjQ5YKU4SbDFjVd'
                    b'GoUoN3u5gfn6dHBVwvnBkr96OPwM-LAWAAA704jdZETqR_LNm1gf82PAXEa7qFxz'
                    b'a_SEP4Q97wL32P1oItaECL2m9egSKBGeLofMC1tL22Mvz2RICLDUvbsA-MAhBJjH'
                    b'1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDB0Tz52RRyT-CFE6zboIEk'
                    b'rJI87RfIltfOiYBZLcrdK2Sk3aCRrg3185PzzR1XGd9asEEG6l3zejhFHaA91O8M')

        # Test with sigers and wigers and cigars
        msg = messagize(serder, sigers=sigers, cigars=cigars, wigers=wigers,
                        nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BB_-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2'
                    b'NfHnEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif'
                    b'48whAmpb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA'
                    b'-KAWAABfKnU9VdFRGI2pQ2gMotaAB3Q8BxNhLRnrXTrKiyi5qhjQ5YKU4SbDFjVd'
                    b'GoUoN3u5gfn6dHBVwvnBkr96OPwM-LAWAAA704jdZETqR_LNm1gf82PAXEa7qFxz'
                    b'a_SEP4Q97wL32P1oItaECL2m9egSKBGeLofMC1tL22Mvz2RICLDUvbsA-MAhBJjH'
                    b'1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDB0Tz52RRyT-CFE6zboIEk'
                    b'rJI87RfIltfOiYBZLcrdK2Sk3aCRrg3185PzzR1XGd9asEEG6l3zejhFHaA91O8M')

        # Test with sigers and seal and wigers and cigars
        source = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        msg = messagize(serder, sigers=sigers, source=source, bonds=seal, wigers=wigers,
                        cigars=cigars, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BCv-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2'
                    b'NfHnEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif'
                    b'48whAmpb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA'
                    b'-XAuDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_k'
                    b'H4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-KAWAABfKnU9VdFRGI2pQ2gMotaAB3Q8'
                    b'BxNhLRnrXTrKiyi5qhjQ5YKU4SbDFjVdGoUoN3u5gfn6dHBVwvnBkr96OPwM-LAW'
                    b'AAA704jdZETqR_LNm1gf82PAXEa7qFxza_SEP4Q97wL32P1oItaECL2m9egSKBGe'
                    b'LofMC1tL22Mvz2RICLDUvbsA-MAhBJjH1MCDssEZMnORskF34AwOFDgDL47513Gi'
                    b'vRvd_QKz0BDB0Tz52RRyT-CFE6zboIEkrJI87RfIltfOiYBZLcrdK2Sk3aCRrg31'
                    b'85PzzR1XGd9asEEG6l3zejhFHaA91O8M-TAXDAvCLRr5luWmp7keDvDuLP0kIqcy'
                    b'BYq79b3Dho1QvrjIMAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')

        # test with multiple seals so collated
        seal0 = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='0',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal1 = SealSource(s='1',
                           d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal2 = SealSource(s='2',
                           d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal3 = BlindState(d='EGhjWjnjDTBTQ5uZ-17_nipeMzaCaADNeMBXa8QmmBev',
                                      u='aB3RS8CZP2ds_ZgUyJBuJyim8P8qLRG9wMANIkWPGzev',
                                      td='EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ',
                                      ts='revoked')
        seal4 = SealEvent(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI',
                         s='3',
                         d='EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z')
        seal5 = BlindState(d='ECVr7QWEp_aqVQuz4yprRFXVxJ-9uWLx_d6oDinlHU6J',
                            u='aG1lSjdJSNl7TiroPl67Uqzd5eFvzmr6bPlL7Lh4ukv8',
                            td='',
                            ts='')
        seal6 = BoundState(d='EFaQ00QW-ZeoMxE9baWcpJbAFXrs5h0ya-wpKnHvMQ0c',
                                      u='aJxtoz6qVeJxPCZvP-qBJifRfIxP3itQBVAAu7JJHxMa',
                                      td='',
                                      ts='',
                                      bn='0',
                                      bd='')
        seal7 = TypeMedia(d='EHYFmR_QWCLz8gZyhc4BQ8xJ-ftZ6OA4fNmuu1ZAvyTE',
                         u='0ABtZWRpYXJyYXdub25jZV8w',
                         mt='application/json',
                         mv='{"name":"Sue","food":"Pizza"}')
        seals = [seal0, seal1, seal2, seal3, seal4, seal5, seal6, seal7]

        msg = messagize(serder, bonds=seals, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BDy-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2'
                    b'NfHnEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif'
                    b'48whAmpb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA'
                    b'-TAuDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjIMAAAEMuNWHss_H_k'
                    b'H4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2zDAvCLRr5luWmp7keDvDuLP0kIqcyBYq7'
                    b'9b3Dho1QvrjIMAADEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-SAY'
                    b'MAABEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2zMAACEMuNWHss_H_k'
                    b'H4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-aA7EGhjWjnjDTBTQ5uZ-17_nipeMzaC'
                    b'aADNeMBXa8QmmBevaB3RS8CZP2ds_ZgUyJBuJyim8P8qLRG9wMANIkWPGzevEBju'
                    b'1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQYrevokedECVr7QWEp_aqVQuz'
                    b'4yprRFXVxJ-9uWLx_d6oDinlHU6JaG1lSjdJSNl7TiroPl67Uqzd5eFvzmr6bPlL'
                    b'7Lh4ukv81AAP1AAP-bAaEFaQ00QW-ZeoMxE9baWcpJbAFXrs5h0ya-wpKnHvMQ0c'
                    b'aJxtoz6qVeJxPCZvP-qBJifRfIxP3itQBVAAu7JJHxMa1AAP1AAPMAAA1AAP-cAj'
                    b'EHYFmR_QWCLz8gZyhc4BQ8xJ-ftZ6OA4fNmuu1ZAvyTE0ABtZWRpYXJyYXdub25j'
                    b'ZV8w6BAGAABhcHBsaWNhdGlvbi9qc29u5BAKAHsibmFtZSI6IlN1ZSIsImZvb2Qi'
                    b'OiJQaXp6YSJ9')

        # Test receipt message with wigers and/or cigars on prior message
        wigers = mgr.sign(ser=serder.raw, verfers=verfers, indexed=True)
        assert isinstance(wigers[0], Siger)
        cigars = mgr.sign(ser=serder.raw, verfers=verfers, indexed=False)  # sign event not receipt

        serder = receipt(pre=pre,
                           sn=int(ked["s"], 16),
                           said=serder.said,
                           kind=Kinds.cesr,
                           pvrsn=Vrsn_2_0, version=Vrsn_1_0)

        # test with wigers
        msg = messagize(serder, wigers=wigers, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BAz-FAb0OKERICAACAAXrctEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2'
                    b'NfHnEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAA-LAWAADB0Tz5'
                    b'2RRyT-CFE6zboIEkrJI87RfIltfOiYBZLcrdK2Sk3aCRrg3185PzzR1XGd9asEEG'
                    b'6l3zejhFHaA91O8M')

        # Test with cigars
        msg = messagize(serder, cigars=cigars, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BA--FAb0OKERICAACAAXrctEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2'
                    b'NfHnEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAA-MAhBJjH1MCD'
                    b'ssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDB0Tz52RRyT-CFE6zboIEkrJI8'
                    b'7RfIltfOiYBZLcrdK2Sk3aCRrg3185PzzR1XGd9asEEG6l3zejhFHaA91O8M')

        # Test with wigers and cigars
        msg = messagize(serder, wigers=wigers, cigars=cigars, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BBV-FAb0OKERICAACAAXrctEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2'
                    b'NfHnEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAA-LAWAADB0Tz5'
                    b'2RRyT-CFE6zboIEkrJI87RfIltfOiYBZLcrdK2Sk3aCRrg3185PzzR1XGd9asEEG'
                    b'6l3zejhFHaA91O8M-MAhBJjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz'
                    b'0BDB0Tz52RRyT-CFE6zboIEkrJI87RfIltfOiYBZLcrdK2Sk3aCRrg3185PzzR1X'
                    b'Gd9asEEG6l3zejhFHaA91O8M')

        # Test with query message
        serder = query(pre=pre,
                       route="log",
                        query=dict(i='DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI'),
                        stamp=helping.DTS_BASE_0,
                        kind=Kinds.cesr,
                        pvrsn=Vrsn_2_0)

        # Test with SealLast and framed for endorsers est evt whose keys use to sign
        source = SealLast(i=pre)
        msg = messagize(serder, sigers=sigers, source=source, nested=True, gvrsn=Vrsn_1_0)
        assert msg == (b'-BBX-FAz0OKERICAACAAXqryEOtc_pUXyVNOyRDMJXTBpFrfEn9e-v56A6RIRVhv'
                    b'4tDEEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn1AAG2021-01-01T0'
                    b'0c00c00d000000p00c004AABAlog4AAA-IAM0J_iDAvCLRr5luWmp7keDvDuLP0k'
                    b'IqcyBYq79b3Dho1QvrjI-YAiEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2'
                    b'NfHn-KAWAABfKnU9VdFRGI2pQ2gMotaAB3Q8BxNhLRnrXTrKiyi5qhjQ5YKU4SbD'
                    b'FjVdGoUoN3u5gfn6dHBVwvnBkr96OPwM')


        """ Done Test """


def test_messagize_v2_native_with_nests():
    """Test messagize utility function with version 2 messages in native CESR
    with nested msg substream attachments

    """
    salter = Salter(raw=b'0123456789abcdef')
    with openDB(name="edy") as db, openKS(name="edy") as ks:
        # Init key pair manager
        mgr = Manager(ks=ks, salt=salter.qb64)
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=True, stem="C")

        # Test with inception message as innie
        serder0 = incept(keys=[verfers[0].qb64], code=MtrDex.Blake3_256,
                        kind=Kinds.cesr, pvrsn=Vrsn_2_0)

        pre0 = serder0.pre
        dig0 = serder0.said

        sigers0 = mgr.sign(ser=serder0.raw, verfers=verfers)  # default indexed True
        assert isinstance(sigers0[0], Siger)

        # test nested forces gvrsn to V2 and uses BodyWithAttachmentGroup
        msg0 = messagize(serder0, sigers=sigers0, nested=True)
        assert isinstance(msg0, bytearray)
        assert msg0 == (b'-BBG-FAu0OKERICAACAAXicpEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2'
                    b'NfHnEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAAAMAAB-JALDOif'
                    b'48whAmpb_4kyksMcz57snMRIuX0bqN1FDe09AlRjMAAA-JAAMAAA-JAA-JAA-JAA'
                    b'-KAWAABfKnU9VdFRGI2pQ2gMotaAB3Q8BxNhLRnrXTrKiyi5qhjQ5YKU4SbDFjVd'
                    b'GoUoN3u5gfn6dHBVwvnBkr96OPwM')


        # Test with inception message as innie
        serder1 = interact(pre=pre0, dig=dig0, kind=Kinds.cesr, pvrsn=Vrsn_2_0)
        sigers1 = mgr.sign(ser=serder1.raw, verfers=verfers)  # default indexed True
        assert isinstance(sigers1[0], Siger)

        # test not framed so uses AttachmentGroup not BodyWithAttachmentGroup
        msg1 = messagize(serder1, sigers=sigers1,framed=False, gvrsn=Vrsn_2_0, )
        assert isinstance(msg1, bytearray)
        assert msg1 == (b'-FAn0OKERICAACAAXixnEPnIYriZ1Yp22y7vkjkLxSCtO5753wO6UGmGp6DE4_qW'
                    b'EP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAABEP8WtjzSzxcEfUQr'
                    b'FQvL542r9-8KZe9o9PapQ2A2NfHn-JAA-CAX-KAWAADpEKBo7AvvhlEmrj7FvUs1'
                    b'Eh2JNpMD0IkGrUAwwDAOAwrFyG1XUjQtALJx8M1j-ZWGhjvEo2BiyP_5a1bwUyEM')


        # now create message using messagize with msg0 and msg1 as nests
        attributes = dict(a=serder0.said, b=serder1.said)
        nonce = '0AB8WKheGX-o1b1SzLaxZr4u'
        dts = '2026-06-24T20:39:40.737875+00:00'  # helping.nowIso8601()
        serder2 = exchept(sender = pre0,
                          receiver = pre0,
                          nonce=nonce,
                          stamp=dts,
                          attributes = attributes,
                          kind=Kinds.cesr,
                          pvrsn=Vrsn_2_0)

        sigers2 = mgr.sign(ser=serder2.raw, verfers=verfers)  # default indexed True
        assert isinstance(sigers2[0], Siger)

        msg2 = messagize(serder2, sigers=sigers2, nests=[msg0, msg1], nested=True)
        assert isinstance(msg2, bytearray)

        assert msg2 == (b'-BDu-FBP0OKERICAACAAXxipEG7fNAXPS9ZsRVaLBiKQKDhKrXAj-jwZAqTv21y6'
                    b'JKKQ0AB8WKheGX-o1b1SzLaxZr4uEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9Pap'
                    b'Q2A2NfHnEP8WtjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHn1AAG2026-06-'
                    b'24T20c39c40d737875p00c004AAA-IAA-IAY0J_aEP8WtjzSzxcEfUQrFQvL542r'
                    b'9-8KZe9o9PapQ2A2NfHn0J_bEPnIYriZ1Yp22y7vkjkLxSCtO5753wO6UGmGp6DE'
                    b'4_qW-KAWAAD1g4mb9KyElx8P-8b1jJU9raMuLQzKCksbUriy7ArulP57iG_gX0ix'
                    b'7J7zinOEqFX2t4h9OcnxbAGjUGw0CZIC-BBG-FAu0OKERICAACAAXicpEP8WtjzS'
                    b'zxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnEP8WtjzSzxcEfUQrFQvL542r9-8K'
                    b'Ze9o9PapQ2A2NfHnMAAAMAAB-JALDOif48whAmpb_4kyksMcz57snMRIuX0bqN1F'
                    b'De09AlRjMAAA-JAAMAAA-JAA-JAA-JAA-KAWAABfKnU9VdFRGI2pQ2gMotaAB3Q8'
                    b'BxNhLRnrXTrKiyi5qhjQ5YKU4SbDFjVdGoUoN3u5gfn6dHBVwvnBkr96OPwM-FAn'
                    b'0OKERICAACAAXixnEPnIYriZ1Yp22y7vkjkLxSCtO5753wO6UGmGp6DE4_qWEP8W'
                    b'tjzSzxcEfUQrFQvL542r9-8KZe9o9PapQ2A2NfHnMAABEP8WtjzSzxcEfUQrFQvL'
                    b'542r9-8KZe9o9PapQ2A2NfHn-JAA-CAX-KAWAADpEKBo7AvvhlEmrj7FvUs1Eh2J'
                    b'NpMD0IkGrUAwwDAOAwrFyG1XUjQtALJx8M1j-ZWGhjvEo2BiyP_5a1bwUyEM')

        """Done Test"""


def test_messagize_v2_json_with_nests():
    """Test messagize utility function with version 2 messages in native CESR
    with nested msg substream attachments

    """
    salter = Salter(raw=b'0123456789abcdef')
    kind = Kinds.json

    with openDB(name="edy") as db, openKS(name="edy") as ks:
        # Init key pair manager
        mgr = Manager(ks=ks, salt=salter.qb64)
        verfers, digers = mgr.incept(icount=1, ncount=0, transferable=True, stem="C")

        # Test with inception message as innie
        serder0 = incept(keys=[verfers[0].qb64], code=MtrDex.Blake3_256,
                        kind=kind, pvrsn=Vrsn_2_0)

        pre0 = serder0.pre
        dig0 = serder0.said

        sigers0 = mgr.sign(ser=serder0.raw, verfers=verfers)  # default indexed True
        assert isinstance(sigers0[0], Siger)

        # test nested forces gvrsn to V2 and uses BodyWithAttachmentGroup
        msg0 = messagize(serder0, sigers=sigers0, nested=True)
        assert isinstance(msg0, bytearray)
        assert msg0 == (b'-BBu-HBW4BBVeyJ2IjoiS0VSSUNBQUNBQUpTT05BQURfLiIsInQiOiJpY3AiLCJk'
                    b'IjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlMV1Ui'
                    b'LCJpIjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0JyNGFncXkwNklON2phS2MzT0lRTHlM'
                    b'V1UiLCJzIjoiMCIsImt0IjoiMSIsImsiOlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6'
                    b'NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoiXSwibnQiOiIwIiwibiI6W10sImJ0Ijoi'
                    b'MCIsImIiOltdLCJjIjpbXSwiYSI6W119-KAWAADdpYFg2ecIl0O7FeUnHN2P_aK-'
                    b'9U_31Hsvt57_duHbLVlG50kep74k6uFccMbXLqxMI0dAMAPDisFFvBcb6qEC')


        # Test with inception message as innie
        serder1 = interact(pre=pre0, dig=dig0, kind=kind, pvrsn=Vrsn_2_0)
        sigers1 = mgr.sign(ser=serder1.raw, verfers=verfers)  # default indexed True
        assert isinstance(sigers1[0], Siger)

        # test not framed so uses AttachmentGroup not BodyWithAttachmentGroup
        msg1 = messagize(serder1, sigers=sigers1,framed=False, gvrsn=Vrsn_2_0, )
        assert isinstance(msg1, bytearray)
        assert msg1 == (b'{"v":"KERICAACAAJSONAADN.","t":"ixn","d":"EOO0xssiJ6P3MLpP86hLGe'
                        b'eG8IAfoT_Rm52_MmIQRVRP","i":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc'
                        b'3OIQLyLWU","s":"1","p":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaKc3OIQL'
                        b'yLWU","a":[]}-CAX-KAWAABCSsGAY7etLuefZ7f8pfn3twCGD38BHF3B1PrduEI'
                        b'qWHFxrHyMl2MLIMhPJMruSlOtM3pvTbWUM2ER5WCHqGQJ')


        # now create message using messagize with msg0 and msg1 as nests
        attributes = dict(a=serder0.said, b=serder1.said)
        nonce = '0AB8WKheGX-o1b1SzLaxZr4u'
        dts = '2026-06-24T20:39:40.737875+00:00'  # helping.nowIso8601()
        serder2 = exchept(sender = pre0,
                          receiver = pre0,
                          nonce=nonce,
                          stamp=dts,
                          attributes = attributes,
                          kind=kind,
                          pvrsn=Vrsn_2_0)

        sigers2 = mgr.sign(ser=serder2.raw, verfers=verfers)  # default indexed True
        assert isinstance(sigers2[0], Siger)

        with pytest.raises(ValueError):  # json is not aligned 24 bit
            msg2 = messagize(serder2, sigers=sigers2, nests=[msg0, msg1], framed=False)


        # test nested to force json to be converted to non-native
        msg1 = messagize(serder1, sigers=sigers1, nested=True, gvrsn=Vrsn_2_0, )
        assert isinstance(msg1, bytearray)
        assert msg1 == (b'-BBe-HBG6BBFAAB7InYiOiJLRVJJQ0FBQ0FBSlNPTkFBRE4uIiwidCI6Iml4biIs'
                    b'ImQiOiJFT08weHNzaUo2UDNNTHBQODZoTEdlZUc4SUFmb1RfUm01Ml9NbUlRUlZS'
                    b'UCIsImkiOiJFQ3RHelhCRGhZQU9kS2VRY1RnQnI0YWdxeTA2SU43amFLYzNPSVFM'
                    b'eUxXVSIsInMiOiIxIiwicCI6IkVDdEd6WEJEaFlBT2RLZVFjVGdCcjRhZ3F5MDZJ'
                    b'TjdqYUtjM09JUUx5TFdVIiwiYSI6W119-KAWAABCSsGAY7etLuefZ7f8pfn3twCG'
                    b'D38BHF3B1PrduEIqWHFxrHyMl2MLIMhPJMruSlOtM3pvTbWUM2ER5WCHqGQJ')


        msg2 = messagize(serder2, sigers=sigers2, nests=[msg0, msg1], framed=False)
        assert isinstance(msg2, bytearray)

        assert msg2 == (b'{"v":"KERICAACAAJSONAAGA.","t":"xip","d":"ECZ9FxiLtkf7sFevUGS15N'
                    b'ONgsGbOe8ybQLlkgzDAXET","u":"0AB8WKheGX-o1b1SzLaxZr4u","i":"ECtG'
                    b'zXBDhYAOdKeQcTgBr4agqy06IN7jaKc3OIQLyLWU","ri":"ECtGzXBDhYAOdKeQ'
                    b'cTgBr4agqy06IN7jaKc3OIQLyLWU","dt":"2026-06-24T20:39:40.737875+0'
                    b'0:00","r":"","q":{},"a":{"a":"ECtGzXBDhYAOdKeQcTgBr4agqy06IN7jaK'
                    b'c3OIQLyLWU","b":"EOO0xssiJ6P3MLpP86hLGeeG8IAfoT_Rm52_MmIQRVRP"}}'
                    b'-CDl-KAWAAAwpw3fOB36R-88UnB8PPjHtT_r_W7Dule_AsjlNjhGyFNhaxM73QL5'
                    b'K6d8ngighdld-JF8mUFmpxN10a4KjpoD-BBu-HBW4BBVeyJ2IjoiS0VSSUNBQUNB'
                    b'QUpTT05BQURfLiIsInQiOiJpY3AiLCJkIjoiRUN0R3pYQkRoWUFPZEtlUWNUZ0Jy'
                    b'NGFncXkwNklON2phS2MzT0lRTHlMV1UiLCJpIjoiRUN0R3pYQkRoWUFPZEtlUWNU'
                    b'Z0JyNGFncXkwNklON2phS2MzT0lRTHlMV1UiLCJzIjoiMCIsImt0IjoiMSIsImsi'
                    b'OlsiRE9pZjQ4d2hBbXBiXzRreWtzTWN6NTdzbk1SSXVYMGJxTjFGRGUwOUFsUmoi'
                    b'XSwibnQiOiIwIiwibiI6W10sImJ0IjoiMCIsImIiOltdLCJjIjpbXSwiYSI6W119'
                    b'-KAWAADdpYFg2ecIl0O7FeUnHN2P_aK-9U_31Hsvt57_duHbLVlG50kep74k6uFc'
                    b'cMbXLqxMI0dAMAPDisFFvBcb6qEC-BBe-HBG6BBFAAB7InYiOiJLRVJJQ0FBQ0FB'
                    b'SlNPTkFBRE4uIiwidCI6Iml4biIsImQiOiJFT08weHNzaUo2UDNNTHBQODZoTEdl'
                    b'ZUc4SUFmb1RfUm01Ml9NbUlRUlZSUCIsImkiOiJFQ3RHelhCRGhZQU9kS2VRY1Rn'
                    b'QnI0YWdxeTA2SU43amFLYzNPSVFMeUxXVSIsInMiOiIxIiwicCI6IkVDdEd6WEJE'
                    b'aFlBT2RLZVFjVGdCcjRhZ3F5MDZJTjdqYUtjM09JUUx5TFdVIiwiYSI6W119-KAW'
                    b'AABCSsGAY7etLuefZ7f8pfn3twCGD38BHF3B1PrduEIqWHFxrHyMl2MLIMhPJMru'
                    b'SlOtM3pvTbWUM2ER5WCHqGQJ')

        """Done Test"""


def test_messagize_with_prior_next():
    """
    Test messagize utility function with prior next modifier on indexed signatures
    """
    pass

    """ Done Test """




if __name__ == "__main__":
    test_messagize_v1()
    test_messagize_v1_mix_v2()
    test_messagize_v2()
    test_messagize_v2_native()
    test_messagize_v1_nested()
    test_messagize_v2_nested()
    test_messagize_v2_native_nested()
    test_messagize_v2_native_with_nests()
    test_messagize_v2_json_with_nests()
    test_messagize_with_prior_next()
