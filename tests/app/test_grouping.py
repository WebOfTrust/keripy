import json
from contextlib import contextmanager

from keri import kering
from keri.app import grouping, habbing
from keri.core import coring, eventing, parsing
from keri.db import dbing



@contextmanager
def openMutlsig(prefix="test", salt=b'0123456789abcdef', temp=True, **kwa):
    with habbing.openHab(name=f"{prefix}_1", salt=salt, transferable=True, temp=temp) as (hby1, hab1), \
            habbing.openHab(name=f"{prefix}_2", salt=salt, transferable=True, temp=temp) as (hby2, hab2), \
            habbing.openHab(name=f"{prefix}_3", salt=salt, transferable=True, temp=temp) as (hby3, hab3):

        # Keverys so we can process each other's inception messages.
        kev1 = eventing.Kevery(db=hab1.db, lax=False, local=False)
        kev2 = eventing.Kevery(db=hab2.db, lax=False, local=False)
        kev3 = eventing.Kevery(db=hab3.db, lax=False, local=False)

        icp1 = hab1.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp1), kvy=kev2)
        parsing.Parser().parse(ims=bytearray(icp1), kvy=kev3)
        icp2 = hab2.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp2), kvy=kev1)
        parsing.Parser().parse(ims=bytearray(icp2), kvy=kev3)
        icp3 = hab3.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp3), kvy=kev1)
        parsing.Parser().parse(ims=bytearray(icp3), kvy=kev2)

        g1 = grouping.Groupy(hby=hby1)
        g2 = grouping.Groupy(hby=hby2)
        g3 = grouping.Groupy(hby=hby3)

        aids = [hab1.pre, hab2.pre, hab3.pre]
        groupies = [g1, g2, g3]

        imsg = dict(
            op=grouping.Ops.icp,
            aids=aids,
            isith="2",
            nsith="2",
            toad=0
        )

        for idx, groupy in enumerate(groupies):
            try:
                groupy.processMessage(imsg)
            except kering.MissingSignatureError:
                pass

        raw = hab1.db.gpse.getLast(hab1.pre)
        msg = json.loads(raw)
        gid = msg["pre"]
        dig = msg["dig"]

        dgkey = dbing.dgKey(gid, dig)
        eraw = hab1.db.getEvt(dgkey)
        mssrdr = coring.Serder(raw=bytes(eraw))  # escrowed event

        dgkey = dbing.dgKey(mssrdr.preb, mssrdr.saidb)
        sigs = hab1.db.getSigs(dgkey)
        sigs.extend(hab2.db.getSigs(dgkey))
        sigs.extend(hab3.db.getSigs(dgkey))

        sigers = [coring.Siger(qb64b=bytes(sig)) for sig in sigs]

        evt = bytearray(eraw)
        evt.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                  count=len(sigers)).qb64b)  # attach cnt
        for sig in sigs:
            evt.extend(sig)

        parsing.Parser().parse(ims=bytearray(evt), kvy=kev3)
        parsing.Parser().parse(ims=bytearray(evt), kvy=kev2)
        parsing.Parser().parse(ims=bytearray(evt), kvy=kev1)

        g1.processEscrows()
        g2.processEscrows()
        g3.processEscrows()

        yield (hby1, hab1), (hby2, hab2), (hby3, hab3)


# def test_multisig_rotate():
#     with openMutlsig(prefix="test") as ((hby1, hab1), (hby2, hab2), (hby3, hab3)):
#
#         assert hab1.pre == "El5WIVmMSnNIsa3Oqib-g5BNkK8uwKOrFvxxPJ_jM5I8"
#         assert hab2.pre == "ESXQU9TMcdFiuVNRxe6YrbeYlwZJn04UyJUEJxR36Qyw"
#         assert hab3.pre == "EHDoHoAMCI4iRgOjNKYuSLdxsATl9mWCN3HlzOptd2XA"
#
#         gid = "Ea69OZWwWIVBvwX5a-LJjg8VAsc7sTL_OlxBHPdhKjow"
#         group1 = hab1.db.gids.get(hab1.pre)
#         assert group1.gid == gid
#
#         g1 = grouping.Groupy(hby=hby1)
#         g2 = grouping.Groupy(hby=hby2)
#         g3 = grouping.Groupy(hby=hby3)
#
#         aids = [hab1.pre, hab2.pre, hab3.pre]
#         groupies = [g1, g2, g3]
#
#         imsg = dict(
#             pre=hab1.pre,
#             op=grouping.Ops.rot,
#             aids=aids,
#             sith="2",
#             toad=0,
#             data=None
#         )
#
#         for idx, groupy in enumerate(groupies):
#             missing = False
#             try:
#                 groupy.processMessage(imsg)
#             except kering.MissingAidError:
#                 missing = True
#             assert missing is True
#
#         # Keverys so we can process each other's inception messages.
#         kev1 = eventing.Kevery(db=hab1.db, lax=False, local=False)
#         kev2 = eventing.Kevery(db=hab2.db, lax=False, local=False)
#         kev3 = eventing.Kevery(db=hab3.db, lax=False, local=False)
#
#         rot1 = hab1.makeOwnEvent(sn=1)
#         parsing.Parser().parse(ims=bytearray(rot1), kvy=kev2)
#         parsing.Parser().parse(ims=bytearray(rot1), kvy=kev3)
#         rot2 = hab2.makeOwnEvent(sn=1)
#         parsing.Parser().parse(ims=bytearray(rot2), kvy=kev1)
#         parsing.Parser().parse(ims=bytearray(rot2), kvy=kev3)
#         rot3 = hab3.makeOwnEvent(sn=1)
#         parsing.Parser().parse(ims=bytearray(rot3), kvy=kev1)
#         parsing.Parser().parse(ims=bytearray(rot3), kvy=kev2)
#
#         for idx, groupy in enumerate(groupies):
#             try:
#                 groupy.processEscrows()
#             except kering.MissingSignatureError:
#                 pass
#
#         raw = hab1.db.gpse.getLast(hab1.pre)
#         msg = json.loads(raw)
#         gid = msg["pre"]
#         dig = msg["dig"]
#
#         dgkey = dbing.dgKey(gid, dig)
#         eraw = hab1.db.getEvt(dgkey)
#         mssrdr = coring.Serder(raw=bytes(eraw))  # escrowed event
#
#         dgkey = dbing.dgKey(mssrdr.preb, mssrdr.saidb)
#         sigs = hab1.db.getSigs(dgkey)
#         sigs.extend(hab2.db.getSigs(dgkey))
#         sigs.extend(hab3.db.getSigs(dgkey))
#
#         sigers = [coring.Siger(qb64b=bytes(sig)) for sig in sigs]
#
#         evt = bytearray(eraw)
#         evt.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
#                                   count=len(sigers)).qb64b)  # attach cnt
#         for sig in sigs:
#             evt.extend(sig)
#
#         parsing.Parser().parse(ims=bytearray(evt), kvy=kev3)
#         parsing.Parser().parse(ims=bytearray(evt), kvy=kev2)
#         parsing.Parser().parse(ims=bytearray(evt), kvy=kev1)
#
#         g1.processEscrows()
#         g2.processEscrows()
#         g3.processEscrows()
#
#         kever = hab1.kevers[gid]
#         assert kever.sn == 1
#         assert kever.ilk == coring.Ilks.rot


# def test_multisig_interact():
#     with openMutlsig(prefix="test") as ((hby1, hab1), (hby2, hab2), (hby3, hab3)):
#
#         assert hab1.pre == "El5WIVmMSnNIsa3Oqib-g5BNkK8uwKOrFvxxPJ_jM5I8"
#         assert hab2.pre == "ESXQU9TMcdFiuVNRxe6YrbeYlwZJn04UyJUEJxR36Qyw"
#         assert hab3.pre == "EHDoHoAMCI4iRgOjNKYuSLdxsATl9mWCN3HlzOptd2XA"
#
#         gid = "Ea69OZWwWIVBvwX5a-LJjg8VAsc7sTL_OlxBHPdhKjow"
#         group1 = hab1.db.gids.get(hab1.pre)
#         assert group1.gid == gid
#
#         g1 = grouping.Groupy(hby=hby1)
#         g2 = grouping.Groupy(hby=hby2)
#         g3 = grouping.Groupy(hby=hby3)
#
#         groupies = [g1, g2, g3]
#
#         imsg = dict(
#             op=grouping.Ops.ixn,
#             pre=hab1.pre,
#             data=[dict(i="EbyFt3XkAn-bHRWliPdDgrbKdfDonjVUVXcYNaKvE30o", s=0,
#                        d="Ee_RcqtCVGAVPsuHnDxGWAjEm2ooU9iOvaIgKpG8yoSU")]
#         )
#
#         for idx, groupy in enumerate(groupies):
#             missing = False
#             try:
#                 groupy.processMessage(imsg)
#             except kering.MissingSignatureError:
#                 missing = True
#             assert missing is True
#
#         raw = hab1.db.gpse.getLast(hab1.pre)
#         msg = json.loads(raw)
#         gid = msg["pre"]
#         dig = msg["dig"]
#
#         dgkey = dbing.dgKey(gid, dig)
#         eraw = hab1.db.getEvt(dgkey)
#         mssrdr = coring.Serder(raw=bytes(eraw))  # escrowed event
#
#         dgkey = dbing.dgKey(mssrdr.preb, mssrdr.saidb)
#         sigs = hab1.db.getSigs(dgkey)
#         sigs.extend(hab2.db.getSigs(dgkey))
#         sigs.extend(hab3.db.getSigs(dgkey))
#
#         sigers = [coring.Siger(qb64b=bytes(sig)) for sig in sigs]
#
#         evt = bytearray(eraw)
#         evt.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
#                                   count=len(sigers)).qb64b)  # attach cnt
#         for sig in sigs:
#             evt.extend(sig)
#
#         # Keverys so we can process the final message.
#         kev1 = eventing.Kevery(db=hab1.db, lax=False, local=False)
#         kev2 = eventing.Kevery(db=hab2.db, lax=False, local=False)
#         kev3 = eventing.Kevery(db=hab3.db, lax=False, local=False)
#
#         parsing.Parser().parse(ims=bytearray(evt), kvy=kev3)
#         parsing.Parser().parse(ims=bytearray(evt), kvy=kev2)
#         parsing.Parser().parse(ims=bytearray(evt), kvy=kev1)
#
#         g1.processEscrows()
#         g2.processEscrows()
#         g3.processEscrows()
#
#         kever = hab1.kevers[gid]
#         assert kever.sn == 1
#         assert kever.ilk == coring.Ilks.ixn
#         assert kever.serder.ked["a"] == [{'i': 'EbyFt3XkAn-bHRWliPdDgrbKdfDonjVUVXcYNaKvE30o', 's': 0,
#                                           'd': 'Ee_RcqtCVGAVPsuHnDxGWAjEm2ooU9iOvaIgKpG8yoSU'}]
