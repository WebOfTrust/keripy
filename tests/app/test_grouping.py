# -*- encoding: utf-8 -*-
"""
tests.app.grouping module

"""
from contextlib import contextmanager

from keri.app import habbing, grouping
from keri.core import coring, eventing, parsing
from keri.db import dbing


def test_counselor():
    salt = b'0123456789abcdef'
    prefix = "counselor"
    with habbing.openHab(name=f"{prefix}_1", salt=salt, transferable=True) as (hby1, hab1), \
            habbing.openHab(name=f"{prefix}_2", salt=salt, transferable=True) as (hby2, hab2), \
            habbing.openHab(name=f"{prefix}_3", salt=salt, transferable=True) as (hby3, hab3):
        counselor = grouping.Counselor(hby=hby1)

        # Keverys so we can process each other's inception messages.
        kev1 = eventing.Kevery(db=hab1.db, lax=True, local=False)
        kev2 = eventing.Kevery(db=hab2.db, lax=True, local=False)
        kev3 = eventing.Kevery(db=hab3.db, lax=True, local=False)

        icp1 = hab1.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp1), kvy=kev2)
        parsing.Parser().parse(ims=bytearray(icp1), kvy=kev3)
        icp2 = hab2.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp2), kvy=kev1)
        parsing.Parser().parse(ims=bytearray(icp2), kvy=kev3)
        icp3 = hab3.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp3), kvy=kev1)
        parsing.Parser().parse(ims=bytearray(icp3), kvy=kev2)

        aids = [hab1.pre, hab2.pre, hab3.pre]
        inits = dict(aids=aids, isith=2, nsith=2, toad=0, wits=[])

        # Create group hab with init params
        ghab = hby1.makeGroupHab(group=f"{prefix}_group1", phab=hab1, **inits)
        prefixer = coring.Prefixer(qb64=ghab.pre)
        seqner = coring.Seqner(sn=0)
        saider = coring.Saider(qb64=prefixer.qb64)

        # Send to Counselor to post process through escrows
        counselor.start(aids=aids, pid=hab1.pre, prefixer=prefixer, seqner=seqner, saider=saider)
        assert len(counselor.postman.evts) == 2  # Send my event to other participants
        evt = counselor.postman.evts.popleft()
        assert evt["src"] == "ECZu3scaTupuSldutwMqMfZOE8NfDdaSSAbVRBafkD8s"
        assert evt["dest"] == "EkQCb1nY0ySX7hlIkMtmsK0TKuXl3JIB6giFLfVdcBDM"
        assert evt["serder"].raw == ((b'{"v":"KERI10JSON0001e7_","t":"icp","d":"EfFRznBFTCjE6L4Muo0mJ3rPpf-31ytLhe7Z'
                                      b'W5FGLpaY","i":"EfFRznBFTCjE6L4Muo0mJ3rPpf-31ytLhe7ZW5FGLpaY","s":"0","kt":"2'
                                      b'","k":["DRd2QdFHY2ymPlzOwW8o5r5mcbMwwUbkwtoGV7X1on2M","DvhIXMDz2Wz9q4iohJ_hR'
                                      b'tJAbE09z3LxnZSs8Nm6kSww","DRHHGMFBQPicaJqKgGWqDyqmRGMksYx7rs491WwcVqtA"],"nt'
                                      b'":"2","n":["ExKDRQLyYUS3O1xme1pbKenP73WqpbKTMopvUSQFRRSw","E2e7tLvlVlER4kkV3'
                                      b'bw36SN8Gz3fJ-3QR2xadxKyed10","Ekhos3Fx8IfwKdfQrfZ_FicfrYiXmvZodQcHV3KNOSlU"]'
                                      b',"bt":"0","b":[],"c":[],"a":[]}'))
        (seqner, saider) = hby1.db.gpse.getLast(keys=(ghab.pre,))  # Escrowed the event for sigs
        assert seqner.sn == 0
        assert saider.qb64 == "EfFRznBFTCjE6L4Muo0mJ3rPpf-31ytLhe7ZW5FGLpaY"

        # Sith 2 so create second signature to get past the first escrow
        ghab2 = hby2.makeGroupHab(group=f"{prefix}_group2", phab=hab2, **inits)
        evt = grouping.getEscrowedEvent(hab2.db, ghab2.pre, 0)
        assert evt == (b'{"v":"KERI10JSON0001e7_","t":"icp","d":"EfFRznBFTCjE6L4Muo0mJ3rP'
                       b'pf-31ytLhe7ZW5FGLpaY","i":"EfFRznBFTCjE6L4Muo0mJ3rPpf-31ytLhe7ZW'
                       b'5FGLpaY","s":"0","kt":"2","k":["DRd2QdFHY2ymPlzOwW8o5r5mcbMwwUbk'
                       b'wtoGV7X1on2M","DvhIXMDz2Wz9q4iohJ_hRtJAbE09z3LxnZSs8Nm6kSww","DR'
                       b'HHGMFBQPicaJqKgGWqDyqmRGMksYx7rs491WwcVqtA"],"nt":"2","n":["ExKD'
                       b'RQLyYUS3O1xme1pbKenP73WqpbKTMopvUSQFRRSw","E2e7tLvlVlER4kkV3bw36'
                       b'SN8Gz3fJ-3QR2xadxKyed10","Ekhos3Fx8IfwKdfQrfZ_FicfrYiXmvZodQcHV3'
                       b'KNOSlU"],"bt":"0","b":[],"c":[],"a":[]}-AABABnsohpWmpZsqYU-3cMaV'
                       b'NF80vX26VFlwB5hLwVU44MimObNR1jTyupmDFyAt7tLF6P8s_pKk9v4P1B2T_Zd9'
                       b'yBA')

        parsing.Parser().parse(ims=bytearray(evt), kvy=kev1)  # parse second signed group inception
        kev1.processEscrows()  # Run escrows for Kevery1 to process all sigs together

        counselor.processEscrows()
        val = hby1.db.gpse.getLast(keys=(ghab.pre,))  # thold met, partial sig escrow should be empty
        assert val is None
        assert len(counselor.cues) == 1
        cue = counselor.cues.popleft()
        assert cue["kin"] == "complete"
        assert cue["pre"] == ghab.pre
        assert cue["sn"] == 0
        assert cue["said"] == "EfFRznBFTCjE6L4Muo0mJ3rPpf-31ytLhe7ZW5FGLpaY"
        counselor.postman.evts.popleft()  # clear events for next step (rotation)

        # Partial rotation
        aids = [hab1.pre, hab2.pre]
        counselor.rotate(ghab=ghab, aids=aids, sith=2, toad=0, cuts=list(), adds=list())
        rec = hby1.db.glwe.get(keys=(ghab.pre,))
        assert rec is not None
        assert rec.aids == aids
        assert rec.sith == 2
        assert rec.toad == 0

        counselor.processEscrows()  # process escrows to get witness-less event to next step
        rec = hby1.db.glwe.get(keys=(ghab.pre,))
        assert rec is None
        assert len(counselor.postman.evts) == 1
        evt = counselor.postman.evts.popleft()
        assert evt["src"] == hab1.pre
        assert evt["dest"] == hab2.pre
        assert evt["topic"] == "multisig"
        assert evt["serder"].raw == ((b'{"v":"KERI10JSON000160_","t":"rot","d":"EPG0VZ17sGRjhT96p5pM1daK5260sHvszP8F'
                                      b'BXISg6k4","i":"ECZu3scaTupuSldutwMqMfZOE8NfDdaSSAbVRBafkD8s","s":"1","p":"EC'
                                      b'Zu3scaTupuSldutwMqMfZOE8NfDdaSSAbVRBafkD8s","kt":"1","k":["DRvAX3fiblON1BsLX'
                                      b'yNKaTYJw87vHMB6bN4_LgsqcD9Q"],"nt":"1","n":["E1Z3cSbGPkx6_vXMW5ZljeMfQQOGuiK'
                                      b'WCybLiHW4_Qz4"],"bt":"0","br":[],"ba":[],"a":[]}'))
        rec = hby1.db.gpae.get(keys=(ghab.pre,))
        assert rec is not None
        assert rec.aids == aids

        # rotate second identifiter in group, process escrows to generate group rotation event.
        hab2.rotate()
        rot = hab2.makeOwnEvent(sn=1)
        parsing.Parser().parse(ims=bytearray(rot), kvy=kev1)  # parse rotation
        counselor.processEscrows()  # second identifier has rotated, second stage clear
        rec = hby1.db.gpae.get(keys=(ghab.pre,))
        assert rec is None

        # partially signed group rotation
        val = hby1.db.gpse.get(keys=(ghab.pre,))
        (seqner, saider) = val[0]
        assert seqner.sn == 1
        assert saider.qb64b == b'EwEVZQHjYW_jju5RS25q1IMoMT1mci-RIUa0m027h5Oo'
        key = dbing.dgKey(ghab.pre, saider.qb64b)  # digest key
        evt = hby1.db.getEvt(key=key)
        assert bytes(evt) == (
            b'{"v":"KERI10JSON0001ed_","t":"rot","d":"EwEVZQHjYW_jju5RS25q1IMoMT1mci-RIUa0m027h5Oo","i":"EfFRznBFTCjE6L'
            b'4Muo0mJ3rPpf-31ytLhe7ZW5FGLpaY","s":"1","p":"EfFRznBFTCjE6L4Muo0mJ3rPpf-31ytLhe7ZW5FGLpaY","kt":"2","k":['
            b'"DRvAX3fiblON1BsLXyNKaTYJw87vHMB6bN4_LgsqcD9Q","DEv9adSy5j4JsgU2QwTx1gbSUxI21P33chZyaw-hS4QM"],"nt":"2","'
            b'n":["E1Z3cSbGPkx6_vXMW5ZljeMfQQOGuiKWCybLiHW4_Qz4","Efe53her4qjlM6nHh4wtIVODSbf5fFx7ZztYxeGJAgBQ","Ekhos3'
            b'Fx8IfwKdfQrfZ_FicfrYiXmvZodQcHV3KNOSlU"],"bt":"0","br":[],"ba":[],"a":[]}')

        serder = coring.Serder(raw=bytes(evt))
        sigers = hab2.mgr.sign(serder.raw, verfers=hab2.kever.verfers, indexed=True, indices=[1])
        msg = eventing.messagize(serder=serder, sigers=sigers)
        assert msg == (b'{"v":"KERI10JSON0001ed_","t":"rot","d":"EwEVZQHjYW_jju5RS25q1IMo'
                       b'MT1mci-RIUa0m027h5Oo","i":"EfFRznBFTCjE6L4Muo0mJ3rPpf-31ytLhe7ZW'
                       b'5FGLpaY","s":"1","p":"EfFRznBFTCjE6L4Muo0mJ3rPpf-31ytLhe7ZW5FGLp'
                       b'aY","kt":"2","k":["DRvAX3fiblON1BsLXyNKaTYJw87vHMB6bN4_LgsqcD9Q"'
                       b',"DEv9adSy5j4JsgU2QwTx1gbSUxI21P33chZyaw-hS4QM"],"nt":"2","n":["'
                       b'E1Z3cSbGPkx6_vXMW5ZljeMfQQOGuiKWCybLiHW4_Qz4","Efe53her4qjlM6nHh'
                       b'4wtIVODSbf5fFx7ZztYxeGJAgBQ","Ekhos3Fx8IfwKdfQrfZ_FicfrYiXmvZodQ'
                       b'cHV3KNOSlU"],"bt":"0","br":[],"ba":[],"a":[]}-AABAB3b6Crm7YW3yj0'
                       b'njd6ruR35d8GBxiRqUfjHzyMf3NMNA_SR9jAQ9c5RtRXj6mm_33GToDHRNcJIxW3'
                       b'8mF9y7eBQ')

        # Create group rotation from second participany

        parsing.Parser().parse(ims=bytearray(msg), kvy=kev1)  # parse second signed group inception
        kev1.processEscrows()  # Run escrows for Kevery1 so he processes all sigs together

        counselor.processEscrows()
        assert len(counselor.cues) == 1
        cue = counselor.cues.popleft()
        assert cue["kin"] == "complete"
        assert cue["pre"] == ghab.pre
        assert cue["sn"] == 1
        assert cue["said"] == "EwEVZQHjYW_jju5RS25q1IMoMT1mci-RIUa0m027h5Oo"

        # Validate successful partial rotation
        nkeys = [hab1.kever.verfers[0].qb64, hab2.kever.verfers[0].qb64]
        ndigs = [hab1.kever.nexter.digs[0], hab2.kever.nexter.digs[0], hab3.kever.nexter.digs[0]]
        assert ghab.kever.sn == 1
        assert [verfer.qb64 for verfer in ghab.kever.verfers] == nkeys
        assert ghab.kever.nexter.digs == ndigs


@contextmanager
def openMutlsig(prefix="test", salt=b'0123456789abcdef', temp=True, **kwa):
    with habbing.openHab(name=f"{prefix}_1", salt=salt, transferable=True, temp=temp) as (hby1, hab1), \
            habbing.openHab(name=f"{prefix}_2", salt=salt, transferable=True, temp=temp) as (hby2, hab2), \
            habbing.openHab(name=f"{prefix}_3", salt=salt, transferable=True, temp=temp) as (hby3, hab3):
        # Keverys so we can process each other's inception messages.
        kev1 = eventing.Kevery(db=hab1.db, lax=True, local=False)
        kev2 = eventing.Kevery(db=hab2.db, lax=True, local=False)
        kev3 = eventing.Kevery(db=hab3.db, lax=True, local=False)

        icp1 = hab1.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp1), kvy=kev2)
        parsing.Parser().parse(ims=bytearray(icp1), kvy=kev3)
        icp2 = hab2.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp2), kvy=kev1)
        parsing.Parser().parse(ims=bytearray(icp2), kvy=kev3)
        icp3 = hab3.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp3), kvy=kev1)
        parsing.Parser().parse(ims=bytearray(icp3), kvy=kev2)

        aids = [hab1.pre, hab2.pre, hab3.pre]

        inits = dict(
            aids=aids,
            toad=0,
            wits=[],
            isith=3,
            nsith=3
        )

        ghab1 = hby1.makeGroupHab(group=f"{prefix}_group1", phab=hab1, **inits)
        ghab2 = hby2.makeGroupHab(group=f"{prefix}_group2", phab=hab2, **inits)
        ghab3 = hby3.makeGroupHab(group=f"{prefix}_group3", phab=hab3, **inits)

        dgkey = dbing.dgKey(ghab1.pre.encode("utf-8"), ghab1.pre.encode("utf-8"))  # digest key
        eraw = hab1.db.getEvt(dgkey)
        sigs = bytearray()
        sigs.extend(bytes(hab1.db.getSigs(dgkey)[0]))
        sigs.extend(bytes(hab2.db.getSigs(dgkey)[0]))
        sigs.extend(bytes(hab3.db.getSigs(dgkey)[0]))

        evt = bytearray(eraw)
        evt.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                  count=3).qb64b)  # attach cnt
        evt.extend(sigs)

        parsing.Parser().parse(ims=bytearray(evt), kvy=kev3)
        parsing.Parser().parse(ims=bytearray(evt), kvy=kev2)
        parsing.Parser().parse(ims=bytearray(evt), kvy=kev1)

        assert ghab1.pre in kev1.kevers
        assert ghab1.pre in kev2.kevers
        assert ghab1.pre in kev3.kevers

        yield (hby1, ghab1), (hby2, ghab2), (hby3, ghab3)
