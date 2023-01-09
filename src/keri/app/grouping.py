# -*- encoding: utf-8 -*-
"""
KERI
keri.app.grouping module

module for enveloping and forwarding KERI message
"""
import json
from ordered_set import OrderedSet as oset

from hio import help
from hio.base import doing
from hio.help import decking

from keri import kering
from keri.app import forwarding, delegating, agenting
from keri.core import coring
from keri.core.coring import Number
from keri.db import dbing, basing
from keri.db.dbing import snKey
from keri.help import helping
from keri.peer import exchanging
from keri.vc import proving

logger = help.ogler.getLogger()


class Counselor(doing.DoDoer):

    def __init__(self, hby, **kwa):

        self.hby = hby
        self.postman = forwarding.Postman(hby=hby)
        self.swain = delegating.Boatswain(hby=self.hby)
        self.witDoer = agenting.WitnessReceiptor(hby=self.hby)
        self.witq = agenting.WitnessInquisitor(hby=hby)

        doers = [self.postman, self.swain, self.witq, self.witDoer, doing.doify(self.escrowDo)]

        super(Counselor, self).__init__(doers=doers, **kwa)

    def start(self, prefixer, seqner, saider, mid, smids, rmids=None):
        """ Begin processing of escrowed group multisig identifier

        Escrow identifier for multisigs, witness receipts and delegation anchor

        Parameters:

            prefixer (Prefixer): prefixer of group identifier
            seqner (Seqner): seqner of inception event of group identifier
            saider (Saider): saider of inception event of group identifier
            mid (str): group member (local) identifier prefix qb64
            smids (list): group signing member ids qb64 (multisig group)
                need to contribute current signing key
            rmids (list | None): group rotating member ids qb64 (multisig group)
                need to contribute digest of next rotating key

        """
        evt = getEscrowedEvent(db=self.hby.db, pre=prefixer.qb64, sn=seqner.sn)
        serder = coring.Serder(raw=evt)
        del evt[:serder.size]

        others = list(oset(smids + (rmids or [])))

        others.remove(mid)  # don't send to self

        print(f"Sending multisig event to {len(others)} other participants")
        for recpt in others:
            self.postman.send(src=mid, dest=recpt, topic="multisig", serder=serder, attachment=evt)

        print(f"Waiting for other signatures for {seqner.sn}...")
        return self.hby.db.gpse.add(keys=(prefixer.qb64,), val=(seqner, saider))


    def rotate(self, ghab, smids, *, rmids=None, isith=None, nsith=None,
               toad=None, cuts=None, adds=None, data=None):
        """ Begin processing of escrowed group multisig identifier

        Escrow identifier for multisigs, witness receipts and delegation anchor

        Parameters:
            ghab (Hab): group identifier Hab
            smids (list): group signing member identifier prefixes qb64
                need to contribute newly current signing keys
            rmids (list): group rotating member identifier prefixes qb64
                need to contribute next rotating key digests
            isith (Optional[int,str]) currentsigning threshold as int or str hex
                 or list of str weights
            nsith (Optional[int,str])next signing threshold as int or str hex
                 or list of str weights
            toad (int) or str hex of witness threshold after cuts and adds
            cuts (list) of qb64 pre of witnesses to be removed from witness list
            adds (list) of qb64 pre of witnesses to be added to witness list
            data (list) of dicts of committed data such as seals

        RotateRecord:
            date (str | None):  datetime of rotation
            smids (list): group signing member identifiers qb64
            smsns (list): of group signing member seq num of last est evt as hex str
            rmids (list): group rotating member identifiers qb64
            rmsns (list): of group rotating member seq num of last est evt as hex strs
            sn (str | None ): at or after proposed seq num of group est event as hex str
            isith (str | list | None):  current signing threshold
            nsith (str | list | None):  next signing threshold
            toad (int | None): threshold of accountable duplicity
            cuts (list | None):  list of backers to remove qb64
            adds (list | None):  list of backers to add qb64
            data (list | None): seals in rotation event



        ToDo: NRR
        Add midxs for each group member identifier or just the local member
        for mhab.pre
        Then store these with rotationRecord to be used by .processPartialAidEscrow()

        This code assumes that at the time of this formation of the group
        rotation record, none of the members in either smids or smids has
        yet to rotate to the key state to be used in the group rotation. This
        takes a snapshot vector clock as list of the sequence numbers to ensure
        all members see the same key state for all other members. Rotation must
        therefore use the keystate that that latest est evt is at least +1
        of the sequence number in the vector clock.
        number of members that must have contributed is configuration dependent




        """
        mid = ghab.mhab.pre
        smids = smids if smids is not None else ghab.smids
        rmids = rmids if rmids is not None else ghab.rmids
        both = list(oset(smids + (rmids or [])))

        if mid not in both:
            raise kering.ConfigurationError(f"local identifier {mid} not elected"
                                            f" as member of rotation: {both}")

        if rmids is None:  # default the same for both lists
            rmids = list(smids)

        smsns = []  # vector clock of sns of signing member last est evt
        for mid in smids:
            try:
                skever = ghab.kevers[mid]
            except KeyError as ex:
                logger.error(f"Missing KEL for group singing member={mid}"
                             f" of rotation for group={ghab.pre}.")
                raise kering.MissingAidError(f"Missing KEL for group signing "
                                             f"member={mid} of rotation for"
                                             f" group={ghab.pre}.") from ex
            smsns.append(Number(num=skever.lastEst.s).numh)

        rmsns = []   # vector clock of sn of rotating member lst est evt
        for mid in rmids:
            try:
                rkever = ghab.kevers[mid]
            except KeyError as ex:
                logger.error(f"Missing KEL for group rotating member={mid}"
                             f" of rotation for group={ghab.pre}.")
                raise kering.MissingAidError(f"Missing KEL for group rotating "
                                             f"member={mid} of rotation for"
                                             f" group={ghab.pre}.") from ex
            rmsns.append(Number(num=rkever.lastEst.s).numh)

        gkever = ghab.kever
        rec = basing.RotateRecord(date=helping.nowIso8601(),
                                  smids=smids, smsns=smsns,
                                  rmids=rmids, rmsns=rmsns,
                                  sn=Number(num=gkever.sn+1).numh,
                                  isith=isith, nsith=nsith,
                                  toad=toad, cuts=cuts, adds=adds,
                                  data=data)

        # perform local member rotation and then wait for own witnesses to receipt
        ghab.mhab.rotate()  # rotate own local member hab
        print(f"Rotated local member={ghab.mhab.pre}, waiting for witness receipts")
        self.witDoer.msgs.append(dict(pre=ghab.mhab.pre, sn=ghab.mhab.kever.sn))
        return self.hby.db.glwe.put(keys=(ghab.pre,), val=rec)

    def complete(self, prefixer, seqner, saider=None):
        """ Check for completed multsig protocol for the specific event

        Parameters:
            prefixer (Prefixer): qb64 identifier prefix of event to check
            seqner (Seqner): sequence number of event to check
            saider (Saider): optional digest of event to verify

        Returns:

        """
        csaider = self.hby.db.cgms.get(keys=(prefixer.qb64, seqner.qb64))
        if not csaider:
            return False
        else:
            if saider and (csaider.qb64 != saider.qb64):
                raise kering.ValidationError(f"invalid multisig protocol escrowed event {csaider.qb64}-{saider.qb64}")

        return True

    def escrowDo(self, tymth, tock=1.0):
        """ Process escrows of group multisig identifiers waiting to be compeleted.

        Steps involve:
           1. Sending local event with sig to other participants
           2. Waiting for signature threshold to be met.
           3. If elected and delegated identifier, send complete event to delegator
           4. If delegated, wait for delegator's anchor
           5. If elected, send event to witnesses and collect receipts.
           6. Otherwise, wait for fully receipted event

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value.  Default to 1.0 to slow down processing

        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            self.processEscrows()
            yield 0.5

    def processEscrows(self):
        self.processLocalWitnessEscrow()
        self.processPartialAidEscrow()
        self.processPartialSignedEscrow()
        self.processDelegateEscrow()
        self.processPartialWitnessEscrow()

    def processLocalWitnessEscrow(self):
        """
        Process escrow of group multisig events that do not have a full compliment of receipts
        from witnesses yet.  When receipting is complete, remove from escrow and cue up a message
        that the event is complete.

        """
        for (pre,), rec in self.hby.db.glwe.getItemIter():  # group partial witness escrow
            ghab = self.hby.habs[pre]
            mid = ghab.mhab.pre
            pkever = ghab.mhab.kever
            dgkey = dbing.dgKey(mid, pkever.serder.saidb)

            # Load all the witness receipts we have so far
            wigs = self.hby.db.getWigs(dgkey)
            # should not require all witnesses merely the witness threshold
            if len(wigs) == len(pkever.wits):  # We have all of them, this event is finished
                self.hby.db.glwe.rem(keys=(pre,))

                rot = self.hby.db.cloneEvtMsg(mid, pkever.sn, pkever.serder.said)  # grab latest est evt

                others = list(oset(rec.smids + (rec.rmids or [])))  # others = list(rec.smids)
                others.remove(mid)
                serder = coring.Serder(raw=rot)
                del rot[:serder.size]

                print(f"Sending local rotation event to {len(others)} other participants")
                for recpt in others:
                    self.postman.send(src=mid, dest=recpt, topic="multisig", serder=serder, attachment=rot)

                return self.hby.db.gpae.put(keys=(ghab.pre,), val=rec)

    def processPartialAidEscrow(self):
        """
        Process escrow of group multisig rotate request for missing rotations by
        other participants.  Message processing will send this local controller's
        rotation event to all other participants then this escrow waits for
        rotations from all other participants to return.

         # group partial member aid escrow
        self.gpae = koming.Komer(db=self, subkey='gpae.',
                                 schema=RotateRecord)

        RotateRecord
            sn: int | None  # sequence number of est event
            isith: str | list | None  # current signing threshold
            nsith: str | list | None  # next signing threshold
            toad: int | None  # threshold of accountable duplicity
            cuts: list | None  # list of backers to remove qb64
            adds: list | None  # list of backers to add qb64
            data: list | None  # seals
            date: str | None  # datetime of rotation
            smids: list | None   # group signing member ids
            rmids: list | None = None  # group rotating member ids

        # group member last contribution records keyed by aid of member
        self.gcrs = koming.Komer(db=self, subkey='gcrs.',
                                 schema=ContributeRecord)
        ContributeRecord
            date (str | None):  datetime of rotation
            smids (list): group signing member identifiers qb64
            smsns (list): of group signing member seq nums of last est evt as hex str
            key (str | None): qb64 of signing key contributed by given member if any
            rmids (list): group rotating member identifiers qb64
            rmsns (list): of group rotating member seq nums of last est evt as hex strs
            dig (str | None): qb64 of rotating key digest contributed by given member if any
            sn (str): of last est evt contributed to by member as hex str
            said (str):  # said of last est evt contributed to by member as qb64


        ContributeRecord database for each member of each group hab as keyed by:
        (group hab aid, member aid) records the reference to members est event that
        contributed to last group est evt as well as contributif mkever.lastEsts.s != grec.smsns[i]:
                            raise kering.GroupFormationError(f"Invalid rotation "
                                                             f"state of smid={mid}.")ed key material
        of either both siging key and rotating key dig from contributing member
        est event.

        The logic for required member rotation (i.e. MUST rotate before group event
        can be formed) is as follows:

        A)  IF a given smid in rotate grec.smids was exposed in the previous
                group est evt as indicated by inclusion in its contribute
                mrec.smids if any assuming no keys are recycled.
            THEN given smid must be rotated before its signing key material can be
                contributed to new rotation event.

        This rule makes the conservative assumption that a rotation is always
        considered prophylactic for all smids even if some of them may not have
        been suspected of compromise. A corner case is that a given member smid
        was not also an rmid of the prior group est event so it could be reused
        as a smid in a subsequent group est event. The conservative prophylatic
        assumption is that regardless of any mitigating circumstance that might
        allow its use without rotation, any smid contributed previously cannot be
        re-contributed for any reason without rotation in a subsequent est event for
        the group. In other words a rotation forces all smids to be prophylatically
        rotated.

        This rule also enforces that any current smid that corresponds to a
        prior rmid that has already been exposed as a smid must therefore be
        rotated so that the member est event that is contributing to the
        new group est event is the first time exposure of the digest of the now smid.
        In other words if the rmid was not exposed as a smid in the contrib record
        then its ok to use the rmid without rotating. So checking the smid covers
        all must rotate cases.


        B)  OTHERWISE the current est event for the smid/rmid MUST NOT be rotated.

        This ensures that every member applies the same logic for evaluating the
        key material contribution of every other member. Each MUST evaluate to
        the same condition of either MUST rotate relative to member last est event
        captured by smsns, rmsns in contrib record or MUST NOT rotate.

        There are Two primary MUST not rotate cases:

        1)  A current member smid does not have a contribute record so it has
                yet to contribute in any way to a group est event. Therefore
                is has yet to expose any key material that thereby requires a
                rotation prior to contribution.

        2)  A current member smid signing key material is newly added as key
                material i.e. is not in the prior contrib record as a smid.

            a)  This covers the case of a custodial signing key that
                that never appears as a next rotating key digest.
                Key member is given by smid

            b) This covers the case of an rmid held in reserve that has yet to
                be exposed as a smid in the contrib record. So the reserve does
                not have to rotate prior to contributing in the current rotate
                record but can use its held in reserve key material as is.


        This logic assumes that a given member is not recycling old key material
        for either signing keys or rotating key digests.
        i.e. logic assumes that each member only exposes each rotating key
        one time only and only uses a given signing key up to the next est event.
        I.E. once a signing key has been rotated out it is never rotated back in.

        Use of an HDK or CSPRNG random key generation algorithm ensures that
        keys will not be recycled. If a member does not protect itself against
        key material recycling then recycled keys may have already been exposed
        making them vulnerable to surprise quantum attack or may have been
        otherwise compromised. This logic does not protect against deep recycling
        only that the last use is either appropriate or MUST be rotated before
        being used in the new rotation. Thus it protects against inadvertent reuse
        of the last keys (i.e. stale keys) and assumes that new keys are never
        recycled.

        Failure Cases:

        For MUST and MUST Not rotate case we must ensure everyone captures
        the same est event for the rotating member in the event that a member
        performs a surprise recovery rotation during group rotation formation
        but after the rotate record is captured and if not that everyone fails.

        In all cases, the same failure logic MUST also apply. The rule is all
        must form the same group or no group must be formed.

        We can enforce either zero or one rotations uniformly but not more than
        one.

        What if the rotating member has rotated more than once since the rotate
        record was captured?

        If so then there is a new race condition.

        We can say that if they have rotated more than once in the short time
        frame of the formation of a new rotation group then there is a problem
        and therefore the formation should fail, in order to prevent the race
        condition.

        Note this is a different race condition than the member rotating only
        once to recover control during the formation process. The MUST rotate
        rules will work if there is only one rotation for a MUST rotate for any
        reason either because of the group rotation or serendipidously for a
        recovery rotation at the same time.

        This means then that we need a hard test that the sn of the MUST rotate set
        must be exactly 1 greater than the sn captured in the rotate record.
        We must check the sn of the latest establishment event not the latest event.
        The sn of the last Est Evt must be 1 greater. The rotate record captures
        the sequence number of the last Est Evt.  By capturing the sn of the last
        est event we can allow there to be interaction events in the KELs of
        members and therefore we do not have to enforce EO (Establishment Only)
        config trait on member KELs.

        Likewise we have the case where the member of a MUST NOT rotate does a
        rotation to recover from a compromise after the rotate record if formed.
        We need a hard test for a MUST NOT rotate which is the sn of the last
        est event MUST equal the sn in the rotate record.
        Otherwise the group rotation formation must fail in order to prevent
        a race condition. This means that the MUST NOT rotate set will fail if
        any of them must perform a recovery rotation during group formation.

        In general on a likelihood frequency basis:

        Members in the MUST NOT rotate set are contributing largely unexposed
        key material that is less likely to have become compromised during group
        formation.

        (the one exception is a group member that has been rotated out and
        rotated back in and its current signing key material may not have been
        used in the group but may have been used otherwise for some time. This
        is only signing key material not next key material that has not been
        exposed).

        Nonetheless, typically its less likely that a MUST NOT member will need
        to perform a recovery rotation during rotation group formation.

        Whereas members in the MUST rotate set in all cases are contributing
        already exposed key material. So the likelihood of a compromise during
        group rotation formation needing a recover rotation during group formation
        is higher. So the current rules avoid group formation failure if one
        rotation happens during formation for MUST rotate members but not
        two or more. So the trade-off is reasonable.




        # group partial signature escrow
        self.gpse = subing.CatCesrIoSetSuber(db=self, subkey='gpse.',
                                             klas=(coring.Seqner, coring.Saider))



        ToDo: NRR

        Questions:

        How does a participant know it has already been rotated to support the
        rotation event?  I thought we were not requiring the sequence numbers
        to be the same?

        Are we assuming that before this escrow is created some other facility
        rotates the participant so we can assume here that the participant has
        always aready been rotated so that its prior next, current, and next
        are already set up to contribute to the this group rotation event?

        The current code is making an assumption that if the zeroth next key digest
        of the local hab is not found amongst the next key digests of the group hab then
        update the group next digests. If is is found then the current group
        digests is correct.  This seems that not all the participants wil generate
        the same rotation event based on what the key state they each see locally
        for other members?

        When creating Habery.group hab and merfers provided then
        gkever.digers are the provided next digers (migers).
        How are the merfers and migers provided? They are provided via
        the makeGroupHab which is provided with the smids and rmids
        so if rmids is set correctly then the migers is already the correct
        set of next digers. So why are we updating it below??

        Seems like logic is assuming perfect rotation has happended for all
        smids and rmids prior to this escrow being checked, otherwise the actual
        rotation event may not include all the prescribed verfers from the smids
        nor all the prescribed digers from the rmids. The logic should be 100%.
        Either all the prescibed smids verfers are included and all prescribed
        rmid digers are included or it fails.

        If we can assume that all the smids and rmids have already performed their
        inidivual member rotation prior the group rotation being formed then
        there should be no need for this escrow. The troubling question is what
        problem does this escrow solve?



        grec includes the dual indices for current and next for new rotation.
        Need to fix this logic to be for new rotation rules
        need to use both rec.smids and rec.rmids
        both = list(oset(smids + (rmids or []))) because next rotation keys may be
            disjoint from current signing keys and all members must contribute
            either both current signing key and next rotating key digest

        Logic to determine if current local hab kever is ok to use is based on:
        if latest prior est event in database has been exposed as current for the local hab
        if so then the local hab must rotate and the sn must be at least one greater
        if current key was not exposed then the local hab does not need to be rotated and the
        unexposed next key can be reused in the new rotation event.



        """
        # ignore saider of group rotation event in this escrow because it is not
        # not yet formed yet ???

        #
        for (pre,), grec in self.hby.db.gpae.getItemIter():  # group partial member aid escrow
            ghab = self.hby.habs[pre]  # get group hab instanace at group hab id pre
            gkever = ghab.kever  # group hab's Kever instance key state
            verfers = gkever.verfers

            # collect merfers of member verfers whose member satisfies
            # rotation rules relative to their previous contribution.
            # None is placeholder for member who has not yet satisfied rotation
            # rules.
            # member's newly rotated verfers in order to contribute to group event

            merfers = [None] * len(grec.smids)
            for i, mid in enumerate(grec.smids):  # assumes kever or else no rec
                mkever = self.hby.kevers[mid]  # get key state for given member

                # walk member kel to find event if event where member contributed to
                # group est event from which verfers is taken
                if (result := gkever.fetchLatestContribFrom(verfer=mkever.verfers[0])) is None:
                    merfers[i] = mkever.verfers[0]

                else:  # use result here
                    sn, csi, merfer = result  # unpack result
                    if mkever.sn > sn:
                        merfers[i] = mkever.verfers[0]
                    else:
                        continue

            if None in merfers:  # not all members have contributed
                continue


            # contribute diger from each rmid member to group event
            migers = [self.hby.kevers[mid].digers[0] for mid in grec.rmids]

            # use new isith when provided otherwise default to prior isith
            isith = grec.isith if grec.isith is not None else gkever.tholder.sith

            # use new nsith when provided otherwise default to prior nsith
            nsith = grec.nsith if grec.nsith is not None else gkever.ntholder.sith

            # rot is locally signed group multisig rotation event message
            # note actual seq num of group rotation event may be later than proposed
            # because an automatic aync interaction event may have occurred while
            # waiting for the group event to process and Hab.rotate just increments

            rot = ghab.rotate(isith=isith, nsith=nsith,
                              toad=grec.toad, cuts=grec.cuts, adds=grec.adds, data=grec.data,
                              merfers=merfers, migers=migers)
            serder = coring.Serder(raw=rot)
            del rot[:serder.size]  # strip signatures from

            others = list(oset(grec.smids + (grec.rmids or []))) # list(rec.smids)
            others.remove(ghab.mhab.pre)
            print(f"Sending rotation event to {len(others)} other participants")
            for recpt in others:
                self.postman.send(src=ghab.mhab.pre, dest=recpt, topic="multisig",
                                  serder=serder, attachment=rot)

            self.hby.db.gpae.rem((pre,))  # remove rot rec from this escrow

            print("Waiting for other signatures...")
            # change below to put the said in the keys not the val
            # should also fix the delegated escrow as well move to key space
            return self.hby.db.gpse.add(keys=(ghab.pre,),
                                        val=(coring.Seqner(sn=serder.sn),
                                             serder.saider))




    def oldProcessPartialAidEscrow(self):
        """
        See new

        """
        # ignore saider because it is not relevant yet ???
        # wait until the keys state relative to the vector clock element for each
        # member of the group shows that they all have rotated their local member
        # hab before calling a rotate on this local member's instance of the group
        # hab
        for (pre,), rec in self.hby.db.gpae.getItemIter():  # group partial escrow
            ghab = self.hby.habs[pre]  # get group hab instanace at group hab id pre
            gkever = ghab.kever  # group hab's Kever instance key state

            merfers = []  # to be newly current verfers of group signing keys
            migers = list(gkever.digers)  # to be newly next digers of rotation keys
            indices = []  # local member's signers who have already rotated

            for aid in rec.smids:
                idx = ghab.smids.index(aid)  # find index into smids for aid
                pkever = self.hby.kevers[aid]  # given state for given participant
                if pkever.digers[0].qb64 != gkever.digers[idx].qb64:
                    indices.append(idx)
                    merfers.append(pkever.verfers[0])
                    migers[idx] = pkever.digers[0]

            if not gkever.ntholder.satisfy(indices):
                continue

            # if weighted and new weights not provided then use prior weight
            if gkever.tholder.weighted and rec.isith is None:
                isith = [gkever.ntholder.sith[idx] for idx in indices]
            else:
                isith = rec.isith  # use provided new isith

            # use new nsith when provided otherwise default to prior nsith
            nsith = rec.nsith if rec.nsith is not None else gkever.ntholder.sith


            rot = ghab.rotate(isith=isith, nsith=nsith,
                              toad=rec.toad, cuts=rec.cuts, adds=rec.adds, data=rec.data,
                              merfers=merfers, migers=migers)
            serder = coring.Serder(raw=rot)
            del rot[:serder.size]

            others = list(oset(rec.smids + (rec.rmids or []))) # list(rec.smids)
            others.remove(ghab.mhab.pre)
            print(f"Sending rotation event to {len(others)} other participants")
            for recpt in others:
                self.postman.send(src=ghab.mhab.pre, dest=recpt, topic="multisig",
                                  serder=serder, attachment=rot)

            self.hby.db.gpae.rem((pre,))  # remove rot rec from this escrow
            print("Waiting for other signatures...")
            return self.hby.db.gpse.add(keys=(ghab.pre,),
                                        val=(coring.Seqner(sn=serder.sn),
                                             serder.saider))

    def processPartialSignedEscrow(self):
        """
        Process escrow of partially signed multisig group KEL events.  Message
        processing will send this local controllers signature to all other participants
        then this escrow waits for signatures from all other participants

        """
        for (pre,), (seqner, saider) in self.hby.db.gpse.getItemIter():  # group partially signed escrow
            snkey = dbing.snKey(pre, seqner.sn)
            sdig = self.hby.db.getKeLast(key=snkey)
            if sdig:
                sraw = self.hby.db.getEvt(key=dbing.dgKey(pre=pre, dig=bytes(sdig)))

                self.hby.db.gpse.rem(keys=(pre,))
                ghab = self.hby.habs[pre]
                kever = ghab.kever
                keys = [verfer.qb64 for verfer in kever.verfers]
                sigs = self.hby.db.getSigs(dbing.dgKey(pre, bytes(sdig)))
                if not sigs:  # otherwise its a list of sigs
                    continue

                sigers = [coring.Siger(qb64b=bytes(sig)) for sig in sigs]
                windex = min([siger.index for siger in sigers])

                # True if Elected to perform delegation and witnessing
                witered = ghab.mhab.kever.verfers[0].qb64 == keys[windex]

                if kever.delegated and kever.ilk in (coring.Ilks.dip, coring.Ilks.drt):
                    # We are a delegated identifier, must wait for delegator approval for dip and drt
                    if witered:  # We are elected to perform delegation and witnessing messaging
                        print(f"We are the witnesser, sending {pre} to delegator")
                        self.swain.msgs.append(dict(pre=pre, sn=seqner.sn))
                    else:
                        anchor = dict(i=pre, s=seqner.snh, d=saider.qb64)
                        self.witq.query(src=ghab.mhab.pre, pre=kever.delegator, anchor=anchor)

                    print("Waiting for delegation approval...")
                    self.hby.db.gdee.add(keys=(pre,), val=(seqner, saider))
                else:  # Non-delegation, move on to witnessing
                    if witered:  # We are elected witnesser, send off event to witnesses
                        print(f"We are the fully signed witnesser {seqner.sn}, sending to witnesses")
                        self.witDoer.msgs.append(dict(pre=pre, sn=seqner.sn))

                    # Move to escrow waiting for witness receipts
                    print(f"Waiting for fully signed witness receipts for {seqner.sn}")
                    self.hby.db.gpwe.add(keys=(pre,), val=(seqner, saider))

    def processDelegateEscrow(self):
        """
        Process escrow of delegate group multisig identifiers that are
        waiting for delegator approval of a recent establishment event.

        """
        for (pre,), (seqner, saider) in self.hby.db.gdee.getItemIter():  # group delegatee escrow
            anchor = dict(i=pre, s=seqner.snh, d=saider.qb64)
            ghab = self.hby.habs[pre]
            kever = ghab.kevers[pre]

            keys = [verfer.qb64 for verfer in kever.verfers]
            witer = ghab.mhab.kever.verfers[0].qb64 == keys[0]  # We are elected to perform delegation and witnessing

            if serder := self.hby.db.findAnchoringEvent(kever.delegator, anchor=anchor):
                aseq = coring.Seqner(sn=serder.sn)
                couple = aseq.qb64b + serder.saidb
                dgkey = dbing.dgKey(pre, saider.qb64b)
                self.hby.db.setAes(dgkey, couple)  # authorizer event seal (delegator/issuer)
                self.hby.db.gdee.rem(keys=(pre,))
                print(f"Delegation approval for {pre} received.")

                if witer:  # We are elected witnesser, send off event to witnesses
                    print(f"We are the witnesser, sending {pre} to witnesses")
                    self.witDoer.msgs.append(dict(pre=pre, sn=seqner.sn))

                # Move to escrow waiting for witness receipts
                print(f"Waiting for witness receipts for {pre}")
                self.hby.db.gpwe.add(keys=(pre,), val=(seqner, saider))

    def processPartialWitnessEscrow(self):
        """
        Process escrow of group multisig events that do not have a full compliment of receipts
        from witnesses yet.  When receipting is complete, remove from escrow and cue up a message
        that the event is complete.

        """
        for (pre,), (seqner, saider) in self.hby.db.gpwe.getItemIter():  # group partial witness escrow
            kever = self.hby.kevers[pre]
            dgkey = dbing.dgKey(pre, saider.qb64)

            # Load all the witness receipts we have so far
            wigs = self.hby.db.getWigs(dgkey)
            if len(wigs) == len(kever.wits):  # We have all of them, this event is finished
                ghab = self.hby.habs[pre]
                keys = [verfer.qb64 for verfer in kever.verfers]
                witer = ghab.mhab.kever.verfers[0].qb64 == keys[0]
                if witer and len(kever.wits) > 0:
                    witnessed = False
                    for cue in self.witDoer.cues:
                        if cue["pre"] == ghab.pre and cue["sn"] == seqner.sn:
                            witnessed = True
                    if not witnessed:
                        continue
                print(f"Witness receipts complete, {pre} confirmed.")
                self.hby.db.gpwe.rem(keys=(pre,))
                self.hby.db.cgms.put(keys=(pre, seqner.qb64), val=saider)

    def pendingEvents(self, pre):
        """ Return information about any pending events for a given AID

        Parameters:
            pre (str): qb64 identifier of distributed multisig AID

        Returns:
            Prefixer, Saider: prefixer of identifier and saider of the event (if available)

        ToDo: NRR
        sn in rec.sn is now a hex str. How is the event data use the sn. Does
        it merely display or does it do logic on the sn?  Need use to change
        to understand its a hex str not an int.

        Note:
        Actual seq num of group rotation event may be later than proposed in
        RotationRecord, rec because an automatic async interaction event may
        have occurred while waiting for the group event to process and
        Hab.rotate just increments whatever is latest sn

        """
        key = (pre,)
        evts = []
        if (rec := self.hby.db.gpae.get(keys=key)) is not None:  # RotateRecord
            data = dict(
                aids=rec.smids,
                sn=rec.sn,
                isith=rec.isith,
                nsith=rec.nsith,
                timestamp=rec.date,
                toad=rec.toad,
                cuts=rec.cuts,
                adds=rec.adds,
                data=rec.data
            )
            evts.append(data)

        if (rec := self.hby.db.glwe.get(keys=key)) is not None:  # RotateRecord
            data = dict(
                aids=rec.smids,
                sn=rec.sn,
                isith=rec.isith,
                nsith=rec.nsith,
                timestamp=rec.date,
                toad=rec.toad,
                cuts=rec.cuts,
                adds=rec.adds,
                data=rec.data
            )
            evts.append(data)

        return evts


def loadHandlers(hby, exc, notifier):
    """ Load handlers for the peer-to-peer distributed group multisig protocol

    Parameters:
        hby (Habery): Database and keystore for environment
        exc (Exchanger): Peer-to-peer message router
        notifier (Notifier): Database for storing mailbox messages

    """
    incept = MultisigInceptHandler(hby=hby, notifier=notifier)
    exc.addHandler(incept)
    rotate = MultisigRotateHandler(hby=hby, notifier=notifier)
    exc.addHandler(rotate)
    interact = MultisigInteractHandler(hby=hby, notifier=notifier)
    exc.addHandler(interact)
    issue = MultisigIssueHandler(notifier=notifier)
    exc.addHandler(issue)


class MultisigInceptHandler(doing.DoDoer):
    """
    Handler for multisig group inception notification EXN messages

    """
    resource = "/multisig/icp"
    persist = True

    def __init__(self, hby, notifier, **kwa):
        """

        Parameters:
            mbx (Mailboxer) of format str names accepted for offers
            cues (decking.Deck) of outbound cue messages from handler

        """
        self.hby = hby
        self.notifier = notifier
        self.msgs = decking.Deck()
        self.cues = decking.Deck()

        super(MultisigInceptHandler, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        """

        Handle incoming messages by parsing and verifying the credential and storing it in the wallet

        Parameters:
            payload is dict representing the body of a multisig/incept message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /credential/issue message
            verfers is list of Verfers of the keys used to sign the message

        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.msgs:
                msg = self.msgs.popleft()

                if "pre" not in msg:
                    logger.error(f"invalid incept message, missing pre.  evt: {msg}")
                    continue

                prefixer = msg["pre"]
                if "payload" not in msg:
                    logger.error(f"invalid incept message, missing payload.  evt: {msg}")
                    continue

                pay = msg["payload"]
                if "aids" not in pay or "ked" not in pay:
                    logger.error(f"invalid incept payload, aids and ked are required.  payload: {pay}")
                    continue

                src = prefixer.qb64
                aids = pay["aids"]

                hab = None
                for aid in aids:
                    if aid in self.hby.habs:
                        hab = self.hby.habs[aid]

                if hab is None:
                    logger.error(f"invalid incept message, no local event in aids: {pay}")
                    continue

                if src not in pay["aids"] or src not in hab.kevers:
                    logger.error(f"invalid incept message, source not knows or not part of group.  evt: {msg}")
                    continue

                data = dict(
                    r='/multisig/icp/init',
                    src=src,
                    aids=aids,
                    ked=pay["ked"]
                )
                self.notifier.add(attrs=data)

                yield
            yield


def multisigInceptExn(hab, aids, ked, delegator=None):
    data = dict(
        aids=aids,
        ked=ked
    )

    if delegator is not None:
        data |= dict(delegator=delegator)

    # Create `exn` peer to peer message to notify other participants UI
    exn = exchanging.exchange(route=MultisigInceptHandler.resource, modifiers=dict(),
                              payload=data)
    ims = hab.endorse(serder=exn, last=True, pipelined=False)
    del ims[:exn.size]

    return exn, ims


class MultisigRotateHandler(doing.DoDoer):
    """
    Handler for multisig group inception notification EXN messages

    """
    resource = "/multisig/rot"

    def __init__(self, hby, notifier, **kwa):
        """

        Parameters:
            mbx (Mailboxer) of format str names accepted for offers
            controller (str) qb64 identity prefix of controller
            cues (decking.Deck) of outbound cue messages from handler

        """
        self.hby = hby
        self.notifier = notifier
        self.msgs = decking.Deck()
        self.cues = decking.Deck()

        super(MultisigRotateHandler, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        """ Process incoming notifications for a group rotation

        Handle incoming messages by parsing and verifiying the credential and storing it in the wallet

        Parameters:
            payload is dict representing the body of a multisig/incept message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /credential/issue message
            verfers is list of Verfers of the keys used to sign the message

        ToDo: NRR
        fix to use both ghab.smids and ghab.rmids

        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.msgs:
                msg = self.msgs.popleft()

                if "pre" not in msg:
                    logger.error(f"invalid rotation message, missing pre.  evt: {msg}")
                    continue

                prefixer = msg["pre"]
                if "payload" not in msg:
                    logger.error(f"invalid rotation message, missing payload.  evt: {msg}")
                    continue

                pay = msg["payload"]
                if "aids" not in pay or "gid" not in pay:
                    logger.error(f"invalid rotation payload, aids and gid are required.  payload: {pay}")
                    continue

                src = prefixer.qb64
                aids = pay["aids"]
                gid = pay["gid"]

                ghab = self.hby.habs[gid]
                if ghab is None:
                    logger.error(f"invalid rotate message, not a local group: {pay}")
                    continue

                if src not in ghab.smids or src not in ghab.kevers:
                    logger.error(f"invalid incept message, source not knows or not part of group.  evt: {msg}")
                    continue

                data = dict(
                    r='/multisig/rot',
                    src=src,
                    aids=aids,
                )
                data["i"] = ghab.pre
                data["toad"] = pay["toad"] if "toad" in pay else None
                data["wits"] = pay["wits"] if "wits" in pay else []
                data["adds"] = pay["adds"] if "adds" in pay else []
                data["cuts"] = pay["cuts"] if "cuts" in pay else []
                data["isith"] = pay["isith"] if "isith" in pay else None
                data["data"] = pay["data"] if "data" in pay else None

                self.notifier.add(attrs=data)

                yield

            yield


def multisigRotateExn(ghab, aids, isith, toad, cuts, adds, data):
    exn = exchanging.exchange(route=MultisigRotateHandler.resource, modifiers=dict(),
                              payload=dict(gid=ghab.pre,
                                           aids=aids,
                                           isith=isith,
                                           toad=toad,
                                           cuts=list(cuts),
                                           adds=list(adds),
                                           data=data)
                              )
    ims = ghab.mhab.endorse(serder=exn, last=True, pipelined=False)
    atc = bytearray(ims[exn.size:])

    return exn, atc


class MultisigInteractHandler(doing.DoDoer):
    """
    Handler for multisig group inception notification EXN messages

    """
    resource = "/multisig/ixn"

    def __init__(self, hby, notifier, **kwa):
        """

        Parameters:
            mbx (Mailboxer) of format str names accepted for offers
            cues (decking.Deck) of outbound cue messages from handler

        """
        self.hby = hby
        self.notifier = notifier
        self.msgs = decking.Deck()
        self.cues = decking.Deck()

        super(MultisigInteractHandler, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        """ Process incoming notifications for a group interaction events

        Handle incoming messages by storing a message in the mailbox of the controller

        Parameters:
            payload is dict representing the body of a multisig/ixn message
            pre is qb64 identifier prefix of sender

        ToDo: NRR
        fix to use both ghab.smids and ghab.rmids

        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.msgs:
                msg = self.msgs.popleft()

                if "pre" not in msg:
                    logger.error(f"invalid rotation message, missing pre.  evt: {msg}")
                    continue

                prefixer = msg["pre"]
                if "payload" not in msg:
                    logger.error(f"invalid rotation message, missing payload.  evt: {msg}")
                    continue

                pay = msg["payload"]
                if "aids" not in pay or "gid" not in pay:
                    logger.error(f"invalid rotation payload, aids and gid are required.  payload: {pay}")
                    continue

                src = prefixer.qb64
                aids = pay["aids"]
                gid = pay["gid"]

                ghab = self.hby.habs[gid]
                if ghab is None:
                    logger.error(f"invalid rotate message, not a local group: {pay}")
                    continue

                if src not in ghab.smids or src not in ghab.kevers:
                    logger.error(f"invalid incept message, source not knows or not part of group.  evt: {msg}")
                    continue

                data = dict(
                    r='/multisig/ixn',
                    src=src,
                    gid=gid,
                    aids=aids,
                )
                data["data"] = pay["data"] if "data" in pay else None

                self.notifier.add(data)
                yield
            yield


def multisigInteractExn(ghab, aids, data):
    """ Create a peer to peer message to propose a multisig group interaction event

    Parameters:
        ghab (Hab): group Hab to endorse the message
        aids (list): qb64 identifier prefixes to include in the interaction event
        data (list): data to anchor in the interaction event

    Returns:
        Serder: Serder of exn message to send
        butearray: attachment signatures
    """

    exn = exchanging.exchange(route=MultisigInteractHandler.resource, modifiers=dict(),
                              payload=dict(gid=ghab.pre,
                                           aids=aids,
                                           data=data)
                              )
    ims = ghab.mhab.endorse(serder=exn, last=True, pipelined=False)
    atc = bytearray(ims[exn.size:])

    return exn, atc


class MultisigIssueHandler(doing.DoDoer):
    """
    Handler for multisig group issuance notification EXN messages

    """
    resource = "/multisig/issue"

    def __init__(self, notifier, **kwa):
        """

        Parameters:
            mbx (Mailboxer) of format str names accepted for offers
            controller (str) qb64 identity prefix of controller
            cues (decking.Deck) of outbound cue messages from handler

        """
        self.notifier = notifier
        self.msgs = decking.Deck()
        self.cues = decking.Deck()

        super(MultisigIssueHandler, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        """

        Handle incoming messages by parsing and verifiying the credential and storing it in the wallet

        Parameters:
            payload is dict representing the body of a multisig/incept message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /credential/issue message
            verfers is list of Verfers of the keys used to sign the message

        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                pl = msg["payload"]

                try:
                    creder = proving.Creder(ked=pl)
                    data = dict(
                        r="/multisig/issue",
                        ked=creder.ked
                    )

                    self.notifier.add(attrs=data)

                except ValueError as ex:
                    logger.error(f"unable to process multisig credential issue proposal {pl}: {ex}")
                yield
            yield


def multisigIssueExn(hab, creder):
    """ Create a peer to peer message to propose a credential issuance from a multisig group identifier

    Parameters:
        hab (Hab): identifier Hab for ensorsing the message to send
        creder (Creder): Creder instance of the issued credential

    Returns:
        Serder: Serder of exn message to send
        butearray: attachment signatures

    """
    exn = exchanging.exchange(route="/multisig/issue", payload=creder.ked)
    evt = hab.mhab.endorse(serder=exn, last=True, pipelined=False)
    atc = bytearray(evt[exn.size:])

    return exn, atc


def getEscrowedEvent(db, pre, sn):
    key = snKey(pre, sn)
    dig = db.getPseLast(key)
    if dig is None:
        dig = db.getKeLast(key)

    dig = bytes(dig)
    key = dbing.dgKey(pre, dig)  # digest key
    msg = db.getEvt(key)
    serder = coring.Serder(raw=bytes(msg))

    sigs = []
    for sig in db.getSigsIter(key):
        sigs.append(coring.Siger(qb64b=bytes(sig)))

    couple = db.getAes(key)

    msg = bytearray()
    msg.extend(serder.raw)
    msg.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                              count=len(sigs)).qb64b)  # attach cnt
    for sig in sigs:
        msg.extend(sig.qb64b)  # attach sig

    if couple is not None:
        msg.extend(coring.Counter(code=coring.CtrDex.SealSourceCouples,
                                  count=1).qb64b)
        msg.extend(couple)

    return msg
