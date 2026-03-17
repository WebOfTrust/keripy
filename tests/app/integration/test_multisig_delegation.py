from collections import deque
from contextlib import contextmanager, ExitStack

from hio.base import Doist

from tests.app.integration.app_helpers import (
    openWit, openCtrlWited, HabHelpers,
    MultisigInceptLeader, MultisigInceptFollower,
    MultisigDelegationApprover, KeystateQueryDoer
)

from keri.core import coring


def test_multisig_delegate():
    """
    End-to-end test for multisig delegation workflow.

    This test covers:
    1. A delegator multisig (dgt) formed by two single-sig participants (dgt1, dgt2)
    2. Two delegate participants (del1, del2) who create a delegated multisig (del)
    3. The delegates having OOBId with the delegator multisig
    4. Delegation approvals from both delegator single-sig AID participants
    5. Keystate queries from delegates to discover the delegation approval seal
    6. Generation of an OOBI for the multisig delegate
    7. Resolution of the multisig delegate OOBI by the delegator
    8. Verifications by the delegator about delegate state
    """
    doist = Doist(limit=0.0, tock=0.03125, real=True)

    # Salts for deterministic key generation
    DGT1_SALT = b'0ABaQTNARS1U1u7VhP0mnEK1'
    DGT2_SALT = b'0ABaQTNARS1U1u7VhP0mnEK2'
    DEL1_SALT = b'0AAB_Fidf5WeZf6VFc53IxV1'
    DEL2_SALT = b'0AAB_Fidf5WeZf6VFc53IxV2'

    # Use ExitStack to open all contexts and flatten nesting
    with ExitStack() as stack:
        # Witness
        wit_ctx = stack.enter_context(openWit(name='wan', tcpPort=6632, httpPort=6642))
        # delegator contexts - dgt1, dgt2
        dgt1_ctx = stack.enter_context(openCtrlWited(name='dgt1', salt=DGT1_SALT))
        dgt2_ctx = stack.enter_context(openCtrlWited(name='dgt2', salt=DGT2_SALT))
        # delegate contexts - del1, del2
        del1_ctx = stack.enter_context(openCtrlWited(name='del1', salt=DEL1_SALT))
        del2_ctx = stack.enter_context(openCtrlWited(name='del2', salt=DEL2_SALT))

        # Enter all doers into the Doist
        wit_deeds: deque = doist.enter(doers=wit_ctx.doers)
        dgt1_deeds: deque = doist.enter(doers=dgt1_ctx.doers)
        dgt2_deeds: deque = doist.enter(doers=dgt2_ctx.doers)
        del1_deeds: deque = doist.enter(doers=del1_ctx.doers)
        del2_deeds: deque = doist.enter(doers=del2_ctx.doers)
        all_deeds = wit_deeds + dgt1_deeds + dgt2_deeds + del1_deeds + del2_deeds

        # Resolve witness OOBIs for all participants - rather than have witness OOBI in "iurls" in config
        for ctx, name in [
            (dgt1_ctx, 'dgt1'),
            (dgt2_ctx, 'dgt2'),
            (del1_ctx, 'del1'),
            (del2_ctx, 'del2')]:
            HabHelpers.resolveOobi(doist, wit_deeds, ctx.hby, wit_ctx.oobi, alias='wan')
            print(f"  {name} resolved witness OOBI", flush=True)

        # Create single sig AIDs for delegator participants (dgt1, dgt2)
        # dgt1 init + incept
        dgt1_hab = dgt1_ctx.hby.makeHab(name='dgt1', isith='1', icount=1, toad=1,
                                        wits=[wit_ctx.pre])
        HabHelpers.collectWitnessReceipts(doist, all_deeds, dgt1_ctx.witReceiptor, dgt1_hab.pre)

        # dgt2 init + incept
        dgt2_hab = dgt2_ctx.hby.makeHab(name='dgt2', isith='1', icount=1, toad=1,
                                        wits=[wit_ctx.pre])
        HabHelpers.collectWitnessReceipts(doist, all_deeds, dgt2_ctx.witReceiptor, dgt2_hab.pre)

        # OOBI Exchange between dgt1, dgt2
        dgt1_oobi = HabHelpers.generateOobi(dgt1_ctx.hby, alias='dgt1')
        dgt2_oobi = HabHelpers.generateOobi(dgt2_ctx.hby, alias='dgt2')

        HabHelpers.resolveOobi(doist, all_deeds, dgt2_ctx.hby, dgt1_oobi, alias='dgt1')
        HabHelpers.resolveOobi(doist, all_deeds, dgt1_ctx.hby, dgt2_oobi, alias='dgt2')

        # Create delegator multisig from del1, del2
        # smids and rmids are the same since all participants here are both signing and rotation members
        dgt_smids = [dgt1_hab.pre, dgt2_hab.pre]
        dgt_rmids = dgt_smids

        # dgt1 is the leader
        dgt_leader = MultisigInceptLeader(
            hby=dgt1_ctx.hby,
            mhab=dgt1_hab,
            smids=dgt_smids,
            rmids=dgt_rmids,
            group='dgt',
            isith='2',
            nsith='2',
            toad=1,
            wits=[wit_ctx.pre],
            postman=dgt1_ctx.postman,
            counselor=dgt1_ctx.counselor,
            witReceiptor=dgt1_ctx.witReceiptor,
        )

        # dgt2 is the follower
        dgt_follower = MultisigInceptFollower(
            hby=dgt2_ctx.hby,
            mhab=dgt2_hab,
            group='dgt',
            postman=dgt2_ctx.postman,
            counselor=dgt2_ctx.counselor,
            notifier=dgt2_ctx.notifier,
            witReceiptor=dgt2_ctx.witReceiptor,
        )

        # Run until multisig inception is complete
        dgt_deeds = doist.enter(doers=[dgt_leader, dgt_follower])
        # Wait for both ghabs to be created and counselor to confirm completion
        while dgt_leader.ghab is None or dgt_follower.ghab is None:
            doist.recur(deeds=all_deeds + dgt_deeds)
        # Now wait for counselor completion
        prefixer = coring.Prefixer(qb64=dgt_leader.ghab.pre)
        seqner = coring.Seqner(sn=0)
        while not dgt1_ctx.counselor.complete(prefixer, seqner):
            doist.recur(deeds=all_deeds + dgt_deeds)
        dgt_ghab = dgt_leader.ghab

        # Verify dgt multisig exists and has correct properties
        assert dgt_ghab is not None, "dgt multisig should exist"
        assert dgt_ghab.pre in dgt1_ctx.hby.kevers, "dgt1 should have dgt kever"
        assert dgt_ghab.pre in dgt2_ctx.hby.kevers, "dgt2 should have dgt kever"
        assert len(dgt_ghab.smids) == 2, "dgt should have 2 signing members"

        # Create delegate participants del1, del2
        # Create del1 single-sig AID
        del1_hab = del1_ctx.hby.makeHab(name='del1', isith='1', icount=1, toad=1,
                                        wits=[wit_ctx.pre])
        HabHelpers.collectWitnessReceipts(doist, all_deeds, del1_ctx.witReceiptor, del1_hab.pre)

        # Create del2 single-sig AID
        del2_hab = del2_ctx.hby.makeHab(name='del2', isith='1', icount=1, toad=1,
                                        wits=[wit_ctx.pre])
        HabHelpers.collectWitnessReceipts(doist, all_deeds, del2_ctx.witReceiptor, del2_hab.pre)

        # Delegates resolve delegator (dgt) OOBI
        dgt_oobi = HabHelpers.generateOobi(dgt1_ctx.hby, alias='dgt')
        HabHelpers.resolveOobi(doist, all_deeds, del1_ctx.hby, dgt_oobi, alias='dgt')
        HabHelpers.resolveOobi(doist, all_deeds, del2_ctx.hby, dgt_oobi, alias='dgt')

        # OOBI exchange between del1 and del2
        del1_oobi = HabHelpers.generateOobi(del1_ctx.hby, alias='del1')
        del2_oobi = HabHelpers.generateOobi(del2_ctx.hby, alias='del2')
        HabHelpers.resolveOobi(doist, all_deeds, del2_ctx.hby, del1_oobi, alias='del1')
        HabHelpers.resolveOobi(doist, all_deeds, del1_ctx.hby, del2_oobi, alias='del2')

        # Create delegated multisig from del1 and del2
        del_smids = [del1_hab.pre, del2_hab.pre]
        del_rmids = del_smids

        # del1 is the leader for the delegate multisig
        del_leader = MultisigInceptLeader(
            hby=del1_ctx.hby,
            mhab=del1_hab,
            smids=del_smids,
            rmids=del_rmids,
            group='del',
            isith='2',
            nsith='2',
            toad=1,
            wits=[wit_ctx.pre],
            delpre=dgt_ghab.pre,  # dgt is the delegator
            postman=del1_ctx.postman,
            counselor=del1_ctx.counselor,
            witReceiptor=del1_ctx.witReceiptor,
        )

        # del2 is the follower for the delegate multisig
        del_follower = MultisigInceptFollower(
            hby=del2_ctx.hby,
            mhab=del2_hab,
            group='del',
            postman=del2_ctx.postman,
            counselor=del2_ctx.counselor,
            notifier=del2_ctx.notifier,
            witReceiptor=del2_ctx.witReceiptor,
        )

        del_deeds = doist.enter(doers=[del_leader, del_follower])

        # Run until the delegate sends the DIP to the delegator
        # This will escrow until delegation is approved
        while del_leader.ghab is None:
            doist.recur(deeds=all_deeds + del_deeds)
        del_ghab = del_leader.ghab

        # Delegators approve delegation (dgt1 and dgt2 confirm)
        # Wait for delegation request to appear in delegables escrow
        while not HabHelpers.hasDelegables(dgt1_ctx.hby.db):
            doist.recur(deeds=all_deeds + del_deeds)

        # Both delegator participants approve (dgt1 is leader, dgt2 is follower)
        dgt1_approver = MultisigDelegationApprover(
            hby=dgt1_ctx.hby,
            ghab=dgt_ghab,
            mhab=dgt1_hab,
            counselor=dgt1_ctx.counselor,
            witReceiptor=dgt1_ctx.witReceiptor,
            witq=dgt1_ctx.witq,
            postman=dgt1_ctx.postman,
            leader=True,  # dgt1 is the leader
        )
        dgt2_approver = MultisigDelegationApprover(
            hby=dgt2_ctx.hby,
            ghab=dgt2_ctx.hby.habByName('dgt'),  # dgt2's copy of dgt
            mhab=dgt2_hab,
            counselor=dgt2_ctx.counselor,
            witReceiptor=dgt2_ctx.witReceiptor,
            witq=dgt2_ctx.witq,
            postman=dgt2_ctx.postman,
            notifier=dgt2_ctx.notifier,
            leader=False,  # dgt2 is the follower
        )
        approver_deeds = doist.enter(doers=[dgt1_approver, dgt2_approver])

        # Run until delegation is approved (anchor event created)
        # Check for the anchor event on the delegator
        while dgt_ghab.kever.sn < 1:
            doist.recur(deeds=all_deeds + del_deeds + approver_deeds)

        # Get witness receipts for the anchor
        HabHelpers.collectWitnessReceipts(doist, all_deeds + approver_deeds, dgt1_ctx.witReceiptor,
                                          dgt_ghab.pre, sn=dgt_ghab.kever.sn)

        # Wait for counselor to complete the anchor
        prefixer = coring.Prefixer(qb64=dgt_ghab.pre)
        seqner = coring.Seqner(sn=dgt_ghab.kever.sn)
        while not dgt1_ctx.counselor.complete(prefixer, seqner):
            doist.recur(deeds=all_deeds + del_deeds + approver_deeds)

        # Allow approvers to release the escrowed DIP event from delegables
        # After counselor completes, the approver's _releaseCompletedDelegations()
        # needs to run to reprocess the DIP with the delegation seal attached
        while del_ghab.pre not in dgt1_ctx.hby.kevers or del_ghab.pre not in dgt2_ctx.hby.kevers:
            doist.recur(deeds=all_deeds + del_deeds + approver_deeds)

        # Delegates query delegator keystate to discover approval anchor and complete delegation
        del1_query = KeystateQueryDoer(
            hby=del1_ctx.hby,
            hab=del1_hab,
            target_pre=dgt_ghab.pre,
            target_sn=dgt_ghab.kever.sn,
            witq=del1_ctx.witq,
            wits=[wit_ctx.pre],
        )
        del2_query = KeystateQueryDoer(
            hby=del2_ctx.hby,
            hab=del2_hab,
            target_pre=dgt_ghab.pre,
            target_sn=dgt_ghab.kever.sn,
            witq=del2_ctx.witq,
            wits=[wit_ctx.pre],
        )
        query_deeds = doist.enter(doers=[del1_query, del2_query])

        # Run until queries complete - check by looking at the kever in del1's database
        while dgt_ghab.pre not in del1_ctx.hby.kevers or del1_ctx.hby.kevers[dgt_ghab.pre].sn < 1:
            doist.recur(deeds=all_deeds + del_deeds + query_deeds)

        # Now the del multisig inception should complete - wait for counselor
        prefixer = coring.Prefixer(qb64=del_ghab.pre)
        seqner = coring.Seqner(sn=0)
        while not del1_ctx.counselor.complete(prefixer, seqner):
            doist.recur(deeds=all_deeds + del_deeds)

        # Verify del delegated multisig exists and has correct properties
        assert del_ghab is not None, "del multisig should exist"
        assert del_ghab.kever.delpre == dgt_ghab.pre, "del delegator should be dgt"
        assert del_ghab.pre in del1_ctx.hby.kevers, "del1 should have del kever"
        assert del_ghab.pre in del2_ctx.hby.kevers, "del2 should have del kever"

        # Before delegators can verify the delegate multisig's events, they need
        # the public keys of the multisig members (del1, del2) to verify signatures.
        del1_oobi = HabHelpers.generateOobi(del1_ctx.hby, alias='del1')
        del2_oobi = HabHelpers.generateOobi(del2_ctx.hby, alias='del2')
        HabHelpers.resolveOobi(doist, all_deeds, dgt1_ctx.hby, del1_oobi, alias='del1')
        HabHelpers.resolveOobi(doist, all_deeds, dgt1_ctx.hby, del2_oobi, alias='del2')
        HabHelpers.resolveOobi(doist, all_deeds, dgt2_ctx.hby, del1_oobi, alias='del1')
        HabHelpers.resolveOobi(doist, all_deeds, dgt2_ctx.hby, del2_oobi, alias='del2')

        # Now delegators query for the delegate's KEL - this should work because
        # eventing.py now checks for existing seals before escrowing to delegables
        dgt1_ctx.witq.query(src=dgt1_hab.pre, pre=del_ghab.pre, sn=0, wits=[wit_ctx.pre])
        dgt2_ctx.witq.query(src=dgt2_hab.pre, pre=del_ghab.pre, sn=0, wits=[wit_ctx.pre])

        # Wait for delegate to appear in delegator kevers
        while del_ghab.pre not in dgt1_ctx.hby.kevers or del_ghab.pre not in dgt2_ctx.hby.kevers:
            doist.recur(deeds=all_deeds)

        # Assertions - Verify delegator knows about delegate
        assert del_ghab.pre in dgt1_ctx.hby.kevers, "dgt1 should know about del after witness query"
        assert del_ghab.pre in dgt2_ctx.hby.kevers, "dgt2 should know about del after witness query"

        # Verify delegation anchor exists
        assert dgt_ghab.kever.sn == 1, "dgt should have two events, icp and ixn (with dip approval anchor)"
        assert del_ghab.kever.sn == 0, "delegate should have exactly one event - dip"

        # Verify delegables escrow is empty (delegation was properly released)
        assert not HabHelpers.hasDelegables(
            dgt1_ctx.hby.db), "dgt1 delegables escrow should be empty"
        assert not HabHelpers.hasDelegables(
            dgt2_ctx.hby.db), "dgt2 delegables escrow should be empty"
