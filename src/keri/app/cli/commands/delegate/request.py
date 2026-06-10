# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.delegate module

"""
import argparse
from ordered_set import OrderedSet as oset

from hio.base import doing

from keri import help
from keri.app import habbing, indirecting, agenting, grouping, forwarding, delegating
from keri.app.cli.common import existing
from keri.app.habbing import GroupHab
from keri.core import coring, serdering
from keri.db import dbing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Resend a delegation request message to a delegator that has not '
                                             'approved a previous delegation.')
parser.set_defaults(handler=lambda args: request(args))
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--dry-run', dest="dryRun", action="store_true",
                    help="print the delegated event and exn that would be resubmitted, then exit "
                         "without sending anything")

def request(args):
    """

    Parameters:
        args(Namespace): parsed arguements namespace object

    """
    name = args.name
    base = args.base
    bran = args.bran
    alias = args.alias

    requestDoer = RequestDoer(name=name, base=base, alias=alias, bran=bran, dryRun=args.dryRun)

    doers = [requestDoer]
    return doers


class RequestDoer(doing.DoDoer):
    def __init__(self, name, base, alias, bran, dryRun=False):
        hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer
        self.witq = agenting.WitnessInquisitor(hby=hby)
        self.postman = forwarding.Poster(hby=hby)
        self.counselor = grouping.Counselor(hby=hby)
        doers = [self.hbyDoer, self.postman]
        self.toRemove = list(doers)
        doers.extend([doing.doify(self.requestDo)])

        self.alias = alias
        self.dryRun = dryRun
        self.hby = hby

        super(RequestDoer, self).__init__(doers=doers)

    def requestDo(self, tymth, tock=0.0):
        """
        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Returns:  doifiable Doist compatible generator method
        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        hab = self.hby.habByName(self.alias)
        if hab is None:
            raise ValueError(f"no AID with alias {self.alias}")

        esc = self.hby.db.gdee.get(keys=(hab.pre,))
        if not esc:
            raise ValueError(f"no escrowed events for {self.alias} ({hab.pre})")

        (seqner, saider) = esc[0]
        evt = hab.makeOwnEvent(sn=seqner.sn)
        delpre = hab.kever.delegator  # get the delegator identifier

        if isinstance(hab, GroupHab):
            phab = hab.mhab
        else:
            phab = self.hby.habByName(f"{self.alias}-proxy")

        exn, atc = delegating.delegateRequestExn(hab.mhab, delpre=delpre, evt=bytes(evt), aids=hab.smids)

        # delegate AID ICP and exn of delegation request EXN
        srdr = serdering.SerderKERI(raw=evt) # coring.Serder(raw=evt)
        del evt[:srdr.size]

        if self.dryRun:
            self.printPreview(hab=hab, phab=phab, delpre=delpre, srdr=srdr, evtatc=evt,
                              exn=exn, exnatc=atc)
            self.remove(self.toRemove)
            return True

        self.postman.send(src=phab.pre, dest=delpre, topic="delegate", serder=srdr, attachment=evt)
        self.postman.send(src=phab.pre, dest=hab.kever.delegator, topic="delegate", serder=exn, attachment=atc)

        while True:
            while self.postman.cues:
                cue = self.postman.cues.popleft()
                if "said" in cue and cue["said"] == exn.said:
                    print("Delegation request resent")
                    self.remove(self.toRemove)
                    return True
                yield self.tock
            yield self.tock

    def printPreview(self, hab, phab, delpre, srdr, evtatc, exn, exnatc):
        """ Print the delegated event and exn a resubmit would send, without sending. """
        smids = hab.smids if isinstance(hab, GroupHab) else None
        print("DRY RUN — nothing submitted. `kli delegate request` would resend:\n")
        print(f"delegate       : {self.alias} ({hab.pre})  sn={hab.kever.sn}")
        print(f"signing member : {phab.pre}")
        print(f"delegator      : {delpre}")
        if smids is not None:
            print(f"smids          : {smids}")

        print("\n--- delegated event to resubmit (fully signed, unchanged SAID) ---")
        print(srdr.pretty())
        print(f"event attachment (signatures/seals): {len(evtatc)} bytes")

        print("\n--- /delegate/request exn (freshly built + signed each run) ---")
        print(exn.pretty())
        print(f"exn said : {exn.said}")
        print(f"exn dt   : {exn.ked['dt']}")
        print(f"exn attachment: {len(exnatc)} bytes")

        print(f"\n--- would POST to delegator {delpre} (topic 'delegate') ---")
        print(f"  1. event {srdr.said} (sn {srdr.sn})")
        print(f"  2. exn   {exn.said}")
        print("\nDRY RUN complete. Re-run without --dry-run to actually resubmit.")
