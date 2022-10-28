# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.delegate module

"""
import argparse
import json
from ordered_set import OrderedSet as oset

from prettytable import PrettyTable

from hio.base import doing

from keri import help
from keri.app import habbing, indirecting, agenting, notifying, grouping, connecting
from keri.app.cli.common import existing, displaying
from keri.core import coring, eventing
from keri.peer import exchanging

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Join group multisig inception, rotation or interaction event.')
parser.set_defaults(handler=lambda args: confirm(args))
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran


def confirm(args):
    """  Wait for and provide interactive confirmation of group multisig inception, rotation or interaction events

    Parameters:
        args(Namespace): parsed arguements namespace object

    """
    name = args.name
    base = args.base
    bran = args.bran

    confirmDoer = ConfirmDoer(name=name, base=base, bran=bran)

    doers = [confirmDoer]
    return doers


class ConfirmDoer(doing.DoDoer):
    """  Doist doer capable of polling for group multisig events and prompting user for action

    """

    def __init__(self, name, base, bran):
        """ Create doer for polling for group multisig events and either approve automatically or prompt user

        Parameters:
            name (str): database environment name
            base (str): database directory prefix
            bran (str): passcode to unlock keystore

        """
        hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer
        self.witq = agenting.WitnessInquisitor(hby=hby)
        self.org = connecting.Organizer(hby=hby)
        self.notifier = notifying.Notifier(hby=hby)
        self.exc = exchanging.Exchanger(db=hby.db, handlers=[])
        grouping.loadHandlers(hby=hby, exc=self.exc, notifier=self.notifier)
        self.counselor = grouping.Counselor(hby=hby)
        self.mbx = indirecting.MailboxDirector(hby=hby, exc=self.exc, topics=['/receipt', '/multisig', '/replay',
                                                                              '/delegate'])

        doers = [self.hbyDoer, self.witq, self.exc, self.mbx, self.counselor]
        self.toRemove = list(doers)
        doers.extend([doing.doify(self.confirmDo)])

        self.hby = hby
        super(ConfirmDoer, self).__init__(doers=doers)

    def confirmDo(self, tymth, tock=0.0):
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

        print("Waiting for group multisig events...")

        while True:
            for keys, notice in self.notifier.noter.notes.getItemIter():
                attrs = notice.attrs
                route = attrs['r']

                if route == '/multisig/icp/init':
                    done = yield from self.incept(attrs)
                    if done:
                        self.notifier.noter.notes.rem(keys=keys)

                    else:
                        delete = input(f"\nDelete event [Y|n]? ")
                        if delete:
                            self.notifier.noter.notes.rem(keys=keys)

                    self.remove(self.toRemove)
                    return True

                if route == '/multisig/ixn':
                    done = yield from self.interact(attrs)
                    if done:
                        self.notifier.noter.notes.rem(keys=keys)

                    else:
                        delete = input(f"\nDelete event [Y|n]? ")
                        if delete:
                            self.notifier.noter.notes.rem(keys=keys)

                    self.remove(self.toRemove)
                    return True

                yield self.tock

            yield self.tock

    def incept(self, attrs):
        """Incept group multisig

        ToDo: NRR
        Add rmids
        """
        smids = attrs["aids"]  # change body mids for group member ids
        rmids = attrs["rmids"] if "rmids" in attrs else None
        ked = attrs["ked"]

        both = list(set(smids + (rmids or [])))

        mhab = None
        for mid in both:
            if mid in self.hby.habs:
                mhab = self.hby.habs[mid]
                break

        if mhab is None:
            print("Invalid multisig group inception request, aid list must contain a local identifier'")
            return False

        inits = dict()

        inits["isith"] = ked["kt"]
        inits["nsith"] = ked["nt"]

        inits["estOnly"] = eventing.TraitCodex.EstOnly in ked["c"]
        inits["DnD"] = eventing.TraitCodex.DoNotDelegate in ked["c"]

        inits["toad"] = ked["bt"]
        inits["wits"] = ked["b"]
        inits["delpre"] = ked["di"] if "di" in ked else None

        print()
        print("Group Multisig Inception proposed:")
        self.showEvent(mhab, both, ked)
        yn = input(f"\nJoin [Y|n]? ")
        approve = yn in ('', 'y', 'Y')

        if approve:
            while True:
                alias = input(f"\nEnter alias for new AID: ")
                if self.hby.habByName(alias) is not None:
                    print(f"AID alias {alias} is already in use, please try again")
                else:
                    break

            try:
                ghab = self.hby.makeGroupHab(group=alias, mhab=mhab,
                                             smids=smids, rmids=rmids, **inits)
            except ValueError as e:
                print(f"{e.args[0]}")
                return False


            prefixer = coring.Prefixer(qb64=ghab.pre)
            seqner = coring.Seqner(sn=0)
            saider = coring.Saider(qb64=prefixer.qb64)
            yield from self.startCounselor(smids, rmids, ghab, prefixer, seqner, saider)

            print()
            displaying.printIdentifier(self.hby, ghab.pre)

            return True


    def interact(self, attrs):
        pre = attrs["gid"]
        smids = attrs["aids"]  # change attrs["aids"]" to "smids"
        rmids = attrs["rmids"] if "rmids" in attrs else None
        data = attrs["data"]

        if pre not in self.hby.habs:
            print(f"Invalid multisig group interaction request {pre} not in Habs")
            return False

        ghab = self.hby.habs[pre]

        both = list(set(smids + (rmids or [])))

        if ghab.mhab.pre not in both:
            print(f"Local AID {ghab.mhab.pre} not a requested signer in {both}")
            return False

        print(f"Group Multisig Interaction for {ghab.name} ({ghab.pre}) proposed:")
        print(f"Data:")
        print(json.dumps(data, indent=2))
        yn = input(f"\nJoin [Y|n]? ")
        approve = yn in ('', 'y', 'Y')

        if approve:
            ixn = ghab.interact(data=data)
            serder = coring.Serder(raw=ixn)
            print(serder.pretty())
            prefixer = coring.Prefixer(qb64=ghab.pre)
            seqner = coring.Seqner(sn=serder.sn)
            saider = coring.Saider(qb64b=serder.saidb)
            yield from self.startCounselor(smids, rmids, ghab, prefixer, seqner, saider)

            print()
            displaying.printIdentifier(self.hby, ghab.pre)

            return True

    def startCounselor(self, smids, rmids, hab, prefixer, seqner, saider):
        self.counselor.start(prefixer=prefixer, seqner=seqner, saider=saider,
                             mid=hab.mhab.pre, smids=smids, rmids=rmids)

        while True:
            saider = self.hby.db.cgms.get(keys=(prefixer.qb64, seqner.qb64))
            if saider is not None:
                break

            yield self.tock

    def showEvent(self, hab, mids, ked):
        print()
        print("Participants:")

        thold = coring.Tholder(sith=ked["kt"])

        tab = PrettyTable()
        fields = ["Local", "Name", "AID"]

        if thold.weighted:
            fields.append("Threshold")

        tab.field_names = fields
        tab.align["Name"] = "l"

        for idx, mid in enumerate(mids):
            if mid == hab.pre:
                row = ["*", hab.name, hab.pre]
                if thold.weighted:
                    row.append(thold.sith[idx])

                tab.add_row(row)
            else:
                m = self.org.get(mid)
                alias = m['alias'] if m else "Unknown Participant"
                row = [" ", alias, mid]
                if thold.weighted:
                    row.append(thold.sith[idx])
                tab.add_row(row)

        print(tab)
        print()
        print("Configuration:")

        tab = PrettyTable()
        tab.field_names = ["Name", "Value"]
        tab.align["Name"] = "l"

        if "di" in ked:
            m = self.org.get(ked["di"])
            alias = m['alias'] if m else "Unknown Delegator"
            tab.add_row(["Delegator", f"{alias} ({ked['di']}))"])

        if not thold.weighted:
            tab.add_row(["Signature Threshold", thold.num])

        tab.add_row(["Establishment Only", eventing.TraitCodex.EstOnly in ked["c"]])
        tab.add_row(["Do Not Delegate", eventing.TraitCodex.DoNotDelegate in ked["c"]])
        tab.add_row(["Witness Threshold", ked["bt"]])
        tab.add_row(["Witnesses", "\n".join(ked["b"])])

        print(tab)
