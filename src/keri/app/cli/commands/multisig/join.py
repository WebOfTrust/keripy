# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.delegate module

"""
import argparse
import json
from ordered_set import OrderedSet as oset

from hio.base import doing
from prettytable import PrettyTable

from keri import help, kering
from keri.app import habbing, indirecting, agenting, notifying, grouping, connecting, forwarding
from keri.app.cli.common import existing, displaying
from keri.core import coring, eventing, scheming, parsing, routing, serdering
from keri.peer import exchanging
from keri.vdr import verifying, credentialing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Join group multisig inception, rotation or interaction event.')
parser.set_defaults(handler=lambda args: confirm(args))
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument("--auto", "-Y", help="auto approve any delegation request non-interactively", action="store_true")


def confirm(args):
    """  Wait for and provide interactive confirmation of group multisig inception, rotation or interaction events

    Parameters:
        args(Namespace): parsed arguements namespace object

    """
    name = args.name
    base = args.base
    bran = args.bran
    auto = args.auto

    confirmDoer = ConfirmDoer(name=name, base=base, bran=bran, auto=auto)

    doers = [confirmDoer]
    return doers


class ConfirmDoer(doing.DoDoer):
    """  Doist doer capable of polling for group multisig events and prompting user for action

    """

    def __init__(self, name, base, bran, auto=False):
        """ Create doer for polling for group multisig events and either approve automatically or prompt user

        Parameters:
            name (str): database environment name
            base (str): database directory prefix
            bran (str): passcode to unlock keystore

        """
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.rgy = credentialing.Regery(hby=self.hby, name=name, base=base)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)  # setup doer
        self.witq = agenting.WitnessInquisitor(hby=self.hby)
        self.org = connecting.Organizer(hby=self.hby)
        self.notifier = notifying.Notifier(hby=self.hby)
        self.exc = exchanging.Exchanger(hby=self.hby, handlers=[])
        self.verifier = verifying.Verifier(hby=self.hby, reger=self.rgy.reger)
        self.rvy = routing.Revery(db=self.hby.db,  lax=True)
        self.hby.kvy.registerReplyRoutes(self.rvy.rtr)
        self.psr = parsing.Parser(kvy=self.hby.kvy, tvy=self.rgy.tvy, rvy=self.rvy, vry=self.verifier, exc=self.exc)

        mux = grouping.Multiplexor(hby=self.hby, notifier=self.notifier)
        grouping.loadHandlers(exc=self.exc, mux=mux)
        self.counselor = grouping.Counselor(hby=self.hby)

        self.registrar = credentialing.Registrar(hby=self.hby, rgy=self.rgy, counselor=self.counselor)
        self.credentialer = credentialing.Credentialer(hby=self.hby, rgy=self.rgy, registrar=self.registrar,
                                                       verifier=self.verifier)

        self.mbx = indirecting.MailboxDirector(hby=self.hby, exc=self.exc, topics=['/receipt', '/multisig', '/replay',
                                                                                   '/delegate'])
        self.postman = forwarding.Poster(hby=self.hby)

        doers = [self.hbyDoer, self.witq,  self.mbx, self.counselor, self.registrar, self.credentialer, self.postman]
        self.toRemove = list(doers)
        doers.extend([doing.doify(self.confirmDo)])
        self.auto = auto
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

        while self.notifier.noter.notes.cntAll() == 0:
            yield self.tock

        for keys, notice in self.notifier.noter.notes.getItemIter():
            attrs = notice.attrs
            route = attrs['r']

            match route:
                case '/multisig/icp':
                    done = yield from self.incept(attrs)
                case '/multisig/ixn':
                    done = yield from self.interact(attrs)
                case '/multisig/rot':
                    done = yield from self.rotate(attrs)
                case '/multisig/rpy':
                    done = yield from self.rpy(attrs)
                case '/multisig/vcp':
                    done = yield from self.vcp(attrs)
                case '/multisig/iss':
                    done = yield from self.iss(attrs)
                case '/multisig/rev':
                    done = yield from self.rev(attrs)
                case '/multisig/exn':
                    done = yield from self.exn(attrs)
                case _:
                    continue

            if done:
                self.notifier.noter.notes.rem(keys=keys)

            else:
                delete = input(f"\nDelete event [Y|n]? ")
                if delete in ("Y", "y"):
                    self.notifier.noter.notes.rem(keys=keys)

            yield self.tock

        self.remove(self.toRemove)

    def incept(self, attrs):
        """ Incept group multisig

        """
        said = attrs["d"]
        exn, pathed = exchanging.cloneMessage(self.hby, said=said)
        payload = exn.ked['a']

        smids = payload["smids"]
        rmids = payload["rmids"] if "rmids" in payload else None
        ked = exn.ked
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

        #original icp
        embeds = exn.ked['e']
        oicp = serdering.SerderKERI(sad=embeds["icp"])

        inits["isith"] = oicp.ked["kt"]
        inits["nsith"] = oicp.ked["nt"]

        inits["estOnly"] = eventing.TraitCodex.EstOnly in oicp.ked["c"]
        inits["DnD"] = eventing.TraitCodex.DoNotDelegate in oicp.ked["c"]

        inits["toad"] = oicp.ked["bt"]
        inits["wits"] = oicp.ked["b"]
        inits["delpre"] = oicp.ked["di"] if "di" in ked else None

        print()
        print("Group Multisig Inception proposed:")
        self.showEvent(mhab, both, oicp.ked)

        if self.auto:
            approve = True
        else:
            yn = input(f"\nJoin [Y|n]? ")
            approve = yn in ('', 'y', 'Y')

        if approve:
            if self.auto:
                alias = "test alias"
            else:
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
                return False

            icp = ghab.makeOwnInception(allowPartiallySigned=True)

            exn, ims = grouping.multisigInceptExn(ghab.mhab,
                                                  smids=ghab.smids,
                                                  rmids=ghab.rmids,
                                                  icp=icp)
            others = list(oset(smids + (rmids or [])))

            others.remove(ghab.mhab.pre)

            for recpt in others:  # this goes to other participants only as a signaling mechanism
                self.postman.send(src=ghab.mhab.pre,
                                  dest=recpt,
                                  topic="multisig",
                                  serder=exn,
                                  attachment=ims)

                while not self.postman.sent(said=exn.said):
                    yield self.tock

                self.postman.cues.clear()

            prefixer = coring.Prefixer(qb64=ghab.pre)
            seqner = coring.Seqner(sn=0)
            saider = coring.Saider(qb64=prefixer.qb64)
            yield from self.startCounselor(ghab, prefixer, seqner, saider)

            print()
            displaying.printIdentifier(self.hby, ghab.pre)

            return True

    def interact(self, attrs):
        said = attrs["d"]
        exn, pathed = exchanging.cloneMessage(self.hby, said=said)
        payload = exn.ked['a']

        pre = payload["gid"]
        smids = payload["smids"]
        rmids = payload["rmids"] if "rmids" in payload else None

        embeds = exn.ked['e']
        # original ixn
        oixn = serdering.SerderKERI(sad=embeds["ixn"])
        data = oixn.ked['a']

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

        if self.auto:
            approve = True
        else:
            yn = input(f"\nJoin [Y|n]? ")
            approve = yn in ('', 'y', 'Y')

        if approve:
            ixn = ghab.interact(data=data)
            serder = serdering.SerderKERI(raw=ixn)

            ixn = ghab.makeOwnEvent(allowPartiallySigned=True, sn=oixn.sn)

            exn, ims = grouping.multisigInteractExn(ghab, aids=ghab.smids, ixn=ixn)
            others = list(oset(smids + (rmids or [])))

            others.remove(ghab.mhab.pre)

            for recpt in others:  # this goes to other participants only as a signaling mechanism
                self.postman.send(src=ghab.mhab.pre,
                                  dest=recpt,
                                  topic="multisig",
                                  serder=exn,
                                  attachment=ims)

                while not self.postman.sent(said=exn.said):
                    yield self.tock

                self.postman.cues.clear()

            prefixer = coring.Prefixer(qb64=ghab.pre)
            seqner = coring.Seqner(sn=serder.sn)
            saider = coring.Saider(qb64b=serder.saidb)
            yield from self.startCounselor(ghab, prefixer, seqner, saider)

            print()
            displaying.printIdentifier(self.hby, ghab.pre)

            return True

    def startCounselor(self, hab, prefixer, seqner, saider):
        self.counselor.start(prefixer=prefixer, seqner=seqner, saider=saider, ghab=hab)

        while True:
            saider = self.hby.db.cgms.get(keys=(prefixer.qb64, seqner.qb64))
            if saider is not None:
                break

            yield self.tock

    def showEvent(self, hab, mids, ked):
        print("Participants:")

        thold = coring.Tholder(sith=ked["kt"])
        self.printMemberTable(mids, hab, thold)

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

    def rotate(self, attrs):
        """ Rotate group multisig

        """
        said = attrs["d"]
        exn, pathed = exchanging.cloneMessage(self.hby, said=said)

        payload = exn.ked['a']
        smids = payload["smids"]
        rmids = payload["rmids"]
        ked = exn.ked

        embeds = ked['e']
        orot = serdering.SerderKERI(sad=embeds["rot"])

        both = list(set(smids + (rmids or [])))

        mhab = None
        for mid in both:
            if mid in self.hby.habs:
                mhab = self.hby.habs[mid]
                break

        if mhab is None:
            print("Invalid multisig group rotation request, signing member list must contain a local identifier'")
            return False

        print()
        print("Group Multisig Rotation proposed:")
        self.showRotation(mhab, smids, rmids, orot.ked)

        if self.auto:
            approve = True
        else:
            yn = input(f"\nJoin [Y|n]? ")
            approve = yn in ('', 'y', 'Y')

        if approve:
            pre = orot.ked['i']
            if pre in self.hby.habs:
                ghab = self.hby.habs[pre]
            else:
                if self.auto:
                    alias = "test alias"
                else:
                    while True:
                        alias = input(f"\nEnter alias for new AID: ")
                        if self.hby.habByName(alias) is not None:
                            print(f"AID alias {alias} is already in use, please try again")
                        else:
                            break

                ghab = self.hby.joinGroupHab(pre, group=alias, mhab=mhab, smids=smids, rmids=rmids)

            try:
                ghab.rotate(serder=orot)
            except ValueError:
                return False

            rot = ghab.makeOwnEvent(allowPartiallySigned=True, sn=orot.sn)

            exn, ims = grouping.multisigRotateExn(ghab,
                                                  smids=ghab.smids,
                                                  rmids=ghab.rmids,
                                                  rot=rot)
            others = list(oset(smids + (rmids or [])))

            others.remove(ghab.mhab.pre)

            for recpt in others:  # this goes to other participants only as a signaling mechanism
                self.postman.send(src=ghab.mhab.pre,
                                  dest=recpt,
                                  topic="multisig",
                                  serder=exn,
                                  attachment=ims)

                while not self.postman.sent(said=exn.said):
                    yield self.tock

                self.postman.cues.clear()

            serder = serdering.SerderKERI(raw=rot)
            prefixer = coring.Prefixer(qb64=ghab.pre)
            seqner = coring.Seqner(sn=serder.sn)

            yield from self.startCounselor(ghab, prefixer, seqner, coring.Saider(qb64=serder.said))

            print()
            displaying.printIdentifier(self.hby, ghab.pre)

            return True

    def showRotation(self, hab, smids, rmids, ked):
        print()
        print("Signing Members")
        thold = coring.Tholder(sith=ked["kt"])
        self.printMemberTable(smids, hab, thold)

        print()
        print("Rotation Members")
        nthold = coring.Tholder(sith=ked["nt"])
        self.printMemberTable(rmids, hab, nthold)

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

        tab.add_row(["Witness Threshold", ked["bt"]])
        if "ba" in ked and ked["ba"]:
            tab.add_row(["Added Witnesses", "\n".join(ked["ba"])])
        if "br" in ked and ked["br"]:
            tab.add_row(["Removed Witnesses", "\n".join(ked["br"])])

        print(tab)

    def printMemberTable(self, mids, hab, thold):
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

    def rpy(self, attrs):
        """  Handle reply messages

        Parameters:
            attrs (dict): attributes of the reply message

        Returns:

        """
        said = attrs["d"]
        exn, pathed = exchanging.cloneMessage(self.hby, said=said)

        sender = exn.ked['i']
        payload = exn.ked['a']
        gid = payload["gid"]
        hab = self.hby.habs[gid] if gid in self.hby.habs else None
        if hab is None:
            raise ValueError(f"credential issuer not a valid AID={gid}")

        contact = self.org.get(sender)
        senderAlias = contact['alias']

        embeds = exn.ked['e']
        rpy = embeds['rpy']
        cid = rpy['a']['cid']
        eid = rpy['a']['eid']
        role = rpy['a']['role']

        if cid == gid:
            controller = hab.name
        else:
            raise ValueError(f"Endpoint role authorization request for wrong controller {gid} != {cid}")

        endpoint = self.org.get(eid)
        if endpoint is None or 'alias' not in endpoint:
            endpointAlias = "Unknown Endpoint"
        else:
            endpointAlias = endpoint['alias']

        print(f"\nEndpoint Role Authorization (from {senderAlias}):")
        print(f"    Controller: {controller} ({cid})")
        print(f"    Role: {role.capitalize()}")
        print(f"    Endpoint Provider: {endpointAlias} ({eid})")

        if self.auto:
            approve = True
        else:
            yn = input(f"\nApprove [Y|n]? ")
            approve = yn in ('', 'y', 'Y')

        if approve:
            # Create and parse the event with "their" signatures
            rserder = serdering.SerderKERI(sad=rpy)
            anc = bytearray(rserder.raw) + pathed["rpy"]
            self.psr.parseOne(ims=bytes(anc))

            # Now sign the event and parse it with our signatures
            anc = hab.endorse(rserder)
            self.psr.parseOne(ims=bytes(anc))

            smids = hab.db.signingMembers(pre=hab.pre)
            smids.remove(hab.mhab.pre)

            for recp in smids:  # this goes to other participants only as a signaling mechanism
                exn, atc = grouping.multisigRpyExn(ghab=hab, rpy=anc)
                self.postman.send(src=hab.mhab.pre,
                                  dest=recp,
                                  topic="multisig",
                                  serder=exn,
                                  attachment=atc)

            while not hab.loadEndRole(cid=cid, role=role, eid=eid):
                self.rgy.processEscrows()
                self.rvy.processEscrowReply()
                yield self.tock

            print(f"End role authorization added for role {role}")

        yield self.tock

    def vcp(self, attrs):
        """  Handle issue messages

        Parameters:
            attrs (dict): attributes of the reply message

        Returns:

        """
        said = attrs["d"]
        exn, pathed = exchanging.cloneMessage(self.hby, said=said)

        sender = exn.ked['i']
        payload = exn.ked['a']
        usage = payload["usage"]
        gid = payload["gid"]
        hab = self.hby.habs[gid] if gid in self.hby.habs else None
        if hab is None:
            raise ValueError(f"credential issuer not a valid AID={gid}")

        contact = self.org.get(sender)
        senderAlias = contact['alias']

        embeds = exn.ked['e']
        print(f"\nGroup Credential Regitry Creation (from {senderAlias}):")
        print(f"Usage: {usage}:\n")

        if self.auto:
            approve = True
        else:
            yn = input(f"\nApprove [Y|n]? ")
            approve = yn in ('', 'y', 'Y')

        if approve:
            # Create and parse the event with "their" signatures
            registryName = input("Name for Registry: ")
            anc = embeds["anc"]
            aserder = serdering.SerderKERI(sad=anc)
            anc = bytearray(aserder.raw) + pathed["anc"]
            self.psr.parseOne(ims=bytes(anc))

            # Now sign the event and parse it with our signatures
            sigers = hab.sign(aserder.raw)
            anc = eventing.messagize(serder=aserder, sigers=sigers)
            self.psr.parseOne(ims=bytes(anc))

            vcp = embeds["vcp"]
            vserder = serdering.SerderKERI(sad=vcp)
            try:
                self.rgy.tvy.processEvent(serder=vserder)
            except kering.MissingAnchorError:
                pass

            self.rgy.makeRegistry(name=registryName, prefix=hab.pre, vcp=vserder)
            self.registrar.incept(vserder, aserder)

            smids = hab.db.signingMembers(pre=hab.pre)
            smids.remove(hab.mhab.pre)

            for recp in smids:  # this goes to other participants only as a signaling mechanism
                exn, atc = grouping.multisigRegistryInceptExn(ghab=hab, vcp=vserder.raw, anc=anc, usage=usage)
                self.postman.send(src=hab.mhab.pre,
                                  dest=recp,
                                  topic="multisig",
                                  serder=exn,
                                  attachment=atc)

            while not self.registrar.complete(vserder.pre, sn=0):
                self.rgy.processEscrows()
                self.verifier.processEscrows()
                yield self.tock

            print(f"Registry {vserder.pre} created.")

        yield self.tock

    def iss(self, attrs):
        """  Handle issue messages

        Parameters:
            attrs (dict): attributes of the reply message

        Returns:

        """
        said = attrs["d"]
        exn, pathed = exchanging.cloneMessage(self.hby, said=said)

        sender = exn.ked['i']

        contact = self.org.get(sender)
        senderAlias = contact['alias']

        embeds = exn.ked['e']
        acdc = embeds["acdc"]
        schema = acdc['s']
        scraw = self.verifier.resolver.resolve(schema)
        if not scraw:
            raise kering.ConfigurationError("Credential schema {} not found".format(schema))

        schemer = scheming.Schemer(raw=scraw)

        issr = acdc["i"]
        hab = self.hby.habs[issr] if issr in self.hby.habs else None
        if hab is None:
            raise ValueError(f"credential issuer not a valid AID={issr}")

        print(f"\nGroup Credential Issuance Proposed (from {senderAlias}):")
        print(f"Credential {acdc['d']}:")
        print(f"    Type: {schemer.sed['title']}")
        print(f"    Issued By: {hab.name} ({hab.pre})")

        if "i" in acdc["a"]:
            isse = acdc['a']['i']
            contact = self.org.get(isse)
            if contact is not None and "alias" in contact:
                print(f"    Issued To: {contact['alias']} ({isse})")
            else:
                print(f"    Issued To: Unknown AID ({isse})")

        print("    Data:")
        for k, v in acdc['a'].items():
            if k not in ('d', 'i'):
                print(f"        {k}: {v}")

        if self.auto:
            approve = True
        else:
            yn = input(f"\nApprove [Y|n]? ")
            approve = yn in ('', 'y', 'Y')

        if approve:
            # Create and parse the event with "their" signatures
            anc = embeds["anc"]
            aserder = serdering.SerderKERI(sad=anc)
            anc = bytearray(aserder.raw) + pathed["anc"]
            self.psr.parseOne(ims=bytes(anc))

            # Now sign the event and parse it with our signatures
            sigers = hab.sign(aserder.raw)
            anc = eventing.messagize(serder=aserder, sigers=sigers)
            self.psr.parseOne(ims=bytes(anc))

            iss = embeds["iss"]
            iserder = serdering.SerderKERI(sad=iss)
            try:
                self.rgy.tvy.processEvent(serder=iserder)
            except kering.MissingAnchorError:
                pass

            acdc = embeds["acdc"]
            creder = serdering.SerderACDC(sad=acdc)
            acdc = bytearray(creder.raw) + pathed["acdc"]
            self.psr.parseOne(ims=bytes(acdc))

            self.credentialer.issue(creder, iserder)
            self.registrar.issue(creder, iserder, aserder)

            smids = hab.db.signingMembers(pre=hab.pre)
            smids.remove(hab.mhab.pre)

            for recp in smids:  # this goes to other participants only as a signaling mechanism
                exn, atc = grouping.multisigIssueExn(ghab=hab, acdc=acdc, iss=iserder.raw, anc=anc)
                self.postman.send(src=hab.mhab.pre,
                                  dest=recp,
                                  topic="multisig",
                                  serder=exn,
                                  attachment=atc)

            while not self.credentialer.complete(said=creder.said):
                self.rgy.processEscrows()
                self.verifier.processEscrows()
                yield self.tock

            print(f"Credential {creder.said} complete.")

        yield self.tock

    def rev(self, attrs):
        """  Handle revocation messages

        Parameters:
            attrs (dict): attributes of the reply message

        Returns:

        """
        said = attrs["d"]
        exn, pathed = exchanging.cloneMessage(self.hby, said=said)

        sender = exn.ked['i']
        payload = exn.ked['a']
        said = payload['said']

        creder = self.verifier.reger.creds.get(keys=(said,))
        if creder is None:
            print(f"invalid credential SAID {said}")
            return

        contact = self.org.get(sender)
        senderAlias = contact['alias']

        embeds = exn.ked['e']
        scraw = self.verifier.resolver.resolve(creder.schema)
        if not scraw:
            raise kering.ConfigurationError("Credential schema {} not found".format(creder.schema))

        schemer = scheming.Schemer(raw=scraw)

        hab = self.hby.habs[creder.issuer]
        if hab is None:
            raise ValueError(f"credential issuer not a valid AID={creder.issuer}")

        print(f"\nGroup Credential Revocation Proposed (from {senderAlias}):")
        print(f"Credential {creder.said}:")
        print(f"    Type: {schemer.sed['title']}")
        print(f"    Issued By: {hab.name} ({hab.pre})")

        if "i" in creder.attrib:
            isse = creder.attrib['i']
            contact = self.org.get(isse)
            if contact is not None and "alias" in contact:
                print(f"    Issued To: {contact['alias']} ({isse})")
            else:
                print(f"    Issued To: Unknown AID ({isse})")

        if self.auto:
            approve = True
        else:
            yn = input(f"\nApprove Revocation [Y|n]? ")
            approve = yn in ('', 'y', 'Y')

        if approve:
            # Create and parse the event with "their" signatures
            anc = embeds["anc"]
            aserder = serdering.SerderKERI(sad=anc)
            anc = bytearray(aserder.raw) + pathed["anc"]
            self.psr.parseOne(ims=bytes(anc))

            # Now sign the event and parse it with our signatures
            sigers = hab.sign(aserder.raw)
            anc = eventing.messagize(serder=aserder, sigers=sigers)
            self.psr.parseOne(ims=bytes(anc))

            rev = embeds["rev"]
            rserder = serdering.SerderKERI(sad=rev)
            try:
                self.rgy.tvy.processEvent(serder=rserder)
            except kering.MissingAnchorError:
                pass

            self.registrar.revoke(creder, rserder, aserder)

            smids = hab.db.signingMembers(pre=hab.pre)
            smids.remove(hab.mhab.pre)

            for recp in smids:  # this goes to other participants only as a signaling mechanism
                exn, atc = grouping.multisigRevokeExn(ghab=hab, said=creder.said, rev=rserder.raw, anc=anc)
                self.postman.send(src=hab.mhab.pre,
                                  dest=recp,
                                  topic="multisig",
                                  serder=exn,
                                  attachment=atc)

            while not self.registrar.complete(creder.said, sn=1):
                self.rgy.processEscrows()
                yield self.tock

            print(f"Credential {creder.said} revoked.")
            if hab.witnesser() and 'i' in creder.attrib:
                recp = creder.attrib['i']
                msgs = []
                for msg in self.hby.db.clonePreIter(pre=creder.issuer):
                    serder = serdering.SerderKERI(raw=msg)
                    atc = msg[serder.size:]
                    msgs.append((serder, atc))
                for msg in self.rgy.reger.clonePreIter(pre=creder.said):
                    serder = serdering.SerderKERI(raw=msg)
                    atc = msg[serder.size:]
                    msgs.append((serder, atc))

                for (serder, atc) in msgs:
                    self.postman.send(src=hab.mhab.pre, dest=recp, topic="credential", serder=serder,
                                      attachment=atc)

                last = msgs[-1][0]
                while not self.postman.sent(said=last.said):
                    yield self.tock

        yield self.tock

    def exn(self, attrs):
        """  Handle exn messages

        Parameters:
            attrs (dict): attributes of the reply message

        Returns:

        """
        said = attrs["d"]
        exn, pathed = exchanging.cloneMessage(self.hby, said=said)
        embeds = exn.ked['e']
        sender = exn.ked['i']

        contact = self.org.get(sender)
        senderAlias = contact['alias']

        eexn = embeds['exn']

        group = eexn["i"]
        hab = self.hby.habs[group] if group in self.hby.habs else None
        if hab is None:
            raise ValueError(f"message sender not a valid AID={group}")

        print(f"Group Peer-2-Peer Message proposal (from {senderAlias}):")
        print(f"    Message Type: {eexn['r']}")
        print(f"    Sending From: {hab.name} ({hab.pre})")
        recp = eexn['a']['i']
        contact = self.org.get(recp)
        if contact is not None and "alias" in contact:
            print(f"    Sending To: {contact['alias']} ({recp})")
        else:
            print(f"    Sending To: Unknown AID ({recp})")

        if self.auto:
            approve = True
        else:
            yn = input(f"\nApprove [Y|n]? ")
            approve = yn in ('', 'y', 'Y')

        if approve:
            eserder = serdering.SerderKERI(sad=eexn)
            anc = bytearray(eserder.raw) + pathed["exn"]
            self.psr.parseOne(ims=bytes(anc))

            msg = hab.endorse(serder=eserder, last=False, pipelined=False)
            msg = msg + pathed["exn"]
            self.psr.parseOne(ims=bytes(msg))

            smids = hab.db.signingMembers(pre=hab.pre)
            smids.remove(hab.mhab.pre)

            for smid in smids:  # this goes to other participants only as a signaling mechanism
                rexn, atc = grouping.multisigExn(ghab=hab, exn=msg)
                self.postman.send(src=hab.mhab.pre,
                                  dest=smid,
                                  topic="multisig",
                                  serder=rexn,
                                  attachment=atc)

            while not self.exc.complete(said=eserder.said):
                self.exc.processEscrow()
                yield self.tock

            if self.exc.lead(hab.mhab, said=exn.said):
                print(f"Sending message {eserder.said} to {recp}")
                atc = exchanging.serializeMessage(self.hby, eserder.said)
                del atc[:eserder.size]
                self.postman.send(src=hab.mhab.pre,
                                  dest=recp,
                                  topic="credential",
                                  serder=eserder,
                                  attachment=atc)

                while not self.postman.sent(said=eserder.said):
                    yield self.tock

                print("... grant message sent")

        yield self.tock
