# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing
from prettytable import PrettyTable

from keri import kering
from keri.app import indirecting, habbing, forwarding, connecting
from keri.app.cli.common import existing
from keri.core import parsing, coring
from keri.help import helping

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Add new endpoint role authorization.')
parser.set_defaults(handler=lambda args: add_end(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument("--roles", "-r", help="KERI enpoint authorization role.", action="append",
                    required=True)


def add_end(args):
    """ Command line tool for adding endpoint role authorizations

    """
    ld = RoleDoer(name=args.name,
                  base=args.base,
                  alias=args.alias,
                  bran=args.bran,
                  roles=args.roles)
    return [ld]


class RoleDoer(doing.DoDoer):

    def __init__(self, name, base, alias, bran, roles):
        self.roles = roles

        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hab = self.hby.habByName(alias)
        self.mbx = indirecting.MailboxDirector(hby=self.hby, topics=['/receipt', '/multisig', '/replay',
                                                                     '/delegate'])
        self.postman = forwarding.Poster(hby=self.hby)
        self.org = connecting.Organizer(hby=self.hby)

        if self.hab is None:
            raise kering.ConfigurationError(f"unknown alias={alias}")

        doers = [self.mbx, self.postman, doing.doify(self.roleDo)]

        super(RoleDoer, self).__init__(doers=doers)

    def roleDo(self, tymth, tock=0.0):
        """ Export any end reply messages previous saved for the provided AID

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

        if not isinstance(self.hab, habbing.GroupHab):
            raise ValueError("non-group AIDs not supported, try `kli ends add` instead.")

        smids = self.hab.db.signingMembers(self.hab.pre)

        tab = PrettyTable()
        tab.field_names = ["From Member", "Adding AID", "In Role", "Local"]
        tab.align["From Member"] = "l"

        auths = []
        for smid in smids:
            ends = self.hab.endsFor(smid)
            for role in self.roles:
                if role in ends:
                    end = ends[role]
                    for k in end.keys():
                        local = ""
                        if smid in self.hby.habs:
                            local = "*"
                            hab = self.hby.habs[smid]
                            name = f"{hab.name} ({smid})"
                        elif (c := self.org.get(smid)) is not None:
                            name = f"{c['alias']} ({smid})"
                        else:
                            name = f"Unknown ({smid})"

                        tab.add_row([name, k, role.capitalize(), local])
                        auths.append(dict(cid=self.hab.pre, role=role, eid=k))

        print(f"Adding the following endpoint role authorizations for {self.hab.pre}")
        print(tab)
        yes = input(f"\nAuthorize new Roles [Y|n]? ")
        if yes not in ("Y", "y"):
            self.remove([self.mbx, self.postman])
            return

        psr = parsing.Parser()
        route = "/end/role/add"
        others = [smid for smid in smids if smid != self.hab.mhab.pre]
        approved = []
        saids = []
        stamp = helping.nowUTC()

        msgs = bytearray()
        for data in auths:
            approved.append(tuple(data.values()))
            msg = self.hab.reply(route=route, data=data, stamp=helping.toIso8601(stamp))
            serder = coring.Serder(raw=msg)
            atc = bytes(msg[serder.size:])
            for o in others:
                self.postman.send(hab=self.hab.mhab, dest=o, topic="multisig", serder=serder,
                                  attachment=atc)

            saids.append(serder.said)
            msgs.extend(msg)

        psr.parse(ims=bytes(msgs), kvy=self.hab.kvy, rvy=self.hab.rvy)

        print("Waiting for approvals from other members...")
        while approved:
            escrowed = self.hab.db.rpes.get(keys=("/end/role",))
            for saider in escrowed:
                if saider.qb64 in saids:
                    continue

                serder = self.hab.db.rpys.get(keys=(saider.qb64,))
                payload = serder.ked['a']
                keys = tuple(payload.values())

                if keys in approved:
                    then = helping.fromIso8601(serder.ked["dt"])
                    if then > stamp:
                        msg = self.hab.endorse(serder=serder)
                        atc = bytes(msg[serder.size:])
                        psr.parse(ims=bytes(msg), kvy=self.hab.kvy, rvy=self.hab.rvy)
                        for o in others:
                            self.postman.send(hab=self.hab.mhab, dest=o, topic="multisig", serder=serder,
                                              attachment=atc)
                    else:
                        self.hab.db.rpes.rem(keys=("/end/role",), val=saider)

                    approved.remove(keys)
            yield 1.0

        while True:
            finished = True
            for keys in approved:
                if not self.hab.loadEndRole(cid=keys[0], role=keys[1], eid=keys[2]):
                    finished = False

            if finished:
                break

            yield 1.0

        print("All endpoint role authorizations approved")
        self.remove([self.mbx, self.postman])
        return
