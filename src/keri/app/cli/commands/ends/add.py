# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing

from keri import kering
from keri.app import habbing, grouping, indirecting, forwarding
from keri.app.agenting import WitnessPublisher
from keri.app.cli.common import existing
from keri.app.notifying import Notifier
from keri.core import parsing
from keri.peer import exchanging

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Add new endpoint role authorization.')
parser.set_defaults(handler=lambda args: add_end(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument("--role", "-r", help="KERI enpoint authorization role.",
                    required=True)
parser.add_argument("--eid", "-e", help="qualified base64 of AID to authorize with new role for the AID identified "
                                        "by alias",
                    required=True)
parser.add_argument("--time", help="timestamp for the end auth", required=False, default=None)


def add_end(args):
    """ Command line tool for adding endpoint role authorizations

    """
    ld = RoleDoer(name=args.name,
                  base=args.base,
                  alias=args.alias,
                  bran=args.bran,
                  role=args.role,
                  eid=args.eid,
                  timestamp=args.time)
    return [ld]


class RoleDoer(doing.DoDoer):

    def __init__(self, name, base, alias, bran, role, eid, timestamp=None):
        self.role = role
        self.eid = eid
        self.timestamp = timestamp

        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hab = self.hby.habByName(alias)
        self.witpub = WitnessPublisher(hby=self.hby)
        self.postman = forwarding.Poster(hby=self.hby)
        notifier = Notifier(self.hby)
        mux = grouping.Multiplexor(self.hby, notifier=notifier)
        exc = exchanging.Exchanger(hby=self.hby, handlers=[])
        grouping.loadHandlers(exc, mux)

        mbx = indirecting.MailboxDirector(hby=self.hby, topics=["/receipt", "/multisig", "/replay"], exc=exc)

        if self.hab is None:
            raise kering.ConfigurationError(f"unknown alias={alias}")

        self.toRemove = [self.witpub, self.postman, mbx]

        super(RoleDoer, self).__init__(doers=self.toRemove + [doing.doify(self.roleDo)])

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

        data = dict(cid=self.hab.pre, role=self.role, eid=self.eid)

        route = "/end/role/add"
        msg = self.hab.reply(route=route, data=data, stamp=self.timestamp)

        parsing.Parser().parse(ims=bytes(msg), kvy=self.hab.kvy, rvy=self.hab.rvy)

        if isinstance(self.hab, habbing.GroupHab):
            smids = self.hab.db.signingMembers(pre=self.hab.pre)
            smids.remove(self.hab.mhab.pre)

            for recp in smids:  # this goes to other participants only as a signaling mechanism
                exn, atc = grouping.multisigRpyExn(ghab=self.hab, rpy=msg)
                self.postman.send(src=self.hab.mhab.pre,
                                  dest=recp,
                                  topic="multisig",
                                  serder=exn,
                                  attachment=atc)

        while not self.hab.loadEndRole(cid=self.hab.pre, role=self.role, eid=self.eid):
            yield self.tock

        self.witpub.msgs.append(dict(pre=self.hab.pre, msg=bytes(msg)))

        while not self.witpub.cues:
            yield self.tock

        print(f"End role authorization added for role {self.role}")

        self.remove(self.toRemove)
        return
