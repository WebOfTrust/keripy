# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing

from keri import kering
from keri.app import indirecting, habbing, forwarding, grouping
from keri.app.cli.common import existing
from keri.core import eventing, parsing, coring

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
parser.add_argument("--role", "-r", help="KERI enpoint authorization role.",
                    required=True)
parser.add_argument("--eid", "-e", help="qualified base64 of AID to authorize with new role for the AID identified "
                                        "by alias",
                    required=False, default=None)


def add_end(args):
    """ Command line tool for adding endpoint role authorizations

    """
    ld = RoleDoer(name=args.name,
                  base=args.base,
                  alias=args.alias,
                  bran=args.bran,
                  role=args.role,
                  eid=args.eid)
    return [ld]


class RoleDoer(doing.DoDoer):

    def __init__(self, name, base, alias, bran, role, eid):
        self.role = role
        self.eid = eid

        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hab = self.hby.habByName(alias)
        self.mbx = indirecting.MailboxDirector(hby=self.hby, topics=['/receipt', '/multisig', '/replay',
                                                                     '/delegate'])
        self.postman = forwarding.Poster(hby=self.hby)

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

        data = dict(cid=self.hab.pre, role=self.role)
        if self.eid is not None:
            data['eid'] = self.eid

        route = "/end/role/add"
        msg = self.hab.reply(route=route, data=data)

        parsing.Parser().parse(ims=bytes(msg), kvy=self.hab.kvy, rvy=self.hab.rvy)

        if isinstance(self.hab, habbing.GroupHab):
            serder = coring.Serder(raw=msg)
            del msg[:serder.size]
            exn, atc = grouping.multisigRpyExn(self.hab, rpy=serder)

            smids = self.hab.db.signingMembers(self.hab.pre)
            smids.remove(self.hab.pre)
            for smid in smids:
                self.postman.send(hab=self.hab.mhab, dest=smid, topic="multisig", serder=serder, attachment=msg)
                self.postman.send(hab=self.hab.mhab, dest=smid, topic="multisig", serder=exn, attachment=atc)

        while not self.hab.loadEndRole(cid=self.hab.pre, role=self.role, eid=self.eid):
            yield self.tock

        self.remove([self.mbx])
        return
