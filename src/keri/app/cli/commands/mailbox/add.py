# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing
from hio.help import Hict

from keri import kering
from keri.app import connecting, habbing, forwarding
from keri.app.agenting import httpClient, WitnessPublisher
from keri.app.cli.common import existing
from keri.core import serdering

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Add mailbox role')
parser.set_defaults(handler=lambda args: add(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--alias', '-a', help='human readable alias for the identifier to whom the credential was issued',
                    required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument("--mailbox", '-w', help="the mailbox AID or alias to add", required=True)


def add(args):
    """ Command line handler for adding an aid to a watcher's list of AIds to watch

    Parameters:
        args(Namespace): parsed command line arguments

    """

    ed = AddDoer(name=args.name,
                 alias=args.alias,
                 base=args.base,
                 bran=args.bran,
                 mailbox=args.mailbox)
    return [ed]


class AddDoer(doing.DoDoer):

    def __init__(self, name, alias, base, bran, mailbox):
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hab = self.hby.habByName(alias)
        self.org = connecting.Organizer(hby=self.hby)
        self.witpub = WitnessPublisher(hby=self.hby)

        if mailbox in self.hby.kevers:
            mbx = mailbox
        else:
            mbx = self.org.find("alias", mailbox)
            if len(mbx) != 1:
                raise ValueError(f"invalid mailbox {mailbox}")
            mbx = mbx[0]['id']

        if not mbx:
            raise ValueError(f"unknown mailbox {mailbox}")

        self.mailbox = mbx

        doers = [doing.doify(self.addDo), self.witpub]

        super(AddDoer, self).__init__(doers=doers)

    def addDo(self, tymth, tock=0.0):
        """ Grant credential by creating /ipex/grant exn message

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

        if isinstance(self.hab, habbing.GroupHab):
            raise ValueError("watchers for multisig AIDs not currently supported")

        kel = self.hab.replay()
        data = dict(cid=self.hab.pre,
                    role=kering.Roles.mailbox,
                    eid=self.mailbox)

        route = "/end/role/add"
        msg = self.hab.reply(route=route, data=data)
        self.hab.psr.parseOne(ims=(bytes(msg)))  # make copy to preserve

        fargs = dict([("kel", kel.decode("utf-8")),
                      ("rpy", msg.decode("utf-8"))])

        headers = (Hict([
            ("Content-Type", "multipart/form-data"),
        ]))

        client, clientDoer = httpClient(self.hab, self.mailbox)
        self.extend([clientDoer])

        client.request(
            method="POST",
            path=f"{client.requester.path}/mailboxes",
            headers=headers,
            fargs=fargs
        )
        while not client.responses:
            yield self.tock

        rep = client.respond()
        if rep.status == 200:
            msg = self.hab.replyEndRole(cid=self.hab.pre, role=kering.Roles.mailbox)
            self.witpub.msgs.append(dict(pre=self.hab.pre, msg=bytes(msg)))

            while not self.witpub.cues:
                yield self.tock

            print(f"Mailbox {self.mailbox} added for {self.hab.name}")

        else:
            print(rep.status, rep.data)

        self.remove([clientDoer, self.witpub])
