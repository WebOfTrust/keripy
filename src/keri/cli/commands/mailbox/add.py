# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
from urllib import parse

from hio.base import doing
from hio.help import Hict, ogler

from ...common import Parsery, setupHby, parseVersion

from ....kering import Kinds, Roles
from ....app import (Organizer, GroupHab,
                     WitnessPublisher, httpClient)


logger = ogler.getLogger()

parser = argparse.ArgumentParser(description='Add mailbox role',
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: add(args))
parser.add_argument('--alias', '-a', help='human readable alias for the identifier to whom the credential was issued',
                    required=True)
parser.add_argument("--mailbox", '-w', help="the mailbox AID or alias to add", required=True)
parser.add_argument("--version", default=None, type=parseVersion,
                    help="KERI protocol and CESR genus version for replay and replies, such as 1.0 or 2.0")


def add(args):
    """Authorize a mailbox using the selected protocol and attachment versions.

    Parameters:
        args(Namespace): parsed command line arguments

    """

    ed = AddDoer(name=args.name,
                 alias=args.alias,
                 base=args.base,
                 bran=args.bran,
                 mailbox=args.mailbox,
                 version=args.version)
    return [ed]


class AddDoer(doing.DoDoer):
    """Publish mailbox authorization and its supporting replay in one selected genus."""

    def __init__(self, name, alias, base, bran, mailbox, version=None):
        """Open the controller with explicit version context, or the current default."""
        self.hby = setupHby(name=name, base=base, bran=bran, version=version)
        self.version = self.hby.version
        self.replyKwargs = (dict(version=version, gvrsn=version, kind=Kinds.json)
                            if version is not None else {})
        self.hab = self.hby.habByName(alias)
        self.org = Organizer(hby=self.hby)
        self.witpub = WitnessPublisher(hby=self.hby)

        if mailbox in self.hby.kevers:
            mbx = mailbox
        else:
            mbx = self.org.findExact("alias", mailbox)
            if len(mbx) == 0:
                raise ValueError(f"no contact found with alias {mailbox!r}")
            if len(mbx) > 1:
                raise ValueError(f"multiple contacts match alias {mailbox!r}, use prefix instead")
            mbx = mbx[0]['id']

        if not mbx:
            raise ValueError(f"unknown mailbox {mailbox}")

        self.mailbox = mbx

        doers = [doing.doify(self.addDo), self.witpub]

        super(AddDoer, self).__init__(doers=doers)

    def addDo(self, tymth, tock=0.0, **kwa):
        """Send replay plus authorization, then publish the accepted mailbox role.

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Returns:
            doifiable Doist compatible generator method

        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        if isinstance(self.hab, GroupHab):
            raise ValueError("watchers for multisig AIDs not currently supported")

        kel = bytearray(self.hab.replay(gvrsn=self.version))
        delkel = bytearray()
        for dmsg in self.hab.db.cloneDelegation(self.hab.kever, gvrsn=self.version):
            delkel.extend(dmsg)
        data = dict(cid=self.hab.pre,
                    role=Roles.mailbox,
                    eid=self.mailbox)

        route = "/end/role/add"
        msg = self.hab.reply(route=route, data=data, **self.replyKwargs)
        self.hab.psr.parseOne(ims=(bytes(msg)))  # make copy to preserve
        fargs = dict([
            ("kel", kel.decode("utf-8")),
            ("rpy", bytes(msg).decode("utf-8")),
        ])
        if delkel:
            fargs["delkel"] = delkel.decode("utf-8")

        headers = (Hict([
            ("Content-Type", "multipart/form-data"),
        ]))

        client, clientDoer = httpClient(self.hab, self.mailbox)
        self.extend([clientDoer])

        path = parse.urljoin(f"{client.requester.path.rstrip('/')}/", "mailboxes")
        client.request(
            method="POST",
            path=path,
            headers=headers,
            fargs=fargs
        )
        while not client.responses:
            yield self.tock

        rep = client.respond()
        if rep.status == 200:
            msg = self.hab.replyEndRole(cid=self.hab.pre, role=Roles.mailbox, **self.replyKwargs)
            self.witpub.msgs.append(dict(pre=self.hab.pre, msg=bytes(msg)))

            while not self.witpub.cues:
                yield self.tock

            print(f"Mailbox {self.mailbox} added for {self.hab.name}")

        else:
            print(rep.status, rep.data)

        self.remove([clientDoer, self.witpub])
