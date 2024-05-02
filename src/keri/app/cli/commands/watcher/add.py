# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing

from keri.app import connecting, habbing, forwarding
from keri.app.cli.common import existing
from keri.core import eventing, serdering

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Add AID or Alias to list of AIDs for a watcher to watch')
parser.set_defaults(handler=lambda args: add(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--alias', '-a', help='human readable alias for the identifier to whom the credential was issued',
                    required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument("--watcher", '-w', help="the watcher AID or alias to add to", required=True)
parser.add_argument("--watched", '-W', help="the watched AID or alias to add")


def add(args):
    """ Command line handler for adding an aid to a watcher's list of AIds to watch

    Parameters:
        args(Namespace): parsed command line arguments

    """

    ed = AddDoer(name=args.name,
                 alias=args.alias,
                 base=args.base,
                 bran=args.bran,
                 watcher=args.watcher,
                 watched=args.watched)
    return [ed]


class AddDoer(doing.DoDoer):

    def __init__(self, name, alias, base, bran, watcher, watched):
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hab = self.hby.habByName(alias)
        self.org = connecting.Organizer(hby=self.hby)

        if watcher in self.hby.kevers:
            wat = watcher
        else:
            wat = self.org.find("alias", watcher)
            if len(wat) != 1:
                raise ValueError(f"invalid recipient {watcher}")
            wat = wat[0]['id']

        if not wat:
            raise ValueError(f"unknown watcher {watcher}")

        if watched in self.hby.kevers:
            watd = watched
        else:
            watd = self.org.find("alias", watched)
            if len(watd) != 1:
                raise ValueError(f"invalid recipient {watched}")
            watd = watd[0]['id']

        if not watd:
            raise ValueError(f"unknown watched {watched}")

        self.watcher = wat
        self.watched = watd

        self.oobi = None
        for (key,), obr in self.hby.db.roobi.getItemIter():
            if obr.cid == watd:
                self.oobi = key

        if not self.oobi:
            raise ValueError(f"no valid oobi for watched {self.watched}")

        doers = [doing.doify(self.addDo)]

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

        postman = forwarding.StreamPoster(hby=self.hby, hab=self.hab, recp=self.watcher, topic="reply")
        for msg in self.hab.db.clonePreIter(pre=self.hab.pre):
            serder = serdering.SerderKERI(raw=msg)
            postman.send(serder=serder, attachment=msg[serder.size:])

        data = dict(cid=self.hab.pre,
                    wid=self.watched,
                    oobi=self.oobi)

        route = "/watcher/aid/add"
        msg = self.hab.reply(route=route, data=data)
        rpy = serdering.SerderKERI(raw=msg)
        postman.send(serder=rpy, attachment=msg[rpy.size:])

        doer = doing.DoDoer(doers=postman.deliver())
        self.extend([doer])

        while not doer.done:
            yield self.tock

        print(f"Request to add {self.watched} to watcher {self.watcher} submitted.")
