# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
from ordered_set import OrderedSet as oset

from hio import help
from hio.base import doing

from keri.app import habbing, forwarding, grouping
from keri.app.cli.common import existing
from keri.core.coring import Ilks
from keri.core import serdering

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Notify other participants of the last event in a group multisig AID')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument("--config", "-c", help="directory override for configuration data")

# Authentication for keystore
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--aeid', help='qualified base64 of non-transferable identifier prefix for  authentication '
                                   'and encryption of secrets in keystore', default=None)


def handler(args):
    """
    Send the /multisig/rot EXN notification message to other members of a multisig group about the last event in the KEL
    Args:
        args(Namespace): arguments object from command line
    """

    name = args.name
    base = args.base
    bran = args.bran
    alias = args.alias

    noticeDoer = NoticeDoer(name=name, base=base, alias=alias, bran=bran)

    doers = [noticeDoer]
    return doers


class NoticeDoer(doing.DoDoer):
    """ DoDoer Sending EXN notices to other participants.
    """

    def __init__(self, name, base, alias, bran):

        hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer
        self.alias = alias
        self.hby = hby

        self.postman = forwarding.Postman(hby=self.hby)
        doers = [self.hbyDoer, self.postman, doing.doify(self.noticeDo)]

        super(NoticeDoer, self).__init__(doers=doers)

    def noticeDo(self, tymth, tock=0.0):
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

        hab = self.hby.habByName(name=self.alias)

        if hab.group:
            (smids, rmids) = hab.members()
            serder = hab.kever.serder
            rot = hab.makeOwnEvent(sn=hab.kever.sn)
            eserder = serdering.SerderKERI(raw=rot)
            del rot[:eserder.size]

            ilk = serder.ked['t']
            others = list(oset(smids + (rmids or [])))  # list(rec.smids)
            others.remove(hab.mhab.pre)

            if ilk in (Ilks.rot,):
                print(f"Sending rot event to {len(others)} participants.")
                exn, ims = grouping.multisigRotateExn(hab,
                                                      aids=smids,
                                                      smids=smids,
                                                      rmids=rmids,
                                                      ked=serder.ked)
            elif ilk in (Ilks.icp,):
                print(f"Sending icp event to {len(others)} participants.")
                exn, ims = grouping.multisigInceptExn(hab,
                                                      aids=smids,
                                                      ked=serder.ked)
            elif ilk in (Ilks.ixn,):
                print(f"Sending ixn event to {len(others)} participants.")
                exn, ims = grouping.multisigInteractExn(hab,
                                                        aids=smids,
                                                        sn=serder.sn,
                                                        data=serder.ked["a"])
            else:
                raise ValueError(f"unsupport event type={ilk}")

            for recpt in others:
                self.postman.send(src=hab.mhab.pre, dest=recpt, topic="multisig",
                                  serder=eserder, attachment=rot)
                self.postman.send(src=hab.mhab.pre,
                                  dest=recpt,
                                  topic="multisig",
                                  serder=exn,
                                  attachment=ims)

            while len(self.postman.cues) != (2 * len(others)):
                yield self.tock

            print(f"Notice for event #{serder.sn} ({serder.ked['t']}) sent.")
            toRemove = [self.hbyDoer, self.postman]
            self.remove(toRemove)

        return
