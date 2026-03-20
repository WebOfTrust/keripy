# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.delegate module

"""
import argparse

from hio.base import doing
from hio.help import ogler

from ...common import setupHby, Parsery

from ....app import (GroupHab, HaberyDoer, WitnessInquisitor,
                     Counselor, Poster, delegateRequestExn)
from ....core import SerderKERI


logger = ogler.getLogger()

parser = argparse.ArgumentParser(description='Resend a delegation request message to a delegator that has not '
                                             'approved a previous delegation.',
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: request(args))
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)

def request(args):
    """

    Parameters:
        args(Namespace): parsed arguements namespace object

    """
    name = args.name
    base = args.base
    bran = args.bran
    alias = args.alias

    requestDoer = RequestDoer(name=name, base=base, alias=alias, bran=bran)

    doers = [requestDoer]
    return doers


class RequestDoer(doing.DoDoer):
    def __init__(self, name, base, alias, bran):
        hby = setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = HaberyDoer(habery=hby)  # setup doer
        self.witq = WitnessInquisitor(hby=hby)
        self.postman = Poster(hby=hby)
        self.counselor = Counselor(hby=hby)
        doers = [self.hbyDoer, self.postman]
        self.toRemove = list(doers)
        doers.extend([doing.doify(self.requestDo)])

        self.alias = alias
        self.hby = hby

        super(RequestDoer, self).__init__(doers=doers)

    def requestDo(self, tymth, tock=0.0, **kwa):
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
        delpre = hab.kever.delpre  # get the delegator identifier

        if isinstance(hab, GroupHab):
            phab = hab.mhab
        else:
            phab = self.hby.habByName(f"{self.alias}-proxy")

        exn, atc = delegateRequestExn(hab.mhab, delpre=delpre, evt=bytes(evt), aids=hab.smids)

        # delegate AID ICP and exn of delegation request EXN
        srdr = SerderKERI(raw=evt)
        del evt[:srdr.size]
        self.postman.send(src=phab.pre, dest=delpre, topic="delegate", serder=srdr, attachment=evt)
        self.postman.send(src=phab.pre, dest=hab.kever.delpre, topic="delegate", serder=exn, attachment=atc)

        while True:
            while self.postman.cues:
                cue = self.postman.cues.popleft()
                if "said" in cue and cue["said"] == exn.said:
                    print("Delegation request resent")
                    self.remove(self.toRemove)
                    return True
                yield self.tock
            yield self.tock
