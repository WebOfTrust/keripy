from hio import help
from hio.base import doing
from hio.help import decking

from keri.app import agenting, grouping
from keri.vdr import issuing, viring

logger = help.ogler.getLogger()


class RegistryInceptDoer(doing.DoDoer):

    def __init__(self, hab, msgs=None, cues=None, **kwa):

        self.hab = hab
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        self.issuer = None
        self.gdoer = grouping.MultiSigGroupDoer(hab=hab)

        doers = [self.gdoer, doing.doify(self.inceptDo, **kwa)]
        super(RegistryInceptDoer, self).__init__(doers=doers)


    def inceptDo(self, tymth, tock=0.0, **kwa):
        """
        Returns:  doifiable Doist compatible generator method for creating a registry
        and sending its inception and anchoring events to witnesses or backers

        Usage:
            add result of doify on this method to doers list
        """
        # start enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)  # finish enter context

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                name = msg["name"]

                reger = viring.Registry(name=self.hab.name, temp=False)
                self.issuer = issuing.Issuer(hab=self.hab, name=name, reger=reger, noBackers=True, **kwa)
                self.extend([doing.doify(self.escrowDo), doing.doify(self.issuerDo)])
                yield self.tock

                while self.issuer.regk not in self.issuer.tevers:
                    yield self.tock

                yield self.tock

            yield self.tock


    def issuerDo(self, tymth, tock=0.0, **opts):
        """
        Process cues from credential issue coroutine

        Parameters:
            tymth is injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock is injected initial tock value
            opts is dict of injected optional additional parameters
        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.issuer.cues:
                cue = self.issuer.cues.popleft()
                cueKin = cue['kin']
                if cueKin == "send":
                    tevt = cue["msg"]
                    witSender = agenting.WitnessPublisher(hab=self.hab, msg=tevt)
                    self.extend([witSender])

                    while not witSender.done:
                        _ = yield self.tock

                    self.remove([witSender])
                    self.cues.append(dict(kin="finished", regk=self.issuer.regk))

                elif cueKin == "kevt":
                    kevt = cue["msg"]
                    witDoer = agenting.WitnessReceiptor(hab=self.hab, msg=kevt)
                    self.extend([witDoer])

                    while not witDoer.done:
                        yield self.tock

                    self.remove([witDoer])

                elif cueKin == "multisig":
                    msg = dict(
                        op=cue["op"],
                        data=cue["data"],
                        reason=cue["reason"]
                    )
                    self.gdoer.msgs.append(msg)
                elif cueKin == "logEvent":
                    self.cues.append(dict(kin="finished", regk=self.issuer.regk))


                yield self.tock
            yield self.tock


    def escrowDo(self, tymth, tock=0.0):
        """
        Returns:  doifiable Doist compatible generator method

        Usage:
            add result of doify on this method to doers list

        Processes the Groupy escrow for group icp, rot and ixn request messages.

        """
        # start enter context
        yield  # enter context
        while True:
            self.issuer.processEscrows()
            yield
