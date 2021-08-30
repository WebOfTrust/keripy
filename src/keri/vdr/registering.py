from hio import help
from hio.base import doing
from hio.help import decking

from keri.app import agenting
from keri.vdr import issuing

logger = help.ogler.getLogger()


class RegistryInceptDoer(doing.DoDoer):

    def __init__(self, hab, msgs=None, cues=None, **kwa):

        self.hab = hab
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()

        doers = [doing.doify(self.inceptDo, **kwa)]
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

                issuer = issuing.Issuer(hab=self.hab, name=name, **kwa)
                yield self.tock

                tevt = issuer.incept
                kevt = issuer.ianchor

                witDoer = agenting.WitnessReceiptor(hab=self.hab, msg=kevt)
                witSender = agenting.WitnessPublisher(hab=self.hab, msg=tevt)
                self.extend([witDoer, witSender])
                _ = yield self.tock

                while not witDoer.done:
                    _ = yield self.tock

                while not witSender.done:
                    _ = yield self.tock

                self.remove([witDoer, witSender])

                self.cues.append(dict(regk=issuer.regk))

                yield self.tock

            yield self.tock
