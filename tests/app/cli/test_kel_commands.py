import time

from hio.base import doing, tyming
from keri.app import habbing, indirecting


def test_kel_commands():
    with habbing.openHab(name="wan", salt=b'wann-the-witness', transferable=False, temp=False) as wanHab, \
            habbing.openHab(name="wil", salt=b'will-the-witness', transferable=False, temp=False) as wilHab, \
            habbing.openHab(name="wes", salt=b'wess-the-witness', transferable=False, temp=False) as wesHab:

        wanDoers = indirecting.setupWitness(name="wan", hab=wanHab, temp=False, tcpPort=5632, httpPort=5642)
        wilDoers = indirecting.setupWitness(name="wil", hab=wilHab, temp=False, tcpPort=5633, httpPort=5643)
        wesDoers = indirecting.setupWitness(name="wes", hab=wesHab, temp=False, tcpPort=5634, httpPort=5644)

        inceptor = CommandDoer()
        doers = wanDoers + wilDoers + wesDoers + [inceptor]

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=doers)
        doist.enter()

        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not tymer.expired:
            doist.recur()
            time.sleep(doist.tock)
        # doist.do(doers=doers)

        assert doist.limit == limit


class CommandDoer(doing.DoDoer):
    """
    DoDoer for running thru the KEL `kli` commands for incepting, rotating and
    creating interaction events.

    """
    def __init__(self, **kwa):

        super(CommandDoer, self).__init__(**kwa)


    def commandDo(self):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        yield self.tock  # enter context
