# -*- encoding: utf-8 -*-
"""
tests.app.cli.commands.multisig

"""

import json
import os
import shutil

from hio.base import doing

from keri.app import indirecting, habbing
from keri.app.cli.commands import incept
from keri.app.cli.commands.multisig.incept import MultiSigInceptOptions, MultiSigInceptDoer
from keri.db import dbing

TEST_DIR = os.path.dirname(os.path.abspath(__file__))

# logger = help.ogler.getLogger()


def test_incept():
    """
    Test the command line interface commands for inception and multi-sig
    distributed keystore inception from all of the seeding identity controllers


    """

    # help.ogler.resetLevel(level=logging.DEBUG)

    for name in ["wan", "wil", "wes", "multisig1", "multisig2", "multisig3"]:
        if os.path.exists('/usr/local/var/keri/db/{}'.format(name)):
            shutil.rmtree('/usr/local/var/keri/db/{}'.format(name))
        if os.path.exists('/usr/local/var/keri/keep/{}'.format(name)):
            shutil.rmtree('/usr/local/var/keri/keep/{}'.format(name))


    with habbing.openHab(name="wan", salt=b'wann-the-witness', transferable=False, temp=False) as wanHab, \
            habbing.openHab(name="wil", salt=b'will-the-witness', transferable=False, temp=False) as wilHab, \
            habbing.openHab(name="wes", salt=b'wess-the-witness', transferable=False, temp=False) as wesHab:

        wanDoers = indirecting.setupWitness(name="wan", hab=wanHab, temp=False, tcpPort=5632, httpPort=5642)
        wilDoers = indirecting.setupWitness(name="wil", hab=wilHab, temp=False, tcpPort=5633, httpPort=5643)
        wesDoers = indirecting.setupWitness(name="wes", hab=wesHab, temp=False, tcpPort=5634, httpPort=5644)

        inceptor = InceptingDoer()
        doers = wanDoers + wilDoers + wesDoers + [inceptor]

        limit = 10.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit)
        doist.do(doers=doers)

        assert doist.limit == limit

        preb = b'Ep4WexrfQvQjblYg9ti12cr7NpKWaXLNP5CXmq_4Zhng'
        digb = b'E5_qNBzfkBc2kWAzGn5UUWhWUVrX4Yk1QBpVXHucygfk'
        dgkey = dbing.dgKey(preb, digb)

        # wigs = wanHab.db.getWigs(dgkey)
        # assert len(wigs) == 3
        # wigs = wilHab.db.getWigs(dgkey)
        # assert len(wigs) == 3
        # wigs = wesHab.db.getWigs(dgkey)
        # assert len(wigs) == 3



class InceptingDoer(doing.DoDoer):

    def __init__(self, **kwa):

        super(InceptingDoer, self).__init__(doers=[self.inceptDo], **kwa)

    @doing.doize()
    def inceptDo(self, tymth=None, tock=0.0):
        yield self.tock

        sigs = ["multisig1", "multisig2", "multisig3"]
        # Create three separate identifiers to seed the multisig group identifier
        for i, sig in enumerate(sigs):
            sigr = incept.InceptDoer(name=sig, proto="tcp", opts=loadInceptOpts(f"multisig-{i+1}-sample.json"))
            self.extend([sigr])
            while not sigr.done:
                yield self.tock

            self.remove([sigr])
            yield self.tock


        for sig in sigs:
            msd = MultiSigInceptDoer(name=sig, opts=loadMultiInceptOpts("multisig-sample.json"))
            self.extend([msd])

            while not msd.done:
                yield self.tock

            self.remove([msd])
            yield self.tock



def loadInceptOpts(filename):
    filepath = os.path.join(TEST_DIR, filename)
    with open(filepath) as f:
        config = json.load(f)
        return incept.InceptOptions(**config)


def loadMultiInceptOpts(filename):
    filepath = os.path.join(TEST_DIR, filename)
    with open(filepath) as f:
        config = json.load(f)
        return MultiSigInceptOptions(**config)


if __name__ == '__main__':
    test_incept()
