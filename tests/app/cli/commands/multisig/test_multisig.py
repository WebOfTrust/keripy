# -*- encoding: utf-8 -*-
"""
tests.app.cli.commands.multisig

"""

import json
import os
import shutil
import time

from hio.base import doing, tyming

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
        doist = doing.Doist(tock=tock, limit=limit, doers=doers)
        doist.enter()

        #assert inceptor.members
        #assert not inceptor.group

        #hab1 = inceptor.members[0].doer.hab
        #assert hab1.pre == 'Eu_se69BU6tYdF2o-YD411OzwbvImOfu1m023Bu8FM_I'
        #assert hab1.db.path == '/usr/local/var/keri/db/multisig1'

        #hab2 = inceptor.members[1].doer.hab
        #assert hab2.pre == 'EEWuHgyO9iTgfz43mtY1IaRH-TrmV-YpcbpPoKKSpz8U'
        #assert hab2.db.path == '/usr/local/var/keri/db/multisig2'

        #hab3 = inceptor.members[2].doer.hab
        #assert hab3.pre == 'E5JuUB6iOaKV5-0EeADj0S3KCvvkUZDnuLw8VPK8Qang'
        #assert hab3.db.path == '/usr/local/var/keri/db/multisig3'

        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not tymer.expired:
            doist.recur()
            time.sleep(doist.tock)
        # doist.do(doers=doers)

        assert doist.limit == limit

        doist.exit()

        preb = b'Ep4WexrfQvQjblYg9ti12cr7NpKWaXLNP5CXmq_4Zhng'  # multisig aid
        digb = b'E5_qNBzfkBc2kWAzGn5UUWhWUVrX4Yk1QBpVXHucygfk'  # multisig inception digest
        dgkey = dbing.dgKey(preb, digb)

        wigs = wanHab.db.getWigs(dgkey)
        # assert len(wigs) == 3
        wigs = wilHab.db.getWigs(dgkey)
        # assert len(wigs) == 3
        wigs = wesHab.db.getWigs(dgkey)
        # assert len(wigs) == 3


#@dataclass
#class Member:
    #"""
    #Multi-sig group member
    #"""
    #name: str  # name of member in group
    #index: int  # index of member in group
    #doer: doing.DoDoer  # DoDoer of member  doer.hab for database

#@dataclass
#class Group:
    #"""
    #Multi-sig group id
    #"""
    #name: str  # name of group
    #count: int  # number of members in group
    #sith: int  # signing threshold
    #doer: doing.DoDoer  # DoDoer of group doer.hab for database

#class InceptingDoer(doing.DoDoer):

    #def __init__(self, **kwa):
        #super(InceptingDoer, self).__init__(doers=[doing.doify(self.inceptDo)], **kwa)
        #self.members = []
        #self.group = None


    #def inceptDo(self, tymth=None, tock=0.0):
        #"""
        #Create Member Doers with habitats
        #Returns:  doifiable Doist compatible generator method
        #Usage:
            #add result of doify on this method to doers list
        #"""
        ## start enter context
        #for i in range(1, 4):
            #name = "multisig" + str(i)
            #doer = incept.InceptDoer(name=name, proto="tcp", opts=loadInceptOpts(f"multisig-{i}-sample.json"))
            #self.members.append(Member(index=i, name=name, doer=doer))
        #self.extend([member.doer for member in self.members])

        #yield self.tock  # finish enter context

        ## start recur context
        #for member in self.members:
            #while not member.doer.done:
                #yield self.tock

            #self.remove([member.doer])
            #yield self.tock

        #member = self.members[0]
        #name = "groupby" + member.name
        #doer = MultiSigInceptDoer(name=name,
                                 #opts=loadMultiInceptOpts("multisig-sample.json"))
        #group = Group(name=name, count=len(members), sith=2, doer=doer)
        #self.extend([group.doer])
        #while not group.doer.done:
            #yield self.tock

        #self.remove([group.doer.done])
        #yield self.tock



class InceptingDoer(doing.DoDoer):
    """
    DoDoer for running the multisig scenario to test the multisig
    `kli` commands.

    """

    def __init__(self, **kwa):

        super(InceptingDoer, self).__init__(doers=[doing.doify(self.inceptDo)], **kwa)


    def inceptDo(self, tymth=None, tock=0.0):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        yield self.tock  # enter context

        sigs = ["multisig1", "multisig2", "multisig3"]
        # Create three separate identifiers to seed the multisig group identifier
        for i, sig in enumerate(sigs):
            opts = loadInceptOpts(f"multisig-{i+1}-sample.json")
            kwa = opts.__dict__
            sigr = incept.InceptDoer(name=sig, proto="tcp", **kwa)
            self.extend([sigr])
            while not sigr.done:
                yield self.tock

            self.remove([sigr])
            yield self.tock

        for sig in sigs:
            opts = loadMultiInceptOpts("multisig-sample.json")
            kwa = opts.__dict__
            msd = MultiSigInceptDoer(name=sig, **kwa)
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
