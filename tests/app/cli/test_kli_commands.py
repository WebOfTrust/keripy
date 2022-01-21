import os
import shutil
import subprocess

import time
from hio.base import doing, tyming

from keri.app import habbing, indirecting, configing
from keri.core import coring

TEST_DIR = os.path.dirname(os.path.abspath(__file__))


def remove_test_dirs(name):
    if os.path.exists(f'/usr/local/var/keri/db/{name}'):
        shutil.rmtree(f'/usr/local/var/keri/db/{name}')
    if os.path.exists(f'/usr/local/var/keri/ks/{name}'):
        shutil.rmtree(f'/usr/local/var/keri/ks/{name}')
    if os.path.exists(f'/usr/local/var/keri/cf/{name}.json'):
        os.remove(f'/usr/local/var/keri/cf/{name}.json')


def test_standalone_kli_commands():
    remove_test_dirs("test")
    script = os.path.join(TEST_DIR.rstrip("tests/app/cli"), "scripts/demo/demo-script.sh")
    res = subprocess.run(["bash", script])

    assert res.returncode == 0


def test_kel_commands():
    remove_test_dirs("witness-test")

    for name in ["wan", "wil", "wes", "test"]:
        if os.path.exists('/usr/local/var/keri/db/{}'.format(name)):
            shutil.rmtree('/usr/local/var/keri/db/{}'.format(name))
        if os.path.exists('/usr/local/var/keri/ks/{}'.format(name)):
            shutil.rmtree('/usr/local/var/keri/ks/{}'.format(name))
        if os.path.exists('/usr/local/var/keri/cf/{}.json'.format(name)):
            os.remove('/usr/local/var/keri/cf/{}.json'.format(name))

    wancf = configing.Configer(name="wan", headDirPath="config", temp=False, reopen=True, clear=False)
    wilcf = configing.Configer(name="wil", headDirPath="config", temp=False, reopen=True, clear=False)
    wescf = configing.Configer(name="wes", headDirPath="config", temp=False, reopen=True, clear=False)

    with habbing.openHby(name="wan", salt=coring.Salter(raw=b'wann-the-witness').qb64, temp=False, cf=wancf) as wanHby, \
            habbing.openHby(name="wil", salt=coring.Salter(raw=b'will-the-witness').qb64, temp=False,
                            cf=wilcf) as wilHby, \
            habbing.openHby(name="wes", salt=coring.Salter(raw=b'wess-the-witness').qb64, temp=False,
                            cf=wescf) as wesHby:

        wanDoers = indirecting.setupWitness(alias="wan", hby=wanHby, tcpPort=5632, httpPort=5642)
        wilDoers = indirecting.setupWitness(alias="wil", hby=wilHby, tcpPort=5633, httpPort=5643)
        wesDoers = indirecting.setupWitness(alias="wes", hby=wesHby, tcpPort=5634, httpPort=5644)

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

        doist.exit()


class CommandDoer(doing.DoDoer):
    """
    DoDoer for running thru the KEL `kli` commands for incepting, rotating and
    creating interaction events.

    """

    def __init__(self, **kwa):

        super(CommandDoer, self).__init__(doers=[doing.doify(self.commandDo)], **kwa)

    def commandDo(self, tymth=None, tock=0.0):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        yield self.tock  # enter context

        # TODO: launch subprocess with Hio that won't block
        # script = os.path.join(TEST_DIR.rstrip("tests/app/cli"), "scripts/demo/demo-witness-script.sh")
        # res = subprocess.run(["bash", script])
        #
        # assert res.returncode == 0
