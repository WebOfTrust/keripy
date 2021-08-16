import json
import os
import shutil
import time

from hio.base import doing, tyming
from keri.app import habbing, indirecting
from keri.app.cli.commands import incept, rotate, interact

TEST_DIR = os.path.dirname(os.path.abspath(__file__))


def test_kel_commands():
    for name in ["wan", "wil", "wes", "test"]:
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

        filepath = os.path.join(TEST_DIR, "gleif-sample.json")
        with open(filepath) as f:
            config = json.load(f)
            opts = incept.InceptOptions(**config)

        kwa = opts.__dict__
        sigr = incept.InceptDoer(name="test", proto="tcp", **kwa)
        self.extend([sigr])
        while not sigr.done:
            yield self.tock

        self.remove([sigr])

        with habbing.existingHab(name="test") as hab:
            assert hab.pre == "Ems5zxn7vzINGbPorX0HvS6izl4ittTKTIkcvJLPSNzA"
            assert hab.kever.ilk == "icp"
            assert hab.kever.sn == 0
            assert hab.kever.tholder.sith == "1"
            assert len(hab.kever.verfers) == 3
            assert hab.kever.verfers[0].qb64 == "Df--qltU7JlBgxNouIGQKg6wYCWlRu6S1y1Xf60MzDRs"
            assert hab.kever.verfers[1].qb64 == "DP1QDQAP1T9yvUXwqiXLyDOP-eXGDAf87DxP9OQTVcVg"
            assert hab.kever.verfers[2].qb64 == "DdPRgRm99DRSE14UNvOJGpkAC7gxIIP7vEE_Aq2cbkQE"

        seal = dict(
            p="EUX0_NKihYcmvuTOSFnLcIf4xhAn0MaAI2FJoCN-gspc",
            s=0,
            d="EpXprWFWmvJx4dP7CqDyXRgoigTVFwEUh6i-6jUCcoU8"
        )

        rotr = rotate.RotateDoer(name="test", sith="2", count=3, proto="tcp", data=[seal])
        self.extend([rotr])
        while not rotr.done:
            yield self.tock

        self.remove([rotr])

        with habbing.existingHab(name="test") as hab:
            assert hab.pre == "Ems5zxn7vzINGbPorX0HvS6izl4ittTKTIkcvJLPSNzA"
            assert hab.kever.ilk == "rot"
            assert hab.kever.sn == 1
            assert hab.kever.tholder.sith == "1"
            assert hab.kever.serder.ked["a"] == [seal]
            assert len(hab.kever.verfers) == 5
            assert hab.kever.verfers[0].qb64 == "DGoZ_S3Q6EvFWVQIxeJj7mV_RSpZZkXpy4zpD3iBOuPg"
            assert hab.kever.verfers[1].qb64 == "DwPgRbOOcLcLDOaerqbGLJZr95xvufLbiuBAUsDBBjNI"
            assert hab.kever.verfers[2].qb64 == "DayE5e3tLMTbzvf2jRItNXGJYRCVobc37r4BV5WYgJMI"
            assert hab.kever.verfers[3].qb64 == "D6yqQbt-YIHUTa8UN5j8T64vq7hGavt8P4C625RKDuSY"
            assert hab.kever.verfers[4].qb64 == "DWjoQfaTHufA5Vz-57GyH_hyYJnomADhuMFVjJTDd6Y0"

        seal1 = dict(
            p="ExvDJbZwXBw1YAQJZlLNxuZXL1vaRnNOulyAqvD4BywU",
            s=3,
            d="E1VpyPRON7sMTKhWB8JVzlknLMTMeCq39MJgJ_jl1kKQ"
        )

        ixnr = interact.InteractDoer(name="test", proto="tcp", data=[seal1])
        self.extend([ixnr])
        while not ixnr.done:
            yield self.tock

        self.remove([ixnr])

        with habbing.existingHab(name="test") as hab:
            assert hab.pre == "Ems5zxn7vzINGbPorX0HvS6izl4ittTKTIkcvJLPSNzA"
            assert hab.kever.ilk == "ixn"
            assert hab.kever.sn == 2
            assert hab.kever.tholder.sith == "1"
            assert hab.kever.serder.ked["a"] == [seal1]
            assert len(hab.kever.verfers) == 5
            assert hab.kever.verfers[0].qb64 == "DGoZ_S3Q6EvFWVQIxeJj7mV_RSpZZkXpy4zpD3iBOuPg"
            assert hab.kever.verfers[1].qb64 == "DwPgRbOOcLcLDOaerqbGLJZr95xvufLbiuBAUsDBBjNI"
            assert hab.kever.verfers[2].qb64 == "DayE5e3tLMTbzvf2jRItNXGJYRCVobc37r4BV5WYgJMI"
            assert hab.kever.verfers[3].qb64 == "D6yqQbt-YIHUTa8UN5j8T64vq7hGavt8P4C625RKDuSY"
            assert hab.kever.verfers[4].qb64 == "DWjoQfaTHufA5Vz-57GyH_hyYJnomADhuMFVjJTDd6Y0"
