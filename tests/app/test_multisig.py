# -*- encoding: utf-8 -*-
"""
tests.app.test_multisig module

"""
import json
import os

import falcon
from falcon import testing
from hio.base import doing
from keri import kering
from keri.app import habbing, storing, kiwiing, grouping, indirecting, directing, agenting, booting, notifying
from keri.core import coring, eventing, parsing

TEST_DIR = os.path.dirname(os.path.abspath(__file__))


class TestDoer(doing.DoDoer):

    def __init__(self, wanHby, hby1, hab1, hby2, hab2, seeder):
        self.hby1 = hby1
        self.hby2 = hby2
        self.hab1 = hab1
        self.hab2 = hab2

        wanDoers = indirecting.setupWitness(alias="wan", hby=wanHby, tcpPort=5632, httpPort=5642)
        wanHab = wanHby.habByName("wan")
        seeder.seedWitEnds(self.hby1.db, witHabs=[wanHab], protocols=[kering.Schemes.http])
        seeder.seedWitEnds(self.hby2.db, witHabs=[wanHab], protocols=[kering.Schemes.http])
        # Verify the group identifier was incepted properly and matches the identifiers
        assert wanHab.pre == "B6KBd3GmnWvjcmE775zNRPCsJfOhasjBbyLjUpYOWvyw"
        assert hab1.pre == "EJTo9FQNKETP4Ux5bwE43go-uN04TMnI3auceEv9Ms2A"
        assert hab2.pre == "EgWTotjwstu_4r-LYrZ59j8qhHwX-P0_9En880ADP_i8"

        self.notifier1 = notifying.Notifier(hby=hby1)
        self.notifier2 = notifying.Notifier(hby=hby2)

        self.app1, doers1 = loadApp(hby1, self.notifier1)
        self.app2, doers2 = loadApp(hby2, self.notifier2)

        doers = wanDoers + doers1 + doers2

        self.toRemove = list(doers)
        doers.extend([doing.doify(self.testDo)])

        super(TestDoer, self).__init__(doers=doers)

    def testDo(self, tymth, tock=0.0):
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        witDoer = agenting.WitnessReceiptor(hby=self.hby1)
        self.extend([witDoer])
        witDoer.msgs.append(dict(pre=self.hab1.pre))
        while not witDoer.cues:
            yield self.tock

        cue = witDoer.cues.popleft()
        print(cue)

        self.remove([witDoer])

        witDoer = agenting.WitnessReceiptor(hby=self.hby2)
        self.extend([witDoer])
        witDoer.msgs.append(dict(pre=self.hab2.pre))
        while not witDoer.cues:
            yield self.tock

        cue = witDoer.cues.popleft()
        print(cue)

        self.remove([witDoer])

        kev1 = eventing.Kevery(db=self.hab1.db, lax=True, local=False)
        kev2 = eventing.Kevery(db=self.hab2.db, lax=True, local=False)

        icp1 = self.hab1.db.cloneEvtMsg(pre=self.hab1.pre, fn=0, dig=self.hab1.kever.serder.said)
        icp2 = self.hab2.db.cloneEvtMsg(pre=self.hab2.pre, fn=0, dig=self.hab2.kever.serder.said)
        parsing.Parser().parse(ims=bytearray(icp1), kvy=kev2)
        parsing.Parser().parse(ims=bytearray(icp2), kvy=kev1)

        client1 = testing.TestClient(self.app1)
        client2 = testing.TestClient(self.app2)

        icpd = dict(aids=[self.hab1.pre, self.hab2.pre],
                    transferable=True,
                    toad=0,
                    isith='2',
                    nsith='2'
                    )

        b = json.dumps(icpd).encode("utf-8")
        response = client1.simulate_post("/groups/group1/icp", body=b)
        assert response.status == falcon.HTTP_200
        serder = coring.Serder(ked=response.json)
        assert serder.pre == serder.said == "EtWwBSsPnLKLv53RNR9xHpaXL0mO7X1LMiDG9shzY6f4"
        b = json.dumps(icpd).encode("utf-8")
        response = client2.simulate_put("/groups/group2/icp", body=b)
        assert response.status == falcon.HTTP_200
        serder = coring.Serder(ked=response.json)
        assert serder.pre == serder.said == "EtWwBSsPnLKLv53RNR9xHpaXL0mO7X1LMiDG9shzY6f4"

        while not (ghab1 := self.hby1.habByName("group1")):
            yield self.tock

        assert ghab1.pre == "EtWwBSsPnLKLv53RNR9xHpaXL0mO7X1LMiDG9shzY6f4"

        while not (ghab2 := self.hby2.habByName("group2")):
            yield self.tock

        assert ghab2.pre == "EtWwBSsPnLKLv53RNR9xHpaXL0mO7X1LMiDG9shzY6f4"

        while len(self.notifier1.getNotes()) != 1 or len(self.notifier2.getNotes()) != 1:
            yield self.tock

        note = self.notifier1.getNotes()[0]
        assert note.pad['a']['r'] == "/multisig/icp/complete"
        assert note.pad['a']['a'] == {'i': 'EtWwBSsPnLKLv53RNR9xHpaXL0mO7X1LMiDG9shzY6f4', 's': 0}
        note = self.notifier2.getNotes()[0]
        assert note.pad['a']['r'] == "/multisig/icp/complete"
        assert note.pad['a']['a'] == {'i': 'EtWwBSsPnLKLv53RNR9xHpaXL0mO7X1LMiDG9shzY6f4', 's': 0}

        rotd = dict(aids=[self.hab1.pre, self.hab2.pre],
                    toad=0,
                    isith='2',
                    nsith='2'
                    )

        b = json.dumps(rotd).encode("utf-8")
        response = client1.simulate_post("/groups/group1/rot", body=b)
        assert response.status == falcon.HTTP_202

        b = json.dumps(rotd).encode("utf-8")
        response = client2.simulate_put("/groups/group2/rot", body=b)
        assert response.status == falcon.HTTP_202

        while not ghab1.kever.sn == 1:
            yield self.tock

        assert ghab1.kever.serder.ked["t"] == coring.Ilks.rot
        assert ghab1.kever.serder.said == "E0Knx0wNcw9gwkU9HPEK9KtMzSzlJcbT4SVMZ47YUOhU"

        while not ghab2.kever.sn == 1:
            yield self.tock

        assert ghab2.kever.serder.ked["t"] == coring.Ilks.rot
        assert ghab2.kever.serder.said == "E0Knx0wNcw9gwkU9HPEK9KtMzSzlJcbT4SVMZ47YUOhU"

        while len(self.notifier1.getNotes()) != 2 or len(self.notifier2.getNotes()) != 2:
            yield self.tock

        notes = self.notifier1.getNotes()
        note = notes[1]
        assert note.pad['a']['r'] == "/multisig/rot/complete"
        assert note.pad['a']['a'] == {'i': 'EtWwBSsPnLKLv53RNR9xHpaXL0mO7X1LMiDG9shzY6f4', 's': 0}
        notes = self.notifier2.getNotes()
        note = notes[1]
        assert note.pad['a']['r'] == "/multisig/rot/complete"
        assert note.pad['a']['a'] == {'i': 'EtWwBSsPnLKLv53RNR9xHpaXL0mO7X1LMiDG9shzY6f4', 's': 0}

        self.remove(self.toRemove)
        return True


wanPre = "B6KBd3GmnWvjcmE775zNRPCsJfOhasjBbyLjUpYOWvyw"


def test_multisig_identifier_ends(seeder):
    salt = coring.Salter(raw=b'wann-the-witness').qb64
    with habbing.openHab(name="multisig1", temp=True, wits=[wanPre]) as (hby1, hab1), \
            habbing.openHab(name="multisig2", temp=True, wits=[wanPre]) as (hby2, hab2), \
            habbing.openHby(name="wan", salt=salt, temp=True) as wanHby:
        testDoer = TestDoer(wanHby, hby1, hab1, hby2, hab2, seeder)

        # Run all participants
        directing.runController(doers=[testDoer], expire=30.0)

        assert testDoer.done is True


def loadApp(hby, notifier):
    app = falcon.App()

    repd = storing.Respondant(hby=hby)
    counselor = grouping.Counselor(hby=hby)
    mbx = indirecting.MailboxDirector(hby=hby, topics=["/receipt", "/replay", "/credential", "/multisig"])

    doers = kiwiing.loadEnds(hby=hby,
                             rep=repd,
                             rgy=None,
                             verifier=None,
                             notifier=notifier,
                             signaler=notifier.signaler,
                             app=app, path="/",
                             registrar=None,
                             credentialer=None,
                             servery=booting.Servery(port=1234),
                             bootConfig=dict(),
                             counselor=counselor)
    doers.extend([repd, counselor, mbx])
    return app, doers
