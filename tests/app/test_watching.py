# -*- encoding: utf-8 -*-
"""
tests.app.watching module

"""
import time

from hio.base import doing, tyming
from hio.core import http
from hio.help import decking

from keri.app import habbing, watching
from keri.core import eventing, parsing, coring


def test_watcher_rotate_handler(seeder):
    with habbing.openHab(name="watcher", transferable=False, temp=True) as (watHby, wat), \
            habbing.openHab(name="ctrl", transferable=True, temp=True) as (ctrlHby, ctrl):

        seeder.seedWatcherEnds(ctrlHby.db)
        kiwi = watching.KiwiServer(hab=wat, controller=ctrl.pre)
        server = http.Server(port=5644, app=kiwi.app)
        httpServerDoer = http.ServerDoer(server=server)

        watKvy = eventing.Kevery(db=wat.db)
        ctrlIcp = ctrl.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(ctrlIcp), kvy=watKvy)
        assert wat.pre == "BZg042qyBYoNC4rII1qdn7sPJPSh5vp5y0xnVYbJPujw"
        assert ctrl.pre == "E5JhBGN4iCe842eVKwq0ZLSNcbHUYwdFFPKJ5atgnXTk"

        habr = ctrl.db.habs.get(ctrl.name)
        habr.watchers = list([wat.pre])
        ctrl.db.habs.pin(ctrl.name, habr)

        rotateDoer = watching.WatcherClientRotateDoer(hab=ctrl, msgs=decking.Deck([wat.pre]))
        doers = [kiwi, httpServerDoer, rotateDoer]

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=doers)
        doist.enter()

        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not tymer.expired:
            doist.recur()
            time.sleep(doist.tock)

        assert doist.limit == limit

        doist.exit()

        assert len(rotateDoer.cues) == 1
        cue = rotateDoer.cues.popleft()

        assert wat.pre != "BZg042qyBYoNC4rII1qdn7sPJPSh5vp5y0xnVYbJPujw"
        assert cue["old"] == "BZg042qyBYoNC4rII1qdn7sPJPSh5vp5y0xnVYbJPujw"
        assert cue["new"] == wat.pre

        habr = ctrl.db.habs.get(ctrl.name)
        assert habr.watchers == [wat.pre]
