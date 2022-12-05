# -*- encoding: utf-8 -*-
"""
Test Falcon Module

Includes Falcon ReST endpoints for testing purposes

"""
import logging

import falcon
from falcon import testing
from hio.base import tyming, doing

from keri import help, kering
from keri.app import habbing
from keri.core import coring
from keri.end import ending

logger = help.ogler.getLogger()


def test_mimes():
    """
    Test mime type namedtuples
    """
    assert ending.Mimes.json == 'application/json'
    assert ending.Mimes.mgpk == 'application/msgpack'
    assert ending.Mimes.cbor == 'application/cbor'
    assert ending.Mimes.cesr == 'application/cesr'

    assert ending.KeriMimes.json == 'application/keri+json'
    assert ending.KeriMimes.mgpk == 'application/keri+msgpack'
    assert ending.KeriMimes.cbor == 'application/keri+cbor'
    assert ending.KeriMimes.cesr == 'application/keri+cesr'

    # Usage: to get Mime from serialization kind
    assert getattr(ending.Mimes, coring.Serials.json.lower()) == ending.Mimes.json
    assert getattr(ending.Mimes, coring.Serials.mgpk.lower()) == ending.Mimes.mgpk
    assert getattr(ending.Mimes, coring.Serials.cbor.lower()) == ending.Mimes.cbor

    assert getattr(ending.KeriMimes, coring.Serials.json.lower()) == ending.KeriMimes.json
    assert getattr(ending.KeriMimes, coring.Serials.mgpk.lower()) == ending.KeriMimes.mgpk
    assert getattr(ending.KeriMimes, coring.Serials.cbor.lower()) == ending.KeriMimes.cbor
    """Done Test"""


def test_signature_designature():
    """
    Test headerize function that creates signature header item
    """
    name = "Hilga"
    base = "test"
    temp = True
    reopen = True

    # setup databases  for dependency injection
    # ks = keeping.Keeper(name=name, temp=temp, reopen=reopen)
    # db = basing.Baser(name=name, temp=temp, reopen=reopen)

    # Setup Habery and Hab
    with habbing.openHby(name=name, base=base) as hby:
        # hby = habbing.Habery(name=name, base=base, temp=temp, free=True)
        hab = hby.makeHab(name=name, icount=3)

        # setup habitat
        # hab = habbing.Habitat(name=name, ks=ks, db=db, temp=temp, icount=3)
        assert hab.pre == 'EGqHykT1gVyuWxsVW6LUUsz_KtLJGYMi_SrohInwvjC-'
        digest = hab.kever.serder.said
        assert digest == hab.pre

        # example body text
        text = (b'{"seid":"BA89hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd68","name":"wit0","dts":"'
                b'2021-01-01T00:00:00.000000+00:00","scheme":"http","host":"localhost","port":'
                b'8080,"path":"/witness"}')

        sigers = hab.sign(ser=text, verfers=hab.kever.verfers)

        # test signature with list markers as indexed sigers and defaults for indexed and signer
        signage = ending.Signage(markers=sigers, indexed=None, signer=None, ordinal=None, digest=None,
                                 kind=None)
        header = ending.signature([signage])  # put it in a list
        assert header == {'Signature': 'indexed="?1";0="AACsufRGYI-sRvS2c0rsOueSoSRtrjODaf48DYLJbLvvD8aHe7b2sWGebZ-y9ichhsxMF3Hhn-3LYSKIrnmH3oIN";1="ABDs7m2-h5l7vpjYtbFXtksicpZK5Oclm43EOkE2xoQOfr08doj73VrlKZOKNfJmRumD3tfaiFFgVZqPgiHuFVoA";2="ACDVOy2LvGgFINUneL4iwA55ypJR6vDpLLbdleEsiANmFazwZARypJMiw9vu2Iu0oL7XCUiUT4JncU8P3HdIp40F"'}

        # test designature
        signages = ending.designature(header["Signature"])
        signage = signages[0]
        assert signage.indexed
        assert not signage.signer
        markers = signage.markers
        for i, (tag, marker) in enumerate(markers.items()):
            assert marker.qb64 == sigers[i].qb64
            assert int(tag) == marker.index == sigers[i].index

        # include signer ordinal digest and kind
        # test signature with list markers as indexed sigers and defaults for indexed and signer
        signage = ending.Signage(markers=sigers,
                                 indexed=True,
                                 signer=hab.pre,
                                 ordinal="0",
                                 digest=digest,
                                 kind="CESR")
        header = ending.signature([signage])  # put it in a list
        assert header == {'Signature': 'indexed="?1";signer="EGqHykT1gVyuWxsVW6LUUsz_KtLJGYMi_SrohInwvjC-";ordinal="0";digest="EGqHykT1gVyuWxsVW6LUUsz_KtLJGYMi_SrohInwvjC-";kind="CESR";0="AACsufRGYI-sRvS2c0rsOueSoSRtrjODaf48DYLJbLvvD8aHe7b2sWGebZ-y9ichhsxMF3Hhn-3LYSKIrnmH3oIN";1="ABDs7m2-h5l7vpjYtbFXtksicpZK5Oclm43EOkE2xoQOfr08doj73VrlKZOKNfJmRumD3tfaiFFgVZqPgiHuFVoA";2="ACDVOy2LvGgFINUneL4iwA55ypJR6vDpLLbdleEsiANmFazwZARypJMiw9vu2Iu0oL7XCUiUT4JncU8P3HdIp40F"'}

        # test designature
        signages = ending.designature(header["Signature"])
        signage = signages[0]
        assert signage.indexed
        assert signage.signer == hab.pre
        assert signage.ordinal == "0"
        assert signage.digest == digest
        assert signage.kind == "CESR"
        markers = signage.markers
        for i, (tag, marker) in enumerate(markers.items()):
            assert marker.qb64 == sigers[i].qb64
            assert int(tag) == marker.index == sigers[i].index

        # test signature with list markers as nonindexed cigars and defaults for indexed and signer
        cigars = hab.sign(ser=text, verfers=hab.kever.verfers, indexed=False)
        signage = ending.Signage(markers=cigars, indexed=None, signer=None, ordinal=None, digest=None,
                                 kind=None)
        header = ending.signature([signage])
        assert header == {'Signature': 'indexed="?0";DAi2TaRNVtGmV8eSUvqHIBzTzIgrQi57vKzw5Svmy7jw="0BCsufRGYI-sRvS2c0rsOueSoSRtrjODaf48DYLJbLvvD8aHe7b2sWGebZ-y9ichhsxMF3Hhn-3LYSKIrnmH3oIN";DNK2KFnL0jUGlmvZHRse7HwNGVdtkM-ORvTZfFw7mDbt="0BDs7m2-h5l7vpjYtbFXtksicpZK5Oclm43EOkE2xoQOfr08doj73VrlKZOKNfJmRumD3tfaiFFgVZqPgiHuFVoA";DDvIoIYqeuXJ4Zb8e2luWfjPTg4FeIzfHzIO8lC56WjD="0BDVOy2LvGgFINUneL4iwA55ypJR6vDpLLbdleEsiANmFazwZARypJMiw9vu2Iu0oL7XCUiUT4JncU8P3HdIp40F"'}


        # test designature
        signages = ending.designature(header["Signature"])
        signage = signages[0]
        assert not signage.indexed
        assert not signage.signer
        markers = signage.markers
        for i, (tag, marker) in enumerate(markers.items()):
            assert marker.qb64 == cigars[i].qb64
            assert tag == cigars[i].verfer.qb64

        #  now combine into one header
        signages = []
        signages.append(ending.Signage(markers=sigers, indexed=True, signer=hab.pre,
                                       ordinal=None, digest=None, kind="CESR"))
        signages.append(ending.Signage(markers=cigars, indexed=False, signer=hab.pre,
                                       ordinal=None, digest=None, kind="CESR"))

        header = ending.signature(signages)
        assert header == {'Signature': 'indexed="?1";signer="EGqHykT1gVyuWxsVW6LUUsz_KtLJGYMi_SrohInwvjC-";kind="CESR";0="AACsufRGYI-sRvS2c0rsOueSoSRtrjODaf48DYLJbLvvD8aHe7b2sWGebZ-y9ichhsxMF3Hhn-3LYSKIrnmH3oIN";1="ABDs7m2-h5l7vpjYtbFXtksicpZK5Oclm43EOkE2xoQOfr08doj73VrlKZOKNfJmRumD3tfaiFFgVZqPgiHuFVoA";2="ACDVOy2LvGgFINUneL4iwA55ypJR6vDpLLbdleEsiANmFazwZARypJMiw9vu2Iu0oL7XCUiUT4JncU8P3HdIp40F",indexed="?0";signer="EGqHykT1gVyuWxsVW6LUUsz_KtLJGYMi_SrohInwvjC-";kind="CESR";DAi2TaRNVtGmV8eSUvqHIBzTzIgrQi57vKzw5Svmy7jw="0BCsufRGYI-sRvS2c0rsOueSoSRtrjODaf48DYLJbLvvD8aHe7b2sWGebZ-y9ichhsxMF3Hhn-3LYSKIrnmH3oIN";DNK2KFnL0jUGlmvZHRse7HwNGVdtkM-ORvTZfFw7mDbt="0BDs7m2-h5l7vpjYtbFXtksicpZK5Oclm43EOkE2xoQOfr08doj73VrlKZOKNfJmRumD3tfaiFFgVZqPgiHuFVoA";DDvIoIYqeuXJ4Zb8e2luWfjPTg4FeIzfHzIO8lC56WjD="0BDVOy2LvGgFINUneL4iwA55ypJR6vDpLLbdleEsiANmFazwZARypJMiw9vu2Iu0oL7XCUiUT4JncU8P3HdIp40F"'}

        # test designature
        signages = ending.designature(header["Signature"])

        signage = signages[0]
        assert signage.indexed
        assert signage.signer == hab.pre
        markers = signage.markers
        for i, (tag, marker) in enumerate(markers.items()):
            assert marker.qb64 == sigers[i].qb64
            assert int(tag) == marker.index == sigers[i].index

        signage = signages[1]
        assert not signage.indexed
        assert signage.signer == hab.pre
        markers = signage.markers
        for i, (tag, marker) in enumerate(markers.items()):
            assert marker.qb64 == cigars[i].qb64
            assert tag == cigars[i].verfer.qb64

        # Test with dict markers
        tags = ["wit0", "wit1", "wit2"]
        signages = []
        markers = {tags[i]: marker for i, marker in enumerate(sigers)}
        signages.append(ending.Signage(markers=markers, signer=hab.pre, indexed=True,
                                       ordinal=None, digest=None, kind="CESR"))
        markers = {tags[i]: marker for i, marker in enumerate(cigars)}
        signages.append(ending.Signage(markers=markers, signer=hab.pre, indexed=False,
                                       ordinal=None, digest=None, kind="CESR"))

        header = ending.signature(signages)
        assert header == {'Signature': 'indexed="?1";signer="EGqHykT1gVyuWxsVW6LUUsz_KtLJGYMi_SrohInwvjC-";kind="CESR";wit0="AACsufRGYI-sRvS2c0rsOueSoSRtrjODaf48DYLJbLvvD8aHe7b2sWGebZ-y9ichhsxMF3Hhn-3LYSKIrnmH3oIN";wit1="ABDs7m2-h5l7vpjYtbFXtksicpZK5Oclm43EOkE2xoQOfr08doj73VrlKZOKNfJmRumD3tfaiFFgVZqPgiHuFVoA";wit2="ACDVOy2LvGgFINUneL4iwA55ypJR6vDpLLbdleEsiANmFazwZARypJMiw9vu2Iu0oL7XCUiUT4JncU8P3HdIp40F",indexed="?0";signer="EGqHykT1gVyuWxsVW6LUUsz_KtLJGYMi_SrohInwvjC-";kind="CESR";wit0="0BCsufRGYI-sRvS2c0rsOueSoSRtrjODaf48DYLJbLvvD8aHe7b2sWGebZ-y9ichhsxMF3Hhn-3LYSKIrnmH3oIN";wit1="0BDs7m2-h5l7vpjYtbFXtksicpZK5Oclm43EOkE2xoQOfr08doj73VrlKZOKNfJmRumD3tfaiFFgVZqPgiHuFVoA";wit2="0BDVOy2LvGgFINUneL4iwA55ypJR6vDpLLbdleEsiANmFazwZARypJMiw9vu2Iu0oL7XCUiUT4JncU8P3HdIp40F"'}

        # test designature
        signages = ending.designature(header["Signature"])

        signage = signages[0]
        assert signage.indexed
        assert signage.signer == hab.pre
        markers = signage.markers
        for i, (tag, marker) in enumerate(markers.items()):
            assert marker.qb64 == sigers[i].qb64
            assert tag == tags[i]

        signage = signages[1]
        assert not signage.indexed
        assert signage.signer == hab.pre
        markers = signage.markers
        for i, (tag, marker) in enumerate(markers.items()):
            assert marker.qb64 == cigars[i].qb64
            assert tag == tags[i]

        # do with non-transferable hab

    """Done Test"""


def test_get_static_sink():
    """
    Test GET to static files
    Uses falcon TestClient
    """
    # must do it here to inject into Falcon endpoint resource instances
    tymist = tyming.Tymist(tyme=0.0)

    myapp = falcon.App()  # falcon.App instances are callable WSGI apps
    ending.loadEnds(myapp, hby=None, tymth=tymist.tymen(), static=True)

    client = testing.TestClient(app=myapp)

    index = ('<html>\n'
             '    <head>\n'
             '        <title>Demo</title>\n'
             '        <!--\n'
             '        <link rel="stylesheet" type="text/css" '
             'href="semantic/dist/semantic.min.css">\n'
             '        <script src="node_modules/jquery/dist/jquery.min.js"></script>\n'
             '        <script src="semantic/dist/semantic.min.js"></script>\n'
             '        -->\n'
             '    </head>\n'
             '    <body>\n'
             '        <!--\n'
             '        <script src="bin/app.js"></script>\n'
             '        <button class="ui button">Follow</button>\n'
             '        -->\n'
             '        <p>Hello World.</p>\n'
             '    </body>\n'
             '</html>\n')

    # get default at  /  which is index.html
    rep = client.simulate_get('/')
    assert rep.status == falcon.HTTP_OK
    assert rep.headers['content-type'] == 'text/html; charset=UTF-8'
    assert len(rep.text) > 0
    assert rep.text == index

    # get default at /static  which is index.html
    rep = client.simulate_get('/static')
    assert rep.status == falcon.HTTP_OK
    assert rep.headers['content-type'] == 'text/html; charset=UTF-8'
    assert len(rep.text) > 0
    assert rep.text == index

    # get default at /static/  e.g. trailing / which is index.html
    rep = client.simulate_get('/static/')
    assert rep.status == falcon.HTTP_OK
    assert rep.headers['content-type'] == 'text/html; charset=UTF-8'
    assert len(rep.text) > 0
    assert rep.text == index

    # get index.html
    rep = client.simulate_get('/index.html')
    assert rep.status == falcon.HTTP_OK
    assert rep.headers['content-type'] == 'text/html; charset=UTF-8'
    assert len(rep.text) > 0
    assert rep.text == index

    # get /static/index.html
    rep = client.simulate_get('/static/index.html')
    assert rep.status == falcon.HTTP_OK
    assert rep.headers['content-type'] == 'text/html; charset=UTF-8'
    assert len(rep.text) > 0
    assert rep.text == index

    # attempt missing file
    rep = client.simulate_get('/static/missing.txt')
    assert rep.status == falcon.HTTP_NOT_FOUND
    assert rep.headers['content-type'] == 'application/json'
    assert rep.json['title'] == 'Missing Resource'

    # get robots.txt
    rep = client.simulate_get('/static/robots.txt')
    assert rep.status == falcon.HTTP_OK
    assert rep.headers['content-type'] == 'text/plain; charset=UTF-8'
    assert rep.text == '# robotstxt.org\n\nUser-agent: *\n'

    # get trial.js
    rep = client.simulate_get('/static/index.js')
    assert rep.status == falcon.HTTP_OK
    assert "javascript" in rep.headers['content-type']
    assert len(rep.text) > 0
    assert rep.text == '// vanilla index.js\n\nm.render(document.body, "Hello world")\n'


def test_seid_api():
    """
    Test the eid endpoint api using falcon TestClient
    """
    # Setup Habery and Hab
    name = 'zoe'
    base = 'test'
    with habbing.openHby(name=name, base=base) as hby:
        hab = hby.makeHab(name=name)
        # hab = setupTestHab(name='zoe')
        # must do it here to inject into Falcon endpoint resource instances
        tymist = tyming.Tymist(tyme=0.0)

        app = falcon.App()  # falcon.App instances are callable WSGI apps
        ending.loadEnds(app, tymth=tymist.tymen(), hby=hby)

        client = testing.TestClient(app=app)

        aid0 = hab.pre
        assert aid0 == 'EAJAEHYWGxz0nJNBvbOzpFR8RonSWa_YyJxULjAH1XEv'
        wit0 = 'BA89hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd68'
        wit1 = 'BBd2Tpxc8KeCEWoq3_RKKRjU_3P-chSser9J4eAtAK6I'
        wit2 = 'BCjDbmdNfb63KOpGV4mmPKwyyp3OzDsRzpNrdL1BRQts'
        wit3 = 'BD_esBko3sppQ0iH5HvMjtGfzJDVe_zH8ajywhjps804'

        role = "witness"
        aid = aid0
        role = 'witness'
        seid = wit0  # identifier prefix of service endpoint
        name = 'wit0'  # user friendly name of endpoint
        dts = '2021-01-01T00:00:00.000000+00:00'  # ISO-8601 datetime string of latest update

        scheme = 'http'
        host = 'localhost'
        port = 8080
        path = '/witness'

        data = dict(seid=seid, name=name, dts=dts, scheme=scheme, host=host, port=port, path=path)
        text = coring.dumps(data)  # default is kind=coring.Serials.json
        assert text == (b'{"seid":"BA89hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd68","name":"wit0","dts":"'
                        b'2021-01-01T00:00:00.000000+00:00","scheme":"http","host":"localhost","port":'
                        b'8080,"path":"/witness"}')

        # sign here  check for non-transferable
        sigers = hab.sign(ser=text, verfers=hab.kever.verfers)
        signage = ending.Signage(markers=sigers, indexed=None, signer=None, ordinal=None, digest=None,
                                 kind=None)
        header = ending.signature([signage])
        assert header == {'Signature': 'indexed="?1";0="AACuduac6au7JSqANK1IaHWP_GlLG9OhPC7Mg52_uRSoddogaYw8mfuyIM6x4lRhKAlxUVDRv_Fh0plB7wx-LSoE"'}

        endpath = "/end/{}/{}".format(aid, role)
        assert endpath == f'/end/{aid0}/witness' # '/end/EFW3cL-Lv4tGnk_WnnruryH4WKaOXw4qeZNU5dG1hUve/witness'
        rep = client.simulate_post(path=endpath,
                                   content_type=falcon.MEDIA_JSON,
                                   headers=header,
                                   body=text)  # accepts bytes
        assert rep.status == falcon.HTTP_OK
        assert rep.json == dict(aid=aid, role=role, data=data)
        assert rep.text == ('{"aid": "EAJAEHYWGxz0nJNBvbOzpFR8RonSWa_YyJxULjAH1XEv", "role": "witness", '
                        '"data": {"seid": "BA89hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd68", "name": '
                        '"wit0", "dts": "2021-01-01T00:00:00.000000+00:00", "scheme": "http", "host": '
                        '"localhost", "port": 8080, "path": "/witness"}}')


    """Done Test"""


def test_get_admin():
    """
    Uses falcon TestClient
    """
    # Setup Habery and Hab
    name = 'zoe'
    base = 'test'
    with habbing.openHby(name=name, base=base) as hby:
        hab = hby.makeHab(name=name)
        # hab = setupTestHab(name='zoe')

    # must do it here to inject into Falcon endpoint resource instances
    tymist = tyming.Tymist(tyme=0.0)

    myapp = falcon.App()  # falcon.App instances are callable WSGI apps
    ending.loadEnds(myapp, tymth=tymist.tymen(), hby=hby)

    client = testing.TestClient(app=myapp)

    rep = client.simulate_get('/admin', )
    assert rep.status == falcon.HTTP_OK
    assert rep.text == '\nKERI Admin\n\n'
    """Done Test"""


def test_get_oobi():
    """
    Uses falcon TestClient
    """
    # Setup Habery and Hab
    name = 'oobi'
    base = 'test'
    salt = coring.Salter(raw=b'0123456789abcdef').qb64
    with habbing.openHby(name=name, base=base, salt=salt) as hby:
        hab = hby.makeHab(name=name)
        msgs = bytearray()
        msgs.extend(hab.makeEndRole(eid=hab.pre,
                                    role=kering.Roles.controller,
                                    stamp=help.nowIso8601()))

        msgs.extend(hab.makeLocScheme(url='http://127.0.0.1:5555',
                                      scheme=kering.Schemes.http,
                                      stamp=help.nowIso8601()))
        hab.psr.parse(ims=msgs)

        # must do it here to inject into Falcon endpoint resource instances
        tymist = tyming.Tymist(tyme=0.0)

        app = falcon.App()  # falcon.App instances are callable WSGI apps
        ending.loadEnds(app, tymth=tymist.tymen(), hby=hby, default=hab.pre)

        client = testing.TestClient(app=app)

        rep = client.simulate_get('/oobi', )
        assert rep.status == falcon.HTTP_OK
        serder = coring.Serder(raw=rep.text.encode("utf-8"))
        assert serder.ked['t'] == coring.Ilks.rpy
        assert serder.ked['r'] == "/loc/scheme"
        assert serder.ked['a']['eid'] == hab.pre
        assert serder.ked['a']['scheme'] == kering.Schemes.http
        assert serder.ked['a']['url'] == "http://127.0.0.1:5555"
        print(serder.pretty())

    """Done Test"""


def test_end_demo():
    """
    Run with rest api client like Paw or PostMan
    """
    webPort = 8089
    # help.ogler.resetLevel(level=logging.DEBUG, globally=True)
    logger.setLevel(logging.INFO)

    logger.info("\nWeb Server on port %s.\n\n", webPort)

    # must do it here to inject into Falcon endpoint resource instances
    doist = doing.Doist()

    doers = ending.setup(name="Test ReST Server",
                         temp=True,
                         webPort=webPort,
                         tymth=doist.tymen())

    logger.info("\nWeb Server on port %s.\n\n", webPort)

    doist.do(doers=doers, limit=1)

    logger.error("\nWeb Server shutdown on port %s.\n\n", webPort)
