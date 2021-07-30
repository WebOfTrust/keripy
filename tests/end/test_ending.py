# -*- encoding: utf-8 -*-
"""
Test Falcon Module

Includes Falcon ReST endpoints for testing purposes

"""
import logging

import falcon
from falcon import testing

import pytest


from hio.base import tyming, doing
from hio.core import wiring, http

from keri import help
from keri.app import keeping, habbing
from keri.db import basing
from keri.core import coring

from keri.end import ending

logger = help.ogler.getLogger()


def test_signatize_designatize():
    """
    Test headerize function that creates signature header item
    """
    name = "Hilga"
    temp = True
    reopen = True

    # setup databases  for dependency injection
    ks = keeping.Keeper(name=name, temp=temp, reopen=reopen)
    db = basing.Baser(name=name, temp=temp,  reopen=reopen)

    # setup habitat
    hab = habbing.Habitat(name=name, ks=ks, db=db, temp=temp, icount=3)

    text = (b'{"seid":"B389hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd68","name":"wit0","dts":"'
                    b'2021-01-01T00:00:00.000000+00:00","scheme":"http","host":"localhost","port":'
                    b'8080,"path":"/witness"}')
    sigers = hab.mgr.sign(ser=text, verfers=hab.kever.verfers)
    header = ending.signatize(sigers)
    assert header == ({'Signature':
                       'indexed="?1";'
                       '0="AA9ag025o3YY8TAWRQhkEDwnt5Vh1Q4O7-F2x_UcXQkWpu32OxKGmCVgw0KvyD3YGvtXUMJf8cteY8tsJku-2jAQ";'
                       '1="ABqyC_jrRNyGZ6desKYAGDxjnEAPXGypyMtT8C8EykIMm49KVadKwNF9-vOuwM7ZpFitLOd20vMZIGUW9CwPlKDQ";'
                       '2="ACcB8zH46Xwi1EyoVPaRxftt0oypIJy0POl_vLEK_RmDIlV834CC3t8tVE0GF1onO1cwo27nn8ngoFhsrqoL7oDQ"'})

    hsigers = ending.designatize(header["Signature"])
    for i, siger in enumerate(sigers):
        assert siger.qb64 == hsigers[i].qb64

    cigars = hab.mgr.sign(ser=text, verfers=hab.kever.verfers, indexed=False)
    header = ending.signatize(cigars)
    assert header == ({'Signature':
                       'indexed="?0";'
                       'DCLZNpE1W0aZXx5JS-ocgHNPMiCtCLnu8rPDlK-bLuPA='
                       '"0B9ag025o3YY8TAWRQhkEDwnt5Vh1Q4O7-F2x_UcXQkWpu32OxKGmCVgw0KvyD3YGvtXUMJf8cteY8tsJku-2jAQ";'
                       'D0rYoWcvSNQaWa9kdGx7sfA0ZV22Qz45G9Nl8XDuYNu0='
                       '"0BqyC_jrRNyGZ6desKYAGDxjnEAPXGypyMtT8C8EykIMm49KVadKwNF9-vOuwM7ZpFitLOd20vMZIGUW9CwPlKDQ";'
                       'DO8ighip65cnhlvx7aW5Z-M9ODgV4jN8fMg7yULnpaMM='
                       '"0BcB8zH46Xwi1EyoVPaRxftt0oypIJy0POl_vLEK_RmDIlV834CC3t8tVE0GF1onO1cwo27nn8ngoFhsrqoL7oDQ"'})

    hcigars = ending.designatize(header["Signature"])
    for i, cigar in enumerate(cigars):
        assert cigar.qb64 == hcigars[i].qb64
        assert cigar.verfer.qb64 == hcigars[i].verfer.qb64
    # do with non-transferable hab

    """Done Test"""


def test_get_static_sink():
    """
    Test GET to static files
    Uses falcon TestClient
    """
    # must do it here to inject into Falcon endpoint resource instances
    tymist = tyming.Tymist(tyme=0.0)

    myapp = falcon.App() # falcon.App instances are callable WSGI apps
    ending.loadEnds(myapp, tymth=tymist.tymen())

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
    assert rep.headers['content-type'] == 'application/javascript; charset=UTF-8'
    assert len(rep.text) > 0
    assert rep.text == '// vanilla index.js\n\nm.render(document.body, "Hello world")\n'


def setupTestHab(name='testia', temp=True, reopen=True):
    """
    Setup shared resources for testing of ReST APIs
    """
    # setup databases  for dependency injection
    ks = keeping.Keeper(name=name, temp=temp, reopen=reopen)
    db = basing.Baser(name=name, temp=temp,  reopen=reopen)

    # setup habitat
    hab = habbing.Habitat(name=name, ks=ks, db=db, temp=temp)

    return hab



def test_seid_api():
    """
    Test the eid endpoint api using falcon TestClient
    """
    hab = setupTestHab(name='zoe')
    # must do it here to inject into Falcon endpoint resource instances
    tymist = tyming.Tymist(tyme=0.0)

    app = falcon.App() # falcon.App instances are callable WSGI apps
    ending.loadEnds(app, tymth=tymist.tymen(), hab=hab)

    client = testing.TestClient(app=app)

    aid0 = hab.pre
    assert aid0 == 'E6vI-DyZz1TVj2M5yQrHneBT_l16Z8McxUOVWfTKB16Y'
    wit0 = 'B389hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd68'
    wit1 = 'Bed2Tpxc8KeCEWoq3_RKKRjU_3P-chSser9J4eAtAK6I'
    wit2 = 'BljDbmdNfb63KOpGV4mmPKwyyp3OzDsRzpNrdL1BRQts'
    wit3 = 'B-_esBko3sppQ0iH5HvMjtGfzJDVe_zH8ajywhjps804'

    role = "witness"
    aid = aid0
    role = 'witness'
    seid = wit0 # identifier prefix of service endpoint
    name = 'wit0'  # user friendly name of endpoint
    dts = '2021-01-01T00:00:00.000000+00:00'  # ISO-8601 datetime string of latest update

    scheme = 'http'
    host = 'localhost'
    port = 8080
    path = '/witness'

    data = dict(seid=seid, name=name, dts=dts, scheme=scheme, host=host, port=port, path=path)
    text = coring.dumps(data)  # default is kind=coring.Serials.json
    assert text == (b'{"seid":"B389hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd68","name":"wit0","dts":"'
                    b'2021-01-01T00:00:00.000000+00:00","scheme":"http","host":"localhost","port":'
                    b'8080,"path":"/witness"}')
    # sign here  check for non-transferable
    sigers = hab.mgr.sign(ser=text, verfers=hab.kever.verfers)
    headers = ending.signatize(sigers)
    assert headers == ({'Signature':
                        'indexed="?1";'
                        '0="AAH-y80HeaPE4s8R265y1dCSFbE6xqbkRhWS-veWTXHZpLlE2A4P0lVGI1Ep2JMPjCRbeTylaD3QVLovzNyOV3Dg"'})

    endpath = "/end/{}/{}".format(aid, role)
    assert endpath == '/end/E6vI-DyZz1TVj2M5yQrHneBT_l16Z8McxUOVWfTKB16Y/witness'
    rep = client.simulate_post(path=endpath,
                               content_type=falcon.MEDIA_JSON,
                               headers=headers,
                               body=text)  # accepts bytes
    assert rep.status == falcon.HTTP_OK
    assert rep.json == dict(aid=aid, role=role, data=data)
    assert rep.text == ('{"aid": "E6vI-DyZz1TVj2M5yQrHneBT_l16Z8McxUOVWfTKB16Y", "role": "witness", '
                    '"data": {"seid": "B389hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd68", "name": '
                    '"wit0", "dts": "2021-01-01T00:00:00.000000+00:00", "scheme": "http", "host": '
                    '"localhost", "port": 8080, "path": "/witness"}}')

    """Done Test"""


def test_get_admin():
    """
    Uses falcon TestClient
    """
    hab = setupTestHab(name='zoe')

    # must do it here to inject into Falcon endpoint resource instances
    tymist = tyming.Tymist(tyme=0.0)

    myapp = falcon.App() # falcon.App instances are callable WSGI apps
    ending.loadEnds(myapp, tymth=tymist.tymen(), hab=hab)

    client = testing.TestClient(app=myapp)

    rep = client.simulate_get('/admin', )
    assert rep.status == falcon.HTTP_OK
    assert rep.text == '\nKERI Admin\n\n'
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


if __name__ == '__main__':
    test_seid_api()
