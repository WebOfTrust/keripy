# -*- encoding: utf-8 -*-
"""
Test Falcon Module

Includes Falcon ReST endpoints for testing purposes

"""
import logging

import falcon
from falcon import testing

import pytest

from hio import help
from hio.base import tyming, doing
from hio.core import wiring, http
from hio.core.http import httping, clienting, serving

from keri.end import ending

logger = help.ogler.getLogger()


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


def test_get_admin():
    """
    Uses falcon TestClient
    """
    # must do it here to inject into Falcon endpoint resource instances
    tymist = tyming.Tymist(tyme=0.0)

    myapp = falcon.App() # falcon.App instances are callable WSGI apps
    ending.loadEnds(myapp, tymth=tymist.tymen())

    client = testing.TestClient(app=myapp)

    rep = client.simulate_get('/admin')
    assert rep.status == falcon.HTTP_OK
    assert rep.text == '\nKERI Admin\n\n'

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
    test_end_demo()
