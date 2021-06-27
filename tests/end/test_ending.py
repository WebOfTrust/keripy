# -*- encoding: utf-8 -*-
"""
Test Falcon Module

Includes Falcon ReST endpoints for testing purposes

"""
import sys
import os
import mimetypes

import time
import json


from collections import OrderedDict as ODict
import time

import falcon
import pytest
import pytest_falcon  # provides pytest falcon client fixture


from hio import help
from hio.help import helping
from hio.base import tyming
from hio.core import wiring
from hio.core import http
from hio.core.http import httping, clienting, serving

from keri.end import ending

logger = help.ogler.getLogger()

# must do it here to inject into Falcon endpoint resource instances
tymist = tyming.Tymist(tyme=0.0)

testApp = falcon.App() # falcon.App instances are callable WSGI apps
ending.loadEnds(testApp, tymth=tymist.tymen())

@pytest.fixture
def app():  # pytest_falcon client fixture assumes there is a fixture named "app"
    return testApp

def test_get_StaticSink(client):  # client is a fixture in pytest_falcon
    """
    Test GET to static files
    """
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
    rep = client.get('/')
    assert rep.status == falcon.HTTP_OK
    assert rep.headers['content-type'] == 'text/html; charset=UTF-8'
    assert len(rep.body) > 0
    assert rep.body == index

    # get default at /static  which is index.html
    rep = client.get('/static')
    assert rep.status == falcon.HTTP_OK
    assert rep.headers['content-type'] == 'text/html; charset=UTF-8'
    assert len(rep.body) > 0
    assert rep.body == index

    # get default at /static/  e.g. trailing / which is index.html
    rep = client.get('/static/')
    assert rep.status == falcon.HTTP_OK
    assert rep.headers['content-type'] == 'text/html; charset=UTF-8'
    assert len(rep.body) > 0
    assert rep.body == index

    # get index.html
    rep = client.get('/index.html')
    assert rep.status == falcon.HTTP_OK
    assert rep.headers['content-type'] == 'text/html; charset=UTF-8'
    assert len(rep.body) > 0
    assert rep.body == index

    # get /static/index.html
    rep = client.get('/static/index.html')
    assert rep.status == falcon.HTTP_OK
    assert rep.headers['content-type'] == 'text/html; charset=UTF-8'
    assert len(rep.body) > 0
    assert rep.body == index

    # attempt missing file
    rep = client.get('/static/missing.txt')
    assert rep.status == falcon.HTTP_NOT_FOUND
    assert rep.headers['content-type'] == 'application/json'
    assert rep.json == {'title': 'Missing Resource',
                        'description': 'File '
                                       '"/Users/Load/Data/Code/public/keripy/src/keri/end/static/missing.txt" '
                                       'not found or forbidden'}

    # get robots.txt
    rep = client.get('/static/robots.txt')
    assert rep.status == falcon.HTTP_OK
    assert rep.headers['content-type'] == 'text/plain; charset=UTF-8'
    assert rep.body == '# robotstxt.org\n\nUser-agent: *\n'

    # get trial.js
    rep = client.get('/static/index.js')
    assert rep.status == falcon.HTTP_OK
    assert rep.headers['content-type'] == 'application/javascript; charset=UTF-8'
    assert len(rep.body) > 0
    assert rep.body == '// vanilla index.js\n\nm.render(document.body, "Hello world")\n'


def test_get_admin(client):  # client is a fixture in pytest_falcon
    """
    PyTest fixtures are registered globally in the pytest package
    So any test function can accept a fixture as a parameter supplied by
    the pytest runner

    pytest_falcon assumes there is a fixture named "app"
    """
    rep = client.get('/admin')
    assert rep.status == falcon.HTTP_OK
    assert rep.body == '\nKERI Admin\n\n'



if __name__ == '__main__':
    pass
