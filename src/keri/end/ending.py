# -*- encoding: utf-8 -*-
"""
keri.end.ending module

ReST API endpoints

"""
import sys
import os

import falcon

from hio.core.http import serving



# Falcon reource endpoints
class AdminEnd:
    def on_get(self, req, rep):
        """
        Handles GET requests
        """
        message = "\nKERI Admin\n\n"
        rep.status = falcon.HTTP_200  # This is the default status
        rep.content_type = "text/html"
        rep.text = message


WEB_DIR_PATH = os.path.dirname(
                os.path.abspath(
                    sys.modules.get(__name__).__file__))
STATIC_DIR_PATH = os.path.join(WEB_DIR_PATH, 'static')

def loadEnds(app, tymth):
    """
    Load endpoints for app with store reference
    This function provides the endpoint resource instances
    with a reference to the tymist virtual time reference

    Parameters:
        tymth (callable):  reference to tymist (Doist, DoDoer) virtual time reference
    """

    sink = serving.StaticSink(staticDirPath=STATIC_DIR_PATH)
    app.add_sink(sink, prefix=sink.DefaultStaticSinkBasePath)

    # Resources are represented by long-lived class instances
    app.add_route('/admin', AdminEnd()) # handles all requests to '/admin' URL path

