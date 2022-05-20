# -*- encoding: utf-8 -*-
"""
keri.app.booting module

"""
import json
import secrets
import string

import falcon
from falcon import media
from hio.base import doing
from hio.core import http
from hio.help import decking

from keri.app import specing, configing, habbing, kiwiing, httping, keeping
from keri.app.cli.common import oobiing
from keri.vdr import credentialing

DEFAULT_PASSCODE_SIZE = 22
PASSCODE_CHARS = string.ascii_lowercase + string.ascii_uppercase + '123456789'


class Servery(doing.DoDoer):
    """ Http Server Manager """

    def __init__(self, port):
        """ Servery init

        Returns a Servery capable of starting and stopping a single HTTP server on the same port

        Parameters:
            port (int): port to listen on for all HTTP server instances
        """
        doers = [doing.doify(self.serverDo)]
        self.msgs = decking.Deck()

        self.port = port
        self.server = None
        self.serverDoer = None

        super(Servery, self).__init__(doers=doers)

    def serverDo(self, tymth, tock=0.0):
        """
        Process cues from Verifier coroutine

        Parameters:
            tymth is injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock is injected initial tock value

        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.msgs:
                yield 1.0

                msg = self.msgs.popleft()
                app = msg["app"]

                if self.serverDoer:
                    self.remove([self.serverDoer])

                if self.server:
                    self.server.close()

                yield 1.0
                self.server = http.Server(port=self.port, app=app)
                self.serverDoer = http.ServerDoer(server=self.server)

                self.extend([self.serverDoer])

            yield self.tock


class PasscodeEnd:
    """ Resource class for passcode manipulation """

    @staticmethod
    def on_get(req, rep):
        """ GET endpoint for passcode resource

        Args:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        ---
        summary: Generate random 22 digit passcode for use in securing and encrypting keystore
        description: Generate random 22 digit passcode for use in securing and encrypting keystore
        tags:
           - Passcode
        responses:
           200:
              description: Randomly generated 22 character passcode formatted as xxxx-xxxxx-xxxx-xxxxx-xxxx

        """

        size = DEFAULT_PASSCODE_SIZE
        if "size" in req.params:
            size = int(req.params["size"])

        code = []
        for x in range(size):
            code.append(PASSCODE_CHARS[secrets.randbelow(len(PASSCODE_CHARS))])

        code = "".join(code)
        body = dict(
            passcode=f"{code[0:4]}-{code[4:9]}-{code[9:13]}-{code[13:18]}-{code[18:]}"
        )

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(body).encode("utf-8")


class BootEnd(doing.DoDoer):
    """ Resource class for boot a cloud agent """

    def __init__(self, servery, base="", temp=False, configFile=None, configDir=None, headDirPath=None, **kwa):
        """ Provides endpoints for initializing and unlocking an agent

        Parameters:
            servery (Servery): HTTP server manager for stopping and restarting HTTP servers
            base (str): optional directory path segment inserted before name
                        that allows further hierarchical differentiation of databases.
                        "" means optional.
            temp (bool): True for testing:
                temporary storage of databases and config file
                weak resources for stretch of salty key
            configFile (str):  name of config file to load
            configDir (str): name of base for directory to load
            headDirPath (str): root path

        """
        self.servery = servery
        self.base = base
        self.temp = temp
        self.configFile = configFile
        self.configDir = configDir
        self.headDirPath = headDirPath
        self.msgs = decking.Deck()
        self.hby = None
        self.rgy = None
        self.bootConfig = dict(
            configFile=configFile,
            configDir=configDir,
            headDirPath=headDirPath
        ) | kwa
        self._kiwinits = kwa

        doers = [doing.doify(self.loadDo)]
        super(BootEnd, self).__init__(doers=doers)

    def loadDo(self, tymth, tock=0.0):
        """ Load oobis and close Habery when done

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Returns:  doifiable Doist compatible generator method for loading oobis using
                  the Oobiery
        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while not self.hby:
            yield self.tock

        obl = oobiing.OobiLoader(hby=self.hby, auto=True)
        self.extend([obl])

        while not obl.done:
            yield self.tock

        self.hby.close()
        self.hby = None

        while True:
            yield 10.0

    def on_get_name(self, _, rep, name=None):
        """ GET endpoint for

        Get keystore status

        Args:
            _: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            name: Keystore name

        ---
        summary: Query KERI environment for keystore name
        tags:
           - Boot
        parameters:
          - in: path
            name: name
            schema:
              type: string
            required: true
            description: predetermined name of keep keystore
            example: alice
        responses:
           200:
              description: No keystore exists
           404:
              description: Keystore exists

        """
        if name is None:
            rep.status = falcon.HTTP_400
            rep.text = "Invalid request"
            return

        ks = keeping.Keeper(name=name,
                            base=self.base,
                            temp=False,
                            reopen=True,
                            headDirPath=self.headDirPath)

        aeid = ks.gbls.get('aeid')
        if aeid is None:
            ks.close()
            rep.status = falcon.HTTP_404
            return

        ks.close()
        rep.status = falcon.HTTP_200

    def on_post(self, req, rep):
        """ POST endpoint for creating a new environment (keystore and database)

        Post creates a new database with aeid encryption key generated from passcode.  Fails
        if database already exists.

        Args:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        ---
        summary: Create KERI environment (database and keystore)
        description: Creates the directories for database and keystore for vacuous KERI instance
                     using name and aeid key or passcode to encrypt datastore.  Fails if directory
                     already exists.
        tags:
           - Boot
        requestBody:
           required: true
           content:
             application/json:
               schema:
                 type: object
                 properties:
                   name:
                     type: string
                     description: human readable nickname for this agent
                     example: alice
                   passcode:
                     type: string
                     description: passcode for encrypting and securing this agent
                     example: RwyY-KleGM-jbe1-cUiSz-p3Ce
        responses:
           200:
              description: JSON object containing status message

        """
        body = req.get_media()

        bran = None
        if "passcode" in body:
            bran = body["passcode"]
            bran = bran.replace("-", "")
        name = body["name"]

        kwa = dict()
        kwa["salt"] = body["salt"] if "salt" in body else None
        kwa["bran"] = bran
        kwa["aeid"] = body["aeid"] if "aeid" in body else None
        kwa["seed"] = body["seed"] if "seed" in body else None

        cf = None
        if self.configFile is not None:
            cf = configing.Configer(name=self.configFile,
                                    base=self.base,
                                    headDirPath=self.configDir,
                                    temp=self.temp,
                                    reopen=True,
                                    clear=False)

        hby = habbing.Habery(name=name, base=self.base, temp=self.temp, cf=cf, headDirPath=self.headDirPath, **kwa)
        rgy = credentialing.Regery(hby=hby, name=name, base=self.base)
        self.hby = hby
        self.rgy = rgy

        rep.status = falcon.HTTP_200
        body = dict(name=name, msg="Agent and keystore created")
        rep.content_type = "application/json"
        rep.data = json.dumps(body).encode("utf-8")

    def on_put(self, req, rep):
        """ PUT endpoint for unlocking an environment (keystore and database)

        Put unlocks a database with aeid encryption key generated from passcode.

        Args:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        ---
        summary: Unlock keystore with aeid encryption key generated from passcode.
        description: Unlock keystore with aeid encryption key generated from passcode..
        tags:
           - Boot
        requestBody:
           required: true
           content:
             application/json:
               schema:
                 type: object
                 properties:
                   name:
                     type: string
                     description: human readable nickname for this agent
                     example: alice
                   passcode:
                     type: string
                     description: passcode for unlocking the agent and decrypting the keystore
                     example: RwyY-KleGM-jbe1-cUiSz-p3Ce
        responses:
           200:
              description: JSON object containing status message

        """
        body = req.get_media()

        bran = None
        if "passcode" in body:
            bran = body["passcode"]
            bran = bran.replace("-", "")
        name = body["name"]

        ks = keeping.Keeper(name=name,
                            base=self.base,
                            temp=False,
                            reopen=True,
                            headDirPath=self.headDirPath)
        aeid = ks.gbls.get('aeid')
        if aeid is None:
            rep.status = falcon.HTTP_400
            rep.text = "Keystore must already exist, exiting"
            return

        ks.close()

        hby = habbing.Habery(name=name, base=self.base, bran=bran, headDirPath=self.headDirPath)
        hbyDoer = habbing.HaberyDoer(habery=hby)
        rgy = credentialing.Regery(hby=hby, name=name, base=self.base)
        rgyDoer = credentialing.RegeryDoer(rgy=rgy)
        self.extend([hbyDoer, rgyDoer])

        doers = kiwiing.setup(hby=hby, rgy=rgy, servery=self.servery, bootConfig=self.bootConfig, **self._kiwinits)
        self.extend(doers)

        rep.status = falcon.HTTP_200
        body = dict(name=name, msg="Agent unlocked")
        rep.content_type = "application/json"
        rep.data = json.dumps(body).encode("utf-8")


def setup(servery, controller="", configFile=None, configDir=None, insecure=True, tcp=5621, adminHttpPort=5623, path="",
          headDirPath=None):
    """ Set up an agent in bootloader mode """
    app = falcon.App(middleware=falcon.CORSMiddleware(
        allow_origins='*', allow_credentials='*', expose_headers=['cesr-attachment', 'cesr-date', 'content-type']))
    if not insecure:
        app.add_middleware(httping.SignatureValidationComponent(hby=None, pre=controller))
    app.req_options.media_handlers.update(media.Handlers())
    app.resp_options.media_handlers.update(media.Handlers())

    servery.msgs.append(dict(app=app))

    kwargs = dict(
        controller=controller,
        insecure=insecure,
        tcp=tcp,
        staticPath=path,
        adminHttpPort=adminHttpPort,
    )

    ends = loadEnds(app=app, configFile=configFile, configDir=configDir, path=path, servery=servery,
                    headDirPath=headDirPath, **kwargs)

    return ends


def loadEnds(app, servery, *, configFile=None, configDir=None, base="", temp=False, headDirPath=None, path, **kwargs):
    """
    Load endpoints for KIWI admin interface into the provided Falcon app

    Parameters:
        app (falcon.App): falcon.App to register handlers with:
        servery (Servery): HTTP server manager for stopping and restarting HTTP servers
        base (str): optional directory path segment inserted before name
            that allows further differentiation with a hierarchy. "" means
            optional.
        temp (bool): assign to .temp
            True then open in temporary directory, clear on close
            Otherwise then open persistent directory, do not clear on close
        configFile: (str) file name override for configuration data
        configDir: (str) directory override for configuration data
        headDirPath: (str) optional path
        path (str): directory location of UI web app files to be served with this API server

    Returns:
        list: doers from registering endpoints

    """
    sink = http.serving.StaticSink(staticDirPath=path)
    app.add_sink(sink, prefix=sink.DefaultStaticSinkBasePath)

    swagsink = http.serving.StaticSink(staticDirPath="./static")
    app.add_sink(swagsink, prefix="/swaggerui")

    passcodeEnd = PasscodeEnd()
    app.add_route("/codes", passcodeEnd)

    bootEnd = BootEnd(configFile=configFile, configDir=configDir, base=base, temp=temp, servery=servery,
                      headDirPath=headDirPath, **kwargs)
    app.add_route("/boot", bootEnd)
    app.add_route("/boot/{name}", bootEnd, suffix="name")

    resources = [passcodeEnd, bootEnd]

    app.add_route("/spec.yaml", specing.SpecResource(app=app, title='KERI Interactive Web Interface API',
                                                     resources=resources))

    return [bootEnd]
