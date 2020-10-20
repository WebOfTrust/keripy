# -*- encoding: utf-8 -*-
"""
KERI
keri.demo.demoing module

Utilities for demos
"""
import os

from hio.base import doing, tyming
from hio.core.tcp import clienting, serving

from ..db import dbing
from ..core import coring, eventing
from . import directing



def runController(secrets,  name="who", role="initiator",
                  remotePort=5621, localPort=5620, limit=0.0):
    """
    Setup and run the demo for name
    """


    print("Setting up Direct Mode demo for {} as {} on tcp port {} to port {}.\n"
          "".format(name,role, localPort, remotePort))

    with dbing.openLogger(name=name) as db:
        kevers = dict()
        # setup components
        hab = directing.Habitat(secrets=secrets, kevers=kevers, db=db)
        client = clienting.Client(host='127.0.0.1', port=remotePort)
        clientDoer = doing.ClientDoer(client=client)
        if role == "initiator":
            director = directing.BobDirector(hab=hab, client=client, tock=0.125)
        else:
            director = directing.EveDirector(hab=hab, client=client, tock=0.125)
        reactor = directing.Reactor(hab=hab, client=client)
        server = serving.Server(host="", port=localPort)
        serverDoer = doing.ServerDoer(server=server)
        directant = directing.Directant(hab=hab, server=server)
        # Reactants created on demand


        tock = 0.03125
        doist = doing.Doist(limit=limit, tock=tock)
        doers = [clientDoer, director, reactor, serverDoer, directant]
        doist.do(doers=doers)

