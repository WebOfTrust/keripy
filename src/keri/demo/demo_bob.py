# -*- encoding: utf-8 -*-
"""
KERI
keri.demo.demoing module

Utilities for demos
"""
import os

from keri.demo import  demoing
from keri.db import dbing
from keri.core import coring, eventing
from keri.demo import directing


def runDemo():
    """
    Setup and run one demo controller for Bob
    """
    name =  "bob"
    remotePort=5621
    localPort=5620
    limit=1.0
    secrets = [
                'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
                'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
                'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
                'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
                'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
                'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
                'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
                'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
                ]

    demoing.runController(secrets=secrets,
                           name=name,
                           role="initiator",
                           remotePort=remotePort,
                           localPort=localPort,
                           limit=limit)




if __name__ == "__main__":
    runDemo()
