# -*- encoding: utf-8 -*-
"""
KERI
keri.demo.demoing module

Utilities for demos
"""
import os


from keri.db import dbing
from keri.core import coring, eventing
from keri.demo import directing


def runDemo():
    """
    Setup and run one demo controller for Eve
    """
    name =  "eve"
    remotePort=5620
    localPort=5621
    limit=1.0

    # set of secrets (seeds for private keys)
    secrets = ['AgjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw',
                'AKUotEE0eAheKdDJh9QvNmSEmO_bjIav8V_GmctGpuCQ',
                'AK-nVhMMJciMPvmF5VZE_9H-nhrgng9aJWf7_UHPtRNM',
                'AT2cx-P5YUjIw_SLCHQ0pqoBWGk9s4N1brD-4pD_ANbs',
                'Ap5waegfnuP6ezC18w7jQiPyQwYYsp9Yv9rYMlKAYL8k',
                'Aqlc_FWWrxpxCo7R12uIz_Y2pHUH2prHx1kjghPa8jT8',
                'AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc',
                'ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s']

    directing.runController(secrets=secrets,
                           name=name,
                           role="validator",
                           remotePort=remotePort,
                           localPort=localPort,
                           limit=limit)




if __name__ == "__main__":
    runDemo()
