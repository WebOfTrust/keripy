import argparse

from keri.app import booting
from keri.app.cli.commands.agent import start

parser = argparse.ArgumentParser(description="Run a demo collection of agents for the vLEI scenario")
parser.set_defaults(handler=lambda args: vlei(args))
parser.add_argument('--config-file',
                    dest="configFile",
                    action='store',
                    default="demo-witness-oobis",
                    help="configuration filename")


def vlei(args):
    print("\n******* Starting Agents for vLEI scenairo testing on ports:"
          "\n\n"
          "    RootGARs:  5620, 5621\n"
          "    ExtGARs:   5622, 5623\n"
          "    IntGARs:   5624, 5625\n"
          "    QARs:      5626, 5627\n"
          "    LARs:      5628, 5629\n"
          "    Person:    5630\n\n"
          "*******\n")

    # RootGAR1
    rootGAR1 = booting.Servery(port=5620)
    booting.setup(servery=rootGAR1, controller="E59KmDbpjK0tRf9Rmc7OlueZVz7LB94DdD3cjQVvPcng",
                  configFile="vlei-root-oobis-schema",
                  configDir="./scripts", insecure=True,
                  path=start.STATIC_DIR_PATH)
    # RootGAR2
    rootGAR2 = booting.Servery(port=5621)
    booting.setup(servery=rootGAR2, controller="E59KmDbpjK0tRf9Rmc7OlueZVz7LB94DdD3cjQVvPcng",
                  configFile="vlei-root-oobis-schema",
                  configDir="./scripts", insecure=True,
                  path=start.STATIC_DIR_PATH)

    # ExtGAR1
    extGAR1 = booting.Servery(port=5622)
    booting.setup(servery=extGAR1, controller="E59KmDbpjK0tRf9Rmc7OlueZVz7LB94DdD3cjQVvPcng",
                  configFile="vlei-gar-oobis-schema",
                  configDir="./scripts", insecure=True,
                  path=start.STATIC_DIR_PATH)
    # ExtGAR2
    extGAR2 = booting.Servery(port=5623)
    booting.setup(servery=extGAR2, controller="E59KmDbpjK0tRf9Rmc7OlueZVz7LB94DdD3cjQVvPcng",
                  configFile="vlei-gar-oobis-schema",
                  configDir="./scripts", insecure=True,
                  path=start.STATIC_DIR_PATH)

    # IntGAR1
    intGAR1 = booting.Servery(port=5624)
    booting.setup(servery=intGAR1, controller="E59KmDbpjK0tRf9Rmc7OlueZVz7LB94DdD3cjQVvPcng",
                  configFile="vlei-gar-oobis-schema",
                  configDir="./scripts", insecure=True,
                  path=start.STATIC_DIR_PATH)
    # IntGAR2
    intGAR2 = booting.Servery(port=5625)
    booting.setup(servery=intGAR2, controller="E59KmDbpjK0tRf9Rmc7OlueZVz7LB94DdD3cjQVvPcng",
                  configFile="vlei-gar-oobis-schema",
                  configDir="./scripts", insecure=True,
                  path=start.STATIC_DIR_PATH)

    # QAR1
    qar1 = booting.Servery(port=5626)
    booting.setup(servery=qar1, controller="E59KmDbpjK0tRf9Rmc7OlueZVz7LB94DdD3cjQVvPcng",
                  configFile="vlei-qar-oobis-schema",
                  configDir="./scripts", insecure=True,
                  path=start.STATIC_DIR_PATH)
    # QAR2
    qar2 = booting.Servery(port=5627)
    booting.setup(servery=qar2, controller="E59KmDbpjK0tRf9Rmc7OlueZVz7LB94DdD3cjQVvPcng",
                  configFile="vlei-qar-oobis-schema",
                  configDir="./scripts", insecure=True,
                  path=start.STATIC_DIR_PATH)

    # LAR1
    lar1 = booting.Servery(port=5628)
    booting.setup(servery=lar1, controller="E59KmDbpjK0tRf9Rmc7OlueZVz7LB94DdD3cjQVvPcng",
                  configFile="vlei-qar-oobis-schema",
                  configDir="./scripts", insecure=True,
                  path=start.STATIC_DIR_PATH)
    # LAR2
    lar2 = booting.Servery(port=5629)
    booting.setup(servery=lar2, controller="E59KmDbpjK0tRf9Rmc7OlueZVz7LB94DdD3cjQVvPcng",
                  configFile="vlei-qar-oobis-schema",
                  configDir="./scripts", insecure=True,
                  path=start.STATIC_DIR_PATH)

    # Person
    person = booting.Servery(port=5630)
    booting.setup(servery=person, controller="E59KmDbpjK0tRf9Rmc7OlueZVz7LB94DdD3cjQVvPcng",
                  configFile="vlei-qar-oobis-schema",
                  configDir="./scripts", insecure=True,
                  path=start.STATIC_DIR_PATH)

    return [rootGAR1, rootGAR2, extGAR1, extGAR2, intGAR1, intGAR2, qar1, qar2, lar1, lar2, person]
