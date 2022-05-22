import argparse

from keri.app import booting
from keri.app.cli.commands.agent import start

parser = argparse.ArgumentParser(description="Run a demo collection of multisig agents")
parser.set_defaults(handler=lambda args: demo(args))
parser.add_argument('--config-file',
                    dest="configFile",
                    action='store',
                    default="demo-witness-oobis",
                    help="configuration filename")


def demo(args):

    print("\n******* Starting Multisig Delegation Agents on ports 5623, 5723, 5823, 5923 "
          ".******\n\n")

    # kli agent start --config-dir ./scripts --config-file demo-witness-oobis --insecure --tcp 5621 -a 5623
    servery0 = booting.Servery(port=5623)
    doers = booting.setup(servery=servery0, controller="E59KmDbpjK0tRf9Rmc7OlueZVz7LB94DdD3cjQVvPcng",
                          configFile=args.configFile,
                          configDir="./scripts", insecure=True, tcp=5621, adminHttpPort=5623,
                          path=start.STATIC_DIR_PATH)

    # kli agent start --config-dir ./scripts --config-file demo-witness-oobis --insecure --tcp 5721 -a 5723
    servery1 = booting.Servery(port=5723)
    doers += booting.setup(servery=servery1, controller="E59KmDbpjK0tRf9Rmc7OlueZVz7LB94DdD3cjQVvPcng",
                           configFile=args.configFile,
                           configDir="./scripts", insecure=True, tcp=5721, adminHttpPort=5723,
                           path=start.STATIC_DIR_PATH)

    # kli agent start --config-dir ./scripts --config-file demo-witness-oobis --insecure --tcp 5821 -a 5823
    servery2 = booting.Servery(port=5823)
    doers += booting.setup(servery=servery2, controller="E59KmDbpjK0tRf9Rmc7OlueZVz7LB94DdD3cjQVvPcng",
                           configFile=args.configFile,
                           configDir="./scripts", insecure=True, tcp=5821, adminHttpPort=5823,
                           path=start.STATIC_DIR_PATH)

    # kli agent start --config-dir ./scripts --config-file demo-witness-oobis --insecure --tcp 5921 -a 5923
    servery3 = booting.Servery(port=5923)
    doers += booting.setup(servery=servery3, controller="E59KmDbpjK0tRf9Rmc7OlueZVz7LB94DdD3cjQVvPcng",
                           configFile=args.configFile,
                           configDir="./scripts", insecure=True, tcp=5921, adminHttpPort=5923,
                           path=start.STATIC_DIR_PATH)

    return doers + [servery0, servery1, servery2, servery3]
