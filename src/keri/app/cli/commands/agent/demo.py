import argparse
import logging

from hio.base import doing

from keri import help, kering
from keri.app.cli.commands.agent import start

parser = argparse.ArgumentParser(description="Run a demo collection of multisig agents")
parser.set_defaults(handler=lambda args: demo(args))


def demo(args):
    help.ogler.level = logging.CRITICAL
    help.ogler.reopen(name="keri", temp=True, clear=True)
    logger = help.ogler.getLogger()

    logger.info("\n******* Starting Multisig Agents multisig1, multisig2, multisig3 "
                ".******\n\n")

    # kli agent start --name multisig1 --pre E4Zq5dxbnWKq5K-Bssn4g_qhBbSwNSI2MH4QYnkEUFDM --insecure --tcp 5621
    # --http 5620 --admin-http-port 5623
    doers = start.runAgent(controller="E4Zq5dxbnWKq5K-Bssn4g_qhBbSwNSI2MH4QYnkEUFDM",
                           name="multisig1", insecure=True,
                           tcp=5621,
                           adminHttpPort=5623)

    # kli agent start --name multisig2 --pre E4Zq5dxbnWKq5K-Bssn4g_qhBbSwNSI2MH4QYnkEUFDM --insecure --tcp 5721
    # --http 5720 --admin-http-port 5723
    doers += start.runAgent(controller="E4Zq5dxbnWKq5K-Bssn4g_qhBbSwNSI2MH4QYnkEUFDM",
                            name="multisig2", insecure=True,
                            tcp=5721,
                            adminHttpPort=5723)

    # kli agent start --name multisig3 --pre E4Zq5dxbnWKq5K-Bssn4g_qhBbSwNSI2MH4QYnkEUFDM --insecure --tcp 5821
    # --http 5820 --admin-http-port 5823
    doers += start.runAgent(controller="E4Zq5dxbnWKq5K-Bssn4g_qhBbSwNSI2MH4QYnkEUFDM",
                            name="multisig3", insecure=True,
                            tcp=5821,
                            adminHttpPort=5823)

    try:
        tock = 0.03125
        doist = doing.Doist(limit=0.0, tock=tock, real=True)
        doist.do(doers=doers)
    except kering.ConfigurationError:
        print(f"prefix for {args.name} does not exist, incept must be run first", )

    logger.info("\n******* Ended Multisig Agents multisig1, multisig2, multisig3 "
                ".******\n\n",)
