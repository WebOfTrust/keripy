import argparse

from keri.app import directing
from keri.app.cli.commands.vc.registry import incept

parser = argparse.ArgumentParser(description="Create a multisig registry for a group identifier")
parser.set_defaults(handler=lambda args: demo(args))


def demo(args):

    ms1 = incept.RegistryInceptor(name="multisig1", registryName="gleif", estOnly=False, noBackers=True, baks=[])
    ms2 = incept.RegistryInceptor(name="multisig2", registryName="gleif", estOnly=False, noBackers=True, baks=[])
    ms3 = incept.RegistryInceptor(name="multisig3", registryName="gleif", estOnly=False, noBackers=True, baks=[])

    doers = [ms1, ms2, ms3]
    directing.runController(doers, expire=0.0)
