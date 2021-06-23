# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
from dataclasses import dataclass

from hio import help
from hio.base import doing
from hio.core.tcp import serving, clienting

from keri.app import habbing
from keri.app.cli.common.command import Command
from keri.help import decking

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a prefix')
parser.set_defaults(handler=lambda opts: InceptDoer(opts=opts),
                    transferable=True,
                    parser=lambda args: parseOptions(args))
parser.add_argument('--transferable', '-t', dest='transferable', action='store_true')
parser.add_argument('--non-transferable', '-nt', dest='transferable', action='store_false')
parser.add_argument('--witness', '-w', dest='witness', action='store', default='')


@dataclass
class InceptOptions:
    name: str
    transferable: bool
    witness: str


def parseOptions(args) -> Command:
    return Command(
        name=args.name,
        handler=args.handler,
        opts=InceptOptions(
            name=args.name,
            transferable=args.transferable,
            witness=args.witness
        )
    )


class InceptDoer(doing.Doer):

    def __init__(self, inq: decking.Deck = None, oqu: decking.Deck = None, tock=0.0, **kwa):
        """
         Input: args
         Output: name
        """
        self.inq = inq if inq is not None else decking.Deck()
        self.oqu = oqu if oqu is not None else decking.Deck()
        super(InceptDoer, self).__init__(tock, **kwa)

    def do(self, tymth=None, tock=0.0, **opts):
        print("hihihi", self.inq)
        if self.inq:
            for opts in self.inq:
                print(opts.name, opts.transferable)
                yield self.tock

                if not self.opts.transferable:
                    # start for witness mode
                    server = serving.Server(host="", port="")
                    serverDoer = doing.ServerDoer(server=server)
                    self.oqu.push(serverDoer)

                if self.opts.witness is not None:
                    # create a direct mode client for now
                    parts = self.opts.witness.split(":")

                    if len(parts) != 2:
                        raise Exception("bad config")

                    client = clienting.Client(host=parts[0], port=int(parts[1]))
                    clientDoer = doing.ClientDoer(client=client)
                    if client is not None:
                        while not client.connected:
                            logger.info("%s:\n waiting for connection to remote %s.\n\n",
                                        self.opts.name, client.ha)
                            yield self.tock

                        logger.info("%s:\n connected to %s.\n\n", self.opts.name, client.ha)
                    self.oqu.push(clientDoer)

                hab = habbing.Habitat(name=self.opts.name,
                                      transferable=self.opts.transferable,
                                      temp=False)

                print(f'Prefix\t\t{hab.pre}')
                print(f'Public key\t{hab.kever.verfers[0].qb64}')
                print()
            yield self.tock

        print("returning")

        return super().do(tymth, tock, **opts)
