# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
from dataclasses import dataclass

from hio.base import doing

from keri import kering
from keri.app.cli.common import rotating, existing, config
from keri.core import coring
from keri.help import helping
from ... import habbing, agenting, indirecting, delegating, forwarding

parser = argparse.ArgumentParser(description='Rotate keys')
parser.set_defaults(handler=lambda args: rotate(args))
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--file', '-f', help='file path of config options (JSON) for rotation', default="", required=False)
parser.add_argument('--next-count', '-C', help='Count of pre-rotated keys (signing keys after next rotation).',
                    default=None, type=int, required=False)
parser.add_argument("--receipt-endpoint", help="Attempt to connect to witness receipt endpoint for witness receipts.",
                    dest="endpoint", action='store_true')
parser.add_argument("--authenticate", '-z', help="Prompt the controller for authentication codes for each witness",
                    action='store_true')
parser.add_argument('--code', help='<Witness AID>:<code> formatted witness auth codes.  Can appear multiple times',
                    default=[], action="append", required=False)
parser.add_argument('--code-time', help='Time the witness codes were captured.', default=None, required=False)

parser.add_argument("--proxy", help="alias for delegation communication proxy", default=None)

rotating.addRotationArgs(parser)


@dataclass
class RotateOptions:
    """
    Configurable options for a rotation performed at the command line.
    Each of the defaults is depended on by the option merge_args_with_file function.
    """
    isith: int | str | list | None
    ncount: int | None
    nsith: int | str | list = '0'
    toad: int = None
    wits: list = None
    witsCut: list = None
    witsAdd: list = None
    data: list = None


def rotate(args):
    """
    Performs a rotation of the identifier of the environment represented by the provided name parameter

        args (parseargs):  Command line argument

    """
    opts = mergeArgsWithFile(args)
    rotDoer = RotateDoer(name=args.name, base=args.base, alias=args.alias, endpoint=args.endpoint,
                         bran=args.bran, wits=opts.wits,
                         cuts=opts.witsCut, adds=opts.witsAdd,
                         isith=opts.isith, nsith=opts.nsith,
                         count=opts.ncount, toad=opts.toad,
                         data=opts.data, proxy=args.proxy, authenticate=args.authenticate,
                         codes=args.code, codeTime=args.code_time)

    doers = [rotDoer]

    return doers


def emptyOptions():
    """
    Empty rotation options used for merging file and command line options
    """
    return RotateOptions(
        isith=None, ncount=None
    )


def mergeArgsWithFile(args):
    """
    Combine the file-based configuration with command line specified arguments
        args (Namespace): the arguments from the command line
    """
    rotate_opts = config.loadFileOptions(args.file, RotateOptions) if args.file != '' else emptyOptions()

    if args.isith is not None:
        rotate_opts.isith = args.isith
    if args.nsith is not None:
        rotate_opts.nsith = args.nsith
    else:
        rotate_opts.nsith = '1'
    if args.next_count is not None:
        rotate_opts.ncount = int(args.next_count)
    else:
        rotate_opts.ncount = 1
    if args.toad is not None:
        rotate_opts.toad = int(args.toad)
    if len(args.witnesses) > 0:
        rotate_opts.wits = args.witnesses
    if len(args.cuts) > 0:
        rotate_opts.witsCut = args.cuts
    if len(args.witness_add) > 0:
        rotate_opts.witsAdd = args.witness_add

    if args.data is not None:
        rotate_opts.data = config.parseData(args.data)

    return rotate_opts


class RotateDoer(doing.DoDoer):
    """
    DoDoer that launches Doers needed to perform a rotation and publication of the rotation event
    to all appropriate witnesses
    """

    def __init__(self, name, base, bran, alias, endpoint=False, isith=None, nsith=None, count=None,
                 toad=None, wits=None, cuts=None, adds=None, data: list = None, proxy=None, authenticate=False,
                 codes=None, codeTime=None):
        """
        Returns DoDoer with all registered Doers needed to perform rotation.

        Parameters:
            name is human-readable str of identifier
            isith is current signing threshold as int or str hex or list of str weights
            nsith is next signing threshold as int or str hex or list of str weights
            count is int next number of signing keys
            toad is int or str hex of witness threshold after cuts and adds
            cuts is list of qb64 pre of witnesses to be removed from witness list
            adds is list of qb64 pre of witnesses to be added to witness list
            data is list of dicts of committed data such as seals
            proxy is optional name of proxy Hab to use to send messages to delegator

       """

        self.alias = alias
        self.isith = isith
        self.nsith = nsith
        self.count = count
        self.toad = toad
        self.data = data
        self.endpoint = endpoint
        self.authenticate = authenticate
        self.codes = codes if codes is not None else []
        self.codeTime = codeTime

        self.wits = wits if wits is not None else []
        self.cuts = cuts if cuts is not None else []
        self.adds = adds if adds is not None else []

        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)  # setup doer

        self.proxy = self.hby.habByName(proxy) if proxy is not None else None
        self.swain = delegating.Anchorer(hby=self.hby, proxy=self.proxy)
        self.postman = forwarding.Poster(hby=self.hby)
        self.mbx = indirecting.MailboxDirector(hby=self.hby, topics=['/receipt', "/replay", "/reply"])
        doers = [self.hbyDoer, self.mbx, self.swain, self.postman, doing.doify(self.rotateDo)]

        super(RotateDoer, self).__init__(doers=doers)

    def rotateDo(self, tymth, tock=0.0):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        hab = self.hby.habByName(name=self.alias)
        if hab is None:
            raise kering.ConfigurationError(f"Alias {self.alias} is invalid")

        receiptor = agenting.Receiptor(hby=self.hby)
        self.extend([receiptor])

        if self.wits:
            if self.adds or self.cuts:
                raise kering.ConfigurationError("you can only specify witnesses or cuts and add")
            ewits = hab.kever.wits

            # wits= [a,b,c]  wits=[b, z]
            self.cuts = set(ewits) - set(self.wits)
            self.adds = set(self.wits) - set(ewits)
            if self.endpoint:
                for wit in self.adds:
                    yield from receiptor.catchup(hab.pre, wit)

        hab.rotate(isith=self.isith, nsith=self.nsith, ncount=self.count, toad=self.toad,
                   cuts=list(self.cuts), adds=list(self.adds),
                   data=self.data)

        auths = {}
        if self.authenticate:
            codeTime = helping.fromIso8601(self.codeTime) if self.codeTime is not None else helping.nowIso8601()
            for arg in self.codes:
                (wit, code) = arg.split(":")
                auths[wit] = f"{code}#{codeTime}"

            for wit in hab.kever.wits:
                if wit in auths:
                    continue
                code = input(f"Entire code for {wit}: ")
                auths[wit] = f"{code}#{helping.nowIso8601()}"

        if hab.kever.delpre:
            self.swain.delegation(pre=hab.pre, sn=hab.kever.sn, auths=auths, proxy=self.proxy)
            print("Waiting for delegation approval...")
            while not self.swain.complete(hab.kever.prefixer, coring.Seqner(sn=hab.kever.sn)):
                yield self.tock

        elif hab.kever.wits:
            if self.endpoint:
                yield from receiptor.receipt(hab.pre, sn=hab.kever.sn, auths=auths)
            else:
                for wit in self.adds:
                    self.mbx.addPoller(hab, witness=wit)

                print("Waiting for witness receipts...")
                witDoer = agenting.WitnessReceiptor(hby=self.hby, auths=auths)
                self.extend(doers=[witDoer])
                yield self.tock

                witDoer.msgs.append(dict(pre=hab.pre))
                while not witDoer.cues:
                    _ = yield self.tock

                self.remove([witDoer])

        if hab.kever.delpre:
            if self.proxy is not None:
                sender = self.proxy
            else:
                sender = hab
            yield from self.postman.sendEventToDelegator(hab=hab, sender=sender, fn=hab.kever.sn)

        print(f'Prefix  {hab.pre}')
        print(f'New Sequence No.  {hab.kever.sn}')
        for idx, verfer in enumerate(hab.kever.verfers):
            print(f'\tPublic key {idx + 1}:  {verfer.qb64}')

        toRemove = [self.hbyDoer, self.swain, self.mbx, self.postman, receiptor]
        self.remove(toRemove)

        return
