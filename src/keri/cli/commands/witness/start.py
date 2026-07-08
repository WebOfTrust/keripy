# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.witness module

Witness command line interface
"""
import argparse
import logging
import os
import sys

from hio.help import ogler

from keri import __version__

from ...common import Parsery, setupHby

from ....app import (Habery, HaberyDoer, Keeper, Configer,
                     runController, setupWitness)
from ....kering import AuthError

logger = ogler.getLogger()


d = "Runs KERI witness controller.\n"
d += "Example:\nwitness -H 5631 -t 5632\n"
parser = argparse.ArgumentParser(description=d, parents=[Parsery.keystore()], conflict_handler='resolve')
parser.set_defaults(handler=lambda args: launch(args))
parser.add_argument('-V', '--version',
                    action='version',
                    version=__version__,
                    help="Prints out version of script runner.")
parser.add_argument('-H', '--http',
                    action='store',
                    default=5631,
                    help="Local port number the HTTP server listens on. Default is 5631.")
parser.add_argument('-T', '--tcp',
                    action='store',
                    default=5632,
                    help="Local port number the TCP server listens on. Default is 5632.")
parser.add_argument('-n', '--name',
                    action='store',
                    default="witness",
                    help="Name of controller. Default is witness.")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument("--config-dir", "-c", dest="configDir", help="directory override for configuration data")
parser.add_argument('--config-file',
                    dest="configFile",
                    action='store',
                    default=None,
                    help="configuration filename override")
parser.add_argument("--keypath", action="store", required=False, default=None)
parser.add_argument("--certpath", action="store", required=False, default=None)
parser.add_argument("--cafilepath", action="store", required=False, default=None)
parser.add_argument("--loglevel", action="store", required=False, default="CRITICAL",
                    help="Set log level to DEBUG | INFO | WARNING | ERROR | CRITICAL. Default is CRITICAL")
parser.add_argument("--logdir", action="store", required=False, default=None,
                    help="directory under which the witness writes its log file. "
                         "If not defined, logs are not written to a file.")
parser.add_argument("--logfile", action="store", required=False, default=None,
                    help="DEPRECATED: use --logdir. Path to a log file; only its directory is used "
                         "(the file name and log subdirectory are derived internally).")
parser.add_argument("--no-prompt", action="store_true", default=None, required=False,
                    help="Disable interactive prompt", dest="noPrompt")


def launch(args):
    # Normalize level case; avoid invalid lowercase values that silently break level filtering
    ogler.level = logging.getLevelName(args.loglevel.upper())

    logdir = args.logdir
    if args.logfile:
        print(f"--logfile is deprecated; use --logdir. Logging to {ogler.path}", file=sys.stderr)
        logdir = os.path.dirname(args.logfile) or "."

    if logdir is not None:  # Must reopen
        ogler.headDirPath = logdir
        ogler.reopen(name=args.name, temp=False, clear=True)

    ogler.getLogger()  # re-applies ogler.level, replaces handlers, binding to "logger" var

    logger.info("\n******* Starting Witness for %s listening: http/%s, tcp/%s "
                ".******\n\n", args.name, args.http, args.tcp)

    runWitness(name=args.name,
               base=args.base,
               alias=args.alias,
               bran=args.bran,
               tcp=int(args.tcp),
               http=int(args.http),
               configDir=args.configDir,
               configFile=args.configFile,
               keypath=args.keypath,
               certpath=args.certpath,
               cafilepath=args.cafilepath,
               noPrompt=args.noPrompt)

    logger.info("\n******* Ended Witness for %s listening: http/%s, tcp/%s"
                ".******\n\n", args.name, args.http, args.tcp)


def runWitness(name="witness", base="", alias="witness", bran="", tcp=5631, http=5632, expire=0.0,
               configDir="", configFile=None, keypath=None, certpath=None, cafilepath=None,
               noPrompt=None):
    """
    Setup and run one witness
    """
    noPrompt = noPrompt if noPrompt is not None else not sys.stdin.isatty()  # When not TTY then do not prompt

    ks = Keeper(name=name,
                base=base,
                temp=False,
                reopen=True)

    aeid = ks.gbls.get('aeid')
    ks.close()  # release LMDB env before Habery/setupHby re-opens the same keystore

    cf = None
    if configFile:
        cf = Configer(name=configFile, headDirPath=configDir, temp=False, reopen=True, clear=False)

    hby = None
    try:
        if aeid is None:
            hby = Habery(name=name, base=base, bran=bran, cf=cf)
        else:
            # Prompt only for TTY; fail fast for no passcode on script/service witness start
            if not bran and noPrompt:
                raise AuthError(f"passcode required for keystore {name!r} but prompting is disabled. "
                                f"pass --passcode or omit --no-prompt in an interactive terminal..")
            hby = setupHby(name=name, base=base, bran=bran, cf=cf, noPrompt=noPrompt)

        hbyDoer = HaberyDoer(habery=hby)  # setup doer
        doers = [hbyDoer]

        doers.extend(setupWitness(alias=alias,
                                  hby=hby,
                                  tcpPort=tcp,
                                  httpPort=http,
                                  keypath=keypath,
                                  certpath=certpath,
                                  cafilepath=cafilepath))

        runController(doers=doers, expire=expire)
    except Exception:
        # Log startup failures at CRITICAL with traceback.
        logger.critical("Witness %r failed to start", name, exc_info=True)
        raise
    finally:
        # Close Habery LMDB to avoid leftover locks on failed start blocking next start attempt
        if hby is not None:
            hby.close()
