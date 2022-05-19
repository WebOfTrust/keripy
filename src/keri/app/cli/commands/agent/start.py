# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.agent module

Witness command line interface
"""

import argparse
import logging
import os

import sys

from keri import help
from keri.app import booting

WEB_DIR_PATH = os.path.dirname(
    os.path.abspath(
        sys.modules.get(__name__).__file__))
STATIC_DIR_PATH = os.path.join(WEB_DIR_PATH, 'static')

d = "Runs KERI Agent controller.\n"
d += "Example:\nagent -t 5621\n"
parser = argparse.ArgumentParser(description=d)
parser.set_defaults(handler=lambda args: launch(args))
parser.add_argument('-T', '--tcp',
                    action='store',
                    default=5621,
                    help="Local port number the HTTP server listens on. Default is 5621.")
parser.add_argument('-a', '--admin-http-port',
                    action='store',
                    default=5623,
                    help="Admin port number the HTTP server listens on. Default is 5623.")
parser.add_argument('--config-file',
                    dest="configFile",
                    action='store',
                    default="",
                    help="configuration filename")
parser.add_argument("--config-dir",
                    dest="configDir",
                    action="store",
                    default=None,
                    help="directory override for configuration data")

parser.add_argument('-c', '--controller',
                    action='store',
                    default=None,
                    help="Identifier prefix to accept control messages from.")
parser.add_argument("-I", '--insecure',
                    action='store_true',
                    help="Run admin HTTP server without checking signatures on controlling requests")
parser.add_argument("-p", "--path",
                    action="store",
                    default=STATIC_DIR_PATH,
                    help="Location of the KIWI app bundle for this agent")


def launch(args):
    """ Launch the agent

    Args:
        args (Namespace) parsed command line argument object:

    Returns:

    """
    help.ogler.level = logging.INFO
    help.ogler.reopen(name="keri", temp=True, clear=True)

    print("\n******* Starting agent listening: http/{}, tcp/{} "
          ".******\n\n".format(args.admin_http_port, args.tcp))

    servery = booting.Servery(port=int(args.admin_http_port))  # Manager of HTTP server environments

    doers = booting.setup(servery=servery, controller=args.controller, configFile=args.configFile,
                          configDir=args.configDir, insecure=args.insecure, tcp=int(args.tcp),
                          adminHttpPort=int(args.admin_http_port), path=args.path)
    return doers + [servery]
