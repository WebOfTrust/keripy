# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.mailbox module

Mailbox host command line interface.

This command starts the standalone mailbox host composition from
``keri.app.mailboxing`` around an existing non-transferable local habitat.
"""
import argparse
import logging
from urllib.parse import urlsplit, urlunsplit, urlparse

from hio.help import ogler

from keri import __version__

from ...common import Parsery, setupHby

from ....app import runController, setupMailbox, Habery, HaberyDoer, Keeper, Configer
from ....kering import Roles, Schemes
d = "Runs KERI mailbox host.\n"
d += "Example:\nmailbox start --alias relay --http 9000\n"
parser = argparse.ArgumentParser(description=d, parents=[Parsery.keystore()], conflict_handler='resolve')
parser.set_defaults(handler=lambda args: launch(args))
parser.add_argument('-V', '--version',
                    action='version',
                    version=__version__,
                    help="Prints out version of script runner.")
parser.add_argument('-H', '--http',
                    action='store',
                    default=None,
                    help="Local port number the HTTP server listens on.")
parser.add_argument('--alias', '-a', help='human readable alias for the local mailbox identifier', required=True)
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
parser.add_argument("--logfile", action="store", required=False, default=None,
                    help="path of the log file. If not defined, logs will not be written to the file.")

logger = ogler.getLogger()

def launch(args):
    """CLI entrypoint that configures logging and runs one mailbox host."""
    ogler.level = logging.getLevelName(args.loglevel)
    if args.logfile is not None:
        ogler.headDirPath = args.logfile
        ogler.reopen(name=args.name, temp=False, clear=True)

    runMailbox(name=args.name,
               base=args.base,
               alias=args.alias,
               bran=args.bran,
               http=args.http,
               configDir=args.configDir,
               configFile=args.configFile,
               keypath=args.keypath,
               certpath=args.certpath,
               cafilepath=args.cafilepath)


def runMailbox(name="mailbox", base="", alias="mailbox", bran="", http=None, expire=0.0,
               configDir="", configFile=None,
               keypath=None, certpath=None, cafilepath=None):
    """Set up and run one mailbox host over an existing local mailbox habitat.

    The selected alias resolves to the hosted non-transferable mailbox AID used for:
        - mailbox authorization target checks
        - forwarded-message storage authorization
        - mailbox-admin routing relative to the stored mailbox URL path when
          its ``/loc/scheme`` record includes a non-root path

    Startup behavior:
        - create the keystore when it does not yet exist
        - create the mailbox AID when the alias does not yet exist
        - reconcile self HTTP(S) location plus self controller/mailbox role
          state from authoritative config or stored state before boot
    """

    cf = _mailboxConfig(name=name, configDir=configDir, configFile=configFile)
    hby = _openMailboxHabery(name=name, base=base, bran=bran, cf=cf)
    hbyDoer = HaberyDoer(habery=hby)

    #
    try:
        hab, startup = _prepareMailboxHabitat(
            hby=hby,
            alias=alias,
            requireConfig=bool(configDir or configFile),
        )
    except Exception as e:
        hby.close()
        raise e

    try:
        http = int(http) if http is not None else urlparse(startup["url"]).port
    except ValueError:
        http = urlparse(startup["url"]).port

    doers = [hbyDoer]
    doers.extend(setupMailbox(alias=alias,
                              hby=hby,
                              httpPort=http,
                              keypath=keypath,
                              certpath=certpath,
                              cafilepath=cafilepath))
    print(f"Mailbox started on port {http}")
    logger.info("\n******* Starting Mailbox for %s listening: http/%s .******\n\n", name, http)
    runController(doers=doers, expire=expire)


def _mailboxConfig(name, configDir="", configFile=None):
    """Return the config file used to bootstrap mailbox host identity state."""
    if configFile is None and not configDir:
        return None

    cfgName = configFile if configFile is not None else name
    return Configer(name=cfgName, base="", headDirPath=configDir, temp=False, reopen=True, clear=False)


def _openMailboxHabery(name, base="", bran="", cf=None, temp=False):
    """Open or create the Habery used by mailbox start.

    This mirrors the witness-start lifecycle instead of using the
    existing-keystore-only helper from `cli.common.existing`.
    """
    ks = Keeper(name=name,
                base=base,
                temp=temp,
                reopen=True)
    aeid = ks.gbls.get('aeid')
    ks.close()

    if aeid is None:
        return Habery(name=name, base=base, bran=bran, cf=cf, temp=temp)
    return setupHby(name=name, base=base, bran=bran, cf=cf, temp=temp)


def _normalizeMailboxUrl(url):
    """Validate and normalize one authoritative mailbox HTTP(S) URL."""
    parts = urlsplit(url)
    if parts.scheme not in (Schemes.http, Schemes.https):
        raise ValueError(f"Mailbox URL must use HTTP(S): {url}")
    if not parts.netloc:
        raise ValueError(f"Mailbox URL is missing host/port: {url}")

    path = parts.path.rstrip("/") or "/"
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment))


def _storedMailboxUrl(hab):
    """Return the one authoritative stored self HTTP(S) URL for mailbox start."""
    urls = {}
    for scheme in (Schemes.https, Schemes.http):
        fetched = hab.fetchUrls(eid=hab.pre, scheme=scheme)
        if fetched and scheme in fetched:
            urls[scheme] = _normalizeMailboxUrl(fetched[scheme])

    if not urls:
        return None
    if len(urls) > 1:
        raise ValueError(f"Local mailbox alias {hab.pre} has more than one HTTP(S) URL; use one authoritative URL for mailbox start")
    return urls[Schemes.https] if Schemes.https in urls else urls[Schemes.http]


def _roleEnabled(hby, cid, role, eid):
    """Return True when the endpoint role is active in `ends.`."""
    end = hby.db.ends.get(keys=(cid, role, eid))
    return bool(end and (end.allowed or end.enabled))


def _mailboxIdentityComplete(hby, hab, url):
    """Return True when stored self state matches the authoritative startup URL."""
    return (_storedMailboxUrl(hab) == _normalizeMailboxUrl(url)
            and _roleEnabled(hby, hab.pre, Roles.controller, hab.pre)
            and _roleEnabled(hby, hab.pre, Roles.mailbox, hab.pre))


def _resolveEffectiveStartup(hab):
    """Choose authoritative startup material from resulting stored state."""
    url = _storedMailboxUrl(hab)
    if url is None:
        return None

    return dict(url=url, datetime=None, source="stored")


def _hasConfigSection(cf, alias):
    """Return True when the loaded config contains the mailbox alias section."""
    if cf is None:
        return False

    conf = cf.get()
    return isinstance(conf, dict) and alias in conf


def _reconcileMailboxIdentity(hby, hab, url):
    """Apply self location/controller/mailbox state needed for mailbox hosting."""
    msgs = bytearray()

    if _storedMailboxUrl(hab) != url:
        scheme = urlsplit(url).scheme
        msgs.extend(hab.makeLocScheme(url=url,
                                      eid=hab.pre,
                                      scheme=scheme))

    if not _roleEnabled(hby, hab.pre, Roles.controller, hab.pre):
        msgs.extend(hab.makeEndRole(eid=hab.pre,
                                    role=Roles.controller,
                                    allow=True))

    if not _roleEnabled(hby, hab.pre, Roles.mailbox, hab.pre):
        msgs.extend(hab.makeEndRole(eid=hab.pre,
                                    role=Roles.mailbox,
                                    allow=True))

    if msgs:
        hab.psr.parse(ims=msgs)

    if not _mailboxIdentityComplete(hby, hab, url):
        raise ValueError("Mailbox startup reconciliation did not produce accepted self location/controller/mailbox state")


def _prepareMailboxHabitat(hby, alias, requireConfig=False):
    """Init or reconcile the hosted non-transferable mailbox AID before serving."""
    hab = hby.habByName(alias)

    if hab is None:
        if not _hasConfigSection(hby.cf, alias):
            raise ValueError("Mailbox startup requires a matching config alias section when the alias does not already exist")

        hab = hby.makeHab(name=alias, transferable=False)
    else:
        hab.reconfigure()

    if hab.kever is None:
        raise ValueError(f"Mailbox alias {alias} is missing accepted key state")
    if hab.kever.prefixer.transferable:
        raise ValueError(f"Mailbox alias {alias} must be non-transferable")

    if requireConfig and not _hasConfigSection(hby.cf, alias):
        raise ValueError(f"Config section '{alias}' is missing")

    startup = _resolveEffectiveStartup(hab)
    if startup is None:
        raise ValueError("Selected alias does not have complete mailbox startup state and no usable configured HTTP(S) mailbox URL was loaded")

    if not _mailboxIdentityComplete(hby, hab, startup["url"]):
        _reconcileMailboxIdentity(hby, hab, startup["url"])

    return hab, startup
