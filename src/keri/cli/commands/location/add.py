# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
from urllib.parse import urlparse


from hio.base import doing
from hio.help import ogler

from ...common import Parsery, setupHby, parseVersion

from .... import ConfigurationError, Kinds, Version

from ....app import (GroupHab, Multiplexor, indirecting,
                     forwarding, WitnessPublisher, Notifier,
                     multisigRpyExn)
from ....app.grouping import loadHandlers

from ....core import Parser
from ....peer import Exchanger


logger = ogler.getLogger()

parser = argparse.ArgumentParser(description='Add new endpoint location record.', 
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: add_loc(args))
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument("--url", "-u", help="Location URL",
                    required=True)
parser.add_argument("--eid", "-e", help="qualified base64 of AID to associate a location with, defaults to alias aid ",
                    required=False, default=None)
parser.add_argument("--time", help="timestamp for the end auth", required=False, default=None)
parser.add_argument('--version', default=None, required=False, type=parseVersion,
                    help='KERI protocol version for the endpoint location reply, such as 1.0 or 2.0')


def add_loc(args):
    """ Command line tool for adding location scheme records

    """
    ld = LocationDoer(name=args.name,
                      base=args.base,
                      alias=args.alias,
                      bran=args.bran,
                      url=args.url,
                      eid=args.eid,
                      timestamp=args.time,
                      version=args.version)
    return [ld]


class LocationDoer(doing.DoDoer):

    def __init__(self, name, base, alias, bran, url, eid, timestamp=None, version=None):
        self.url = url
        self.eid = eid
        self.timestamp = timestamp
        self.version = version
        self.replyKwargs = dict(version=version, gvrsn=version, kind=Kinds.json) if version is not None else {}

        self.hby = setupHby(name=name, base=base, bran=bran)
        self.hab = self.hby.habByName(alias)
        self.witpub = WitnessPublisher(hby=self.hby)
        self.postman = forwarding.Poster(hby=self.hby, version=version, kind=Kinds.json)
        notifier = Notifier(self.hby)
        mux = Multiplexor(self.hby, notifier=notifier)
        exc = Exchanger(hby=self.hby, handlers=[])
        loadHandlers(exc, mux)

        mbx = indirecting.MailboxDirector(hby=self.hby, topics=["/receipt", "/multisig", "/replay"], exc=exc,
                                          **self.replyKwargs)

        if self.hab is None:
            raise ConfigurationError(f"unknown alias={alias}")

        self.toRemove = [self.witpub, self.postman, mbx]

        super(LocationDoer, self).__init__(doers=self.toRemove + [doing.doify(self.roleDo)])

    def roleDo(self, tymth, tock=0.0, **kwa):
        """ Export any end reply messages previous saved for the provided AID

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Returns:
            doifiable Doist compatible generator method

        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        up = urlparse(self.url)
        eid = self.eid if self.eid is not None else self.hab.pre

        msg = self.hab.makeLocScheme(url=self.url, eid=eid, scheme=up.scheme, **self.replyKwargs)
        parser_version = self.version if self.version is not None else Version
        parser = Parser(version=parser_version)
        parser.parse(ims=bytes(msg), kvy=self.hab.kvy, rvy=self.hab.rvy)

        if isinstance(self.hab, GroupHab):
            smids = self.hab.db.signingMembers(pre=self.hab.pre)
            smids.remove(self.hab.mhab.pre)

            for recp in smids:  # this goes to other participants only as a signaling mechanism
                exn, atc = multisigRpyExn(ghab=self.hab, rpy=msg,
                                          version=self.version, kind=Kinds.json)
                self.postman.send(src=self.hab.mhab.pre,
                                  dest=recp,
                                  topic="multisig",
                                  serder=exn,
                                  attachment=atc)

        while not self.hab.loadLocScheme(scheme=up.scheme, eid=eid, gvrsn=self.version):
            yield self.tock

        self.witpub.msgs.append(dict(pre=self.hab.pre, msg=bytes(msg)))

        while not self.witpub.cues:
            yield self.tock

        print(f"Location {self.url} added for aid {eid} with scheme {up.scheme}")

        self.remove(self.toRemove)
        return
