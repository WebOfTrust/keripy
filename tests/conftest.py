"""
Configure PyTest

Use this module to configure pytest
https://docs.pytest.org/en/latest/pythonpath.html

"""
import os
import shutil
import multicommand

import pytest
from hio.base import doing

from keri import kering
from keri.core import scheming, coring
from keri.db import basing
from keri.help import helping
from keri.app.cli import commands


@pytest.fixture()
def mockHelpingNowUTC(monkeypatch):
    """
    Replace nowUTC universally with fixed value for testing
    """

    def mockNowUTC():
        """
        Use predetermined value for now (current time)
        '2021-01-01T00:00:00.000000+00:00'
        """
        return helping.fromIso8601("2021-01-01T00:00:00.000000+00:00")

    monkeypatch.setattr(helping, "nowUTC", mockNowUTC)


@pytest.fixture()
def mockCoringRandomNonce(monkeypatch):
    """ Replay randomNonce with fixed falue for testing"""

    def mockRandomNonce():
        return "A9XfpxIl1LcIkMhUSCCC8fgvkuX8gG9xK3SM-S8a8Y_U"

    monkeypatch.setattr(coring, "randomNonce", mockRandomNonce)


@pytest.fixture
def seeder():
    return DbSeed


class DbSeed:
    @staticmethod
    def seedWitEnds(db, protocols=None, temp=True):
        """ Add endpoint and location records for well known test witnesses

        Args:
            db (Baser): database to add records
            protocols (list) array of str protocol names to load URLs for.
            temp (bool): flag for creating end for witnesses with temp databases
        Returns:

        """
        if protocols is None:
            protocols = [kering.Schemes.tcp, kering.Schemes.http]

        wits = dict()
        if temp:
            wits['wan'] = 'B6KBd3GmnWvjcmE775zNRPCsJfOhasjBbyLjUpYOWvyw'
            wits['wes'] = 'B3y3efWXFxXRJYYkggXjp-lJSoDsyqt7kok03edvHeas'
            wits['wil'] = 'B7L80wOpOxsItVk1p4tYiK6vNjVVLExvhB5yGEuk864U'
        else:
            wits['wan'] = 'BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo'
            wits['wes'] = 'Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c'
            wits['wil'] = 'BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw'

        wanEndKeys = (wits['wan'], "controller",
                      wits['wan'])
        ender = basing.EndpointRecord(allowed=True)  # create new record
        db.ends.pin(keys=wanEndKeys, val=ender)  # overwrite

        if kering.Schemes.tcp in protocols:
            locer = basing.LocationRecord(url="tcp://127.0.0.1:5632/")  # create new record
            wanLocKeys = (wits['wan'], kering.Schemes.tcp)
            db.locs.pin(keys=wanLocKeys, val=locer)  # overwrite

        if kering.Schemes.http in protocols:
            httplocer = basing.LocationRecord(url="http://127.0.0.1:5642/")  # create new record
            wanHttpLocKeys = (wits['wan'], kering.Schemes.http)
            db.locs.pin(keys=wanHttpLocKeys, val=httplocer)  # overwrite

        wesEndKeys = (wits['wes'], "controller",
                      wits['wes'])
        ender = basing.EndpointRecord(allowed=True)  # create new record
        db.ends.pin(keys=wesEndKeys, val=ender)  # overwrite

        if kering.Schemes.tcp in protocols:
            locer = basing.LocationRecord(url="tcp://127.0.0.1:5634/")  # create new record
            wesLocKeys = (wits['wes'], kering.Schemes.tcp)
            db.locs.pin(keys=wesLocKeys, val=locer)  # overwrite

        if kering.Schemes.http in protocols:
            httplocer = basing.LocationRecord(url="http://127.0.0.1:5644/")  # create new record
            wesHttpLocKeys = (wits['wes'], kering.Schemes.http)
            db.locs.pin(keys=wesHttpLocKeys, val=httplocer)  # overwrite

        wilEndKeys = ('B7L80wOpOxsItVk1p4tYiK6vNjVVLExvhB5yGEuk864U', "controller",
                      'B7L80wOpOxsItVk1p4tYiK6vNjVVLExvhB5yGEuk864U')
        ender = basing.EndpointRecord(allowed=True)  # create new record
        db.ends.pin(keys=wilEndKeys, val=ender)  # overwrite
        if kering.Schemes.tcp in protocols:
            locer = basing.LocationRecord(url="tcp://127.0.0.1:5633/")  # create new record
            wilLocKeys = ('B7L80wOpOxsItVk1p4tYiK6vNjVVLExvhB5yGEuk864U', kering.Schemes.tcp)
            db.locs.pin(keys=wilLocKeys, val=locer)  # overwrite

        if kering.Schemes.http in protocols:
            httplocer = basing.LocationRecord(url="http://127.0.0.1:5643/")  # create new record
            wilHttpLocKeys = ('B7L80wOpOxsItVk1p4tYiK6vNjVVLExvhB5yGEuk864U', kering.Schemes.http)
            db.locs.pin(keys=wilHttpLocKeys, val=httplocer)  # overwrite

    @staticmethod
    def seedWatcherEnds(db, protocols=None):
        """ Add endpoint and location records for well known test watchers

        Args:
            db (Baser): database to add records
            protocols (list) array of str protocol names to load URLs for.
        Returns:

        """
        if protocols is None:
            protocols = [kering.Schemes.tcp, kering.Schemes.http]

        watEndKeys = ('BZg042qyBYoNC4rII1qdn7sPJPSh5vp5y0xnVYbJPujw', "controller",
                      'BZg042qyBYoNC4rII1qdn7sPJPSh5vp5y0xnVYbJPujw')
        ender = basing.EndpointRecord(allowed=True)  # create new record
        db.ends.pin(keys=watEndKeys, val=ender)  # overwrite

        if kering.Schemes.tcp in protocols:
            locer = basing.LocationRecord(url="tcp://127.0.0.1:5634/")  # create new record
            watLocKeys = ('BZg042qyBYoNC4rII1qdn7sPJPSh5vp5y0xnVYbJPujw', kering.Schemes.tcp)
            db.locs.pin(keys=watLocKeys, val=locer)  # overwrite

        if kering.Schemes.http in protocols:
            httplocer = basing.LocationRecord(url="http://127.0.0.1:5644/")  # create new record
            watHttpLocKeys = ('BZg042qyBYoNC4rII1qdn7sPJPSh5vp5y0xnVYbJPujw', kering.Schemes.http)
            db.locs.pin(keys=watHttpLocKeys, val=httplocer)  # overwrite

    @staticmethod
    def seedSchema(db):
        raw = (
            b'{"$id": "E1MCiPag0EWlqeJGzDA9xxr1bUSUR4fZXtqHDrwdXgbk", "$schema": '
            b'"http://json-schema.org/draft-07/schema#", "title": "Legal Entity vLEI Credential", "description": "A '
            b'vLEI Credential issued by a Qualified vLEI issuer to a Legal Entity", "credentialType": '
            b'"LegalEntityvLEICredential", "properties": {"v": {"type": "string"}, "d": {"type": "string"}, '
            b'"i": {"type": "string"}, "ri": {"description": "credential status registry", "type": "string"}, '
            b'"s": {"description": "schema SAID", "type": "string"}, "a": {"description": "data block", "properties": '
            b'{"d": {"type": "string"}, "i": {"type": "string"}, "dt": {"description": "issuance date time", '
            b'"format": "date-time", "type": "string"}, "LEI": {"type": "string"}}, "additionalProperties": false, '
            b'"required": ["i", "dt", "LEI"], "type": "object"}, "e": {"description": "edges block", '
            b'"type": "object"}, "r": {"type": "object", "description": "rules block"}}, "additionalProperties": '
            b'false, "required": ["i", "ri", "s", "d", "e", "r"], "type": "object"}')

        schemer = scheming.Schemer(raw=raw)
        db.schema.pin(schemer.said, schemer)

        raw = (
            b'{"$id":"ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI",'
            b'"$schema":"http://json-schema.org/draft-07/schema#","title":"GLEIF vLEI Credential","description":"The '
            b'vLEI Credential issued to GLEIF","credentialType":"GLEIFvLEICredential","type":"object","properties":{'
            b'"v":{"type":"string"},"d":{"type":"string"},"i":{"type":"string"},"ri":{"description":"credential '
            b'status registry","type":"string"},"s":{"description":"schema SAID","type":"string"},'
            b'"a":{"description":"data block","properties":{"d":{"type":"string"},"i":{"type":"string"},'
            b'"dt":{"description":"issuance date time","format":"date-time","type":"string"},'
            b'"LEI":{"type":"string"}},"additionalProperties":false,"required":["d","dt","LEI"],"type":"object"},'
            b'"e":{"type":"object"}},"additionalProperties":false,"required":["d","i","ri"]}')

        schemer = scheming.Schemer(raw=raw)
        db.schema.pin(schemer.said, schemer)

        raw = (
            b'{"$id":"EPz3ZvjQ_8ZwRKzfA5xzbMW8v8ZWLZhvOn2Kw1Nkqo_Q",'
            b'"$schema":"http://json-schema.org/draft-07/schema#","title":"Legal Entity vLEI Credential",'
            b'"description":"A vLEI Credential issued by a Qualified vLEI issuer to a Legal Entity",'
            b'"credentialType":"LegalEntityvLEICredential","properties":{"v":{"type":"string"},"d":{"type":"string"},'
            b'"i":{"type":"string"},"ri":{"description":"credential status registry","type":"string"},'
            b'"s":{"description":"schema SAID","type":"string"},"a":{"description":"data block","properties":{"d":{'
            b'"type":"string"},"i":{"type":"string"},"dt":{"description":"issuance date time","format":"date-time",'
            b'"type":"string"},"LEI":{"type":"string"}},"additionalProperties":false,"required":["i","dt","LEI"],'
            b'"type":"object"},"e":{"description":"edges block","properties":{"d":{"description":"SAID of edges '
            b'block","type":"string"},"qualifiedvLEIIssuervLEICredential":{"description":"node SAID of issuer '
            b'credential","properties":{"n":{"type":"string"}},"additionalProperties":false,"required":["n"],'
            b'"type":"object"}},"additionalProperties":false,"required":["d","qualifiedvLEIIssuervLEICredential"],'
            b'"type":"object"},"r":{"type":"array","items":{"type":"object"},"description":"rules block",'
            b'"minItems":0}},"additionalProperties":false,"required":["i","ri","s","d","e","r"],"type":"object"}')

        schemer = scheming.Schemer(raw=raw)
        db.schema.pin(schemer.said, schemer)

        raw = (
            b'{"$id":"EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw",'
            b'"$schema":"http://json-schema.org/draft-07/schema#","title":"Qualified vLEI Issuer Credential",'
            b'"description":"A vLEI Credential issued by GLEIF to Qualified vLEI Issuers which allows the Qualified '
            b'vLEI Issuers to issue, verify and revoke Legal Entity vLEI Credentials and Legal Entity Official '
            b'Organizational Role vLEI Credentials","credentialType":"QualifiedvLEIIssuervLEICredential",'
            b'"properties":{"v":{"type":"string"},"d":{"type":"string"},"i":{"type":"string"},'
            b'"ri":{"description":"credential status registry","type":"string"},"s":{"description":"schema SAID",'
            b'"type":"string"},"a":{"description":"data block","properties":{"d":{"type":"string"},'
            b'"i":{"type":"string"},"dt":{"description":"issuance date time","format":"date-time","type":"string"},'
            b'"LEI":{"type":"string"},"gracePeriod":{"default":90,"type":"integer"}},"additionalProperties":false,'
            b'"required":["i","dt","LEI"],"type":"object"},"e":{"type":"object"}},"additionalProperties":false,'
            b'"required":["i","ri","s","d"],"type":"object"}')

        schemer = scheming.Schemer(raw=raw)
        db.schema.pin(schemer.said, schemer)


class Helpers:

    @staticmethod
    def remove_test_dirs(name):
        if os.path.exists(f'/usr/local/var/keri/db/{name}'):
            shutil.rmtree(f'/usr/local/var/keri/db/{name}')
        if os.path.exists(f'/usr/local/var/keri/ks/{name}'):
            shutil.rmtree(f'/usr/local/var/keri/ks/{name}')
        if os.path.exists(f'/usr/local/var/keri/reg/{name}'):
            shutil.rmtree(f'/usr/local/var/keri/reg/{name}')
        if os.path.exists(f'/usr/local/var/keri/cf/{name}.json'):
            os.remove(f'/usr/local/var/keri/cf/{name}.json')
        if os.path.exists(f'/usr/local/var/keri/cf/{name}'):
            shutil.rmtree(f'/usr/local/var/keri/cf/{name}')


@pytest.fixture
def helpers():
    return Helpers


class CommandDoer(doing.DoDoer):
    """
    DoDoer for running a single command-line command by initializing
    the doers for that command and executing them until they complete.

    """

    def __init__(self, command, **kwa):
        self.command = command
        super(CommandDoer, self).__init__(doers=[doing.doify(self.cmdDo)], **kwa)

    def cmdDo(self, tymth, tock=0.0):
        """  Execute single command from .command by parsing and executing the resulting doers """

        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        parser = multicommand.create_parser(commands)
        args = parser.parse_args(self.command)
        assert args.handler is not None
        doers = args.handler(args)

        self.extend(doers)

        while True:
            done = True
            for doer in doers:
                if not doer.done:
                    done = False

            if done:
                break
            yield self.tock

        return True
