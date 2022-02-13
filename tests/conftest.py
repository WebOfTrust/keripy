"""
Configure PyTest

Use this module to configure pytest
https://docs.pytest.org/en/latest/pythonpath.html

"""
import pytest

from keri import kering
from keri.db import basing
from keri.help import helping


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

