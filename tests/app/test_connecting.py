# -*- encoding: utf-8 -*-
"""
tests.app.connecting module
"""
import io
import os

import pytest

from keri import kering
from keri.app import connecting, habbing
from keri.core import signing


def test_organizer():
    joe = "EtyPSuUjLyLdXAtGMrsTt0-ELyWeU8fJcymHiGOfuaSA"
    bob = "EuEQX8At31X96iDVpigv-rTdOKvFiWFunbJ1aDfq89IQ"
    ken = "EFC7f_MEPE5dboc_E4yG15fnpMD34YaU3ue6vnDLodJU"
    jen = "ED61oxVwVNf_olqR5wAhAjvuK59xuBOJXnJPGhwWDYoc"
    wil = "EPzeu5_C80nzPc_BGUHVBkXXfNmlS55Ayl7Rd1I0gWFE"
    sal = "Eo60ITGA69z4jNBU4RsvbgsjfAHFcTM2HVEXea1SvnXk"
    joed = dict(first="Joe", last="Jury", address="9934 Glen Creek St.", city="Lawrence", state="MA", zip="01841",
                company="HCF", alias="joe")
    bobd = dict(first="Bob", last="Burns", address="37 East Shadow Brook St.", city="Sebastian", state="FL",
                zip="32958", company="HCF", alias="bob")
    kend = dict(first="Ken", last="Knight", address="28 Williams Ave.", city="Bridgewater", state="NJ", zip="08807",
                company="GLEIF", alias="ken")
    jend = dict(first="Jen", last="Jones", address="7977 Manor Street", city="Henderson", state="KY", zip="42420",
                company="GLEIF", alias="jen")
    wild = dict(first="Will", last="Weaver", address="7196 2nd Dr.", city="Norwich", state="CT", zip="06360",
                company="GLEIF", alias="will")
    sald = dict(first="Sally", last="Smith", address="31 Gainsway Court", city="Lake Charles", state="LA",
                zip="70605",
                company="GLEIF", alias="sally")

    with habbing.openHby(name="test", temp=True) as hby:
        org = connecting.Organizer(hby=hby)

        org.replace(pre=joe, data=joed)
        org.replace(pre=bob, data=bobd)
        org.replace(pre=ken, data=kend)
        org.replace(pre=jen, data=jend)
        org.replace(pre=wil, data=wild)
        org.replace(pre=sal, data=sald)

        contacts = org.list()
        assert len(contacts) == 6
        data = {d["id"]: d for d in contacts}
        assert joe in data
        assert bob in data
        assert ken in data
        assert jen in data
        assert wil in data
        assert sal in data

        d = org.get(pre=bob)
        assert d["id"] == bob
        assert d["first"] == "Bob"
        assert d["address"] == "37 East Shadow Brook St."
        assert d["city"] == "Sebastian"

        d = org.get(pre=sal)
        assert d["id"] == sal
        assert d["first"] == "Sally"
        assert d["alias"] == "sally"

        d = org.get(pre="E8AKUcbZyik8EdkOwXgnyAxO5mSIPJWGZ_o7zMhnNnjo")
        assert d is None

        d = org.get(pre=jen)
        assert d["id"] == jen
        assert d["first"] == "Jen"
        assert d["last"] == "Jones"
        org.set(pre=jen, field="last", val="Smith")
        d = org.get(pre=jen)
        assert d["last"] == "Smith"

        org.unset(pre=jen, field="first")
        d = org.get(pre=jen)
        assert d["id"] == jen
        assert "first" not in d
        assert d["last"] == "Smith"

        org.update(pre=ken, data=dict(
            first="Kenneth",
            mobile="222-555-1212"
        ))

        d = org.get(pre=ken)
        assert d == {'address': '28 Williams Ave.',
                     'alias': 'ken',
                     'city': 'Bridgewater',
                     'company': 'GLEIF',
                     'first': 'Kenneth',
                     'id': 'EFC7f_MEPE5dboc_E4yG15fnpMD34YaU3ue6vnDLodJU',
                     'last': 'Knight',
                     'mobile': '222-555-1212',
                     'state': 'NJ',
                     'zip': '08807'}

        org.replace(pre=ken, data=kend)
        d = org.get(pre=ken)
        assert d == {'address': '28 Williams Ave.',
                     'alias': 'ken',
                     'city': 'Bridgewater',
                     'company': 'GLEIF',
                     'first': 'Ken',
                     'id': 'EFC7f_MEPE5dboc_E4yG15fnpMD34YaU3ue6vnDLodJU',
                     'last': 'Knight',
                     'state': 'NJ',
                     'zip': '08807'}

        org.rem(pre=wil)
        d = org.get(pre=wil)
        assert d is None
        org.replace(pre=wil, data=wild)

        companies = org.values(field="company")
        assert companies == ["GLEIF", "HCF"]

        grouped = org.find(field="company", val="HCF")
        data = {d["id"]: d for d in grouped}
        assert len(data) == 2
        assert joe in data
        assert bob in data

        grouped = org.find(field="company", val="GLEIF")
        data = {d["id"]: d for d in grouped}
        assert len(data) == 4
        assert ken in data
        assert jen in data
        assert wil in data
        assert sal in data

        d = org.get(pre=ken)
        assert d == {'address': '28 Williams Ave.',
                     'alias': 'ken',
                     'city': 'Bridgewater',
                     'company': 'GLEIF',
                     'first': 'Ken',
                     'id': 'EFC7f_MEPE5dboc_E4yG15fnpMD34YaU3ue6vnDLodJU',
                     'last': 'Knight',
                     'state': 'NJ',
                     'zip': '08807'}

        # Update the Jen's data signature by signing garbage
        nonce = signing.Salter().qb64
        cigar = hby.signator.sign(ser=nonce.encode("utf-8"))
        hby.db.ccigs.pin(keys=(jen,), val=cigar)
        with pytest.raises(kering.ValidationError):
            org.get(pre=jen)

        # This will fail too because it contains Jen
        with pytest.raises(kering.ValidationError):
            org.find(field="company", val="GLEIF")


def test_organizer_imgs():

    with habbing.openHab(name="test", transferable=True, temp=True) as (hby, hab):
        org = connecting.Organizer(hby=hby)
        pre = "EFC7f_MEPE5dboc_E4yG15fnpMD34YaU3ue6vnDLodJU"
        data = bytearray(os.urandom(100000))
        assert len(data) == 100000
        stream = io.BytesIO(data)

        org.setImg(pre, "image/png", stream)

        img = bytearray()
        for chunk in org.getImg(pre):
            img.extend(chunk)

        assert img == data

        md = org.getImgData(pre=pre)
        assert md["type"] == "image/png"
        assert md["length"] == len(data)

        pre = "Eo60ITGA69z4jNBU4RsvbgsjfAHFcTM2HVEXea1SvnXk"
        md = org.getImgData(pre=pre)
        assert md is None

        img = bytearray()
        for chunk in org.getImg(pre):
            img.extend(chunk)

        assert len(img) == 0
