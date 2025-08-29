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


def test_base_organizer():
    """Test BaseOrganizer with custom database configuration"""
    joe = "EtyPSuUjLyLdXAtGMrsTt0-ELyWeU8fJcymHiGOfuaSA"
    bob = "EuEQX8At31X96iDVpigv-rTdOKvFiWFunbJ1aDfq89IQ"
    
    joed = {"first": "Joe", "last": "Jury", "address": "9934 Glen Creek St.", "city": "Lawrence", "state": "MA", "zip": "01841",
                "company": "HCF", "alias": "joe"}
    bobd = {"first": "Bob", "last": "Burns", "address": "37 East Shadow Brook St.", "city": "Sebastian", "state": "FL",
                "zip": "32958", "company": "HCF", "alias": "bob"}

    with habbing.openHby(name="test", temp=True) as hby:
        # Test BaseOrganizer with contact databases (same as Organizer)
        base_org = connecting.BaseOrganizer(
            hby=hby,
            cigsdb=hby.db.ccigs,
            datadb=hby.db.cons,
            fielddb=hby.db.cfld,
            imgsdb=hby.db.imgs
        )

        # Test basic CRUD operations
        base_org.replace(pre=joe, data=joed)
        retrieved = base_org.get(pre=joe)
        assert retrieved["first"] == "Joe"
        assert retrieved["last"] == "Jury"
        assert retrieved["id"] == joe

        # Test update
        base_org.update(pre=bob, data=bobd)
        retrieved = base_org.get(pre=bob)
        assert retrieved["first"] == "Bob"

        # Test list
        contacts = base_org.list()
        assert len(contacts) == 2

        # Test find
        results = base_org.find(field="company", val="HCF")
        assert len(results) == 2

        # Test values
        companies = base_org.values(field="company")
        assert "HCF" in companies

        # Test set
        base_org.set(pre=joe, field="phone", val="555-1234")
        retrieved = base_org.get(pre=joe, field="phone")
        assert retrieved == "555-1234"

        # Test unset
        base_org.unset(pre=joe, field="phone")
        retrieved = base_org.get(pre=joe, field="phone")
        assert retrieved is None

        # Test rem
        base_org.rem(pre=joe)
        retrieved = base_org.get(pre=joe)
        assert retrieved is None


def test_identifier_organizer():
    """Test IdentifierOrganizer with identifier databases"""
    aid1 = "EtyPSuUjLyLdXAtGMrsTt0-ELyWeU8fJcymHiGOfuaSA"
    aid2 = "EuEQX8At31X96iDVpigv-rTdOKvFiWFunbJ1aDfq89IQ"

    # Sample identifier metadata
    id1_data = {"name": "Primary ID", "description": "Main identifier", "role": "controller", 
                   "created": "2025-08-29T00:00:00Z", "status": "active"}
    id2_data = {"name": "Secondary ID", "description": "Backup identifier", "role": "witness",
                   "created": "2025-08-29T01:00:00Z", "status": "active"}

    with habbing.openHby(name="test", temp=True) as hby:
        # Test IdentifierOrganizer 
        id_org = connecting.IdentifierOrganizer(hby=hby)

        # Test basic CRUD operations
        id_org.replace(pre=aid1, data=id1_data)
        retrieved = id_org.get(pre=aid1)
        assert retrieved["name"] == "Primary ID"
        assert retrieved["role"] == "controller"
        assert retrieved["id"] == aid1

        # Test update
        id_org.update(pre=aid2, data=id2_data)
        retrieved = id_org.get(pre=aid2)
        assert retrieved["name"] == "Secondary ID"

        # Test list
        identifiers = id_org.list()
        assert len(identifiers) == 2

        # Test find by role
        controllers = id_org.find(field="role", val="controller")
        assert len(controllers) == 1
        assert controllers[0]["name"] == "Primary ID"

        witnesses = id_org.find(field="role", val="witness")
        assert len(witnesses) == 1
        assert witnesses[0]["name"] == "Secondary ID"

        # Test values
        roles = id_org.values(field="role")
        assert "controller" in roles
        assert "witness" in roles

        statuses = id_org.values(field="status")
        assert "active" in statuses

        # Test set field
        id_org.set(pre=aid1, field="version", val="1.0")
        retrieved = id_org.get(pre=aid1, field="version")
        assert retrieved == "1.0"

        # Test unset field
        id_org.unset(pre=aid1, field="version")
        retrieved = id_org.get(pre=aid1, field="version")
        assert retrieved is None

        # Test rem
        id_org.rem(pre=aid1)
        retrieved = id_org.get(pre=aid1)
        assert retrieved is None

        # Verify only one identifier remains
        identifiers = id_org.list()
        assert len(identifiers) == 1
        assert identifiers[0]["name"] == "Secondary ID"


def test_organizer_vs_identifier_organizer_separation():
    """Test that Organizer and IdentifierOrganizer store data separately"""
    contact_id = "EtyPSuUjLyLdXAtGMrsTt0-ELyWeU8fJcymHiGOfuaSA"
    identifier_id = "EuEQX8At31X96iDVpigv-rTdOKvFiWFunbJ1aDfq89IQ"

    contact_data = {"first": "John", "last": "Doe", "company": "ACME Corp"}
    identifier_data = {"name": "Test ID", "role": "controller", "status": "active"}

    with habbing.openHby(name="test", temp=True) as hby:
        # Create both organizers
        contact_org = connecting.Organizer(hby=hby)
        id_org = connecting.IdentifierOrganizer(hby=hby)

        # Add data to both
        contact_org.replace(pre=contact_id, data=contact_data)
        id_org.replace(pre=identifier_id, data=identifier_data)

        # Verify contact organizer only has contact data
        contacts = contact_org.list()
        assert len(contacts) == 1
        assert contacts[0]["first"] == "John"
        assert contacts[0]["company"] == "ACME Corp"

        # Verify identifier organizer only has identifier data  
        identifiers = id_org.list()
        assert len(identifiers) == 1
        assert identifiers[0]["name"] == "Test ID"
        assert identifiers[0]["role"] == "controller"

        # Verify cross-contamination doesn't occur
        assert contact_org.get(pre=identifier_id) is None
        assert id_org.get(pre=contact_id) is None

        # Test with same ID in both systems (should be separate)
        same_id = "EFC7f_MEPE5dboc_E4yG15fnpMD34YaU3ue6vnDLodJU"
        contact_org.replace(pre=same_id, data={"name": "Contact Person"})
        id_org.replace(pre=same_id, data={"name": "Identifier Name"})

        contact_data = contact_org.get(pre=same_id)
        id_data = id_org.get(pre=same_id)

        assert contact_data["name"] == "Contact Person"
        assert id_data["name"] == "Identifier Name"
        # They should be completely separate
        assert contact_data != id_data


def test_identifier_organizer_imgs():
    """Test IdentifierOrganizer image functionality"""
    with habbing.openHab(name="test", transferable=True, temp=True) as (hby, hab):
        id_org = connecting.IdentifierOrganizer(hby=hby)
        pre = "EFC7f_MEPE5dboc_E4yG15fnpMD34YaU3ue6vnDLodJU"

        # Create test image data
        data = bytearray(os.urandom(50000))
        assert len(data) == 50000
        stream = io.BytesIO(data)

        # Test setImg
        id_org.setImg(pre, "image/jpeg", stream)

        # Test getImg
        img = bytearray()
        for chunk in id_org.getImg(pre):
            img.extend(chunk)

        assert img == data

        # Test getImgData
        md = id_org.getImgData(pre=pre)
        assert md["type"] == "image/jpeg"
        assert md["length"] == len(data)

        # Test non-existent image
        non_existent = "Eo60ITGA69z4jNBU4RsvbgsjfAHFcTM2HVEXea1SvnXk"
        md = id_org.getImgData(pre=non_existent)
        assert md is None

        img = bytearray()
        for chunk in id_org.getImg(non_existent):
            img.extend(chunk)

        assert len(img) == 0


def test_base_organizer_inheritance():
    """Test that Organizer and IdentifierOrganizer properly inherit from BaseOrganizer"""
    with habbing.openHby(name="test", temp=True) as hby:
        contact_org = connecting.Organizer(hby=hby)
        id_org = connecting.IdentifierOrganizer(hby=hby)

        # Test inheritance
        assert isinstance(contact_org, connecting.BaseOrganizer)
        assert isinstance(id_org, connecting.BaseOrganizer)

        # Test that they have all the expected methods
        expected_methods = ['update', 'replace', 'set', 'unset', 'rem', 'get', 'list', 'find', 'values', 
                          'setImg', 'getImgData', 'getImg']
        
        for method in expected_methods:
            assert hasattr(contact_org, method)
            assert hasattr(id_org, method)
            assert callable(getattr(contact_org, method))
            assert callable(getattr(id_org, method))
        
        # Test that database attributes are set correctly
        assert contact_org.cigsdb == hby.db.ccigs
        assert contact_org.datadb == hby.db.cons
        assert contact_org.fielddb == hby.db.cfld
        assert contact_org.imgsdb == hby.db.imgs
        
        assert id_org.cigsdb == hby.db.icigs
        assert id_org.datadb == hby.db.icons
        assert id_org.fielddb == hby.db.ifld
        assert id_org.imgsdb == hby.db.iimgs
