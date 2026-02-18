# -*- encoding: utf-8 -*-
"""
tests.app.cli.commands.contacts.test_contacts module

Tests for KLI contacts commands: get, add, rename, delete
"""
import json
import pytest

import multicommand

from keri.app import habbing, organizing as connecting
from keri.app.cli import commands


def test_contacts_get_by_aid(capsys):
    """Test getting a contact by AID"""
    joe = "EtyPSuUjLyLdXAtGMrsTt0-ELyWeU8fJcymHiGOfuaSA"
    joed = dict(first="Joe", last="Jury", alias="joe", company="HCF")

    with habbing.openHby(name="test-get-aid", temp=True) as hby:
        org = connecting.Organizer(hby=hby)
        org.replace(pre=joe, data=joed)

        # Test the get logic directly
        contact = org.get(joe)
        assert contact is not None
        assert contact["id"] == joe
        assert contact["first"] == "Joe"
        assert contact["alias"] == "joe"

        # Verify command parser is correct
        parser = multicommand.create_parser(commands)
        args = parser.parse_args(["contacts", "get", "--name", "test", "--aid", joe])
        assert args.handler is not None
        assert args.aid == joe
        assert args.alias is None


def test_contacts_get_by_alias(capsys):
    """Test getting a contact by alias"""
    bob = "EuEQX8At31X96iDVpigv-rTdOKvFiWFunbJ1aDfq89IQ"
    bobd = dict(first="Bob", last="Burns", alias="bob", company="HCF")

    with habbing.openHby(name="test-get-alias", temp=True) as hby:
        org = connecting.Organizer(hby=hby)
        org.replace(pre=bob, data=bobd)

        # Test the find/get logic directly
        contacts = org.find('alias', f"^bob$")
        assert len(contacts) == 1
        contact = contacts[0]
        assert contact["id"] == bob
        assert contact["first"] == "Bob"
        assert contact["alias"] == "bob"

        # Verify command parser is correct
        parser = multicommand.create_parser(commands)
        args = parser.parse_args(["contacts", "get", "--name", "test", "--alias", "bob"])
        assert args.handler is not None
        assert args.alias == "bob"
        assert args.aid is None


def test_contacts_get_not_found():
    """Test getting a non-existent contact"""
    with habbing.openHby(name="test-get-notfound", temp=True) as hby:
        org = connecting.Organizer(hby=hby)

        contact = org.get("ENonExistent123456789012345678901234567890123")
        assert contact is None


def test_contacts_add_new():
    """Test adding a new contact"""
    ken = "EFC7f_MEPE5dboc_E4yG15fnpMD34YaU3ue6vnDLodJU"

    with habbing.openHby(name="test-add-new", temp=True) as hby:
        org = connecting.Organizer(hby=hby)

        # Test the add logic directly (using update)
        data = {'alias': 'ken', 'company': 'GLEIF', 'city': 'Frankfurt'}
        org.update(ken, data)

        contact = org.get(ken)
        assert contact["id"] == ken
        assert contact["alias"] == "ken"
        assert contact["company"] == "GLEIF"
        assert contact["city"] == "Frankfurt"

        # Verify command parser is correct
        parser = multicommand.create_parser(commands)
        args = parser.parse_args(["contacts", "add", "--name", "test",
                                  "--oobi", "http://127.0.0.1:5642/oobi/" + ken,
                                  "--alias", "ken", "--field", "company=GLEIF",
                                  "--field", "city=Frankfurt"])
        assert args.handler is not None
        assert args.oobi == "http://127.0.0.1:5642/oobi/" + ken
        assert args.alias == "ken"
        assert args.fields == ["company=GLEIF", "city=Frankfurt"]


def test_contacts_add_update():
    """Test updating an existing contact"""
    jen = "ED61oxVwVNf_olqR5wAhAjvuK59xuBOJXnJPGhwWDYoc"
    jend = dict(first="Jen", last="Jones", alias="jen", company="GLEIF")

    with habbing.openHby(name="test-add-update", temp=True) as hby:
        org = connecting.Organizer(hby=hby)
        org.replace(pre=jen, data=jend)

        # Test the update logic - preserves existing fields
        org.update(jen, {'mobile': '555-1212'})

        contact = org.get(jen)
        assert contact["id"] == jen
        assert contact["first"] == "Jen"  # preserved
        assert contact["alias"] == "jen"  # preserved
        assert contact["mobile"] == "555-1212"  # added


def test_contacts_add_field_parsing():
    """Test add command field parsing"""
    parser = multicommand.create_parser(commands)
    args = parser.parse_args(["contacts", "add", "--name", "test",
                              "--oobi", "http://127.0.0.1:5642/oobi/Etest123",
                              "--field", "key1=value1",
                              "--field", "key2=value with spaces"])
    assert args.oobi == "http://127.0.0.1:5642/oobi/Etest123"
    assert args.fields == ["key1=value1", "key2=value with spaces"]

    # Parse fields like the command does
    data = {}
    for field in args.fields:
        key, val = field.split('=', 1)
        data[key] = val

    assert data == {"key1": "value1", "key2": "value with spaces"}


def test_contacts_rename():
    """Test renaming a contact alias"""
    sal = "Eo60ITGA69z4jNBU4RsvbgsjfAHFcTM2HVEXea1SvnXk"
    sald = dict(first="Sally", last="Smith", alias="sally", company="GLEIF")

    with habbing.openHby(name="test-rename", temp=True) as hby:
        org = connecting.Organizer(hby=hby)
        org.replace(pre=sal, data=sald)

        # Test the rename logic directly
        org.set(sal, 'alias', 'sal')

        contact = org.get(sal)
        assert contact["alias"] == "sal"

        # Verify command parser is correct
        parser = multicommand.create_parser(commands)
        args = parser.parse_args(["contacts", "rename", "--name", "test",
                                  "--old-alias", "sally", "--alias", "sal"])
        assert args.handler is not None
        assert args.old_alias == "sally"
        assert args.alias == "sal"


def test_contacts_rename_by_aid():
    """Test renaming a contact by AID"""
    joe = "EtyPSuUjLyLdXAtGMrsTt0-ELyWeU8fJcymHiGOfuaSA"
    joed = dict(first="Joe", alias="joe")

    with habbing.openHby(name="test-rename-aid", temp=True) as hby:
        org = connecting.Organizer(hby=hby)
        org.replace(pre=joe, data=joed)

        org.set(joe, 'alias', 'joseph')

        contact = org.get(joe)
        assert contact["alias"] == "joseph"

        # Verify command parser
        parser = multicommand.create_parser(commands)
        args = parser.parse_args(["contacts", "rename", "--name", "test",
                                  "--aid", joe, "--alias", "joseph"])
        assert args.aid == joe
        assert args.alias == "joseph"


def test_contacts_rename_not_found():
    """Test finding a non-existent contact for rename"""
    with habbing.openHby(name="test-rename-notfound", temp=True) as hby:
        org = connecting.Organizer(hby=hby)

        contacts = org.find('alias', f"^nonexistent$")
        assert len(contacts) == 0


def test_contacts_delete():
    """Test deleting a contact"""
    bob = "EuEQX8At31X96iDVpigv-rTdOKvFiWFunbJ1aDfq89IQ"
    bobd = dict(first="Bob", last="Burns", alias="bob", company="HCF")

    with habbing.openHby(name="test-delete", temp=True) as hby:
        org = connecting.Organizer(hby=hby)
        org.replace(pre=bob, data=bobd)

        # Verify contact exists
        assert org.get(bob) is not None

        # Test the delete logic directly
        org.rem(bob)

        # Verify contact was deleted
        assert org.get(bob) is None


def test_contacts_delete_parser():
    """Test delete command parser"""
    parser = multicommand.create_parser(commands)

    # Test with --alias and --yes
    args = parser.parse_args(["contacts", "delete", "--name", "test",
                              "--alias", "bob", "--yes"])
    assert args.handler is not None
    assert args.alias == "bob"
    assert args.yes is True

    # Test with --aid
    args = parser.parse_args(["contacts", "delete", "--name", "test",
                              "--aid", "Etest123", "-y"])
    assert args.aid == "Etest123"
    assert args.yes is True


def test_contacts_delete_not_found():
    """Test deleting a non-existent contact"""
    with habbing.openHby(name="test-delete-notfound", temp=True) as hby:
        org = connecting.Organizer(hby=hby)

        contacts = org.find('alias', f"^nonexistent$")
        assert len(contacts) == 0

        contact = org.get("ENonExistent123456789012345678901234567890123")
        assert contact is None


def test_contacts_list_parser():
    """Test list command parser (existing command)"""
    parser = multicommand.create_parser(commands)
    args = parser.parse_args(["contacts", "list", "--name", "test"])
    assert args.handler is not None
    assert args.name == "test"


def test_contacts_query_parser():
    """Test query command parser"""
    parser = multicommand.create_parser(commands)

    # Test with --contact-alias
    args = parser.parse_args(["contacts", "query", "--name", "test",
                              "--alias", "myid", "--contact-alias", "mycontact"])
    assert args.handler is not None
    assert args.alias == "myid"
    assert args.contact_alias == "mycontact"

    # Test with --contact-aid
    args = parser.parse_args(["contacts", "query", "--name", "test",
                              "--alias", "myid", "--contact-aid", "Etest123"])
    assert args.contact_aid == "Etest123"


def test_contacts_workflow():
    """Test complete contact workflow: add, rename, get, delete"""
    wil = "EPzeu5_C80nzPc_BGUHVBkXXfNmlS55Ayl7Rd1I0gWFE"

    with habbing.openHby(name="test-workflow", temp=True) as hby:
        org = connecting.Organizer(hby=hby)

        # 1. Add contact
        org.update(wil, {'alias': 'will', 'first': 'Will', 'company': 'GLEIF'})
        contact = org.get(wil)
        assert contact["alias"] == "will"

        # 2. Rename contact
        org.set(wil, 'alias', 'william')
        contact = org.get(wil)
        assert contact["alias"] == "william"

        # 3. Find by new alias
        contacts = org.find('alias', f"^william$")
        assert len(contacts) == 1
        assert contacts[0]["first"] == "Will"

        # 4. Update with more fields
        org.update(wil, {'mobile': '555-1234'})
        contact = org.get(wil)
        assert contact["mobile"] == "555-1234"
        assert contact["first"] == "Will"  # preserved

        # 5. Delete contact
        org.rem(wil)
        assert org.get(wil) is None


def test_contacts_find_parser():
    """Test find command parser"""
    parser = multicommand.create_parser(commands)

    # Default field is alias
    args = parser.parse_args(["contacts", "find", "--name", "test", "--value", "cfca"])
    assert args.handler is not None
    assert args.field == "alias"
    assert args.value == "cfca"

    # Explicit field
    args = parser.parse_args(["contacts", "find", "--name", "test",
                              "--field", "company", "--value", "GLEIF"])
    assert args.field == "company"
    assert args.value == "GLEIF"


def test_contacts_find():
    """Test finding contacts by field value pattern"""
    aid1 = "EtyPSuUjLyLdXAtGMrsTt0-ELyWeU8fJcymHiGOfuaSA"
    aid2 = "EuEQX8At31X96iDVpigv-rTdOKvFiWFunbJ1aDfq89IQ"
    aid3 = "EFC7f_MEPE5dboc_E4yG15fnpMD34YaU3ue6vnDLodJU"

    with habbing.openHby(name="test-find", temp=True) as hby:
        org = connecting.Organizer(hby=hby)
        org.replace(pre=aid1, data={'alias': 'yuan.cfca', 'company': 'CFCA'})
        org.replace(pre=aid2, data={'alias': 'li.cfca', 'company': 'CFCA'})
        org.replace(pre=aid3, data={'alias': 'bob.gleif', 'company': 'GLEIF'})

        # Find by alias pattern
        contacts = org.find('alias', 'cfca')
        assert len(contacts) == 2
        aliases = {c['alias'] for c in contacts}
        assert aliases == {'yuan.cfca', 'li.cfca'}

        # Find by company field
        contacts = org.find('company', 'GLEIF')
        assert len(contacts) == 1
        assert contacts[0]['alias'] == 'bob.gleif'

        # No matches
        contacts = org.find('alias', 'nonexistent')
        assert len(contacts) == 0


def test_contacts_multiple_alias_match():
    """Test handling of multiple contacts with similar aliases"""
    joe1 = "EtyPSuUjLyLdXAtGMrsTt0-ELyWeU8fJcymHiGOfuaSA"
    joe2 = "EuEQX8At31X96iDVpigv-rTdOKvFiWFunbJ1aDfq89IQ"

    with habbing.openHby(name="test-multi", temp=True) as hby:
        org = connecting.Organizer(hby=hby)
        org.replace(pre=joe1, data={'alias': 'joe'})
        org.replace(pre=joe2, data={'alias': 'joey'})

        # Exact match should return one
        contacts = org.find('alias', f"^joe$")
        assert len(contacts) == 1
        assert contacts[0]['id'] == joe1

        # Partial match returns both
        contacts = org.find('alias', 'joe')
        assert len(contacts) == 2
