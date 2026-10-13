"""Signed declarations a witness makes about itself: /decl/tags and /decl/attribs.

A witness AID is non-transferable, so its prefix is its public key and does not commit to the
contents of its inception event — and nothing in the ecosystem fetches that KEL anyway, because
verifying a witness receipt needs the prefix alone. A configuration trait therefore cannot carry a
fact about a witness to anybody. Reply messages can: they are signed by the witness's own key,
ordered under BADA, and already replayed through its OOBI, which is why /loc/scheme and
/end/role/{action} live there. These two routes follow that pattern exactly.

Tags and attribs are separate routes rather than one, because BADA orders each route independently.
A witness's tags change almost never and its contact address changes often; sharing a route would
mean re-signing and re-timestamping a `testnet` assertion in order to correct a typo in an email.
"""

import pytest

from keri.kering import Vrsn_1_0, Kinds, ValidationError
from keri.core import Salter, Diger
from keri.core.serdering import SerderKERI
from keri.app import openHby


def _witness_and_validator(withby, valhby):
    """A non-transferable witness, and a separate validator that has seen its inception.

    The validator is a hab so that its own parser is used, already wired to a Kevery and a Revery
    the way any real node's is. Hand-assembling that wiring in a test proves less than reusing it.
    """
    withab = withby.makeHab(
        name="wit", isith="1", icount=1, transferable=False, version=Vrsn_1_0, kind=Kinds.json
    )
    assert not withab.kever.prefixer.transferable

    valhab = valhby.makeHab(
        name="val", isith="1", icount=1, transferable=True, version=Vrsn_1_0, kind=Kinds.json
    )
    valhab.psr.parse(bytearray(withab.msgOwnInception(framed=True, gvrsn=Vrsn_1_0)))
    assert withab.pre in valhab.kevers

    return withab, valhab


def _decl(hab, **kwa):
    """A declaration reply at this repo's v1 test settings."""
    return bytearray(hab.makeDeclTags(version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0, **kwa)) \
        if "tags" in kwa else \
        bytearray(hab.makeDeclAttribs(version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0, **kwa))


def test_a_witness_declares_a_tag_and_a_validator_records_it():
    """The whole point, end to end: the witness says testnet and a stranger can read it back."""
    salt = Salter(raw=b'abcdef0123456789').qb64
    with openHby(name="wit", base="test", salt=salt, version=Vrsn_1_0) as withby, \
            openHby(name="val", base="test", salt=salt, version=Vrsn_1_0) as valhby:
        withab, valhab = _witness_and_validator(withby, valhby)

        valhab.psr.parse(_decl(withab, tags=["testnet"]))

        record = valhby.db.decls.get(keys=(withab.pre, "tags"))
        assert record is not None
        assert record.tags == ["testnet"]


def test_a_witness_declares_attribs_under_a_separate_route():
    """Separate route, separate BADA ordering: correcting a contact must not touch the tag."""
    salt = Salter(raw=b'abcdef0123456789').qb64
    with openHby(name="wit", base="test", salt=salt, version=Vrsn_1_0) as withby, \
            openHby(name="val", base="test", salt=salt, version=Vrsn_1_0) as valhby:
        withab, valhab = _witness_and_validator(withby, valhby)

        valhab.psr.parse(_decl(withab, tags=["testnet"]))
        tagged = valhby.db.dans.get(keys=(withab.pre, "tags"))

        valhab.psr.parse(_decl(withab, attribs={"operator": "Bakobo"}))
        assert valhby.db.decls.get(keys=(withab.pre, "attribs")).attribs == {"operator": "Bakobo"}

        # The tag declaration's own authorization is untouched by the attrib declaration.
        assert valhby.db.dans.get(keys=(withab.pre, "tags")).qb64 == tagged.qb64


def test_a_later_declaration_supersedes_an_earlier_one():
    """BADA: a newer timestamp from the same AID replaces the older reply."""
    salt = Salter(raw=b'abcdef0123456789').qb64
    with openHby(name="wit", base="test", salt=salt, version=Vrsn_1_0) as withby, \
            openHby(name="val", base="test", salt=salt, version=Vrsn_1_0) as valhby:
        withab, valhab = _witness_and_validator(withby, valhby)

        valhab.psr.parse(_decl(withab, attribs={"contact": "old@example.test"},
                               stamp="2026-01-01T00:00:00.000000+00:00"))
        valhab.psr.parse(_decl(withab, attribs={"contact": "new@example.test"},
                               stamp="2026-02-01T00:00:00.000000+00:00"))
        record = valhby.db.decls.get(keys=(withab.pre, "attribs"))
        assert record.attribs == {"contact": "new@example.test"}


def test_an_earlier_declaration_does_not_supersede_a_later_one():
    """The other half of BADA, and the one that makes a rollback attack fail."""
    salt = Salter(raw=b'abcdef0123456789').qb64
    with openHby(name="wit", base="test", salt=salt, version=Vrsn_1_0) as withby, \
            openHby(name="val", base="test", salt=salt, version=Vrsn_1_0) as valhby:
        withab, valhab = _witness_and_validator(withby, valhby)

        valhab.psr.parse(_decl(withab, tags=["testnet"],
                               stamp="2026-02-01T00:00:00.000000+00:00"))
        valhab.psr.parse(_decl(withab, tags=[],
                               stamp="2026-01-01T00:00:00.000000+00:00"))
        assert valhby.db.decls.get(keys=(withab.pre, "tags")).tags == ["testnet"]


#: ``EID`` is replaced with the declaring witness's real prefix at run time. Using a placeholder
#: prefix instead would make the last case pass for the wrong reason: an unparseable eid raises
#: out of Prefixer before the tags check is ever reached, so the test would be asserting the eid
#: check twice and never exercising the one it names.
@pytest.mark.parametrize(
    "data",
    [
        {"tags": ["testnet"]},                  # no eid
        {"eid": "EID"},                         # no tags
        {"eid": "EID", "tags": "testnet"},      # tags present but not a list
    ],
)
def test_a_malformed_tag_declaration_is_refused(data):
    """The route's own shape check, before BADA and before anything is written."""
    salt = Salter(raw=b'abcdef0123456789').qb64
    with openHby(name="wit", base="test", salt=salt, version=Vrsn_1_0) as withby, \
            openHby(name="val", base="test", salt=salt, version=Vrsn_1_0) as valhby:
        withab, valhab = _witness_and_validator(withby, valhby)

        data = {k: (withab.pre if v == "EID" else v) for k, v in data.items()}
        msg = withab.reply(route="/decl/tags", data=data, version=Vrsn_1_0,
                           kind=Kinds.json, gvrsn=Vrsn_1_0)

        # Driven at the handler rather than through the parser, which logs a bad message and moves
        # on rather than propagating: the contract under test is that the route refuses the shape.
        serder = SerderKERI(raw=bytes(msg))
        with pytest.raises(ValidationError):
            valhab.kvy.processReplyDeclTags(
                serder=serder, diger=Diger(qb64=serder.said), route=serder.ked["r"]
            )

        # And the refusal leaves nothing behind, so a retry is honest rather than hopeful.
        valhab.psr.parse(bytearray(msg))
        assert valhby.db.decls.get(keys=(withab.pre, "tags")) is None
