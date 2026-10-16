# -*- encoding: utf-8 -*-
"""
tests.app.mailboxing module

"""
import importlib
import os

import falcon
from falcon import testing
import pytest

from hio.help import decking

from keri.app import AuthorizedForwardHandler, Mailboxer, openCF, openHby
from keri.app.mailboxing import MailboxAddRemoveEnd, MailboxStart, _mailboxAdminPath, setupMailbox
from keri.app.configing import Configer
from keri.app.storing import Respondant
from keri.core import Diger, Kevery, Parser, Salter, SerderKERI, exchange, routing
from keri.kering import Kinds, Roles, Version, Vrsn_1_0, Vrsn_2_0
from keri.peer import Exchanger, specialExchange


mailbox_start = importlib.import_module("keri.cli.commands.mailbox.start")


def _collect_replay(hab, gvrsn=Version):
    """Collect one habitat replay in the same delegation-first order used by mailbox admin."""
    body = bytearray()
    for msg in hab.db.clonePreIter(pre=hab.pre, gvrsn=gvrsn):
        body.extend(msg)
    for msg in hab.db.cloneDelegation(hab.kever, gvrsn=gvrsn):
        body.extend(msg)
    return body


def _mailbox_admin_client(hby, hab, route="/mailboxes"):
    """Build a focused Falcon client exposing only one mailbox admin route."""
    cues = decking.Deck()
    rvy = routing.Revery(db=hby.db, cues=cues)
    kvy = Kevery(db=hby.db, lax=True, local=False, rvy=rvy, cues=cues)
    kvy.registerReplyRoutes(router=rvy.rtr)

    app = falcon.App()
    app.add_route(route,
                  MailboxAddRemoveEnd(hby=hby, hab=hab, kvy=kvy, rvy=rvy, exc=None))
    return testing.TestClient(app)


def _multipart_body(partContentType=None, **fields):
    """Create one minimal multipart body for mailbox admin endpoint tests."""
    boundary = "----keri-mailbox-admin-boundary"
    body = bytearray()

    for name, value in fields.items():
        if value is None:
            continue
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(f'Content-Disposition: form-data; name="{name}"\r\n'.encode("utf-8"))
        if partContentType:
            body.extend(f"Content-Type: {partContentType}\r\n".encode("utf-8"))
        body.extend(b"\r\n")
        body.extend(value.encode("utf-8"))
        body.extend(b"\r\n")

    body.extend(f"--{boundary}--\r\n".encode("utf-8"))
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def _post_mailbox_admin(client, *, path="/mailboxes", fields=None, content_type="text/plain", body=b""):
    """Post either raw bytes or mailbox-admin multipart fields to one admin path."""
    if fields is not None:
        body, content_type = _multipart_body(**fields)

    return client.simulate_post(
        path,
        headers={"Content-Type": content_type},
        body=body,
    )


@pytest.mark.parametrize("version", [Vrsn_1_0, Vrsn_2_0], ids=["v1", "v2"])
def test_mailbox_add_remove_end_accepts_multipart_add(version):
    """Mailbox admin accepts the legacy multipart add envelope for a direct controller."""
    with openHby(name="mailbox-provider", version=version, salt=Salter(raw=b"mailbox-provider0").qb64) as providerHby, \
            openHby(name="mailbox-controller", version=version, salt=Salter(raw=b"mailbox-controller").qb64) as controllerHby:
        mailboxHab = providerHby.makeHab(name="mbx", transferable=False, version=version)
        controller = controllerHby.makeHab(name="alice", transferable=True, version=version)
        client = _mailbox_admin_client(providerHby, mailboxHab)

        rep = _post_mailbox_admin(client, fields={
            "kel": _collect_replay(controller, gvrsn=version).decode("utf-8"),
            "rpy": controller.makeEndRole(mailboxHab.pre, Roles.mailbox, allow=True,
                                          version=version, gvrsn=version).decode("utf-8"),
        })

        assert rep.status_code == 200
        assert rep.json == {
            "cid": controller.pre,
            "role": Roles.mailbox,
            "eid": mailboxHab.pre,
            "allowed": True,
        }
        assert providerHby.db.ends.get(keys=(controller.pre, Roles.mailbox, mailboxHab.pre)).allowed


def test_mailbox_add_remove_end_accepts_multipart_delegated_add():
    """Mailbox admin accepts delegated controller add when `delkel` carries delegator evidence."""
    with openHby(name="mailbox-provider-delegated",
                 salt=Salter(raw=b"mailbox-provider1").qb64) as providerHby, \
            openHby(name="mailbox-controller-delegated",
                    salt=Salter(raw=b"mailbox-controller1").qb64) as controllerHby:
        mailboxHab = providerHby.makeHab(name="mbx", transferable=False)
        delegator = controllerHby.makeHab(name="delegator", transferable=True)
        controller = controllerHby.makeHab(name="alice", transferable=True, delpre=delegator.pre)

        delegator.interact(data=[dict(i=controller.pre, s="0", d=controller.pre)])
        for msg in delegator.db.clonePreIter(pre=delegator.pre):
            controller.psr.parse(ims=msg)

        client = _mailbox_admin_client(providerHby, mailboxHab)
        rep = _post_mailbox_admin(client, fields={
            "kel": bytearray(controller.replay()).decode("utf-8"),
            "delkel": b"".join(controller.db.cloneDelegation(controller.kever)).decode("utf-8"),
            "rpy": controller.makeEndRole(mailboxHab.pre, Roles.mailbox, allow=True).decode("utf-8"),
        })

        assert rep.status_code == 200
        assert rep.json["cid"] == controller.pre
        assert providerHby.db.ends.get(keys=(controller.pre, Roles.mailbox, mailboxHab.pre)).allowed


def test_mailbox_add_remove_end_accepts_multipart_cut_after_add():
    """Mailbox admin accepts a cut after a previously accepted mailbox add."""
    with openHby(name="mailbox-provider-cut", salt=Salter(raw=b"mailbox-provider2").qb64) as providerHby, \
            openHby(name="mailbox-controller-cut", salt=Salter(raw=b"mailbox-controller-cut").qb64) as controllerHby:
        mailboxHab = providerHby.makeHab(name="mbx", transferable=False)
        controller = controllerHby.makeHab(name="alice", transferable=True)
        client = _mailbox_admin_client(providerHby, mailboxHab)

        rep = _post_mailbox_admin(client, fields={
            "kel": _collect_replay(controller).decode("utf-8"),
            "rpy": controller.makeEndRole(mailboxHab.pre, Roles.mailbox, allow=True).decode("utf-8"),
        })
        assert rep.status_code == 200

        rep = _post_mailbox_admin(client, fields={
            "kel": _collect_replay(controller).decode("utf-8"),
            "rpy": controller.makeEndRole(mailboxHab.pre, Roles.mailbox, allow=False).decode("utf-8"),
        })

        assert rep.status_code == 200
        assert rep.json == {
            "cid": controller.pre,
            "role": Roles.mailbox,
            "eid": mailboxHab.pre,
            "allowed": False,
        }
        assert not providerHby.db.ends.get(keys=(controller.pre, Roles.mailbox, mailboxHab.pre)).allowed


def test_mailbox_admin_path_uses_stored_mailbox_url_path_without_root_alias():
    """Mailbox admin is served relative to the stored mailbox URL path only."""
    with openHby(name="mailbox-provider-path",
                 salt=Salter(raw=b"mailbox-provider-path").qb64) as providerHby, \
            openHby(name="mailbox-controller-path",
                    salt=Salter(raw=b"mailbox-controller-path").qb64) as controllerHby:
        mailboxHab = providerHby.makeHab(name="mbx", transferable=False)
        controller = controllerHby.makeHab(name="alice", transferable=True)
        mailboxUrl = f"http://127.0.0.1:5632/{mailboxHab.pre}"
        mailboxHab.psr.parse(ims=bytearray(mailboxHab.makeLocScheme(
            url=mailboxUrl,
            eid=mailboxHab.pre,
            scheme="http",
        )))

        adminPath = _mailboxAdminPath(mailboxHab)
        assert adminPath == f"/{mailboxHab.pre}/mailboxes"

        client = _mailbox_admin_client(providerHby, mailboxHab, route=adminPath)
        fields = {
            "kel": _collect_replay(controller).decode("utf-8"),
            "rpy": controller.makeEndRole(mailboxHab.pre, Roles.mailbox, allow=True).decode("utf-8"),
        }

        rep = _post_mailbox_admin(client, fields=fields)
        assert rep.status_code == 404

        rep = _post_mailbox_admin(client, path=adminPath, fields=fields)
        assert rep.status_code == 200
        assert rep.json["allowed"] is True


def test_mailbox_admin_path_requires_loaded_self_location():
    """Mailbox admin path is derived only from loaded self location state."""
    with openHby(name="mailbox-provider-missing-loc",
                 salt=Salter(raw=b"mailbox-provider-missing").qb64) as providerHby:
        mailboxHab = providerHby.makeHab(name="mbx", transferable=False)

        with pytest.raises(ValueError, match="loaded self HTTP"):
            _mailboxAdminPath(mailboxHab)


def test_setup_mailbox_requires_self_identity_state_before_boot():
    """Mailbox host boot fails until self location and self role state are accepted."""
    with openHby(name="mailbox-provider-boot", base="tenant-a",
                 salt=Salter(raw=b"mailbox-provider-boot").qb64) as providerHby:
        mailboxHab = providerHby.makeHab(name="mbx", transferable=False)

        with pytest.raises(ValueError, match="loaded self HTTP"):
            setupMailbox(providerHby, alias="mbx")

        mailboxHab.psr.parse(ims=bytearray(mailboxHab.makeLocScheme(
            url=f"http://127.0.0.1:5632/{mailboxHab.pre}",
            eid=mailboxHab.pre,
            scheme="http",
        )))
        with pytest.raises(ValueError, match="self controller authorization"):
            setupMailbox(providerHby, alias="mbx")

        mailboxHab.psr.parse(ims=bytearray(mailboxHab.makeEndRole(
            mailboxHab.pre,
            Roles.controller,
            allow=True,
        )))
        with pytest.raises(ValueError, match="self mailbox authorization"):
            setupMailbox(providerHby, alias="mbx")

        mailboxHab.psr.parse(ims=bytearray(mailboxHab.makeEndRole(
            mailboxHab.pre,
            Roles.mailbox,
            allow=True,
        )))
        doers = setupMailbox(providerHby, alias="mbx", httpPort=9000)
        mailbox = next(doer for doer in doers if isinstance(doer, Respondant)).mbx
        try:
            assert f"/{providerHby.base}/" in mailbox.path
        finally:
            mailbox.close(clear=True)
            for doer in doers:
                if hasattr(doer, "server"):
                    doer.server.close()


@pytest.mark.parametrize("version", [None, Vrsn_1_0, Vrsn_2_0], ids=["default", "v1", "v2"])
def test_mailbox_start_creates_missing_alias_from_config_startup_material(version):
    """Mailbox start bootstrap reuses Hab config application for alias startup material."""
    effective = version if version is not None else Version
    cf = Configer(name=f"mailbox-start-cf-{os.urandom(4).hex()}",
                  temp=True,
                  reopen=True,
                  clear=False)
    hby = None
    try:
        cf.put({
            "relay": {
                "dt": "2026-04-07T12:00:00.000000+00:00",
                "curls": ["http://127.0.0.1:5632/relay"],
            }
        })

        hby = mailbox_start._openMailboxHabery(
            name=f"mailbox-start-config-{os.urandom(4).hex()}",
            cf=cf,
            temp=True,
            version=version,
        )
        hab, startup = mailbox_start._prepareMailboxHabitat(hby=hby, alias="relay")

        assert hby.version == effective
        assert hab.kever.serder.pvrsn == effective
        assert hby.psr.version == effective
        # Reconciliation of an existing alias must use the same selected genus.
        same, _ = mailbox_start._prepareMailboxHabitat(hby=hby, alias="relay")
        assert same is hab
        wire = hab.replyEndRole(cid=hab.pre, gvrsn=effective, version=effective)
        frames = Parser(version=effective).parse(ims=wire, framed=True, processive=False)
        assert frames
        assert all(frame.serder.pvrsn == effective for frame in frames)
        assert startup["source"] == "stored"
        assert not hab.kever.prefixer.transferable
        assert hab.fetchUrls(eid=hab.pre, scheme="http")["http"] == "http://127.0.0.1:5632/relay"
        assert hby.db.ends.get(keys=(hab.pre, Roles.controller, hab.pre)).allowed
        assert hby.db.ends.get(keys=(hab.pre, Roles.mailbox, hab.pre)).allowed
        # The actual host composition must receive the same context as bootstrap.
        doers = setupMailbox(hby, alias="relay", httpPort=0)
        try:
            runtime = next(doer for doer in doers if isinstance(doer, MailboxStart))
            assert runtime.parser.version == effective
        finally:
            for doer in doers:
                if hasattr(doer, "server"):
                    doer.server.close()
    finally:
        if hby is not None:
            hby.close(clear=hby.temp)
        cf.close(clear=cf.temp)


@pytest.mark.parametrize("enabled", [None, False, True], ids=["default", "disabled", "enabled"])
def test_setup_mailbox_honors_kram_configuration(enabled):
    """The real host accepts signed queries and enforces configured replay protection."""
    with openCF(name="mailbox-kram", temp=True) as cf:
        config = {"relay": {
            "dt": "2026-04-07T12:00:00.000000+00:00",
            "curls": ["http://127.0.0.1:5632/relay"],
        }}
        if enabled is not None:
            config["kram"] = {
                "enabled": enabled,
                "denials": [],
                "caches": {"~": [1000, 60000, 120000, 300000, 60000, 120000, 300000]},
            }
        cf.put(config)
        with openHby(name="mailbox-kram", temp=True, cf=cf, version=Vrsn_2_0) as hby, \
                openHby(name="mailbox-kram-controller", temp=True, version=Vrsn_2_0) as controllerHby:
            mailbox_start._prepareMailboxHabitat(hby=hby, alias="relay")
            controller = controllerHby.makeHab(name="controller", version=Vrsn_2_0)
            doers = setupMailbox(hby, alias="relay", httpPort=0)
            mailbox = next(doer for doer in doers if isinstance(doer, Respondant)).mbx
            try:
                host = next(doer for doer in doers if isinstance(doer, MailboxStart))
                host.parser.parse(ims=bytearray(controller.msgOwnEvent(
                    sn=0, framed=True, gvrsn=Vrsn_2_0)))
                host.cues.clear()
                wire = controller.query(pre=controller.pre, src=controller.pre, route="mbx",
                                        query={"topics": {"/reply": 0}}, kind=Kinds.json)
                query = SerderKERI(raw=wire)
                host.parser.parse(ims=bytearray(wire))
                assert len([cue for cue in host.cues if cue["kin"] == "stream"]) == 1
                cache = hby.db.kramMSGC.get(keys=(controller.pre, query.said))
                if enabled:
                    assert cache is not None
                    assert cache.mdt == query.stamp
                else:
                    assert cache is None
                host.parser.parse(ims=bytearray(wire))
                assert len([cue for cue in host.cues if cue["kin"] == "stream"]) == (1 if enabled else 2)
            finally:
                mailbox.close(clear=True)
                for doer in doers:
                    if hasattr(doer, "server"):
                        doer.server.close()


def test_mailbox_start_requires_config_when_alias_is_missing():
    """Mailbox start does not offer a CLI bootstrap path in KERIpy."""
    hby = mailbox_start._openMailboxHabery(
        name=f"mailbox-start-no-config-{os.urandom(4).hex()}",
        temp=True,
    )
    try:
        with pytest.raises(ValueError, match="matching config alias section"):
            mailbox_start._prepareMailboxHabitat(hby=hby, alias="relay")
    finally:
        hby.close(clear=hby.temp)


def test_mailbox_start_rejects_incomplete_config_startup_material():
    """Mailbox start fails when Hab config application does not yield usable self state."""
    cf = Configer(name=f"mailbox-start-bad-cf-{os.urandom(4).hex()}",
                  temp=True,
                  reopen=True,
                  clear=False)
    hby = None
    try:
        cf.put({
            "relay": {
                "dt": "2026-04-07T12:00:00.000000+00:00",
            }
        })
        hby = mailbox_start._openMailboxHabery(
            name=f"mailbox-start-bad-{os.urandom(4).hex()}",
            cf=cf,
            temp=True,
        )

        with pytest.raises(ValueError, match="complete mailbox startup state"):
            mailbox_start._prepareMailboxHabitat(hby=hby, alias="relay", requireConfig=True)
    finally:
        if hby is not None:
            hby.close(clear=hby.temp)
        cf.close(clear=cf.temp)


def test_mailbox_add_remove_end_rejects_invalid_requests():
    """Mailbox admin rejects malformed envelopes, invalid replies, and unaccepted auth state.

    This test is intentionally broad because the endpoint has two layers of
    failure:
        1. request-shape validation before ingest
        2. post-ingest acceptance checks against resulting `ends.` state

    Each block below labels one distinct seam to show which regression surface changed on failures.
    """
    with openHby(name="mailbox-provider-invalid",
                 salt=Salter(raw=b"mailbox-provider3").qb64) as providerHby, \
            openHby(name="mailbox-controller-invalid",
                    salt=Salter(raw=b"mailbox-controller3").qb64) as controllerHby:
        mailboxHab = providerHby.makeHab(name="mbx", transferable=False)
        otherMailbox = providerHby.makeHab(name="other", transferable=False)
        controller = controllerHby.makeHab(name="alice", transferable=True)
        unauthorized = controllerHby.makeHab(name="bob", transferable=True)
        client = _mailbox_admin_client(providerHby, mailboxHab)

        # Reject non-multipart content types. KERIpy keeps this endpoint on the
        # legacy multipart envelope instead of reparsing raw CESR bodies.
        rep = _post_mailbox_admin(client, body=b"not multipart", content_type="text/plain")
        assert rep.status_code == 406

        # Reject envelopes missing the controller KEL replay.
        rep = _post_mailbox_admin(client, fields={
            "rpy": controller.makeEndRole(mailboxHab.pre, Roles.mailbox, allow=True).decode("utf-8"),
        })
        assert rep.status_code == 400
        assert "missing kel" in rep.text

        # Reject envelopes missing the terminal signed authorization reply.
        rep = _post_mailbox_admin(client, fields={
            "kel": _collect_replay(controller).decode("utf-8"),
        })
        assert rep.status_code == 400
        assert "missing rpy" in rep.text

        # Reject replies on the wrong route before checking mailbox-specific
        # payload fields. This keeps route errors clearer than generic
        # cid/role/eid payload failures.
        rep = _post_mailbox_admin(client, fields={
            "kel": _collect_replay(controller).decode("utf-8"),
            "rpy": controller.makeLocScheme(url="http://127.0.0.1:5632", eid=mailboxHab.pre).decode("utf-8"),
        })
        assert rep.status_code == 400
        assert "Unsupported mailbox authorization route" in rep.text

        # Reject `/end/role/*` replies that do not target the mailbox role.
        rep = _post_mailbox_admin(client, fields={
            "kel": _collect_replay(controller).decode("utf-8"),
            "rpy": controller.makeEndRole(mailboxHab.pre, Roles.watcher, allow=True).decode("utf-8"),
        })
        assert rep.status_code == 400
        assert "role=mailbox" in rep.text

        # Reject replies whose `eid` points at a different hosted mailbox AID.
        rep = _post_mailbox_admin(client, fields={
            "kel": _collect_replay(controller).decode("utf-8"),
            "rpy": controller.makeEndRole(otherMailbox.pre, Roles.mailbox, allow=True).decode("utf-8"),
        })
        assert rep.status_code == 403
        assert "does not match hosted mailbox" in rep.text

        # Reject empty multipart `kel` field values even when the field exists.
        rep = _post_mailbox_admin(client, fields={
            "kel": "",
            "rpy": controller.makeEndRole(mailboxHab.pre, Roles.mailbox, allow=True).decode("utf-8"),
        })
        assert rep.status_code == 400
        assert "missing kel" in rep.text

        # Reject non-CESR `rpy` field values before runtime ingest.
        rep = _post_mailbox_admin(client, fields={
            "kel": _collect_replay(controller).decode("utf-8"),
            "rpy": "not cesr",
        })
        assert rep.status_code == 400
        assert "invalid mailbox authorization reply" in rep.text

        # Reject replies that parse correctly but do not survive acceptance into
        # `ends.` state. Here the KEL belongs to `alice` while the signed reply
        # was produced by `bob`, so normal KERI processing must refuse it.
        rep = _post_mailbox_admin(client, fields={
            "kel": _collect_replay(controller).decode("utf-8"),
            "rpy": unauthorized.makeEndRole(mailboxHab.pre, Roles.mailbox, allow=True).decode("utf-8"),
        })
        assert rep.status_code == 403
        assert "was not accepted" in rep.text


@pytest.mark.parametrize("version", [Vrsn_1_0, Vrsn_2_0])
def test_authorized_forwarder_preserves_versioned_payloads(version):
    """Mailbox authorization gates both v1 embeds and current-main v2 nested messages."""
    with openHby(name="authorized-forward", temp=True, version=Vrsn_2_0) as hby:
        sender = hby.makeHab(name="sender", transferable=True)
        mailbox = hby.makeHab(name="mailbox", transferable=False)
        mbx = Mailboxer(name="authorized-forward", temp=True)
        try:
            forwarder = AuthorizedForwardHandler(hby=hby, mbx=mbx, mailboxAid=mailbox.pre)
            parser = Parser(kvy=hby.kvy, exc=Exchanger(hby=hby, handlers=[forwarder]),
                            version=version)
            topic = f"{sender.pre}/echo"
            for allowed, count in ((None, 0), (True, 1), (False, 1)):
                if allowed is not None:
                    # Both the grant and cut must pass the real local reply verifier.
                    sender.psr.parse(ims=sender.makeEndRole(mailbox.pre, Roles.mailbox, allow=allowed))
                    assert hby.db.ends.get(keys=(sender.pre, Roles.mailbox, mailbox.pre)).allowed is allowed
                child = exchange(sender=sender.pre, route="/echo", attributes=dict(allowed=allowed),
                                 version=version, kind=Kinds.json)
                if version.major == 1:
                    carried = sender.endorse(child, last=False, framed=False, gvrsn=version)
                    parent, attachments = specialExchange(sender=sender.pre, route="/fwd",
                        modifiers=dict(pre=sender.pre, topic="echo"), attributes={},
                        embeds=dict(evt=carried), version=version, kind=Kinds.json)
                    # Leave the isolated parent frame open for its pathed attachments.
                    wire = sender.endorse(parent, last=False, framed=True, gvrsn=version)
                    wire.extend(attachments)
                else:
                    # Current-main forwarding binds the body digest and retains its signed nested child.
                    parent = exchange(sender=sender.pre, route="/fwd",
                        modifiers=dict(pre=sender.pre, topic="echo"),
                        attributes=dict(evt=Diger(ser=child.raw).qb64), version=version, kind=Kinds.json)
                    wire = sender.endorse(parent, nests=[sender.endorse(child, nested=True)])
                parser.parse(ims=wire, local=False)
                rows = list(mbx.cloneTopicIter(topic=topic))
                assert len(rows) == count
                if allowed:
                    parsed = Parser(version=version).parse(ims=bytearray(rows[0][2]), processive=False)
                    assert len(parsed) == 1
                    assert parsed[0].serder.raw == child.raw
        finally:
            mbx.close(clear=True)


@pytest.mark.parametrize("version", ["1.0", "2.0"])
def test_mailbox_start_selects_protocol_without_changing_version_output(version, monkeypatch, capsys):
    """Keep distribution-version output separate from the host's protocol context."""
    launches = []
    monkeypatch.setattr(mailbox_start, "runMailbox", lambda **kwargs: launches.append(kwargs))
    args = mailbox_start.parser.parse_args([
        "--name", "mailbox", "--alias", "relay", "--protocol-version", version,
    ])
    args.handler(args)
    expected = Vrsn_1_0 if version == "1.0" else Vrsn_2_0
    assert launches[0]["version"] == expected
    with pytest.raises(SystemExit) as printed:
        mailbox_start.parser.parse_args(["--version"])
    assert printed.value.code == 0
    assert mailbox_start.__version__ in capsys.readouterr().out


@pytest.mark.parametrize("partContentType,large", [("application/cesr", False), (None, True)])
def test_mailbox_admin_reads_cesr_parts_without_the_text_part_buffer(partContentType, large):
    """Read real CESR fields regardless of media label or Falcon's text-buffer limit."""
    with openHby(name="mailbox-parts-provider") as providerHby, \
            openHby(name="mailbox-parts-controller") as controllerHby:
        mailbox = providerHby.makeHab(name="mbx", transferable=False)
        controller = controllerHby.makeHab(name="alice", transferable=True)
        kel = _collect_replay(controller)
        if large:
            # Repeated accepted events are a valid replay, and cross Falcon's 1 MiB text cap.
            kel *= 1024 * 1024 // len(kel) + 1
            assert len(kel) > 1024 * 1024
        body, contentType = _multipart_body(partContentType=partContentType,
            kel=kel.decode("utf-8"),
            rpy=controller.makeEndRole(mailbox.pre, Roles.mailbox).decode("utf-8"))
        rep = _post_mailbox_admin(_mailbox_admin_client(providerHby, mailbox),
                                 content_type=contentType, body=body)
        assert rep.status_code == 200
        assert providerHby.db.ends.get(keys=(controller.pre, Roles.mailbox, mailbox.pre)).allowed


def test_mailbox_admin_confirms_the_submitted_reply_not_an_older_authorization():
    """An accepted duplicate is idempotent; a new unsigned reply cannot borrow its state."""
    with openHby(name="mailbox-reply-provider") as providerHby, \
            openHby(name="mailbox-reply-controller") as controllerHby:
        mailbox = providerHby.makeHab(name="mbx", transferable=False)
        controller = controllerHby.makeHab(name="alice", transferable=True)
        client = _mailbox_admin_client(providerHby, mailbox)
        kel = _collect_replay(controller).decode("utf-8")
        signed = controller.makeEndRole(mailbox.pre, Roles.mailbox,
                                       stamp="2021-01-01T00:00:00.000000+00:00")
        accepted = SerderKERI(raw=signed)
        assert _post_mailbox_admin(client, fields=dict(kel=kel, rpy=signed.decode("utf-8"))).status_code == 200
        assert _post_mailbox_admin(client, fields=dict(kel=kel, rpy=accepted.raw.decode("utf-8"))).status_code == 200
        different = SerderKERI(raw=controller.makeEndRole(mailbox.pre, Roles.mailbox,
                                       stamp="2021-01-01T00:00:01.000000+00:00"))
        assert different.said != accepted.said
        rep = _post_mailbox_admin(client, fields=dict(kel=kel, rpy=different.raw.decode("utf-8")))
        assert rep.status_code == 403
        assert providerHby.db.eans.get(keys=(controller.pre, Roles.mailbox, mailbox.pre)).qb64 == accepted.said


def test_authorized_forwarder_ignores_malformed_recipient_and_topic():
    """Malformed mailbox selectors do not escape into the host's parsing loop."""
    with openHby(name="mailbox-malformed-forward") as hby:
        mailbox = hby.makeHab(name="mbx", transferable=False)
        sender = hby.makeHab(name="sender", transferable=True)
        sender.psr.parse(ims=sender.makeEndRole(mailbox.pre, Roles.mailbox))
        mbx = Mailboxer(name="malformed-forward", temp=True)
        try:
            handler = AuthorizedForwardHandler(hby=hby, mbx=mbx, mailboxAid=mailbox.pre)
            for modifiers in ({}, dict(topic="echo"), dict(pre=sender.pre),
                              dict(pre=[], topic="echo"), dict(pre=sender.pre, topic=[])):
                parent, _ = specialExchange(sender=sender.pre, route="/fwd", modifiers=modifiers,
                                             attributes={}, version=Vrsn_1_0, kind=Kinds.json)
                handler.handle(serder=parent, attachments=[])
            assert list(mbx.cloneTopicIter(topic=f"{sender.pre}/echo")) == []
        finally:
            mbx.close(clear=True)


def test_mailbox_admin_rejects_non_utf8_fields():
    """Invalid field encoding remains a request error instead of a server failure."""
    with openHby(name="mailbox-invalid-encoding") as hby:
        mailbox = hby.makeHab(name="mbx", transferable=False)
        body, contentType = _multipart_body(kel="not-utf8", rpy="unused")
        rep = _post_mailbox_admin(_mailbox_admin_client(hby, mailbox),
                                 content_type=contentType, body=body.replace(b"not-utf8", b"\xff"))
        assert rep.status_code == 400
        assert "UTF-8" in rep.text
