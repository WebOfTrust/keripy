# -*- encoding: utf-8 -*-
"""
tests.app.mailboxing module

"""
import importlib

import falcon
from falcon import testing
import pytest

from hio.help import decking

from keri.app import openHby
from keri.app.mailboxing import MailboxAddRemoveEnd
from keri.core import Kevery, Salter, routing
from keri.kering import Roles


def _collect_replay(hab):
    """Collect one habitat replay in the same delegation-first order used by mailbox admin."""
    body = bytearray()
    for msg in hab.db.clonePreIter(pre=hab.pre):
        body.extend(msg)
    for msg in hab.db.cloneDelegation(hab.kever):
        body.extend(msg)
    return body


def _mailbox_admin_client(hby, hab):
    """Build a focused Falcon client exposing only the mailbox admin endpoint."""
    cues = decking.Deck()
    rvy = routing.Revery(db=hby.db, cues=cues)
    kvy = Kevery(db=hby.db, lax=True, local=False, rvy=rvy, cues=cues)
    kvy.registerReplyRoutes(router=rvy.rtr)

    app = falcon.App()
    app.add_route("/mailboxes",
                  MailboxAddRemoveEnd(hby=hby, hab=hab, kvy=kvy, rvy=rvy, exc=None))
    return testing.TestClient(app)


def _multipart_body(**fields):
    """Create one minimal multipart body for mailbox admin endpoint tests."""
    boundary = "----keri-mailbox-admin-boundary"
    body = bytearray()

    for name, value in fields.items():
        if value is None:
            continue
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8"))
        body.extend(value.encode("utf-8"))
        body.extend(b"\r\n")

    body.extend(f"--{boundary}--\r\n".encode("utf-8"))
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def _post_mailbox_admin(client, *, fields=None, content_type="text/plain", body=b""):
    """Post either raw bytes or mailbox-admin multipart fields to `/mailboxes`."""
    if fields is not None:
        body, content_type = _multipart_body(**fields)

    return client.simulate_post(
        "/mailboxes",
        headers={"Content-Type": content_type},
        body=body,
    )


def test_mailbox_add_remove_end_accepts_multipart_add():
    """Mailbox admin accepts the legacy multipart add envelope for a direct controller."""
    with openHby(name="mailbox-provider", salt=Salter(raw=b"mailbox-provider0").qb64) as providerHby, \
            openHby(name="mailbox-controller", salt=Salter(raw=b"mailbox-controller").qb64) as controllerHby:
        mailboxHab = providerHby.makeHab(name="mbx", transferable=False)
        controller = controllerHby.makeHab(name="alice", transferable=True)
        client = _mailbox_admin_client(providerHby, mailboxHab)

        rep = _post_mailbox_admin(client, fields={
            "kel": _collect_replay(controller).decode("utf-8"),
            "rpy": controller.makeEndRole(mailboxHab.pre, Roles.mailbox, allow=True).decode("utf-8"),
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
