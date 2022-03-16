# -*- encoding: utf-8 -*-
"""
tests.app.agent_kiwiserver module

"""
import json

import falcon

from keri.app import booting, specing, kiwiing, habbing


def test_spec_resource():

    with habbing.openHby(name="eve", base="test") as hby:
        app = falcon.App()
        servery = booting.Servery(port=1234)

        # Add a simple endpoint
        passcodeEnd = booting.PasscodeEnd()
        app.add_route("/codes", passcodeEnd)

        # Add a resource with multiple endpoints for different methods
        bootEnd = booting.BootEnd(servery=servery)
        app.add_route("/boot", bootEnd)

        # Add a few with no resolutions at the root (resource=None for /group)
        multiIcpEnd = kiwiing.MultisigInceptEnd(hby=hby)
        app.add_route("/groups/{alias}/icp", multiIcpEnd)
        multiRotEnd = kiwiing.MultisigEventEnd(hby=hby)
        app.add_route("/groups/{alias}/rot", multiRotEnd, suffix="rot")

        resources = [passcodeEnd, bootEnd, multiIcpEnd, multiRotEnd]
        specRes = specing.SpecResource(app=app, title='KERI Interactive Web Interface API', resources=resources)

        sd = specRes.spec.to_dict()
        assert "paths" in sd
        paths = sd["paths"]
        print()
        print(paths)
        assert "/codes" in paths
        codes = paths["/codes"]
        assert len(codes) == 1
        assert "get" in codes

        assert "/boot" in paths
        boot = paths["/boot"]
        assert len(boot) == 2
        assert "post" in boot
        assert "put" in boot

        assert "/groups/{alias}/icp" in paths
        icp = paths["/groups/{alias}/icp"]
        assert len(icp) == 2
        assert "post" in icp
        assert "put" in icp

        assert "/groups/{alias}/rot" in paths
        rot = paths["/groups/{alias}/rot"]
        assert len(rot) == 2
        assert "post" in rot
        assert "put" in rot

        # Assert on the entire JSON to ensure we are getting all the docs
        js = json.dumps(sd)
        assert js == (('{"paths": {"/codes": {"get": {"summary": "Generate random 22 digit passcode '
                       'for use in securing and excrypting keystore", "description": "Generate '
                       'random 22 digit passcode for use in securing and excrypting keystore", '
                       '"tags": ["Passcode"], "responses": {"200": {"description": "Randomly '
                       'generated 22 character passcode formatted as '
                       'xxxx-xxxxx-xxxx-xxxxx-xxxx"}}}}, "/boot": {"post": {"summary": "Create KERI '
                       'environment (database and keystore)", "description": "Creates the '
                       'directories for database and keystore for vacuous KERI instance using name '
                       'and aeid key or passcode to encrypt datastore.  Fails if directory already '
                       'exists.", "tags": ["Boot"], "requestBody": {"required": true, "content": '
                       '{"application/json": {"schema": {"type": "object", "properties": {"name": '
                       '{"type": "string", "description": "human readable nickname for this agent"}, '
                       '"passcode": {"type": "string", "description": "passcode for encrypting and '
                       'securing this agent"}}}}}}, "responses": {"200": {"description": "JSON '
                       'object containing status message"}}}, "put": {"summary": "Unlock keystore '
                       'with aeid encryption key generated from passcode.", "description": "Unlock '
                       'keystore with aeid encryption key generated from passcode..", "tags": '
                       '["Boot"], "requestBody": {"required": true, "content": {"application/json": '
                       '{"schema": {"type": "object", "properties": {"name": {"type": "string", '
                       '"description": "human readable nickname for this agent"}, "passcode": '
                       '{"type": "string", "description": "passcode for unlocking the agent and '
                       'decrypting the keystore"}}}}}}, "responses": {"200": {"description": "JSON '
                       'object containing status message"}}}}, "/groups/{alias}/icp": {"post": '
                       '{"summary": "Initiate a multisig group inception", "description": "Initiate '
                       'a multisig group inception with the participants identified by the  provided '
                       'AIDs", "tags": ["Groups"], "parameters": [{"in": "path", "name": "alias", '
                       '"schema": {"type": "string"}, "required": true, "description": "Human '
                       'readable alias for the identifier to create"}], "requestBody": {"required": '
                       'true, "content": {"application/json": {"schema": {"type": "object", '
                       '"properties": {"aids": {"type": "array", "items": {"type": "string"}, '
                       '"description": "List of qb64 AIDs of participants in multisig group"}, '
                       '"notify": {"type": "boolean", "required": false, "description": "True means '
                       'to send mutlsig incept exn message to other participants"}, "toad": {"type": '
                       '"integer", "description": "Witness receipt threshold"}, "wits": {"type": '
                       '"array", "items": {"type": "string"}, "description": "List of qb64 AIDs of '
                       'witnesses to be used for the new group identfier"}, "isith": {"type": '
                       '"string", "description": "Signing threshold for the new group identifier"}, '
                       '"nsith": {"type": "string", "description": "Next signing threshold for the '
                       'new group identifier"}}}}}}, "responses": {"200": {"description": "Multisig '
                       'group AID inception initiated."}}}, "put": {"summary": "Participate in a '
                       'multisig group inception", "description": "Participate in a multisig group '
                       'rotation", "tags": ["Groups"], "parameters": [{"in": "path", "name": '
                       '"alias", "schema": {"type": "string"}, "required": true, "description": '
                       '"Human readable alias for the identifier to create"}], "requestBody": '
                       '{"required": true, "content": {"application/json": {"schema": {"type": '
                       '"object", "properties": {"aids": {"type": "array", "items": {"type": '
                       '"string"}, "description": "List of qb64 AIDs of participants in multisig '
                       'group"}, "notify": {"type": "boolean", "required": false, "description": '
                       '"True means to send mutlsig incept exn message to other participants"}, '
                       '"toad": {"type": "integer", "description": "Witness receipt threshold"}, '
                       '"wits": {"type": "array", "items": {"type": "string"}, "description": "List '
                       'of qb64 AIDs of witnesses to be used for the new group identfier"}, "isith": '
                       '{"type": "string", "description": "Signing threshold for the new group '
                       'identifier"}, "nsith": {"type": "string", "description": "Next signing '
                       'threshold for the new group identifier"}}}}}}, "responses": {"200": '
                       '{"description": "Multisig group AID inception initiated."}}}}, '
                       '"/groups/{alias}/rot": {"post": {"summary": "Initiate a multisig group '
                       'rotation", "description": "Initiate a multisig group rotation with the '
                       'participants identified by the provided AIDs", "tags": ["Groups"], '
                       '"parameters": [{"in": "path", "name": "alias", "schema": {"type": "string"}, '
                       '"required": true, "description": "Human readable alias for the identifier to '
                       'create"}], "requestBody": {"required": true, "content": {"application/json": '
                       '{"schema": {"type": "object", "properties": {"aids": {"type": "array", '
                       '"items": {"type": "string"}, "description": "List of qb64 AIDs of '
                       'participants in multisig group"}, "notify": {"type": "boolean", "required": '
                       'false, "description": "True means to send mutlsig incept exn message to '
                       'other participants"}, "toad": {"type": "integer", "description": "Witness '
                       'receipt threshold"}, "witnesses": {"type": "array", "items": {"type": '
                       '"string"}, "description": "List of qb64 AIDs of witnesses to be used for the '
                       'new group identfier"}, "isith": {"type": "string", "description": "Signing '
                       'threshold for the new group identifier"}, "nsith": {"type": "string", '
                       '"description": "Next signing threshold for the new group identifier"}}}}}}, '
                       '"responses": {"204": {"description": "Multisig group AID inception '
                       'initiated."}}}, "put": {"summary": "Participate in a multisig group '
                       'rotation", "description": "Participate in a multisig group rotation", '
                       '"tags": ["Groups"], "responses": {"202": {"description": "rotation '
                       'participation initiated"}}}}}, "info": {"title": "KERI Interactive Web '
                       'Interface API", "version": "1.0.0"}, "openapi": "3.0.2"}'))
