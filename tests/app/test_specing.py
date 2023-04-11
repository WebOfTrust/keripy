# -*- encoding: utf-8 -*-
"""
tests.app.agent_kiwiserver module

"""
import json

import falcon

from keri.app import booting, specing, kiwiing, habbing, grouping, notifying


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
        app.add_route("/boot/{name}", bootEnd, suffix="name")

        lockEnd = kiwiing.LockEnd(servery=booting.Servery(port=1234), bootConfig=dict())
        app.add_route("/lock", lockEnd)

        resources = [passcodeEnd, bootEnd, lockEnd]
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

        assert "/boot/{name}" in paths
        boot = paths["/boot/{name}"]
        assert len(boot) == 1
        assert "get" in boot

        assert "/lock" in paths
        lock = paths["/lock"]
        assert len(lock) == 1
        assert "post" in lock

        # Assert on the entire JSON to ensure we are getting all the docs
        js = json.dumps(sd)

        print(js)

        assert js == ('{"paths": {"/codes": {"get": {"summary": "Generate random 22 digit passcode '
                      'for use in securing and encrypting keystore", "description": "Generate '
                      'random 22 digit passcode for use in securing and encrypting keystore", '
                      '"tags": ["Passcode"], "responses": {"200": {"description": "Randomly '
                      'generated 22 character passcode formatted as '
                      'xxxx-xxxxx-xxxx-xxxxx-xxxx"}}}}, "/boot": {"post": {"summary": "Create KERI '
                      'environment (database and keystore)", "description": "Creates the '
                      'directories for database and keystore for vacuous KERI instance using name '
                      'and aeid key or passcode to encrypt datastore.  Fails if directory already '
                      'exists.", "tags": ["Boot"], "requestBody": {"required": true, "content": '
                      '{"application/json": {"schema": {"type": "object", "properties": {"name": '
                      '{"type": "string", "description": "human readable nickname for this agent", '
                      '"example": "alice"}, "passcode": {"type": "string", "description": "passcode '
                      'for encrypting and securing this agent", "example": '
                      '"RwyY-KleGM-jbe1-cUiSz-p3Ce"}}}}}}, "responses": {"200": {"description": '
                      '"JSON object containing status message"}}}, "put": {"summary": "Unlock '
                      'keystore with aeid encryption key generated from passcode.", "description": '
                      '"Unlock keystore with aeid encryption key generated from passcode..", '
                      '"tags": ["Boot"], "requestBody": {"required": true, "content": '
                      '{"application/json": {"schema": {"type": "object", "properties": {"name": '
                      '{"type": "string", "description": "human readable nickname for this agent", '
                      '"example": "alice"}, "passcode": {"type": "string", "description": "passcode '
                      'for unlocking the agent and decrypting the keystore", "example": '
                      '"RwyY-KleGM-jbe1-cUiSz-p3Ce"}}}}}}, "responses": {"200": {"description": '
                      '"JSON object containing status message"}}}}, "/lock": {"post": {"summary": '
                      '"Lock", "description": "Reloads the API to the boot version", "tags": '
                      '["Lock"], "responses": {"200": {"description": "locked"}}}}, "/boot/{name}": '
                      '{"get": {"summary": "Query KERI environment for keystore name", "tags": '
                      '["Boot"], "parameters": [{"in": "path", "name": "name", "schema": {"type": '
                      '"string"}, "required": true, "description": "predetermined name of keep '
                      'keystore", "example": "alice"}], "responses": {"202": {"description": '
                      '"Keystore exists"}, "404": {"description": "No keystore exists"}}}}}, '
                      '"info": {"title": "KERI Interactive Web Interface API", "version": "1.0.0"}, '
                      '"openapi": "3.0.2"}')
