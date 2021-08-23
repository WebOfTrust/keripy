# -*- encoding: utf-8 -*-
"""
keri.core.scheming module

self-addressing and schema support
"""

import hashlib
import json
from collections import namedtuple

import blake3
import cbor2 as cbor
import jsonschema
import msgpack

from . import coring
from .coring import Matter, MtrDex, Serials, Saider, Ids
from .. import help
from ..kering import ValidationError, DeserializationError, EmptyMaterialError


logger = help.ogler.getLogger()


class CacheResolver:
    """
    Sample jsonschema resolver for loading schema $ref references from a local hash.

    """

    def __init__(self, cache=None):
        """
        Create a jsonschema resolver that can be used for loading references to schema remotely.

        Parameters:
            cache (dict) is an optional pre-loaded cache of schema
        """
        self.cache = cache if cache is not None else dict()

    def add(self, key, schema):
        """
        Add schema to cache for resolution

        Parameters:
            key (str) URI to resolve to the schema
            schema (bytes) is bytes of the schema for the URI
        """
        self.cache[key] = schema

    def resolve(self, uri):
        if uri not in self.cache:
            raise ValueError("{} ref not found".format(uri))

        ref = self.cache[uri]
        return ref

    def handler(self, uri):
        """
        Handler provided to jsonschema for cache resolution

        Parameters:
            uri (str) the URI to resolve
        """
        ref = self.resolve(uri)
        schemr = Schemer(raw=ref)
        return schemr.sed

    def resolver(self, scer=b''):
        """
        Returns a jsonschema resolver for returning locally cached schema based on self-addressing
        identifier URIs.

        Parameters:
            scer (bytes) is the source document that is being processed for reference resolution

        """
        return jsonschema.RefResolver("", scer, handlers={"did": self.handler})


jsonSchemaCache = CacheResolver(cache={
    "E7brwlefuH-F_KU_FPWAZR78A3pmSVDlnfJUqnm8Lhr4":
        b'{"$id": "E7brwlefuH-F_KU_FPWAZR78A3pmSVDlnfJUqnm8Lhr4", "$schema": '
        b'"http://json-schema.org/draft-07/schema#", "title": "GLEIF vLEI Credential", "description": "The vLEI '
        b'Credential issued to GLEIF", "type": "object", "properties": {"v": {"type": "string"}, "i": {"type": '
        b'"string"}, "ti": {"type": "string"}, "x": {"description": "schema block", "type": "string"}, '
        b'"d": {"description": "data block", "properties": {"i": {"type": "string"}, "si": {"type": "string"}, '
        b'"issuanceDate": {"format": "date-time", "type": "string"}, "credentialStatus": {"type": "string"}, '
        b'"LEI": {"type": "string"}, "type": {"contains": {"const": "GLEIFvLEICredential"}, "type": "array"}}, '
        b'"additionalProperties": false, "required": ["i", "issuanceDate", "credentialStatus", "LEI", "type"], '
        b'"type": "object"}}, "additionalProperties": false, "required": ["i", "d"]}',
    "EWPMkW-_BU6gh1Y8kizXHchFdmvu_i1wYlYbAC3aJABk":
        b'{"$id": "EWPMkW-_BU6gh1Y8kizXHchFdmvu_i1wYlYbAC3aJABk", "$schema": '
        b'"http://json-schema.org/draft-07/schema#", "title": "Legal Entity Engagement Context Role vLEI Credential", '
        b'"description": "A vLEI Role Credential issued to representatives of a Legal Entity in other than official '
        b'roles but in functional or other context of engagement", "properties": {"v": {"type": "string"}, '
        b'"i": {"type": "string"}, "ti": {"type": "string"}, "x": {"description": "schema block", "type": "string"}, '
        b'"d": {"description": "data block", "properties": {"i": {"type": "string"}, "si": {"type": "string"}, '
        b'"issuanceDate": {"format": "date-time", "type": "string"}, "credentialStatus": {"type": "string"}, '
        b'"LEI": {"type": "string"}, "personLegalName": {"type": "string"}, "engagementContextRole": {"type": '
        b'"string"}, "type": {"contains": {"const": "LegalEntityEngagementContextRolevLEICredential"}, '
        b'"type": "array"}}, "additionalProperties": false, "required": ["i", "issuanceDate", "credentialStatus", '
        b'"LEI", "personLegalName", "engagementContextRole", "type"], "type": "object"}, "s": {"contains": {"type": '
        b'"object"}, "description": "source block", "items": {"properties": {"qualifiedvLEIIssuervLEICredential": {'
        b'"type": "string"}}, "additionalProperties": false, "required": ["qualifiedvLEIIssuervLEICredential"], '
        b'"type": "object"}, "maxItems": 1, "minItems": 1, "type": "array"}}, "additionalProperties": false, '
        b'"required": ["i", "s", "d"], "type": "object"}',
    "EUZ_F1do5sG78zeeA_8CChT5utRpOXQK4GYnv0WGRfuU":
        b'{"$id": "EUZ_F1do5sG78zeeA_8CChT5utRpOXQK4GYnv0WGRfuU", "$schema": '
        b'"http://json-schema.org/draft-07/schema#", "title": "Legal Entity Official Organizational Role vLEI '
        b'Credential", "description": "A vLEI Role Credential issued by a Qualified vLEI issuer to official '
        b'representatives of a Legal Entity", "properties": {"v": {"type": "string"}, "i": {"type": "string"}, '
        b'"ti": {"type": "string"}, "x": {"description": "schema block", "type": "string"}, "d": {"description": '
        b'"data block", "properties": {"i": {"type": "string"}, "si": {"type": "string"}, "issuanceDate": {"format": '
        b'"date-time", "type": "string"}, "credentialStatus": {"type": "string"}, "LEI": {"type": "string"}, '
        b'"personLegalName": {"type": "string"}, "officialRole": {"type": "string"}, "type": {"contains": {"const": '
        b'"LegalEntityOfficialOrganizationalRolevLEICredential"}, "type": "array"}}, "additionalProperties": false, '
        b'"required": ["i", "issuanceDate", "credentialStatus", "LEI", "personLegalName", "officialRole", "type"], '
        b'"type": "object"}, "s": {"contains": {"type": "object"}, "description": "source block", "items": {'
        b'"properties": {"qualifiedvLEIIssuervLEICredential": {"type": "string"}}, "additionalProperties": false, '
        b'"required": ["qualifiedvLEIIssuervLEICredential"], "type": "object"}, "maxItems": 1, "minItems": 1, '
        b'"type": "array"}}, "additionalProperties": false, "required": ["i", "s", "d"], "type": "object"}',
    "E-BRq9StLuC9DxGgiFiy2XND0fFgzyn8cjptlcdvGEFY":
        b'{"$id": "E-BRq9StLuC9DxGgiFiy2XND0fFgzyn8cjptlcdvGEFY", "$schema": '
        b'"http://json-schema.org/draft-07/schema#", "title": "Legal Entity vLEI Credential", "description": "A vLEI '
        b'Credential issued by a Qualified vLEI issuer to a Legal Entity", "properties": {"v": {"type": "string"}, '
        b'"i": {"type": "string"}, "ti": {"type": "string"}, "x": {"description": "schema block", "type": "string"}, '
        b'"d": {"description": "data block", "properties": {"i": {"type": "string"}, "si": {"type": "string"}, '
        b'"issuanceDate": {"format": "date-time", "type": "string"}, "credentialStatus": {"type": "string"}, '
        b'"LEI": {"type": "string"}, "type": {"contains": {"const": "LegalEntityvLEICredential"}, "type": "array"}}, '
        b'"additionalProperties": false, "required": ["i", "issuanceDate", "credentialStatus", "LEI", "type"], '
        b'"type": "object"}, "s": {"contains": {"type": "object"}, "description": "source block", "items": {'
        b'"properties": {"qualifiedvLEIIssuervLEICredential": {"type": "string"}}, "additionalProperties": false, '
        b'"required": ["qualifiedvLEIIssuervLEICredential"], "type": "object"}, "maxItems": 1, "minItems": 1, '
        b'"type": "array"}}, "additionalProperties": false, "required": ["i", "s", "d"], "type": "object"}',
    "E9bX8Do0nb1Eq986HvoJ2iNO00TjC6J_2En8Du9L-hYU":
        b'{"$id": "E9bX8Do0nb1Eq986HvoJ2iNO00TjC6J_2En8Du9L-hYU", "$schema": '
        b'"http://json-schema.org/draft-07/schema#", "title": "Qualified vLEI Issuer Credential", "description": "A '
        b'vLEI Credential issued by GLEIF to Qualified vLEI Issuers which allows the Qualified vLEI Issuers to issue, '
        b'verify and revoke Legal Entity vLEI Credentials and Legal Entity Official Organizational Role vLEI '
        b'Credentials", "properties": {"v": {"type": "string"}, "i": {"type": "string"}, "ti": {"type": "string"}, '
        b'"x": {"description": "schema block", "type": "string"}, "d": {"description": "data block", "properties": {'
        b'"i": {"type": "string"}, "si": {"type": "string"}, "issuanceDate": {"format": "date-time", '
        b'"type": "string"}, "credentialStatus": {"type": "string"}, "LEI": {"type": "string"}, "gracePeriod": {'
        b'"default": 90, "type": "integer"}, "type": {"contains": {"const": "QualifiedvLEIIssuervLEICredential"}, '
        b'"type": "array"}}, "additionalProperties": false, "required": ["i", "issuanceDate", "credentialStatus", '
        b'"LEI", "type"], "type": "object"}}, "additionalProperties": false, "required": ["i", "d"], '
        b'"type": "object"}',
})


class JSONSchema:
    """
    JSON Schema support class
    """
    id_ = Ids.dollar  # ID Field Label

    def __init__(self, resolver=CacheResolver()):
        self.resolver = resolver

    def resolve(self, uri):
        return self.resolver.resolve(uri)

    def load(self, raw=b'', kind=Serials.json):
        if kind == Serials.json:
            try:
                sed = json.loads(raw.decode("utf-8"))
            except Exception as ex:
                raise DeserializationError("Error deserializing JSON: {} {}"
                                           "".format(raw.decode("utf-8"), ex))

        elif kind == Serials.mgpk:
            try:
                sed = msgpack.loads(raw)
            except Exception as ex:
                raise DeserializationError("Error deserializing MGPK: {} {}"
                                           "".format(raw, ex))

        elif kind == Serials.cbor:
            try:
                sed = cbor.loads(raw)
            except Exception as ex:
                raise DeserializationError("Error deserializing CBOR: {} {}"
                                           "".format(raw, ex))
        else:
            raise ValueError("Invalid serialization kind = {}".format(kind))

        if self.id_ in sed:
            saider = Saider(qb64=sed[self.id_], label=self.id_)
            said = sed[self.id_]
            if not saider.verify(sed, prefixed=True, kind=kind, label=self.id_):
                raise ValidationError("invalid self-addressing identifier {} instead of {} in schema = {}"
                                      "".format(said, saider.qb64, sed))
        else:
            raise ValidationError("missing ID field {} in schema = {}"
                                  "".format(self.id_, sed))

        return sed, kind, saider

    @staticmethod
    def dump(sed, kind=Serials.json):
        raw = coring.dumps(sed, kind)
        return raw

    @staticmethod
    def detect(raw=b''):
        """
        Returns True if content represents JSON Schema by checking
            for $schema;  False otherwise
        """

        try:
            raw.index(b'"$schema"')
        except ValueError:
            return False

        return True

    @staticmethod
    def verify_schema(schema):
        """
        Returns True if the provided schema validates successfully
          as complaint Draft 7 JSON Schema False otherwise

        Parameters:
            schema (dict): is the JSON schema to verify
        """
        try:
            jsonschema.Draft7Validator.check_schema(schema=schema)
        except jsonschema.exceptions.SchemaError:
            return False

        return True

    def verify_json(self, schema=b'', raw=b''):
        """
        Returns True if the JSON passes validation against the
           provided complaint Draft 7 JSON Schema.  Returns False
           if raw is not valid JSON, schema is not valid JSON Schema or
           the validation fails

        Parameters:
              schema (bytes): is the schema use for validation
              raw (bytes): is JSON to validate against the Schema
        """
        try:
            d = json.loads(raw)
            jsonschema.validate(instance=d, schema=schema, resolver=self.resolver.resolver(scer=raw))
        except jsonschema.exceptions.ValidationError as ex:
            logger.error(f'jsonschema.exceptions.ValidationError {ex}')
            return False
        except jsonschema.exceptions.SchemaError as ex:
            logger.error(f'jsonschema.exceptions.SchemaError {ex}')
            return False
        except json.decoder.JSONDecodeError as ex:
            logger.error(f'json.decoder.JSONDecodeError {ex}')
            return False

        return True


class Schemer:
    """
    Schemer is KERI schema serializer-deserializer class
    Verifies self-addressing identifier base on schema type
    Only supports current version VERSION

    Has the following public properties:

    Properties:
        .raw is bytes of serialized event only
        .sed is JSON schema dict
        .kind is Schema kind string value (see namedtuple coring.Serials)
        .saider is Saider instance of self-addressing identifier
        .said  is qb64 digest from .saider

    Hidden Attributes:
          ._raw is bytes of serialized schema only
          ._sed is JSON schema dict
          ._kind is schema kind string value (see namedtuple coring.Serials)
            supported kinds are 'JSONSchema'
          ._code is default code for .saider
          ._saider is Saider instance of digest of .raw


    """

    def __init__(self, raw=b'', sed=None, kind=None, typ=JSONSchema(), code=MtrDex.Blake3_256):
        """
        Deserialize if raw provided
        Serialize if sed provided but not raw
        When serilaizing if kind provided then use kind instead of field in sed

        Parameters:
          raw is bytes of serialized schema
          sed is JSON dict or None
            if None its deserialized from raw
          schemaType is the type of schema
          kind is serialization kind string value or None (see namedtuple coring.Serials)
            supported kinds are 'json', 'cbor', 'msgpack', 'binary'
            if kind is None then its extracted from ked or raw
          code is .saider default digest code

        """

        self._code = code
        self.typ = typ
        if raw:
            self.raw = raw
        elif sed:
            self._kind = kind
            self.sed = sed
        else:
            raise ValueError("Improper initialization need raw or sed.")

        if not self._verify_schema():
            raise ValidationError("invalid kind {} for schema {}"
                                  "".format(self.kind, self.sed))

    def _inhale(self, raw):
        """
        Loads type specific Schema ked and verifies the self-addressing identifier
            of the raw content

        Parameters:
            raw: JSON to load

        """

        sed, kind, saider = self.typ.load(raw=raw)

        return sed, kind, saider

    def _exhale(self, sed, kind=None):
        """
        Dumps type specific Schema JSON and returns the raw bytes, sed
           and schema kind

        Parameters:
            sed: JSON to load
            kind (Schema) tuple of schema type

        """
        saider = Saider(sad=sed, code=self._code, label=self.typ.id_)
        sed[self.typ.id_] = saider.qb64
        raw = self.typ.dump(sed)

        return raw, sed, kind, saider

    @property
    def raw(self):
        """ raw property getter """
        return self._raw

    @raw.setter
    def raw(self, raw):
        """ raw property setter """
        sed, kind, saider = self._inhale(raw=raw)
        self._raw = bytes(raw)  # crypto ops require bytes not bytearray
        self._sed = sed
        self._kind = kind
        self._saider = saider

    @property
    def sed(self):
        """ ked property getter"""
        return self._sed

    @sed.setter
    def sed(self, sed):
        """ ked property setter  assumes ._kind """
        raw, sed, kind, saider = self._exhale(sed=sed, kind=self._kind)
        self._raw = raw
        self._kind = kind
        self._sed = sed
        self._saider = saider

    @property
    def kind(self):
        """ kind property getter """
        return self._kind

    @kind.setter
    def kind(self, kind):
        """ kind property setter Assumes ._ked """
        raw, kind, sed = self._exhale(sed=self._sed, kind=kind)
        self._raw = raw
        self._sed = sed
        self._kind = kind
        self._saider = Saider(raw=self._raw, code=self._code, label=Ids.dollar)

    @property
    def saider(self):
        """ saider property getter """
        return self._saider

    @property
    def said(self):
        """ said property getter, relies on saider """
        return self.saider.qb64

    def verify(self, raw=b''):
        """
        Returns True if derivation from ked for .code matches .qb64 and
                If prefixed also verifies ked["i"] matches .qb64
                False otherwise

        Parameters:
            raw (bytes): is serialised JSON content to verify against schema
        """

        return self.typ.verify_json(schema=self.sed, raw=raw)

    def _verify_schema(self):
        """
        Returns True if derivation from ked for .code matches .qb64 and
                If prefixed also verifies ked["i"] matches .qb64
                False otherwise

        """

        return self.typ.verify_schema(schema=self.sed)



