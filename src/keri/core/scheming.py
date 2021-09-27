# -*- encoding: utf-8 -*-
"""
keri.core.scheming module

self-addressing and schema support
"""

import json

import cbor2 as cbor
import jsonschema
import msgpack

from . import coring
from .coring import MtrDex, Serials, Saider, Ids
from .. import help
from ..kering import ValidationError, DeserializationError

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
            return None

        ref = self.cache[uri]
        return ref

    def handler(self, uri):
        """
        Handler provided to jsonschema for cache resolution

        Parameters:
            uri (str) the URI to resolve
        """
        ref = self.resolve(uri)
        if not ref:
            return None

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
    "E3n2Od38xMVDoM6Km-Awse_Cw9z0RtUJN-j0MQo642xw": b'{"$id":"E3n2Od38xMVDoM6Km-Awse_Cw9z0RtUJN-j0MQo642xw",'
                                                    b'"$schema":"http://json-schema.org/draft-07/schema#",'
                                                    b'"title":"Legal Entity Official Organizational Role vLEI '
                                                    b'Credential","description":"A vLEI Role Credential issued by a '
                                                    b'Qualified vLEI issuer to official representatives of a Legal '
                                                    b'Entity","properties":{"v":{"type":"string"},'
                                                    b'"d":{"type":"string"},"i":{"type":"string"},'
                                                    b'"s":{"description":"schema SAID","type":"string"},'
                                                    b'"a":{"description":"data block","properties":{"d":{'
                                                    b'"type":"string"},"i":{"type":"string"},'
                                                    b'"dt":{"description":"issuance date time","format":"date-time",'
                                                    b'"type":"string"},"ri":{"description":"credential status '
                                                    b'registry","type":"string"},"LEI":{"type":"string"},'
                                                    b'"personLegalName":{"type":"string"},"officialRole":{'
                                                    b'"type":"string"},"t":{"contains":{'
                                                    b'"const":"LegalEntityOfficialOrganizationalRolevLEICredential"},'
                                                    b'"type":"array"}},"additionalProperties":false,"required":["i",'
                                                    b'"dt","ri","LEI","personLegalName","officialRole","t"],'
                                                    b'"type":"object"},"p":{"contains":{"type":"object"},'
                                                    b'"description":"source block","items":{"properties":{'
                                                    b'"qualifiedvLEIIssuervLEICredential":{"description":"chain to '
                                                    b'issuer credential","properties":{"d":{"type":"string"},'
                                                    b'"i":{"type":"string"}},"additionalProperties":false,'
                                                    b'"type":"object"}},"additionalProperties":false,"required":['
                                                    b'"qualifiedvLEIIssuervLEICredential"],"type":"object"},'
                                                    b'"maxItems":1,"minItems":1,"type":"array"}},'
                                                    b'"additionalProperties":false,"required":["i","s","d"],'
                                                    b'"type":"object"}',
    "EJEY6JAAVfAh8-yBTV37rHaJ9b_VKvkZunz_oJupzsvQ": b'{"$id":"EJEY6JAAVfAh8-yBTV37rHaJ9b_VKvkZunz_oJupzsvQ",'
                                                    b'"$schema":"http://json-schema.org/draft-07/schema#",'
                                                    b'"title":"Legal Entity vLEI Credential","description":"A vLEI '
                                                    b'Credential issued by a Qualified vLEI issuer to a Legal '
                                                    b'Entity","properties":{"v":{"type":"string"},'
                                                    b'"d":{"type":"string"},"i":{"type":"string"},'
                                                    b'"s":{"description":"schema SAID","type":"string"},'
                                                    b'"a":{"description":"data block","properties":{"d":{'
                                                    b'"type":"string"},"i":{"type":"string"},'
                                                    b'"dt":{"description":"issuance date time","format":"date-time",'
                                                    b'"type":"string"},"ri":{"description":"credential status '
                                                    b'registry","type":"string"},"LEI":{"type":"string"},'
                                                    b'"t":{"contains":{"const":"LegalEntityvLEICredential"},'
                                                    b'"type":"array"}},"additionalProperties":false,"required":["i",'
                                                    b'"dt","ri","LEI","t"],"type":"object"},"p":{"contains":{'
                                                    b'"type":"object"},"description":"source block",'
                                                    b'"items":{"properties":{"qualifiedvLEIIssuervLEICredential":{'
                                                    b'"description":"chain to issuer credential","properties":{"d":{'
                                                    b'"type":"string"},"i":{"type":"string"}},'
                                                    b'"additionalProperties":false,"type":"object"}},'
                                                    b'"additionalProperties":false,"required":['
                                                    b'"qualifiedvLEIIssuervLEICredential"],"type":"object"},'
                                                    b'"maxItems":1,"minItems":1,"type":"array"}},'
                                                    b'"additionalProperties":false,"required":["i","s","d"],'
                                                    b'"type":"object"}',
    "EmaEqu_zIkxXKsrNJFTJq_s2c96McS8yzHhcvYDW8u5A": b'{"$id":"EmaEqu_zIkxXKsrNJFTJq_s2c96McS8yzHhcvYDW8u5A",'
                                                    b'"$schema":"http://json-schema.org/draft-07/schema#",'
                                                    b'"title":"Legal Entity Engagement Context Role vLEI Credential",'
                                                    b'"description":"A vLEI Role Credential issued to representatives '
                                                    b'of a Legal Entity in other than official roles but in '
                                                    b'functional or other context of engagement","properties":{"v":{'
                                                    b'"type":"string"},"d":{"type":"string"},"i":{"type":"string"},'
                                                    b'"s":{"description":"schema SAID","type":"string"},'
                                                    b'"a":{"description":"data block","properties":{"d":{'
                                                    b'"type":"string"},"i":{"type":"string"},'
                                                    b'"dt":{"description":"issuance date time","format":"date-time",'
                                                    b'"type":"string"},"ri":{"description":"credential status '
                                                    b'registry","type":"string"},"LEI":{"type":"string"},'
                                                    b'"personLegalName":{"type":"string"},"engagementContextRole":{'
                                                    b'"type":"string"},"t":{"contains":{'
                                                    b'"const":"LegalEntityEngagementContextRolevLEICredential"},'
                                                    b'"type":"array"}},"additionalProperties":false,"required":["i",'
                                                    b'"dt","ri","LEI","personLegalName","engagementContextRole","t"],'
                                                    b'"type":"object"},"p":{"contains":{"type":"object"},'
                                                    b'"description":"source block","items":{"properties":{'
                                                    b'"qualifiedvLEIIssuervLEICredential":{"description":"chain to '
                                                    b'issuer credential","properties":{"d":{"type":"string"},'
                                                    b'"i":{"type":"string"}},"additionalProperties":false,'
                                                    b'"type":"object"}},"additionalProperties":false,"required":['
                                                    b'"qualifiedvLEIIssuervLEICredential"],"type":"object"},'
                                                    b'"maxItems":1,"minItems":1,"type":"array"}},'
                                                    b'"additionalProperties":false,"required":["i","s","d"],'
                                                    b'"type":"object"}',
    # GLEIFvLEICredential
    "ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc": b'{"$id":"ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc",'
                                                    b'"$schema":"http://json-schema.org/draft-07/schema#",'
                                                    b'"title":"GLEIF vLEI Credential","description":"The vLEI '
                                                    b'Credential issued to GLEIF","type":"object","properties":{"v":{'
                                                    b'"type":"string"},"d":{"type":"string"},"i":{"type":"string"},'
                                                    b'"s":{"description":"schema SAID","type":"string"},'
                                                    b'"a":{"description":"data block","properties":{"d":{'
                                                    b'"type":"string"},"i":{"type":"string"},'
                                                    b'"dt":{"description":"issuance date time","format":"date-time",'
                                                    b'"type":"string"},"ri":{"description":"credential status '
                                                    b'registry","type":"string"},"LEI":{"type":"string"},'
                                                    b'"t":{"contains":{"const":"GLEIFvLEICredential"},'
                                                    b'"type":"array"}},"additionalProperties":false,"required":["d",'
                                                    b'"dt","ri","LEI","t"],"type":"object"},"p":{"maxItems":0,'
                                                    b'"minItems":0,"type":"array"}},"additionalProperties":false,'
                                                    b'"required":["d","i"]}',
    # QualifiedvLEIIssuervLEICredential
    "E-_XCbf1LJ0v9CR7g-_gOknf5dpoZROgF7qG5T8mXCv8": b'{"$id":"E-_XCbf1LJ0v9CR7g-_gOknf5dpoZROgF7qG5T8mXCv8",'
                                                    b'"$schema":"http://json-schema.org/draft-07/schema#",'
                                                    b'"title":"Qualified vLEI Issuer Credential","description":"A '
                                                    b'vLEI Credential issued by GLEIF to Qualified vLEI Issuers which '
                                                    b'allows the Qualified vLEI Issuers to issue, verify and revoke '
                                                    b'Legal Entity vLEI Credentials and Legal Entity Official '
                                                    b'Organizational Role vLEI Credentials","properties":{"v":{'
                                                    b'"type":"string"},"d":{"type":"string"},"i":{"type":"string"},'
                                                    b'"s":{"description":"schema SAID","type":"string"},'
                                                    b'"a":{"description":"data block","properties":{"d":{'
                                                    b'"type":"string"},"i":{"type":"string"},'
                                                    b'"dt":{"description":"issuance date time","format":"date-time",'
                                                    b'"type":"string"},"ri":{"description":"credential status '
                                                    b'registry","type":"string"},"LEI":{"type":"string"},'
                                                    b'"gracePeriod":{"default":90,"type":"integer"},"t":{"contains":{'
                                                    b'"const":"QualifiedvLEIIssuervLEICredential"},"type":"array"}},'
                                                    b'"additionalProperties":false,"required":["i","dt","ri","LEI",'
                                                    b'"t"],"type":"object"},"p":{"maxItems":0,"minItems":0,'
                                                    b'"type":"array"}},"additionalProperties":false,"required":["i",'
                                                    b'"d"],"type":"object"}',
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
        except Exception:
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
        if raw:
            self.raw = raw
        elif sed:
            self.typ = typ
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
        self.typ = self._sniff(raw)
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

    @staticmethod
    def _sniff(raw):
        try:
            raw.index(b'"$schema"')
        except ValueError:
            pass
        else:
            return JSONSchema()

        # Default for now is JSONSchema because we don't support any other
        return JSONSchema()

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
        raw, kind, sed, saider = self._exhale(sed=self._sed, kind=kind)
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
