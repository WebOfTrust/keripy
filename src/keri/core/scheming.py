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

QualifiedVLEIIssuerVLEICredential = "ESAItgWbOyCvcNAqkJFBZqxG2-h69fOkw7Rzk0gAqkqo"


class CacheResolver:
    """ Sample jsonschema resolver for loading schema $ref references from a local hash.

    """

    def __init__(self, cache=None):
        """ Create a jsonschema resolver that can be used for loading references to schema remotely.

        Parameters:
            cache (Optional(dict)) is an optional pre-loaded cache of schema
        """
        self.cache = cache if cache is not None else dict()

    def add(self, key, schema):
        """ Add schema to cache for resolution

        Parameters:
            key (str): URI to resolve to the schema
            schema (bytes): is bytes of the schema for the URI
        """
        self.cache[key] = schema

    def resolve(self, uri):
        if uri not in self.cache:
            return None

        ref = self.cache[uri]
        return ref

    def handler(self, uri):
        """ Handler provided to jsonschema for cache resolution

        Parameters:
            uri (str): the URI to resolve
        """
        ref = self.resolve(uri)
        if not ref:
            return None

        schemr = Schemer(raw=ref)
        return schemr.sed

    def resolver(self, scer=b''):
        """ Locally cached schema resolver

        Returns a jsonschema resolver for returning locally cached schema based on self-addressing
        identifier URIs.

        Parameters:
            scer (Optional(bytes)) is the source document that is being processed for reference resolution

        """
        return jsonschema.RefResolver("", scer, handlers={"did": self.handler})


jsonSchemaCache = CacheResolver(cache={
    "EHjnQDFqeaAOYsg8Aa-L3ugPZYA5LvNArunSntXzERns": b'{"$id":"EHjnQDFqeaAOYsg8Aa-L3ugPZYA5LvNArunSntXzERns",'
                                                    b'"$schema":"http://json-schema.org/draft-07/schema#",'
                                                    b'"title":"Legal Entity Official Organizational Role vLEI '
                                                    b'Credential","description":"A vLEI Role Credential issued by a '
                                                    b'Qualified vLEI issuer to official representatives of a Legal '
                                                    b'Entity",'
                                                    b'"credentialType":"LegalEntityOfficialOrganizationalRolevLEICreden'
                                                    b'tial","properties":{"v":{"type":"string"},'
                                                    b'"d":{"type":"string"},"i":{"type":"string"},'
                                                    b'"s":{"description":"schema SAID","type":"string"},'
                                                    b'"a":{"description":"data block","properties":{"d":{'
                                                    b'"type":"string"},"i":{"type":"string"},'
                                                    b'"dt":{"description":"issuance date time","format":"date-time",'
                                                    b'"type":"string"},"ri":{"description":"credential status '
                                                    b'registry","type":"string"},"LEI":{"type":"string"},'
                                                    b'"personLegalName":{"type":"string"},"officialRole":{'
                                                    b'"type":"string"}},"additionalProperties":false,"required":["i",'
                                                    b'"dt","ri","LEI","personLegalName","officialRole"],'
                                                    b'"type":"object"},"p":{"contains":{"type":"object"},'
                                                    b'"description":"source block","items":{"properties":{'
                                                    b'"legalEntityvLEICredential":{"description":"chain to issuer '
                                                    b'credential","properties":{"d":{"type":"string"},'
                                                    b'"i":{"type":"string"}},"additionalProperties":false,'
                                                    b'"type":"object"}},"additionalProperties":false,"required":['
                                                    b'"legalEntityvLEICredential"],"type":"object"},"maxItems":1,'
                                                    b'"minItems":1,"type":"array"},"r":{"contains":{"type":"object"},'
                                                    b'"description":"rules block","type":"array"}},'
                                                    b'"additionalProperties":false,"required":["i","s","d","r"],'
                                                    b'"type":"object"}',
    "EYKd_PUuCGvoMfTu6X3NZrLKl1LsvFN60M-P23ZTiKQ0": b'{"$id":"EYKd_PUuCGvoMfTu6X3NZrLKl1LsvFN60M-P23ZTiKQ0",'
                                                    b'"$schema":"http://json-schema.org/draft-07/schema#",'
                                                    b'"title":"Legal Entity vLEI Credential","description":"A vLEI '
                                                    b'Credential issued by a Qualified vLEI issuer to a Legal '
                                                    b'Entity","credentialType":"LegalEntityvLEICredential",'
                                                    b'"properties":{"v":{"type":"string"},"d":{"type":"string"},'
                                                    b'"i":{"type":"string"},"s":{"description":"schema SAID",'
                                                    b'"type":"string"},"a":{"description":"data block","properties":{'
                                                    b'"d":{"type":"string"},"i":{"type":"string"},'
                                                    b'"dt":{"description":"issuance date time","format":"date-time",'
                                                    b'"type":"string"},"ri":{"description":"credential status '
                                                    b'registry","type":"string"},"LEI":{"type":"string"}},'
                                                    b'"additionalProperties":false,"required":["i","dt","ri","LEI"],'
                                                    b'"type":"object"},"p":{"contains":{"type":"object"},'
                                                    b'"description":"source block","items":{"properties":{'
                                                    b'"qualifiedvLEIIssuervLEICredential":{"description":"chain to '
                                                    b'issuer credential","properties":{"d":{"type":"string"},'
                                                    b'"i":{"type":"string"}},"additionalProperties":false,'
                                                    b'"type":"object"}},"additionalProperties":false,"required":['
                                                    b'"qualifiedvLEIIssuervLEICredential"],"type":"object"},'
                                                    b'"maxItems":1,"minItems":1,"type":"array"},"r":{"contains":{'
                                                    b'"type":"object"},"description":"rules block","type":"array"}},'
                                                    b'"additionalProperties":false,"required":["i","s","d","r"],'
                                                    b'"type":"object"}',
    "EvaAd8yXN6HhHdxAQ7i_b1CGi-O6OZusI_xeVjs_olZ0": b'{"$id":"EvaAd8yXN6HhHdxAQ7i_b1CGi-O6OZusI_xeVjs_olZ0",'
                                                    b'"$schema":"http://json-schema.org/draft-07/schema#",'
                                                    b'"title":"Legal Entity Engagement Context Role vLEI Credential",'
                                                    b'"description":"A vLEI Role Credential issued to representatives '
                                                    b'of a Legal Entity in other than official roles but in '
                                                    b'functional or other context of engagement",'
                                                    b'"credentialType":"LegalEntityEngagementContextRolevLEICredential",'
                                                    b'"properties":{"v":{"type":"string"},"d":{"type":"string"},'
                                                    b'"i":{"type":"string"},"s":{"description":"schema SAID",'
                                                    b'"type":"string"},"n":{"description":"one time use nonce",'
                                                    b'"type":"string"},"a":{"description":"data block","properties":{'
                                                    b'"d":{"type":"string"},"i":{"type":"string"},'
                                                    b'"dt":{"description":"issuance date time","format":"date-time",'
                                                    b'"type":"string"},"ri":{"description":"credential status '
                                                    b'registry","type":"string"},"LEI":{"type":"string"},'
                                                    b'"personLegalName":{"type":"string"},"engagementContextRole":{'
                                                    b'"type":"string"}},"additionalProperties":false,"required":["i",'
                                                    b'"dt","ri","LEI","personLegalName","engagementContextRole"],'
                                                    b'"type":"object"},"p":{"contains":{"type":"object"},'
                                                    b'"description":"source block","items":{"properties":{'
                                                    b'"legalEntityvLEICredential":{"description":"chain to issuer '
                                                    b'credential","properties":{"d":{"type":"string"},'
                                                    b'"i":{"type":"string"}},"additionalProperties":false,'
                                                    b'"type":"object"}},"additionalProperties":false,"required":['
                                                    b'"legalEntityvLEICredential"],"type":"object"},"maxItems":1,'
                                                    b'"minItems":1,"type":"array"},"r":{"contains":{"type":"object"},'
                                                    b'"description":"rules block","type":"array"}},'
                                                    b'"additionalProperties":false,"required":["v","i","s","d","r",'
                                                    b'"a"],"type":"object"}',
    "EIZPo6FxMZvZkX-463o9Og3a2NEKEJa-E9J5BXOsdpVg": b'{"$id":"EIZPo6FxMZvZkX-463o9Og3a2NEKEJa-E9J5BXOsdpVg",'
                                                    b'"$schema":"http://json-schema.org/draft-07/schema#",'
                                                    b'"title":"GLEIF vLEI Credential","description":"The vLEI '
                                                    b'Credential issued to GLEIF",'
                                                    b'"credentialType":"GLEIFvLEICredential","type":"object",'
                                                    b'"properties":{"v":{"type":"string"},"d":{"type":"string"},'
                                                    b'"i":{"type":"string"},"s":{"description":"schema SAID",'
                                                    b'"type":"string"},"a":{"description":"data block","properties":{'
                                                    b'"d":{"type":"string"},"i":{"type":"string"},'
                                                    b'"dt":{"description":"issuance date time","format":"date-time",'
                                                    b'"type":"string"},"ri":{"description":"credential status '
                                                    b'registry","type":"string"},"LEI":{"type":"string"}},'
                                                    b'"additionalProperties":false,"required":["d","dt","ri","LEI"],'
                                                    b'"type":"object"},"p":{"maxItems":0,"minItems":0,'
                                                    b'"type":"array"}},"additionalProperties":false,"required":["d",'
                                                    b'"i"]}',
    "ESAItgWbOyCvcNAqkJFBZqxG2-h69fOkw7Rzk0gAqkqo": b'{"$id":"ESAItgWbOyCvcNAqkJFBZqxG2-h69fOkw7Rzk0gAqkqo",'
                                                    b'"$schema":"http://json-schema.org/draft-07/schema#",'
                                                    b'"title":"Qualified vLEI Issuer Credential","description":"A '
                                                    b'vLEI Credential issued by GLEIF to Qualified vLEI Issuers which '
                                                    b'allows the Qualified vLEI Issuers to issue, verify and revoke '
                                                    b'Legal Entity vLEI Credentials and Legal Entity Official '
                                                    b'Organizational Role vLEI Credentials",'
                                                    b'"credentialType":"QualifiedvLEIIssuervLEICredential",'
                                                    b'"properties":{"v":{"type":"string"},"d":{"type":"string"},'
                                                    b'"i":{"type":"string"},"s":{"description":"schema SAID",'
                                                    b'"type":"string"},"a":{"description":"data block","properties":{'
                                                    b'"d":{"type":"string"},"i":{"type":"string"},'
                                                    b'"dt":{"description":"issuance date time","format":"date-time",'
                                                    b'"type":"string"},"ri":{"description":"credential status '
                                                    b'registry","type":"string"},"LEI":{"type":"string"},'
                                                    b'"gracePeriod":{"default":90,"type":"integer"}},'
                                                    b'"additionalProperties":false,"required":["i","dt","ri","LEI"],'
                                                    b'"type":"object"},"p":{"maxItems":0,"minItems":0,'
                                                    b'"type":"array"}},"additionalProperties":false,"required":["i",'
                                                    b'"d"],"type":"object"}',
})


class JSONSchema:
    """ JSON Schema support class
    """
    id_ = Ids.dollar  # ID Field Label

    def __init__(self, resolver=CacheResolver()):
        """ Initialize instance

        Parameters:
            resolver(Optional(Resolver)): instance used by JSONSchema parsing to resolve external refs

        """
        self.resolver = resolver

    def resolve(self, uri):
        """ Resolve remote reference to schema

        Parameters:
            uri (str): uniform resource identifier of schema to load

        """
        return self.resolver.resolve(uri)

    def load(self, raw, kind=Serials.json):
        """ Schema loader

        Loads schema based on kind by performing deserialization on raw bytes of schema

        Parameters:
            raw (bytes): raw serialized schema
            kind (Optional(Serials)): serialization kind of schema raw content

        Returns:
            tuple: (dict, Serials, Saider) of schema

        """
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
        """ Serailize schema based on kind

        Parameters:
            sed (dict): in memory representation of schema
            kind (Optional(Serials)): kind of serialization to perform.  Defaults to JSON

        Returns:
            bytes: Serialized schema

        """
        raw = coring.dumps(sed, kind)
        return raw

    @staticmethod
    def detect(raw):
        """ Detect if raw content is JSON Schema

        Parameters:
            raw (bytes): data to check for JSON Schema

        Returns:
            boolean: True if content represents JSON Schema by checking
                    for $schema;  False otherwise

        """

        try:
            raw.index(b'"$schema"')
        except ValueError:
            return False

        return True

    @staticmethod
    def verify_schema(schema):
        """ Validate schema integrity

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
        """ Verify the raw content against the schema for JSON that conforms to the schema

        Parameters:
            schema (bytes): is the schema use for validation
            raw (bytes): is JSON to validate against the Schema

        Returns:
            boolean: True if the JSON passes validation against the
                   provided complaint Draft 7 JSON Schema.  Returns False
                   if raw is not valid JSON, schema is not valid JSON Schema or
                   the validation fails
        """
        try:
            d = json.loads(raw)
            jsonschema.validate(instance=d, schema=schema, resolver=self.resolver.resolver(scer=raw))
        except jsonschema.exceptions.ValidationError as ex:
            print(ex)
            logger.error(f'jsonschema.exceptions.ValidationError {ex}')
            return False
        except jsonschema.exceptions.SchemaError as ex:
            print(ex)
            logger.error(f'jsonschema.exceptions.SchemaError {ex}')
            return False
        except json.decoder.JSONDecodeError as ex:
            print(ex)
            logger.error(f'json.decoder.JSONDecodeError {ex}')
            return False
        except Exception:
            return False

        return True


class Schemer:
    """ Schemer is KERI schema serializer-deserializer class

    Verifies self-addressing identifier base on schema type
    Only supports current version VERSION

    Has the following public properties:

    Properties:
        .raw (bytes): of serialized event only
        .sed (dict): schema dict
        .kind (Schema): kind string value (see namedtuple coring.Serials)
        .saider (Saider): instance of self-addressing identifier
        .said  (qb64): digest from .saider

    Hidden Attributes:
          ._raw (bytes): of serialized schema only
          ._sed (JSON): schema dict
          ._kind (schema): kind string value (see namedtuple coring.Serials)
            supported kinds are 'JSONSchema'
          ._code (default): code for .saider
          ._saider (Saider): instance of digest of .raw


    """

    def __init__(self, raw=b'', sed=None, kind=None, typ=JSONSchema(), code=MtrDex.Blake3_256):
        """  Initialize instance of Schemer

        Deserialize if raw provided
        Serialize if sed provided but not raw
        When serilaizing if kind provided then use kind instead of field in sed

        Parameters:
          raw (bytes): of serialized schema
          sed (dict): dict or None
            if None its deserialized from raw
          typ (JSONSchema): type of schema
          kind (serialization): kind string value or None (see namedtuple coring.Serials)
            supported kinds are 'json', 'cbor', 'msgpack', 'binary'
            if kind (None): then its extracted from ked or raw
          code (MtrDex): default digest code

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
        """ Dumps type specific Schema JSON and returns the raw bytes, sed and schema kind

        Parameters:
            sed: (dict): JSON to load
            kind (Schema) tuple of schema type

        """
        saider = Saider(sad=sed, code=self._code, label=self.typ.id_)
        sed[self.typ.id_] = saider.qb64
        raw = self.typ.dump(sed)

        return raw, sed, kind, saider

    @staticmethod
    def _sniff(raw):
        """ Determine type of schema from raw bytes

        Parameters:
            raw (bytes): serialized schema

        """
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
