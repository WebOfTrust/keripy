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
from .coring import MtrDex, Serials, Saider, Saids
from .. import help, kering
from ..kering import ValidationError, DeserializeError

logger = help.ogler.getLogger()


class CacheResolver:
    """ Sample jsonschema resolver for loading schema $ref references from a local hash.

    """

    def __init__(self, db):
        """ Create a jsonschema resolver that can be used for loading references to schema remotely.

        Parameters:
            db (Baser) is a database instance to store and retrieve json schema SADs

        """
        self.db = db

    def add(self, key, schema):
        """ Add schema to cache for resolution

        Parameters:
            key (str): URI to resolve to the schema
            schema (bytes): is bytes of the schema for the URI
        """
        schemer = Schemer(raw=schema)
        if schemer.said != key:
            return

        self.db.schema.pin(key, schemer)

    def resolve(self, uri):
        schemer = self.db.schema.get(uri)
        if schemer is None:
            return None
        return schemer.raw

    def handler(self, uri):
        """ Handler provided to jsonschema for cache resolution

        Parameters:
            uri (str): the URI to resolve
        """
        try:
            idx = uri.rindex(":")
            key = uri[idx+1:]
        except ValueError:
            key = uri

        schemer = self.db.schema.get(key)
        if not schemer:
            return None

        return schemer.sed

    def resolver(self, scer=b''):
        """ Locally cached schema resolver

        Returns a jsonschema resolver for returning locally cached schema based on self-addressing
        identifier URIs.

        Parameters:
            scer (Optional(bytes)) is the source document that is being processed for reference resolution

        """
        return jsonschema.RefResolver("", scer, handlers={"did": self.handler})


class JSONSchema:
    """ JSON Schema support class
    """
    id_ = Saids.dollar  # ID Field Label

    def __init__(self, resolver=None):
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
        if self.resolver is None:
            return None

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
                raise DeserializeError("Error deserializing JSON: {} {}"
                                           "".format(raw.decode("utf-8"), ex))

        elif kind == Serials.mgpk:
            try:
                sed = msgpack.loads(raw)
            except Exception as ex:
                raise DeserializeError("Error deserializing MGPK: {} {}"
                                           "".format(raw, ex))

        elif kind == Serials.cbor:
            try:
                sed = cbor.loads(raw)
            except Exception as ex:
                raise DeserializeError("Error deserializing CBOR: {} {}"
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
            kwargs = dict()
            if self.resolver is not None:
                kwargs["resolver"] = self.resolver.resolver(scer=raw)
            jsonschema.validate(instance=d, schema=schema, **kwargs)
        except jsonschema.exceptions.ValidationError as ex:
            raise kering.ValidationError(f'Credential validation exception: {ex}')
        except jsonschema.exceptions.SchemaError as ex:
            raise kering.ValidationError(f'Schema exception: {ex}')
        except json.decoder.JSONDecodeError as ex:
            raise kering.ValidationError(f"Credential JSON exception: {ex}")
        except Exception as ex:
            raise kering.ValidationError(f"Credential Exception: {ex}")

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
        When serializing if kind provided then use kind instead of field in sed

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
        self._saider = Saider(raw=self._raw, code=self._code, label=Saids.dollar)

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

    def pretty(self, *, size=1024):
        """
        Returns str JSON of .sed with pretty formatting

        ToDo: add default size limit on pretty when used for syslog UDP MCU
        like 1024 for ogler.logger
        """
        return json.dumps(self.sed, indent=1)[:size if size is not None else None]

    def _verify_schema(self):
        """
        Returns True if derivation from ked for .code matches .qb64 and
                If prefixed also verifies ked["i"] matches .qb64
                False otherwise

        """

        return self.typ.verify_schema(schema=self.sed)
