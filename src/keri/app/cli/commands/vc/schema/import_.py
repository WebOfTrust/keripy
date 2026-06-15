# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.vc.schema.import_ module

"""
import argparse

from hio.base import doing

from keri import help, kering
from keri.app.cli.common import existing
from keri.core import scheming
from keri.core.scheming import Schemer
from keri.db.subing import SchemerSuber

logger = help.ogler.getLogger()

importParser = argparse.ArgumentParser(description="Import ACDC JSON schema file into the schema database")
importParser.set_defaults(handler=lambda args: import_schema(args),
                          transferable=True)
importParser.add_argument("--name", "-n", help="keystore name and file location of KERI keystore", required=True)
importParser.add_argument("--base", "-b", help="additional optional prefix to file location of KERI keystore",
                          required=False, default="")
importParser.add_argument("--passcode", "-p", help="21 character encryption passcode for keystore (is not saved)",
                          dest="bran", default=None)
importParser.add_argument("--schema", "-s", help="path to ACDC JSON schema file to import", required=True)


def import_schema(args):
    """Command line handler for importing ACDC JSON schema files."""
    idoer = ImportDoer(name=args.name,
                       base=args.base,
                       bran=args.bran,
                       schema=args.schema)
    return [idoer]

def importSchema(schemerSuber: SchemerSuber, path: str):
    """
    Imports a schema file from a given path to a provided schema DB.
    """
    try:
        with open(path, "rb") as f:
            raw = f.read()
        schemer = Schemer(raw=raw)
        schemerSuber.pin(keys=(schemer.said,), val=schemer)
        return schemer.said
    except FileNotFoundError:
        raise kering.ConfigurationError(f"Schema file not found: {path}")
    except kering.DeserializeError as ex:
        raise kering.ConfigurationError(f"Invalid JSON in schema file: {ex}") from ex
    except kering.ValidationError as ex:
        raise kering.ConfigurationError(f"Schema validation failed: {ex}") from ex
    except ValueError as ex:
        raise kering.ConfigurationError(f"Error importing schema: {ex}") from ex

class ImportDoer(doing.DoDoer):
    """DoDoer that imports one ACDC JSON schema into an existing Habery."""

    def __init__(self, name, base, bran, schema, **kwa):
        self.schemaPath = schema
        self.hby = existing.setupHby(name=name, base=base, bran=bran)

        doers = [doing.doify(self.importDo)]
        super(ImportDoer, self).__init__(doers=doers, **kwa)

    def importDo(self, tymth, tock=0.0, **kwa):
        """Import ACDC JSON schema file into the schema database."""
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        said = importSchema(self.hby.db.schema, self.schemaPath)
        print(f"Schema successfully imported with SAID: {said}")

