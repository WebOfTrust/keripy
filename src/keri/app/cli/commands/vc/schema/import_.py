# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.vc.schema module

"""
import argparse
import json

from hio.base import doing

from ...... import help, kering
from ....common import existing
from ......core import scheming

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Import ACDC JSON schema file into the schema database')
parser.set_defaults(handler=lambda args: import_schema(args))
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--schema', '-s', help='path to ACDC JSON schema file to import', required=True)


def import_schema(args):
    """ Command line handler for importing ACDC JSON schema files

    """
    idoer = ImportDoer(name=args.name,
                       base=args.base,
                       bran=args.bran,
                       schema=args.schema)
    return [idoer]


class ImportDoer(doing.DoDoer):

    def __init__(self, name, base, bran, schema):
        self.schemaPath = schema
        self.hby = existing.setupHby(name=name, base=base, bran=bran)

        doers = [doing.doify(self.importDo)]

        super(ImportDoer, self).__init__(doers=doers)

    def importDo(self, tymth, tock=0.0, **kwa):
        """ Import ACDC JSON schema file into the schema database

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Returns:  doifiable Doist compatible generator method

        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        try:
            # Read the schema file
            with open(self.schemaPath, 'rb') as f:
                raw = f.read()

            # Create Schemer instance which validates the schema
            schemer = scheming.Schemer(raw=raw)

            # Store the schema in the database
            self.hby.db.schema.pin(keys=(schemer.said,), val=schemer)

            print(f"Schema successfully imported with SAID: {schemer.said}")

        except FileNotFoundError:
            raise kering.ConfigurationError(f"Schema file not found: {self.schemaPath}")
        except json.JSONDecodeError as e:
            raise kering.ConfigurationError(f"Invalid JSON in schema file: {e}")
        except kering.ValidationError as e:
            raise kering.ConfigurationError(f"Schema validation failed: {e}")
        except Exception as e:
            raise kering.ConfigurationError(f"Error importing schema: {e}")
