import importlib
import sys

from keri.core import coring

MIGRATIONS = ["rekey_habs"]


class Migrator:

    def __init__(self, db):
        self.db = db

    def migrate(self):
        for migration in MIGRATIONS:
            if self.db.migs.get(keys=(migration,)) is not None:
                continue

            modName = f"keri.db.migrations.{migration}"
            mod = importlib.import_module(modName)
            try:
                sys.stdout.write(f"Running migration {modName}... ")
                mod.migrate(self.db)
                print("done.")
            except Exception as e:
                print(f"Abandoning migratoin {migration} with error: {e}")
                return

            self.db.migs.pin(keys=(migration,), val=coring.Dater())

    def current(self):
        return self.db.migs.get(MIGRATIONS[-1]) is not None

    def complete(self, name=None):
        migrations = []
        if not name:
            for mig in MIGRATIONS:
                dater = self.db.migs.get(keys=(mig,))
                migrations.append((mig, dater))
        else:
            if name not in MIGRATIONS:
                raise ValueError(f"No migration named {name}")
            migrations.append((name, self.db.migs.get(keys=(name,))))

        return migrations
