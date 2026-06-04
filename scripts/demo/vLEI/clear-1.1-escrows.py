#!/usr/bin/env python3
"""Empty 1.1.x escrow sub-dbs that 1.2.x cannot parse.

1.1.x stores `pdes` as a plain LMDB sub-db keyed `<prefix>.<digest>`. 1.2.7
re-types it as an `OnIoDupSuber` whose reader splits the key on `.` and runs
`int(suffix, 16)` — which crashes on the qb64 digest. After 1.1.x has fully
anchored a delegated event there is no reason to keep the residue, so we
drop the sub-db contents before handing the keystore to 1.2.x.

Usage: clear-1.1-escrows.py <keystore-name>
"""
import sys

# Trigger keri package init in the order kli uses to avoid the
# keri.db.basing <-> keri.core.eventing circular import that fires when
# basing is imported before app.
from keri.app import habbing  # noqa: F401
from keri.db import basing


def main(name: str) -> None:
    db = basing.Baser(name=name, base="", temp=False, reopen=False)
    db.reopen()
    try:
        with db.env.begin(write=True) as txn:
            for sdb in (db.pdes, db.pses, db.pwes, db.uwes, db.ooes, db.ldes, db.qnfs):
                txn.drop(sdb, delete=False)
    finally:
        db.close()
    print(f"Cleared 1.1.x escrows for {name}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: clear-1.1-escrows.py <keystore-name>")
    main(sys.argv[1])
