from keri.app import keeping, habbing
from keri.db import basing


def openHabitat(name="test"):
    ks = keeping.Keeper(name=name, temp=False)  # not opened by default, doer opens
    ksDoer = keeping.KeeperDoer(keeper=ks)  # doer do reopens if not opened and closes
    db = basing.Baser(name=name, temp=False, reload=True)  # not opened by default, doer opens
    dbDoer = basing.BaserDoer(baser=db)  # doer do reopens if not opened and closes

    # setup habitat
    hab = habbing.Habitat(name=name, ks=ks, db=db, temp=False, create=False)
    habDoer = habbing.HabitatDoer(habitat=hab)  # setup doer

    doers = [ksDoer, dbDoer, habDoer]

    return hab, doers
