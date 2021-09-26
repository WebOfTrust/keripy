import json

from keri.app import habbing, delegating, keeping
from keri.db import basing


def test_delegating():
    # delegator
    with habbing.openHab(name="del", salt=b'0123456789abcdef', transferable=True, temp=True) as delHab:
        assert delHab.pre == "E5R24em6RjYzygDkAqM2Sr3cYkFJIObwxc7bvJ68w0rU"

        # delegatee
        ks = keeping.Keeper(name="deb", temp=True)
        ks.reopen()
        db = basing.Baser(name="deb", temp=True)
        db.reopen()

        delegatey = delegating.Delegatey(db=db, ks=ks)
        msg = dict(
            delpre="E5R24em6RjYzygDkAqM2Sr3cYkFJIObwxc7bvJ68w0rU",
            salt="0123456789abcdef",
            transferable=True,
            icount=1,
            ncount=1,
            isith=1,
            nsith=1,
        )
        delegatey.processMessage(msg)

        print(delegatey.posts[0])
        print(delegatey.posts[0]["srdr"].pretty())

        delsrdr = delegatey.posts[0]["srdr"]
        assert delsrdr.ked["t"] == "dip"
        assert delsrdr.ked["i"] == "EF9yk0lgzGXTJxDLmJitz07EUwdOrBghWUYamcQLlISw"
        assert delsrdr.ked["di"] == "E5R24em6RjYzygDkAqM2Sr3cYkFJIObwxc7bvJ68w0rU"
        # assert delegatey.posts[0]["srdr"].pre == []
