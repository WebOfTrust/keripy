# -*- encoding: utf-8 -*-
"""
tests.acdc.test_registering module

"""

from keri.acdc import messaging
from keri.acdc.registering import RegistryStore
from keri.acdc.regbasing import RegBaser
from keri.core import Diger
from keri.db import openLMDB


def test_registry_store_clone_tel():
    """Accepted TEL events dump as a contiguous CESR stream keyed by registry SAID."""
    with openLMDB(cls=RegBaser, name="test-clone-tel", temp=True) as baser:
        store = RegistryStore(baser)
        issuer = "EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ"
        stamp = "2020-08-22T17:50:09.988921+00:00"
        rip = messaging.regcept(
            israid=issuer,
            uuid="0AAxyHwW6htOZ_rANOaZb2N2",
            stamp=stamp,
        )
        blid = Diger(ser=b"clone-tel-blid").qb64
        bup = messaging.blindate(
            regid=rip.said,
            prior=rip.said,
            blid=blid,
            sn=1,
            stamp=stamp,
        )

        store.accept(rip.said, 0, rip)
        store.accept(rip.said, 1, bup)

        assert list(store.cloneTelIter(rip.said)) == [bytes(rip.raw), bytes(bup.raw)]
        assert store.cloneTel(rip.said) == bytes(rip.raw) + bytes(bup.raw)
        assert store.cloneTel(rip.said, sn=1) == bytes(bup.raw)
        assert store.cloneTel(rip.said, sn=2) == b""
        assert store.cloneTel("EunknownRegistrySaidxxxxxxxxxxxxxx") == b""
