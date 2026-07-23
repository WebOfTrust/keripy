# -*- encoding: utf-8 -*-
"""
tests.acdc.test_regbasing module

"""

import os

from keri.acdc import messaging, regbasing
from keri.core import coring, serdering
from keri.db import openLMDB, subing


def test_regbaser_store_contract():
    """Test the native six-store registry database contract."""
    with openLMDB(cls=regbasing.RegBaser,
                  name="test-regbaser", temp=True) as baser:
        assert isinstance(baser, regbasing.RegBaser)
        assert baser.opened
        assert baser.TailDirPath == os.path.join("keri", "acdc", "reg")
        assert any(
            part.startswith(baser.TempPrefix)
            for part in baser.path.split(os.path.sep)
        )

        assert isinstance(baser.evts, subing.SerderSuber)
        assert baser.evts.klas is serdering.SerderACDC
        assert isinstance(baser.ancs, subing.CatCesrSuber)
        assert baser.ancs.klas == (coring.Number, coring.Diger)
        assert isinstance(baser.tels, subing.CesrOnSuber)
        assert baser.tels.klas is coring.Saider
        assert isinstance(baser.heads, subing.CesrSuber)
        assert baser.heads.klas is coring.Saider
        assert isinstance(baser.maes, subing.B64OnIoSetSuber)
        assert isinstance(baser.ooes, subing.B64OnIoSetSuber)

        for name in ("evts", "ancs", "tels", "heads", "maes", "ooes"):
            assert getattr(baser, name).sdb.flags()["dupsort"] is False

        issuer = "EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ"
        serder = messaging.regcept(
            israid=issuer,
            uuid="0AAxyHwW6htOZ_rANOaZb2N2",
            stamp="2020-08-22T17:50:09.988921+00:00",
        )
        saider = coring.Saider(qb64=serder.said)
        source = (coring.Number(num=3), coring.Diger(qb64=serder.said))

        assert baser.evts.put(keys=serder.said, val=serder)
        assert baser.ancs.put(keys=serder.said, val=source)
        assert baser.tels.put(keys=serder.said, on=0, val=saider)
        assert baser.heads.put(keys=serder.said, val=saider)
        assert baser.maes.add(keys=serder.said, on=1, val=serder.said)
        assert baser.ooes.add(keys=serder.said, on=1, val=serder.said)

        assert baser.evts.get(keys=serder.said).raw == serder.raw
        assert baser.ancs.get(keys=serder.said)[0].num == 3
        assert baser.ancs.get(keys=serder.said)[1].qb64 == serder.said
        assert baser.tels.get(keys=serder.said, on=0).qb64 == serder.said
        assert baser.heads.get(keys=serder.said).qb64 == serder.said
        assert baser.maes.get(keys=serder.said, on=1) == [(serder.said,)]
        assert baser.ooes.get(keys=serder.said, on=1) == [(serder.said,)]

    assert baser.opened is False
