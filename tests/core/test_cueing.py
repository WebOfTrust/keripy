# -*- encoding: utf-8 -*-
"""
tests.core.test_cueing module

"""
import time
from hio.base import doing, tyming
from hio.help import decking

from keri.core import cueing


def test_funneler():

    src1 = decking.Deck()
    src2 = decking.Deck()
    src3 = decking.Deck()
    recp = decking.Deck()

    f = cueing.Funneler(srcs=[src1, src2, src3], dest=recp)

    src1.append("a1")
    src1.append("a2")
    src1.append("a3")
    src2.append("b1")
    src2.append("b2")
    src3.append("c1")
    src3.append("c2")
    src3.append("c3")
    src3.append("c4")

    f.processCues()

    assert len(recp) == 3
    assert list(recp) == ["a1", "b1", "c1"]

    for _ in range(3):
        f.processCues()

    assert len(recp) == 9
    assert list(recp) == ["a1", "b1", "c1", "a2", "b2", "c2", "a3", "c3", "c4"]
    assert len(src1) == 0
    assert len(src2) == 0
    assert len(src3) == 0

    recp.clear()
    assert len(recp) == 0

    src1.append("a1")
    src1.append("a2")
    src1.append("a3")
    src2.append("b1")
    src2.append("b2")
    src3.append("c1")
    src3.append("c2")
    src3.append("c3")
    src3.append("c4")

    limit = 0.5
    tock = 0.03125
    doist = doing.Doist(tock=tock, limit=limit, doers=[f])
    doist.enter()

    tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

    while not tymer.expired:
        doist.recur()
        time.sleep(doist.tock)

    assert doist.limit == limit
    doist.exit()

    assert len(recp) == 9
    assert list(recp) == ["a1", "b1", "c1", "a2", "b2", "c2", "a3", "c3", "c4"]
    assert len(src1) == 0
    assert len(src2) == 0
    assert len(src3) == 0


if __name__ == "__main__":
    test_funneler()
