from keri.app.cli.common import grouping
from keri.core import coring


def test_digest_ungrouping():
    dig1 = "ECTCqZ6lS49I_57nQ0IYHifKJ7c1KByj45BVdfVrd0zw"
    dig2 = "ED2dtv5eDcmW-jHJ3hyO-t5vSVSPS_x8bofBwE7Chtvo"
    dig3 = "EyAWI-dDzLrTWPN9dOiEP833JG3ilueLRmHudceu9zgY"

    tholder = coring.Tholder(sith="1")
    digs = [dig1, dig2, dig3]

    msdigers = []
    for dig in digs:
        nexter = coring.Nexter(qb64=dig)

        dig = grouping.extractDig(nexter, tholder)
        msdigers.append(dig)


    nxt = coring.Nexter(sith="3", digs=[diger.qb64 for diger in msdigers]).qb64
    assert nxt == "EQL9rtA6EKES8Ig4GEfabNtd7DTvt0_-jp230QhBeaXA"
