import pytest

from keri.core.coring import Versify, Serials
from keri.kering import Version, EmptyMaterialError, DerivationError
from keri.vdr import eventing
from keri.vdr.eventing import rotate, TraitDex, issue, revoke, backer_issue, backer_revoke, Ilks, Prefixer


def test_incept():
    """
    Test incept utility function
    """

    pre = "DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM"
    bak1 = "EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"
    bak2 = "DSEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU"
    bak3 = "Dvxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"

    # no backers, allowed to add later
    serder = eventing.incept(pre, baks=[])
    assert serder.raw == (b'{"v":"KERI10JSON0000a0_","i":"E_TB9WKVB4Zx-Wu3-u1_RQWy2ZrDccaOj2xUpHQcg0MA",'
                          b'"ii":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","t":"vcp","c":[],"b":[]}')

    # no backers allowed
    serder = eventing.incept(pre, baks=[], cnfg=[TraitDex.NoBackers])
    assert serder.raw == (b'{"v":"KERI10JSON0000a4_","i":"EEDVlhKzGXA6C7n1igQF8m4WfTAEuwuvitgoM4DI3iCs",'
                          b'"ii":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","t":"vcp","c":["NB"],"b":[]}')

    # no backers allows, one attempted
    with pytest.raises(ValueError):
        eventing.incept(pre, cnfg=[TraitDex.NoBackers],
                        baks=[bak1])

    # one backer
    serder = eventing.incept(pre,
                             baks=[bak1])
    assert serder.raw == (b'{"v":"KERI10JSON0000ce_","i":"E_e9zbZI8WCMNoaY1b-3aEVB59M6dc2Br8EDJ1_ozK-8",'
                          b'"ii":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","t":"vcp","c":[],'
                          b'"b":["EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"]}')

    # 3 backers
    serder = eventing.incept(pre,
                             baks=[bak1,
                                   bak2,
                                   bak3
                                   ])
    assert serder.raw == (b'{"v":"KERI10JSON00012c_","i":"EEuFeIT3_0_IAaNg8D-5AxO6UtQCmD17n77iksL048Go",'
                          b'"ii":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","t":"vcp","c":[],'
                          b'"b":["EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc",'
                          b'"DSEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU",'
                          b'"Dvxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"]}')

    """ End Test """


def test_rotate():
    """
    Test rotate functionality

    """
    pre = "DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM"
    bak1 = "EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"
    bak2 = "DSEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU"
    bak3 = "Dvxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"

    serder = rotate(pre=pre,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    baks=[])
    assert serder.raw == (b'{"v":"KERI10JSON000099_","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",'
                          b'"ii":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"1","t":"vrt","b":[]}')

    serder = rotate(pre=pre,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=3,
                    baks=[bak1])
    assert serder.raw == (b'{"v":"KERI10JSON0000c7_","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",'
                          b'"ii":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"3","t":"vrt",'
                          b'"b":["EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"]}')

    serder = rotate(pre=pre,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=4,
                    baks=[bak1, bak2, bak3])
    assert serder.raw == (b'{"v":"KERI10JSON000125_","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",'
                          b'"ii":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"4","t":"vrt",'
                          b'"b":["EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc",'
                          b'"DSEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU",'
                          b'"Dvxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"]}')

    with pytest.raises(ValueError):
        rotate(pre=pre,
               regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
               sn=0,
               baks=[])

    """ End Test """


def test_simple_issue_revoke():
    vcdig = "DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM"
    regk = "EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw"

    serder = issue(vcdig=vcdig, regk=regk)
    assert serder.raw == (b'{"v":"KERI10JSON000092_","i":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0",'
                          b'"t":"iss","ri":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw"}')

    serder = revoke(vcdig=vcdig, regk=regk)
    assert serder.raw == (b'{"v":"KERI10JSON000092_","i":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"1",'
                          b'"t":"rev","ri":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw"}')

    """ End Test """


def test_backer_issue_revoke():
    vcdig = "DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM"
    regk = "EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw"
    sn = 3
    dig = "Ezpq06UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-PLMZ1H4"

    serder = backer_issue(vcdig=vcdig, regk=regk, regsn=sn, regd=dig)
    assert serder.raw == (b'{"v":"KERI10JSON000105_","i":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM",'
                          b'"ii":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","s":"0","t":"bis",'
                          b'"ra":{"i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","s":3,'
                          b'"d":"Ezpq06UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-PLMZ1H4"}}')

    serder = backer_revoke(vcdig=vcdig, regk=regk, regsn=sn, regd=dig)
    assert serder.raw == (b'{"v":"KERI10JSON0000d1_","i":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"1",'
                          b'"t":"rev","ra":{"i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","s":3,'
                          b'"d":"Ezpq06UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-PLMZ1H4"}}')

    """ End Test """


def test_prefixer():
    pre = "DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM"
    vs = Versify(version=Version, kind=Serials.json, size=0)

    with pytest.raises(EmptyMaterialError):
        prefixer = Prefixer()

    # vcp, backers allowed no backers
    ked = dict(v=vs,
               i="",
               ii=pre,
               s="{:x}".format(0),
               t=Ilks.vcp,
               c=[],
               b=[]
               )
    prefixer = Prefixer(ked=ked)
    assert prefixer.qb64 == "E_TB9WKVB4Zx-Wu3-u1_RQWy2ZrDccaOj2xUpHQcg0MA"
    assert prefixer.verify(ked=ked) is True
    assert prefixer.verify(ked=ked, prefixed=True) is False

    # Invalid event type
    ked = dict(v=vs,
               i="",
               ii=pre,
               s="{:x}".format(0),
               t=Ilks.iss,
               c=[],
               b=[]
               )
    with pytest.raises(DerivationError):
        prefixer = Prefixer(ked=ked)

    # vcp, no backers allowed
    ked = dict(v=vs,
               i="",
               ii=pre,
               s="{:x}".format(0),
               t=Ilks.vcp,
               c=[TraitDex.NoBackers],
               b=[]
               )
    prefixer = Prefixer(ked=ked)
    assert prefixer.qb64 == "EEDVlhKzGXA6C7n1igQF8m4WfTAEuwuvitgoM4DI3iCs"
    assert prefixer.verify(ked=ked) is True
    assert prefixer.verify(ked=ked, prefixed=True) is False

    bak1 = "EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"
    bak2 = "DSEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU"
    bak3 = "Dvxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"

    # vcp, one backer
    ked = dict(v=vs,
               i="",
               ii=pre,
               s="{:x}".format(0),
               t=Ilks.vcp,
               c=[],
               b=[bak1]
               )
    prefixer = Prefixer(ked=ked)
    assert prefixer.qb64 == "E_e9zbZI8WCMNoaY1b-3aEVB59M6dc2Br8EDJ1_ozK-8"
    assert prefixer.verify(ked=ked) is True
    assert prefixer.verify(ked=ked, prefixed=True) is False

    # vcp, many backers
    ked = dict(v=vs,
               i="",
               ii=pre,
               s="{:x}".format(0),
               t=Ilks.vcp,
               c=[],
               b=[bak1, bak2, bak3]
               )
    prefixer = Prefixer(ked=ked)
    assert prefixer.qb64 == "EEuFeIT3_0_IAaNg8D-5AxO6UtQCmD17n77iksL048Go"
    assert prefixer.verify(ked=ked) is True
    assert prefixer.verify(ked=ked, prefixed=True) is False

    """ End Test """


if __name__ == "__main__":
    test_prefixer()
