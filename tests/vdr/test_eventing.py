# -*- encoding: utf-8 -*-
"""
tests.vdr.eventing module

"""
import pytest

from keri.app import habbing, keeping
from keri.core import coring
from keri.core import eventing as keventing
from keri.core.coring import versify, Serials, Ilks, MtrDex, Prefixer, Serder, Signer, Seqner
from keri.db import basing
from keri.db.dbing import snKey, dgKey
from keri.kering import Version, EmptyMaterialError, DerivationError, MissingAnchorError, ValidationError, \
    MissingWitnessSignatureError, LikelyDuplicitousError
from keri.vdr import eventing, viring
from keri.vdr.eventing import rotate, issue, revoke, backerIssue, backerRevoke, Tever, Tevery


def test_incept(mockCoringRandomNonce):
    """
    Test incept utility function
    """

    pre = "DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM"
    bak1 = "EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"
    bak2 = "DSEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU"
    bak3 = "Dvxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"

    # no backers, allowed to add later
    serder = eventing.incept(pre, baks=[], code=MtrDex.Blake3_256)
    assert serder.raw == (b'{"v":"KERI10JSON00010f_","t":"vcp","d":"ECqB8xnRxq6gEdJTx6i139PWFx1SxKrj9vrD'
                          b'T6K8SmoI","i":"ECqB8xnRxq6gEdJTx6i139PWFx1SxKrj9vrDT6K8SmoI","ii":"DntNTPnDF'
                          b'BnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","c":[],"bt":"0","b":[],"n":"A9X'
                          b'fpxIl1LcIkMhUSCCC8fgvkuX8gG9xK3SM-S8a8Y_U"}')

    # no backers allowed
    serder = eventing.incept(pre, baks=[], cnfg=[keventing.TraitDex.NoBackers], code=MtrDex.Blake3_256)
    assert serder.raw == (b'{"v":"KERI10JSON000113_","t":"vcp","d":"Eq_gOwuCGVGsSZ7jyjwCXLUMAqtFy3weHtiQ'
                          b'idn3ES4s","i":"Eq_gOwuCGVGsSZ7jyjwCXLUMAqtFy3weHtiQidn3ES4s","ii":"DntNTPnDF'
                          b'BnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","c":["NB"],"bt":"0","b":[],"n":'
                          b'"A9XfpxIl1LcIkMhUSCCC8fgvkuX8gG9xK3SM-S8a8Y_U"}')

    # no backers allows, one attempted
    with pytest.raises(ValueError):
        eventing.incept(pre, cnfg=[keventing.TraitDex.NoBackers],
                        baks=[bak1])

    # with backer dupes
    with pytest.raises(ValueError):
        eventing.incept(pre, cnfg=[],
                        baks=[bak1, bak1, bak2])

    # with oob toad
    with pytest.raises(ValueError):
        eventing.incept(pre, cnfg=[], toad=4,
                        baks=[bak1, bak2, bak3])

    # with oob toad
    with pytest.raises(ValueError):
        eventing.incept(pre, cnfg=[], toad=1,
                        baks=[])

    # one backer
    serder = eventing.incept(pre,
                             baks=[bak1],
                             code=MtrDex.Blake3_256)
    assert serder.raw == (b'{"v":"KERI10JSON00013d_","t":"vcp","d":"EPZ5YaOGsME24nrC1mSanqNAvfdlu86eUSCT'
                          b'LAN-VlYY","i":"EPZ5YaOGsME24nrC1mSanqNAvfdlu86eUSCTLAN-VlYY","ii":"DntNTPnDF'
                          b'BnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","c":[],"bt":"1","b":["EXvR3p8V9'
                          b'5W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"],"n":"A9XfpxIl1LcIkMhUSCCC8fgvkuX8gG9xK'
                          b'3SM-S8a8Y_U"}')

    # 3 backers
    serder = eventing.incept(pre,
                             baks=[bak1, bak2, bak3],
                             code=MtrDex.Blake3_256)
    assert serder.raw == (b'{"v":"KERI10JSON00019b_","t":"vcp","d":"Eu1JcYDELhghtQxIRXOLZrSjHgiHe__sLRNS'
                          b'bnoq8vfc","i":"Eu1JcYDELhghtQxIRXOLZrSjHgiHe__sLRNSbnoq8vfc","ii":"DntNTPnDF'
                          b'BnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","c":[],"bt":"3","b":["EXvR3p8V9'
                          b'5W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc","DSEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBA'
                          b'vN9XNU","Dvxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"],"n":"A9XfpxIl1LcIkMh'
                          b'USCCC8fgvkuX8gG9xK3SM-S8a8Y_U"}')

    # one backer, with threshold
    serder = eventing.incept(pre,
                             toad=1,
                             baks=[bak1],
                             code=MtrDex.Blake3_256)
    assert serder.raw == (b'{"v":"KERI10JSON00013d_","t":"vcp","d":"EPZ5YaOGsME24nrC1mSanqNAvfdlu86eUSCT'
                          b'LAN-VlYY","i":"EPZ5YaOGsME24nrC1mSanqNAvfdlu86eUSCTLAN-VlYY","ii":"DntNTPnDF'
                          b'BnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","c":[],"bt":"1","b":["EXvR3p8V9'
                          b'5W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"],"n":"A9XfpxIl1LcIkMhUSCCC8fgvkuX8gG9xK'
                          b'3SM-S8a8Y_U"}')

    # 3 backers, with threshold
    serder = eventing.incept(pre,
                             toad=2,
                             baks=[bak1, bak2, bak3],
                             code=MtrDex.Blake3_256)
    assert serder.raw == (b'{"v":"KERI10JSON00019b_","t":"vcp","d":"ESOWrRA6DUsDXfUM7qa4zXZIeclTXBk_UT0D'
                          b'Md8sVaZ8","i":"ESOWrRA6DUsDXfUM7qa4zXZIeclTXBk_UT0DMd8sVaZ8","ii":"DntNTPnDF'
                          b'BnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","c":[],"bt":"2","b":["EXvR3p8V9'
                          b'5W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc","DSEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBA'
                          b'vN9XNU","Dvxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"],"n":"A9XfpxIl1LcIkMh'
                          b'USCCC8fgvkuX8gG9xK3SM-S8a8Y_U"}')

    """ End Test """


def test_rotate():
    """
    Test rotate functionality

    """
    dig = "EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg"
    bak1 = "EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"
    bak2 = "DSEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU"
    bak3 = "Dvxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"

    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    baks=[])
    assert serder.raw == (b'{"v":"KERI10JSON0000dd_","t":"vrt","d":"E6wRYL3zJt01lxwcOOQX_kMlymRxItazZK-f'
                          b'6rSN6hUM","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"EY2L3ycqK9'
                          b'645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"1","bt":"0","br":[],"ba":[]}')

    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=3,
                    baks=[bak1])
    assert serder.raw == (
        b'{"v":"KERI10JSON0000dd_","t":"vrt","d":"EMb9ZC8dyqew_2xCVfmyyw1NbrppR_6CYSqr'
        b'1XEpmqc0","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"EY2L3ycqK9'
        b'645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"3","bt":"1","br":[],"ba":[]}')

    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=4,
                    baks=[bak1, bak2, bak3])
    assert serder.raw == (
        b'{"v":"KERI10JSON0000dd_","t":"vrt","d":"Egsdw8tjKQnte4nOFcKhSQtm2OYX6fr_t3S4'
        b'nmCoVjRk","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"EY2L3ycqK9'
        b'645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"4","bt":"3","br":[],"ba":[]}')

    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=4,
                    baks=[bak1, bak2, bak3],
                    cuts=[bak2])
    assert serder.raw == (
        b'{"v":"KERI10JSON00010b_","t":"vrt","d":"EvGU3Lg15VcRtPxjwjChUNq8Oskgh-bL6Dfl'
        b'x3RqAK8s","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"EY2L3ycqK9'
        b'645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"4","bt":"2","br":["DSEpNJeSJjxo6oAx'
        b'kNE8eCOJg2HRPstqkeHWBAvN9XNU"],"ba":[]}')

    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=4,
                    baks=[bak1, bak2, bak3],
                    cuts=[bak2, bak3])
    assert serder.raw == (
        b'{"v":"KERI10JSON00013a_","t":"vrt","d":"E2zIZzY6_Uo-o_xFYpOy9g0RTV-rRR-dpdRv'
        b'DZH-dpt4","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"EY2L3ycqK9'
        b'645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"4","bt":"1","br":["DSEpNJeSJjxo6oAx'
        b'kNE8eCOJg2HRPstqkeHWBAvN9XNU","Dvxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"'
        b'],"ba":[]}')

    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=4,
                    baks=[bak1, bak2, bak3],
                    cuts=[bak1, bak2, bak3])
    assert serder.raw == (
        b'{"v":"KERI10JSON000169_","t":"vrt","d":"E3PD8P5heDckdc6XuMZUKIBf7jZfCMNd3rmq'
        b'ZwXbzILo","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"EY2L3ycqK9'
        b'645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"4","bt":"0","br":["EXvR3p8V95W8J7Ui'
        b'4-mEzZ79S-A1esAnJo1Kmzq80Jkc","DSEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU"'
        b',"Dvxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"],"ba":[]}')

    # invalid cut
    with pytest.raises(ValueError):
        rotate(dig=dig,
               regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
               sn=4,
               baks=[bak1, bak3],
               cuts=[bak2])

    # invalid cut
    with pytest.raises(ValueError):
        rotate(dig=dig,
               regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
               sn=4,
               baks=[bak1, bak3],
               cuts=[bak2])

    # invalid toad
    with pytest.raises(ValueError):
        rotate(dig=dig,
               regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
               sn=4,
               toad=2,
               baks=[bak1, bak3],
               cuts=[bak3])

    # invalid sn
    with pytest.raises(ValueError):
        rotate(dig=dig,
               regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
               sn=0,
               baks=[])

    # adds
    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=4,
                    adds=[bak1],
                    baks=[bak2, bak3])
    assert serder.raw == (b'{"v":"KERI10JSON00010b_","t":"vrt","d":"EIMYQ7WEeUoVmVTMOFSOHJBsJH3UYEsZrNps'
                          b'm3te7F00","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"EY2L3ycqK9'
                          b'645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"4","bt":"3","br":[],"ba":["EXvR3p8V'
                          b'95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"]}')

    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=4,
                    toad=2,
                    adds=[bak1, bak2, bak3],
                    baks=[])
    assert serder.raw == (b'{"v":"KERI10JSON000169_","t":"vrt","d":"Eq4iNxvCB6esL8I0jhdTXNvhjzPFo5mL51YD'
                          b'5VHiPumo","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"EY2L3ycqK9'
                          b'645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"4","bt":"2","br":[],"ba":["EXvR3p8V'
                          b'95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc","DSEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWB'
                          b'AvN9XNU","Dvxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"]}')

    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=4,
                    toad=3,
                    adds=[bak2, bak3],
                    baks=[bak1])
    assert serder.raw == (
        b'{"v":"KERI10JSON00013a_","t":"vrt","d":"E-Zpq4N18HYXIvCjNuyfHBvjGCw6GjY5Ga1o'
        b'HSS1SNg4","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"EY2L3ycqK9'
        b'645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"4","bt":"3","br":[],"ba":["DSEpNJeS'
        b'Jjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU","Dvxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJD'
        b'pC0nQXw"]}')

    # invalid dupe add
    with pytest.raises(ValueError):
        rotate(dig=dig,
               regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
               sn=4,
               baks=[bak2, bak3],
               adds=[bak2])

    # invalid dupe add
    with pytest.raises(ValueError):
        rotate(dig=dig,
               regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
               sn=4,
               baks=[bak3],
               cuts=[bak2, bak3])

    # invalid toad
    with pytest.raises(ValueError):
        rotate(dig=dig,
               regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
               sn=5,
               toad=3,
               adds=[bak2, bak3],
               baks=[])

    """ End Test """


def test_simple_issue_revoke(mockHelpingNowUTC):
    vcdig = "DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM"
    regk = "EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw"
    dig = "EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg"

    serder = issue(vcdig=vcdig, regk=regk)

    assert serder.raw == (b'{"v":"KERI10JSON0000ed_","t":"iss","d":"ECHrBbeRqJetvXNdus1sBC6B_je6JGctcMoA'
                          b'06sGKcJo","i":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","ri":"E'
                          b'E3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","dt":"2021-01-01T00:00:00.00000'
                          b'0+00:00"}')

    serder = revoke(vcdig=vcdig, regk=regk, dig=dig)

    assert serder.raw == (b'{"v":"KERI10JSON000120_","t":"rev","d":"EKhhSHdpU7UiZlXHBUolUYHp-RmUBFjPj0K3'
                          b'j1g6lI1c","i":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"1","ri":"E'
                          b'E3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"EY2L3ycqK9645aEeQKP941xojS'
                          b'iuiHsw4Y6yTW-PmsBg","dt":"2021-01-01T00:00:00.000000+00:00"}')

    """ End Test """


def test_backer_issue_revoke(mockHelpingNowUTC):
    vcdig = "DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM"
    regk = "EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw"
    sn = 3
    regd = "Ezpq06UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-PLMZ1H4"
    dig = "EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg"

    serder = backerIssue(vcdig=vcdig, regk=regk, regsn=sn, regd=regd)
    assert serder.raw == (b'{"v":"KERI10JSON000160_","t":"bis","d":"E9vdPfc963ao3kQtC-24LTRmrpLaiMapaYw7'
                          b'uHRJXB0A","i":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","ii":"EE3Xv6CWw'
                          b'EMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","s":"0","ra":{"i":"EE3Xv6CWwEMpW-99rhPD'
                          b'9IHFCR2LN5ienLVI8yG5faBw","s":3,"d":"Ezpq06UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-PL'
                          b'MZ1H4"},"dt":"2021-01-01T00:00:00.000000+00:00"}')

    serder = backerRevoke(vcdig=vcdig, regk=regk, regsn=sn, regd=regd, dig=dig)
    assert serder.raw == (b'{"v":"KERI10JSON00015f_","t":"brv","d":"ECJxA7vksudFA3J1XUwiAEt1CduU7yyYRBkq'
                          b'FdZjgGJw","i":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"1","p":"EY'
                          b'2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","ra":{"i":"EE3Xv6CWwEMpW-99rhPD9'
                          b'IHFCR2LN5ienLVI8yG5faBw","s":3,"d":"Ezpq06UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-PLM'
                          b'Z1H4"},"dt":"2021-01-01T00:00:00.000000+00:00"}')
    """ End Test """


def test_prefixer():
    pre = "DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM"
    vs = versify(version=Version, kind=Serials.json, size=0)

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
    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer.qb64 == "ErSHsjEplmw3PbN3MQdD4ov06Tc1rFhrYnfWav0MiPpc"
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
        prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)

    # vcp, no backers allowed
    ked = dict(v=vs,
               i="",
               ii=pre,
               s="{:x}".format(0),
               t=Ilks.vcp,
               c=[keventing.TraitDex.NoBackers],
               b=[]
               )
    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer.qb64 == "EXSaijZBI9UDifg2lpJjiR22ZluMPHXWafscfymwt3JU"
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
    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer.qb64 == "E6QS7DZSlXuAZ32nCUj2-M3_bqUAFRZD_gmPTiL56ymk"
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
    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer.qb64 == "EpGQ9M17ZPANMEAtGmQEbz7KHwC7tC-CR2IW9g3VSino"
    assert prefixer.verify(ked=ked) is True
    assert prefixer.verify(ked=ked, prefixed=True) is False

    """ End Test """


def test_tever_escrow(mockCoringRandomNonce):
    with pytest.raises(ValueError):
        Tever()

    # registry with no backers, invalid anchor
    with basing.openDB() as db, keeping.openKS() as kpr, viring.openReger() as reg:
        hby, hab = buildHab(db, kpr)
        vcp = eventing.incept(hab.pre,
                              baks=[],
                              toad=0,
                              cnfg=[],
                              code=MtrDex.Blake3_256)
        regk = vcp.pre
        assert regk == "EPK-Hu02OQv4S6qLhj5d0srw_qtazj0YptbrL8Rgb0mk"
        assert vcp.said == "EPK-Hu02OQv4S6qLhj5d0srw_qtazj0YptbrL8Rgb0mk"
        assert vcp.ked["ii"] == hab.pre

        # anchor to nothing, exception expected
        seqner = Seqner(sn=4)

        # invalid seal sn
        with pytest.raises(ValidationError):
            Tever(serder=vcp, seqner=seqner, saider=None, db=db, reger=reg)

    # registry with no backers
    with basing.openDB() as db, keeping.openKS() as kpr, viring.openReger() as reg:
        hby, hab = buildHab(db, kpr)
        vcp = eventing.incept(hab.pre,
                              baks=[],
                              toad=0,
                              cnfg=[],
                              code=MtrDex.Blake3_256)
        regk = vcp.pre

        # anchoring event not in db, exception and escrow
        seqner = Seqner(sn=1)

        with pytest.raises(MissingAnchorError):
            Tever(serder=vcp, seqner=seqner, db=db, reger=reg)

        dgkey = dgKey(pre=regk, dig=vcp.said)
        vcp = reg.getTvt(dgkey)
        assert bytes(vcp) == (b'{"v":"KERI10JSON00010f_","t":"vcp","d":"EPK-Hu02OQv4S6qLhj5d0srw_qtazj0Yptbr'
                              b'L8Rgb0mk","i":"EPK-Hu02OQv4S6qLhj5d0srw_qtazj0YptbrL8Rgb0mk","ii":"Evzy4Lumz'
                              b'atnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A","s":"0","c":[],"bt":"0","b":[],"n":"A9X'
                              b'fpxIl1LcIkMhUSCCC8fgvkuX8gG9xK3SM-S8a8Y_U"}')
        dig = reg.getTae(snKey(pre=regk, sn=0))
        assert bytes(dig) == b'EPK-Hu02OQv4S6qLhj5d0srw_qtazj0YptbrL8Rgb0mk'

    # registry with backers, no signatures.  should escrow
    with basing.openDB() as db, keeping.openKS() as kpr, viring.openReger() as reg:
        hby, hab = buildHab(db, kpr)
        vcp = eventing.incept(hab.pre,
                              baks=["BoOcciw30IVQsaenKXpiyMVrjtPDW3KeD_6KFnSfoaqI"],
                              toad=1,
                              cnfg=[],
                              code=MtrDex.Blake3_256)
        regk = vcp.pre

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(regk, vcp.ked["s"], vcp.saider.qb64)

        rot = hab.rotate(data=[rseal._asdict()])
        rotser = Serder(raw=rot)

        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        diger = rotser.saider

        with pytest.raises(MissingWitnessSignatureError):
            Tever(serder=vcp, seqner=seqner, saider=diger, db=db, reger=reg)

        dgkey = dgKey(pre=regk, dig=vcp.said)
        vcp = reg.getTvt(dgkey)
        assert bytes(vcp) == (b'{"v":"KERI10JSON00013d_","t":"vcp","d":"Ezb-3Q4ymf15asSWwTmR38qJ7RkGxOE2jnuK'
                              b'qX11_9Mo","i":"Ezb-3Q4ymf15asSWwTmR38qJ7RkGxOE2jnuKqX11_9Mo","ii":"Evzy4Lumz'
                              b'atnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A","s":"0","c":[],"bt":"1","b":["BoOcciw30'
                              b'IVQsaenKXpiyMVrjtPDW3KeD_6KFnSfoaqI"],"n":"A9XfpxIl1LcIkMhUSCCC8fgvkuX8gG9xK'
                              b'3SM-S8a8Y_U"}')

        anc = reg.getAnc(dgkey)
        assert bytes(anc) == b'0AAAAAAAAAAAAAAAAAAAAAAQE9e6TzbXk2qxwAa5UPkauqhHfSOGp2jLvGUccGA1Zt0w'
        assert reg.getTel(snKey(pre=regk, sn=0)) is None
        dig = reg.getTwe(snKey(pre=regk, sn=0))
        assert bytes(dig) == b'Ezb-3Q4ymf15asSWwTmR38qJ7RkGxOE2jnuKqX11_9Mo'


def test_tever_no_backers(mockHelpingNowUTC, mockCoringRandomNonce):
    # registry with no backers
    # registry with backer and receipt
    with basing.openDB() as db, keeping.openKS() as kpr, viring.openReger() as reg:
        hby, hab = buildHab(db, kpr)

        vcp = eventing.incept(hab.pre,
                              baks=[],
                              toad=0,
                              cnfg=["NB"],
                              code=MtrDex.Blake3_256)
        regk = vcp.pre

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(i=regk, s=vcp.ked["s"], d=vcp.saider.qb64)

        rot = hab.rotate(data=[rseal._asdict()])
        rotser = Serder(raw=rot)

        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        diger = rotser.saider

        tev = Tever(serder=vcp, seqner=seqner, saider=diger, db=db, reger=reg)

        assert tev.prefixer.qb64 == vcp.pre
        assert tev.sn == 0

        dgkey = dgKey(pre=regk, dig=vcp.said)
        assert bytes(reg.getTvt(dgkey)) == (
            b'{"v":"KERI10JSON000113_","t":"vcp","d":"EyJmDpUFYIof-2AJYlxskODX56_DFdI5oww5'
            b'0X7rxQvM","i":"EyJmDpUFYIof-2AJYlxskODX56_DFdI5oww50X7rxQvM","ii":"Evzy4Lumz'
            b'atnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A","s":"0","c":["NB"],"bt":"0","b":[],"n":'
            b'"A9XfpxIl1LcIkMhUSCCC8fgvkuX8gG9xK3SM-S8a8Y_U"}'
        )

        assert bytes(reg.getAnc(dgkey)) == (
            b'0AAAAAAAAAAAAAAAAAAAAAAQEjO6aCWlwTbW0KmphM0S9fOzw4Xh1Uyh5WW0g1Qe4YEM')
        assert bytes(reg.getTel(snKey(pre=regk, sn=0))) == b'EyJmDpUFYIof-2AJYlxskODX56_DFdI5oww50X7rxQvM'
        assert reg.getTibs(dgkey) == []
        assert reg.getTwe(snKey(pre=regk, sn=0)) is None

        # try to rotate a backerless registry
        vrt = eventing.rotate(regk, dig=vcp.said)
        rseal = keventing.SealEvent(regk, vrt.ked["s"], vrt.saider.qb64)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = Serder(raw=rot)
        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        diger = rotser.saider

        # should raise validation err because rotation is not supported
        with pytest.raises(ValidationError):
            tev.update(serder=vrt, seqner=seqner, saider=diger)

        vcdig = b'EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU'

        iss = eventing.issue(vcdig=vcdig.decode("utf-8"), regk=regk)

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(iss.ked["i"], iss.ked["s"], iss.saider.qb64)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = Serder(raw=rot)
        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        diger = rotser.saider

        tev.update(iss, seqner=seqner, saider=diger)

        vci = vcdig
        dgkey = dgKey(pre=vci, dig=iss.said)
        assert bytes(reg.getTvt(dgkey)) == (
            b'{"v":"KERI10JSON0000ed_","t":"iss","d":"EhRtGoDP0k9PLgK9uPi8DQOqzb0l0kXdZ4h3'
            b'9AfSx-YY","i":"EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU","s":"0","ri":"E'
            b'yJmDpUFYIof-2AJYlxskODX56_DFdI5oww50X7rxQvM","dt":"2021-01-01T00:00:00.00000'
            b'0+00:00"}')
        assert bytes(reg.getAnc(dgkey)) == b'0AAAAAAAAAAAAAAAAAAAAAAwEsa75XVdJnIhUoopnWvOvlNfr1AIvIdReY8XATBwmWxc'

        # revoke vc with no backers
        rev = eventing.revoke(vcdig=vcdig.decode("utf-8"), regk=regk, dig=iss.said)

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(rev.ked["i"], rev.ked["s"], rev.saider.qb64)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = Serder(raw=rot)
        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        diger = rotser.saider

        tev.update(rev, seqner=seqner, saider=diger)
        dgkey = dgKey(pre=vci, dig=rev.said)
        assert bytes(reg.getTvt(dgkey)) == (
            b'{"v":"KERI10JSON000120_","t":"rev","d":"EdSLsFrPCB1mXd4skDxKC6hxCL_augN6M7cN'
            b'QV4PznDc","i":"EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU","s":"1","ri":"E'
            b'yJmDpUFYIof-2AJYlxskODX56_DFdI5oww50X7rxQvM","p":"EhRtGoDP0k9PLgK9uPi8DQOqzb'
            b'0l0kXdZ4h39AfSx-YY","dt":"2021-01-01T00:00:00.000000+00:00"}')

        # assert reg.getAnc(dgkey) == b'0AAAAAAAAAAAAAAAAAAAAABAECgc6yHeTRhsKh1M7k65feWZGCf_MG0dWoei5Q6SwgqU'


def test_tever_backers(mockHelpingNowUTC, mockCoringRandomNonce):
    # registry with backer and receipt
    with basing.openDB() as db, keeping.openKS() as kpr, viring.openReger() as reg:
        valSecret = 'AgjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw'

        # create receipt signer prefixer default code is non-transferable
        valSigner = Signer(qb64=valSecret, transferable=False)
        valPrefixer = Prefixer(qb64=valSigner.verfer.qb64)
        valpre = valPrefixer.qb64
        assert valpre == 'B8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc'

        hby, hab = buildHab(db, kpr)

        vcp = eventing.incept(hab.pre,
                              baks=[valpre],
                              toad=1,
                              cnfg=[],
                              code=MtrDex.Blake3_256)
        regk = vcp.pre
        valCigar = valSigner.sign(ser=vcp.raw, index=0)

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(i=regk, s=vcp.ked["s"], d=vcp.saider.qb64)

        rot = hab.rotate(data=[rseal._asdict()])
        rotser = Serder(raw=rot)

        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        diger = rotser.saider

        tev = Tever(serder=vcp, seqner=seqner, saider=diger, bigers=[valCigar], db=db, reger=reg)

        dgkey = dgKey(pre=regk, dig=vcp.said)
        assert bytes(reg.getTvt(dgkey)) == (
            b'{"v":"KERI10JSON00013d_","t":"vcp","d":"ENcQCIV5OOwo7LJmpuJirC6AvRf6ptA_ihxk'
            b'7dNMjH8k","i":"ENcQCIV5OOwo7LJmpuJirC6AvRf6ptA_ihxk7dNMjH8k","ii":"Evzy4Lumz'
            b'atnQ1GB1LpIinFlqxzksir-EZ7dRGI0Br6A","s":"0","c":[],"bt":"1","b":["B8KY1sKmg'
            b'yjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc"],"n":"A9XfpxIl1LcIkMhUSCCC8fgvkuX8gG9xK'
            b'3SM-S8a8Y_U"}')
        assert bytes(reg.getAnc(dgkey)) == b'0AAAAAAAAAAAAAAAAAAAAAAQEWndBQnA4bv3vkk1F3VcxGbwN6yDaERq9MACn9ph2fs0'
        assert bytes(reg.getTel(snKey(pre=regk, sn=0))) == b'ENcQCIV5OOwo7LJmpuJirC6AvRf6ptA_ihxk7dNMjH8k'
        assert [bytes(tib) for tib in reg.getTibs(dgkey)] == [b'AATP_jogkLiPumDfwc_1mu-pYtJu5bvbr7vcqngvZrhn9VfDvFBhQ3'
                                                              b'SZDYlDhPKh9FsjmzR2EWRKpgYv6jF2PBBA']
        assert reg.getTwe(snKey(pre=regk, sn=0)) is None

        debSecret = 'AKUotEE0eAheKdDJh9QvNmSEmO_bjIav8V_GmctGpuCQ'

        # create receipt signer prefixer default code is non-transferable
        debSigner = Signer(qb64=debSecret, transferable=False)
        debPrefixer = Prefixer(qb64=debSigner.verfer.qb64)
        debpre = debPrefixer.qb64
        assert debpre == 'BbWeWTNGXPMQrVuJmScNQn81YF7T2fhh2kXwT8E_NbeI'

        vrt = eventing.rotate(regk, dig=vcp.said, baks=[valpre], adds=[debpre])
        valCigar = valSigner.sign(ser=vrt.raw, index=0)
        debCigar = debSigner.sign(ser=vrt.raw, index=1)

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(regk, vrt.ked["s"], vrt.saider.qb64)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = Serder(raw=rot)
        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        diger = rotser.saider

        tev.update(serder=vrt, seqner=seqner, saider=diger, bigers=[valCigar, debCigar])

        assert tev.baks == ['B8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc',
                            'BbWeWTNGXPMQrVuJmScNQn81YF7T2fhh2kXwT8E_NbeI']

        vcdig = b'EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU'

        bis = eventing.backerIssue(vcdig=vcdig.decode("utf-8"), regk=regk, regsn=tev.sn, regd=tev.serder.said)
        valCigar = valSigner.sign(ser=bis.raw, index=0)
        debCigar = debSigner.sign(ser=bis.raw, index=1)

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(bis.ked["i"], bis.ked["s"], bis.saider.qb64)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = Serder(raw=rot)
        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        diger = rotser.saider

        tev.update(bis, seqner=seqner, saider=diger, bigers=[valCigar, debCigar])

        vci = vcdig
        dgkey = dgKey(pre=vci, dig=bis.said)
        assert bytes(reg.getTvt(dgkey)) == (
            b'{"v":"KERI10JSON000160_","t":"bis","d":"Ehry3apI8AIyI7HUnulglQIgiKeJ24hVPFwb'
            b'MEA4VBgE","i":"EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU","ii":"ENcQCIV5O'
            b'Owo7LJmpuJirC6AvRf6ptA_ihxk7dNMjH8k","s":"0","ra":{"i":"ENcQCIV5OOwo7LJmpuJi'
            b'rC6AvRf6ptA_ihxk7dNMjH8k","s":1,"d":"EBy8AmzVGvl07kcRe1Y-EIm_veCUBcDnU176jvl'
            b'X1m78"},"dt":"2021-01-01T00:00:00.000000+00:00"}')


def test_tevery():
    with basing.openDB() as db, keeping.openKS() as kpr, viring.openReger() as reg:
        hby, hab = buildHab(db, kpr)

        vcp = eventing.incept(hab.pre,
                              baks=[],
                              toad=0,
                              cnfg=["NB"],
                              code=MtrDex.Blake3_256)
        regk = vcp.pre

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(i=regk, s=vcp.ked["s"], d=vcp.saider.qb64)

        rot = hab.rotate(data=[rseal._asdict()])
        rotser = Serder(raw=rot)

        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        diger = rotser.saider

        tvy = Tevery(reger=reg, db=db)

        tvy.processEvent(serder=vcp, seqner=seqner, saider=diger)

        assert regk in tvy.tevers
        tev = tvy.tevers[regk]
        assert tev.prefixer.qb64 == vcp.pre
        assert tev.sn == 0

        # send vcp again, get error
        with pytest.raises(LikelyDuplicitousError):
            tvy.processEvent(serder=vcp, seqner=seqner, saider=diger)

        # process issue vc event
        vcdig = b'EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU'

        iss = eventing.issue(vcdig=vcdig.decode("utf-8"), regk=regk)

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(iss.ked["i"], iss.ked["s"], iss.saider.qb64)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = Serder(raw=rot)
        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        diger = rotser.saider

        tvy.processEvent(serder=iss, seqner=seqner, saider=diger)
        status = tev.vcState(vcdig.decode("utf-8"))
        assert status.ked['et'] == Ilks.iss
        assert status.sn == 0

        # revoke the vc
        rev = eventing.revoke(vcdig=vcdig.decode("utf-8"), regk=regk, dig=iss.said)

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(rev.ked["i"], rev.ked["s"], rev.saider.qb64)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = Serder(raw=rot)
        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        diger = rotser.saider

        tvy.processEvent(serder=rev, seqner=seqner, saider=diger)
        status = tev.vcState(vcdig.decode("utf-8"))
        assert status.ked["et"] == Ilks.rev
        assert status.sn == 1


def test_tevery_process_escrow(mockCoringRandomNonce):
    with basing.openDB() as db, keeping.openKS() as kpr, viring.openReger() as reg:
        hby, hab = buildHab(db, kpr)

        vcp = eventing.incept(hab.pre,
                              baks=[],
                              toad=0,
                              cnfg=["NB"],
                              code=MtrDex.Blake3_256)
        regk = vcp.pre

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(i=regk, s=vcp.ked["s"], d=vcp.saider.qb64)

        seqner = Seqner(sn=1)
        diger = coring.Diger(qb64b=b'EjO6aCWlwTbW0KmphM0S9fOzw4Xh1Uyh5WW0g1Qe4YEM')

        tvy = Tevery(reger=reg, db=db)

        with pytest.raises(MissingAnchorError):  # Process before the Hab rotation event, will escrow
            tvy.processEvent(serder=vcp, seqner=seqner, saider=diger)

        assert regk not in tvy.tevers

        rot = hab.rotate(data=[rseal._asdict()])  # Now rotate so the achoring KEL event gets into the database
        rotser = coring.Serder(raw=rot)
        assert rotser.saidb == diger.qb64b

        tvy.processEscrows()  # process escrows and now the Tever event is good.
        assert regk in tvy.tevers
        tev = tvy.tevers[regk]
        assert tev.prefixer.qb64 == vcp.pre
        assert tev.sn == 0


def buildHab(db, ks, name="test"):
    """Utility to setup Habery and Hab for testing purposes
    Returns:
       tuple (Habery, Hab):
    """
    secrets = [
        'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
        'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
        'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
        'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
        'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
        'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
        'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
        'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
    ]
    secrecies = []
    for secret in secrets:  # convert secrets to secrecies
        secrecies.append([secret])
    # setup hab
    hby = habbing.Habery(name=name, temp=True, ks=ks, db=db)
    hab = hby.makeHab(name=name, secrecies=secrecies)
    # hab = habbing.Habitat(ks=ks, db=db, secrecies=secrecies, temp=True)
    return (hby, hab)


if __name__ == "__main__":
    test_tever_escrow()
    test_tevery_process_escrow()
