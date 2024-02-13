# -*- encoding: utf-8 -*-
"""
tests.vdr.eventing module

"""
import pytest

from keri.app import habbing, keeping
from keri.core import coring, serdering
from keri.core import eventing as keventing
from keri.core.coring import versify, Serials, Ilks, MtrDex, Prefixer, Signer, Seqner, Saider
from keri.db import basing
from keri.db.dbing import snKey, dgKey
from keri.kering import Version, EmptyMaterialError, DerivationError, MissingAnchorError, ValidationError, \
    MissingWitnessSignatureError, LikelyDuplicitousError
from keri.vdr import eventing, viring
from keri.vdr.eventing import rotate, issue, revoke, backerIssue, backerRevoke, Tever, Tevery

from tests.vdr import buildHab


def test_incept(mockCoringRandomNonce):
    """
    Test incept utility function
    """

    pre = "DAtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM"
    bak1 = "EAvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"
    bak2 = "DBEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU"
    bak3 = "DCxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"

    # no backers, allowed to add later
    serder = eventing.incept(pre, baks=[], code=MtrDex.Blake3_256)
    assert serder.raw == (b'{"v":"KERI10JSON00010f_","t":"vcp","d":"ELkr1d1qLyIXVPfuaEjkDJIfgxXarUjoB0RN'
                        b'mswxHnvD","i":"ELkr1d1qLyIXVPfuaEjkDJIfgxXarUjoB0RNmswxHnvD","ii":"DAtNTPnDF'
                        b'BnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","c":[],"bt":"0","b":[],"n":"A9X'
                        b'fpxIl1LcIkMhUSCCC8fgvkuX8gG9xK3SM-S8a8Y_U"}')

    # no backers allowed
    serder = eventing.incept(pre, baks=[], cnfg=[keventing.TraitDex.NoBackers], code=MtrDex.Blake3_256)
    assert serder.raw == (b'{"v":"KERI10JSON000113_","t":"vcp","d":"EBoBPh3N5nr1tItAUCkXNx3vShB_Be6iiQPX'
                        b'Bsg2LvxA","i":"EBoBPh3N5nr1tItAUCkXNx3vShB_Be6iiQPXBsg2LvxA","ii":"DAtNTPnDF'
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
    assert serder.raw == (b'{"v":"KERI10JSON00013d_","t":"vcp","d":"EHYybz8zckAN_4rj8JfuKMogmWr7gRLKxf_I'
                    b'6AwmpZ6x","i":"EHYybz8zckAN_4rj8JfuKMogmWr7gRLKxf_I6AwmpZ6x","ii":"DAtNTPnDF'
                    b'BnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","c":[],"bt":"1","b":["EAvR3p8V9'
                    b'5W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"],"n":"A9XfpxIl1LcIkMhUSCCC8fgvkuX8gG9xK'
                    b'3SM-S8a8Y_U"}')

    # 3 backers
    serder = eventing.incept(pre,
                             baks=[bak1, bak2, bak3],
                             code=MtrDex.Blake3_256)
    assert serder.raw == (b'{"v":"KERI10JSON00019b_","t":"vcp","d":"ECw3lpxt56pRMeh7VnZStljriimMfm5or0Ka'
                        b'aNv7PSHl","i":"ECw3lpxt56pRMeh7VnZStljriimMfm5or0KaaNv7PSHl","ii":"DAtNTPnDF'
                        b'BnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","c":[],"bt":"3","b":["EAvR3p8V9'
                        b'5W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc","DBEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBA'
                        b'vN9XNU","DCxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"],"n":"A9XfpxIl1LcIkMh'
                        b'USCCC8fgvkuX8gG9xK3SM-S8a8Y_U"}')

    # one backer, with threshold
    serder = eventing.incept(pre,
                             toad=1,
                             baks=[bak1],
                             code=MtrDex.Blake3_256)
    assert serder.raw == (b'{"v":"KERI10JSON00013d_","t":"vcp","d":"EHYybz8zckAN_4rj8JfuKMogmWr7gRLKxf_I'
                        b'6AwmpZ6x","i":"EHYybz8zckAN_4rj8JfuKMogmWr7gRLKxf_I6AwmpZ6x","ii":"DAtNTPnDF'
                        b'BnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","c":[],"bt":"1","b":["EAvR3p8V9'
                        b'5W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"],"n":"A9XfpxIl1LcIkMhUSCCC8fgvkuX8gG9xK'
                        b'3SM-S8a8Y_U"}')

    # 3 backers, with threshold
    serder = eventing.incept(pre,
                             toad=2,
                             baks=[bak1, bak2, bak3],
                             code=MtrDex.Blake3_256)
    assert serder.raw == (b'{"v":"KERI10JSON00019b_","t":"vcp","d":"EGqiHHLDIMr7VYNhDSnmsjOMpaLUOBRAgxvb'
                        b'rXYSFDfk","i":"EGqiHHLDIMr7VYNhDSnmsjOMpaLUOBRAgxvbrXYSFDfk","ii":"DAtNTPnDF'
                        b'BnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","c":[],"bt":"2","b":["EAvR3p8V9'
                        b'5W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc","DBEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBA'
                        b'vN9XNU","DCxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"],"n":"A9XfpxIl1LcIkMh'
                        b'USCCC8fgvkuX8gG9xK3SM-S8a8Y_U"}')

    """ End Test """


def test_rotate():
    """
    Test rotate functionality

    """
    dig = "EA2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg"
    bak1 = "EBvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"
    bak2 = "DAEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU"
    bak3 = "DBxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"

    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    baks=[])
    assert serder.raw == (b'{"v":"KERI10JSON0000dd_","t":"vrt","d":"EF_SBZzjflcJaTTTdRTfY-JLfaqOHJpa7EMO'
                          b'xqFwWXff","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"EA2L3ycqK9'
                          b'645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"1","bt":"0","br":[],"ba":[]}')

    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=3,
                    baks=[bak1])
    assert serder.raw == (b'{"v":"KERI10JSON0000dd_","t":"vrt","d":"EGsKu5qY-uuI9WucRkI__NvcuSKfe6R6bSvz'
                          b'G2i_hq04","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"EA2L3ycqK9'
                          b'645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"3","bt":"1","br":[],"ba":[]}')


    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=4,
                    baks=[bak1, bak2, bak3])
    assert serder.raw == (b'{"v":"KERI10JSON0000dd_","t":"vrt","d":"EKyZjgvjCihaqOqb58URdrrrHXKAavlV3N7U'
                          b'9WAneTK6","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"EA2L3ycqK9'
                          b'645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"4","bt":"3","br":[],"ba":[]}')

    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=4,
                    baks=[bak1, bak2, bak3],
                    cuts=[bak2])
    assert serder.raw == (b'{"v":"KERI10JSON00010b_","t":"vrt","d":"EKI7bCJ3DHxpxidDAhRBrMVI_te-JqEN55ln'
                        b'HMz-8JXg","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"EA2L3ycqK9'
                        b'645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"4","bt":"2","br":["DAEpNJeSJjxo6oAx'
                        b'kNE8eCOJg2HRPstqkeHWBAvN9XNU"],"ba":[]}')

    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=4,
                    baks=[bak1, bak2, bak3],
                    cuts=[bak2, bak3])
    assert serder.raw == (b'{"v":"KERI10JSON00013a_","t":"vrt","d":"EG30uAZOrLHjfscyFGeay1cUt_Clnq4xXo59'
                    b'MTKyM2JM","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"EA2L3ycqK9'
                    b'645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"4","bt":"1","br":["DAEpNJeSJjxo6oAx'
                    b'kNE8eCOJg2HRPstqkeHWBAvN9XNU","DBxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"'
                    b'],"ba":[]}')


    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=4,
                    baks=[bak1, bak2, bak3],
                    cuts=[bak1, bak2, bak3])
    assert serder.raw == (b'{"v":"KERI10JSON000169_","t":"vrt","d":"EBoHO7SMctYvqVFhnwtWASPf3t9KAsn5WbpG'
                    b'1Ew9RURO","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"EA2L3ycqK9'
                    b'645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"4","bt":"0","br":["EBvR3p8V95W8J7Ui'
                    b'4-mEzZ79S-A1esAnJo1Kmzq80Jkc","DAEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU"'
                    b',"DBxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"],"ba":[]}')

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
    assert serder.raw == (b'{"v":"KERI10JSON00010b_","t":"vrt","d":"EBGnLp2Dlt-57wU6fT9mS9Xwkcirvrw7ySr1'
                        b'-aoP27bi","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"EA2L3ycqK9'
                        b'645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"4","bt":"3","br":[],"ba":["EBvR3p8V'
                        b'95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"]}')

    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=4,
                    toad=2,
                    adds=[bak1, bak2, bak3],
                    baks=[])
    assert serder.raw == (b'{"v":"KERI10JSON000169_","t":"vrt","d":"EMpFiUdRTiJ7lrpNCs8mkBQzRieTW2PwYrpY'
                    b'mK4ri256","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"EA2L3ycqK9'
                    b'645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"4","bt":"2","br":[],"ba":["EBvR3p8V'
                    b'95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc","DAEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWB'
                    b'AvN9XNU","DBxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"]}')

    serder = rotate(dig=dig,
                    regk="EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
                    sn=4,
                    toad=3,
                    adds=[bak2, bak3],
                    baks=[bak1])
    assert serder.raw == (b'{"v":"KERI10JSON00013a_","t":"vrt","d":"EDkaxfBYXFe2gBpOdTcTqlGn37vZUMtui212'
                        b'vcMBQQIJ","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"EA2L3ycqK9'
                        b'645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"4","bt":"3","br":[],"ba":["DAEpNJeS'
                        b'Jjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU","DBxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJD'
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

    vcdig = "DAtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM"
    regk = "EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw"
    dig = "EB2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg"

    serder = issue(vcdig=vcdig, regk=regk)

    assert serder.raw == (b'{"v":"KERI10JSON0000ed_","t":"iss","d":"EELqqdELW6CUVWfmsbt5sxfQfEOykyOWdUV1'
                    b'2biBR4TH","i":"DAtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","ri":"E'
                    b'E3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","dt":"2021-01-01T00:00:00.00000'
                    b'0+00:00"}')

    serder = revoke(vcdig=vcdig, regk=regk, dig=dig)

    assert serder.raw == (b'{"v":"KERI10JSON000120_","t":"rev","d":"EGtAthwVjf0O9qsSz0HR-C63DSEBhn3kRoxv'
                    b'muRFECOQ","i":"DAtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"1","ri":"E'
                    b'E3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"EB2L3ycqK9645aEeQKP941xojS'
                    b'iuiHsw4Y6yTW-PmsBg","dt":"2021-01-01T00:00:00.000000+00:00"}')

    """ End Test """


def test_backer_issue_revoke(mockHelpingNowUTC):

    vcdig = "DAtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM"
    regk = "EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw"
    sn = 3
    regd = "EBpq06UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-PLMZ1H4"
    dig = "EC2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg"

    serder = backerIssue(vcdig=vcdig, regk=regk, regsn=sn, regd=regd)
    assert serder.raw == (b'{"v":"KERI10JSON000162_","t":"bis","d":"EK9X5Ih5z68pKA-dHMuEZXt_2avkzM8i1_gD'
                          b'KlFBGDM7","i":"DAtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","ii":"EE3Xv6CWw'
                          b'EMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","s":"0","ra":{"i":"EE3Xv6CWwEMpW-99rhPD'
                          b'9IHFCR2LN5ienLVI8yG5faBw","s":"3","d":"EBpq06UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-'
                          b'PLMZ1H4"},"dt":"2021-01-01T00:00:00.000000+00:00"}')


    serder = backerRevoke(vcdig=vcdig, regk=regk, regsn=sn, regd=regd, dig=dig)
    assert serder.raw == (b'{"v":"KERI10JSON000161_","t":"brv","d":"EMBHVoEIM4GfoLtelLD6erwNLyO39PUyEAcC'
                          b'-N77OGoq","i":"DAtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"1","p":"EC'
                          b'2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","ra":{"i":"EE3Xv6CWwEMpW-99rhPD9'
                          b'IHFCR2LN5ienLVI8yG5faBw","s":"3","d":"EBpq06UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-P'
                          b'LMZ1H4"},"dt":"2021-01-01T00:00:00.000000+00:00"}')

    """ End Test """


def test_prefixer():

    pre = "DAtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM"
    vs = versify(version=Version, kind=Serials.json, size=0)

    with pytest.raises(EmptyMaterialError):
        prefixer = Prefixer()

    # vcp, backers allowed no backers
    # ["v", "d", "i", "s", "t", "bt", "b", "c"]
    ked = dict(v=vs,
               d="",  # qb64 SAID
               i="",  # qb64 pre
               ii=pre,
               s="{:x}".format(0),
               t=Ilks.vcp,
               bt=0,
               b=[],
               c=[],
               )
    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer.qb64 == 'EDj0Kq4tFBNGKxpdfX2nCfIvYJ-v1MJ24H1dsPfUqzmB'
    assert prefixer.verify(ked=ked) is True
    assert prefixer.verify(ked=ked, prefixed=True) is False

    # Invalid event type
    #["v", "i", "s", "t", "ri", "dt"]
    ked = dict(v=vs,
               d="",  # qb64 SAID
               i="",
               s="{:x}".format(0),
               t=Ilks.iss,
               ri="",
               dt="",
               )
    #with pytest.raises(DerivationError):
    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)

    # vcp, no backers allowed
    ked = dict(v=vs,
               d="",  # qb64 SAID
               i="",
               ii=pre,
               s="{:x}".format(0),
               t=Ilks.vcp,
               bt=0,
               b=[],
               c=[keventing.TraitDex.NoBackers],
               )
    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer.qb64 == 'EDz0QmMxf4Dk0C9uiP-y3okN-Bej2IAXSj8UwQgb3NsL'
    assert prefixer.verify(ked=ked) is True
    assert prefixer.verify(ked=ked, prefixed=True) is False

    bak1 = "EAvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"
    bak2 = "DBEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU"
    bak3 = "DCxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"

    # vcp, one backer
    ked = dict(v=vs,
               d="",  # qb64 SAID
               i="",
               ii=pre,
               s="{:x}".format(0),
               t=Ilks.vcp,
               bt=1,
               b=[bak1],
               c=[],
               )
    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer.qb64 == 'EIDRsRwJQNw2ujTeoztpEPxN6XRmBB2bnxWlOzJ9OQHk'
    assert prefixer.verify(ked=ked) is True
    assert prefixer.verify(ked=ked, prefixed=True) is False

    # vcp, many backers
    ked = dict(v=vs,
               d="",  # qb64 SAID
               i="",
               ii=pre,
               s="{:x}".format(0),
               t=Ilks.vcp,
               bt=2,
               b=[bak1, bak2, bak3],
               c=[],
               )
    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer.qb64 == 'EMsbtrSOa_lNwDMhpdXphmbItPBcaB0qSboopPo9Ub-s'
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
        assert regk == 'EJfe0JaRiSWTCnasczAPkvZ-M2dd5nnhxcTcS59ssXg5'
        assert vcp.said == vcp.pre
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
        assert bytes(vcp) == (b'{"v":"KERI10JSON00010f_","t":"vcp","d":"EJfe0JaRiSWTCnasczAPkvZ-M2dd5nnhxcTc'
                              b'S59ssXg5","i":"EJfe0JaRiSWTCnasczAPkvZ-M2dd5nnhxcTcS59ssXg5","ii":"EPst_DQ1d'
                              b'8VCMGHB475dgKWCxO3qX4HlvW_4_lsrVZ9Q","s":"0","c":[],"bt":"0","b":[],"n":"A9X'
                              b'fpxIl1LcIkMhUSCCC8fgvkuX8gG9xK3SM-S8a8Y_U"}')

        dig = reg.getTae(snKey(pre=regk, sn=0))
        assert bytes(dig) == b'EJfe0JaRiSWTCnasczAPkvZ-M2dd5nnhxcTcS59ssXg5'

    # registry with backers, no signatures.  should escrow
    with basing.openDB() as db, keeping.openKS() as kpr, viring.openReger() as reg:
        hby, hab = buildHab(db, kpr)
        vcp = eventing.incept(hab.pre,
                              baks=["BAOcciw30IVQsaenKXpiyMVrjtPDW3KeD_6KFnSfoaqI"],
                              toad=1,
                              cnfg=[],
                              code=MtrDex.Blake3_256)
        regk = vcp.pre

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(regk, vcp.ked["s"], vcp.said)

        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)

        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        #diger = rotser.saider
        saider = Saider(qb64=rotser.said)

        with pytest.raises(MissingWitnessSignatureError):
            Tever(serder=vcp, seqner=seqner, saider=saider, db=db, reger=reg)

        dgkey = dgKey(pre=regk, dig=vcp.said)
        vcp = reg.getTvt(dgkey)
        assert bytes(vcp) == (b'{"v":"KERI10JSON00013d_","t":"vcp","d":"EGMjDTKwtL24UE06lU1ZR6LGBQFZTRa5bFiA'
                    b'3WDTa8GO","i":"EGMjDTKwtL24UE06lU1ZR6LGBQFZTRa5bFiA3WDTa8GO","ii":"EPst_DQ1d'
                    b'8VCMGHB475dgKWCxO3qX4HlvW_4_lsrVZ9Q","s":"0","c":[],"bt":"1","b":["BAOcciw30'
                    b'IVQsaenKXpiyMVrjtPDW3KeD_6KFnSfoaqI"],"n":"A9XfpxIl1LcIkMhUSCCC8fgvkuX8gG9xK'
                    b'3SM-S8a8Y_U"}')

        anc = reg.getAnc(dgkey)
        assert bytes(anc) == b'0AAAAAAAAAAAAAAAAAAAAAABEAfW0zq1WbQ7e6fYQ8EvEZUpZ6nn1RX_Zjmczeke6JTx'
        assert reg.getTel(snKey(pre=regk, sn=0)) is None
        dig = reg.getTwe(snKey(pre=regk, sn=0))
        assert bytes(dig) ==b'EGMjDTKwtL24UE06lU1ZR6LGBQFZTRa5bFiA3WDTa8GO'


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
        rseal = keventing.SealEvent(i=regk, s=vcp.ked["s"], d=vcp.said)

        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)

        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        #diger = rotser.saider
        saider = Saider(qb64=rotser.said)

        tev = Tever(serder=vcp, seqner=seqner, saider=saider, db=db, reger=reg)

        assert tev.prefixer.qb64 == vcp.pre
        assert tev.sn == 0

        dgkey = dgKey(pre=regk, dig=vcp.said)
        assert bytes(reg.getTvt(dgkey)) == (b'{"v":"KERI10JSON000113_","t":"vcp","d":"ECRIn7b_Y6aB-G3x45-fPb_LQgke8CDq0taW'
                b'GplUj03s","i":"ECRIn7b_Y6aB-G3x45-fPb_LQgke8CDq0taWGplUj03s","ii":"EPst_DQ1d'
                b'8VCMGHB475dgKWCxO3qX4HlvW_4_lsrVZ9Q","s":"0","c":["NB"],"bt":"0","b":[],"n":'
                b'"A9XfpxIl1LcIkMhUSCCC8fgvkuX8gG9xK3SM-S8a8Y_U"}')


        assert bytes(reg.getAnc(dgkey)) == b'0AAAAAAAAAAAAAAAAAAAAAABEFEUzOixM-Avz6VPmQoB59eYQ2oan9ltJ1JOSe-QQFRq'
        assert bytes(reg.getTel(snKey(pre=regk, sn=0))) == b'ECRIn7b_Y6aB-G3x45-fPb_LQgke8CDq0taWGplUj03s'
        assert reg.getTibs(dgkey) == []
        assert reg.getTwe(snKey(pre=regk, sn=0)) is None

        # try to rotate a backerless registry
        vrt = eventing.rotate(regk, dig=vcp.said)
        rseal = keventing.SealEvent(regk, vrt.ked["s"], vrt.said)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)
        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        #diger = rotser.saider
        saider = Saider(qb64=rotser.said)

        # should raise validation err because rotation is not supported
        with pytest.raises(ValidationError):
            tev.update(serder=vrt, seqner=seqner, saider=saider)

        vcdig = b'EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU'

        iss = eventing.issue(vcdig=vcdig.decode("utf-8"), regk=regk)

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(iss.ked["i"], iss.ked["s"], iss.said)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)
        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        #diger = rotser.saider
        saider = Saider(qb64=rotser.said)

        tev.update(iss, seqner=seqner, saider=saider)

        vci = vcdig
        dgkey = dgKey(pre=vci, dig=iss.said)
        assert bytes(reg.getTvt(dgkey)) == (b'{"v":"KERI10JSON0000ed_","t":"iss","d":"EPlZDm4GgNl2aZNvHyfbk-B8mN6dNMMdJxrR'
                                    b'LovbJSCS","i":"EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU","s":"0","ri":"E'
                                    b'CRIn7b_Y6aB-G3x45-fPb_LQgke8CDq0taWGplUj03s","dt":"2021-01-01T00:00:00.00000'
                                       b'0+00:00"}')
        assert bytes(reg.getAnc(dgkey)) == b'0AAAAAAAAAAAAAAAAAAAAAADEOMHrVBAHEJ-5qHzoBLLvBj_m9761m7CavMZmVOXgZpT'

        # revoke vc with no backers
        rev = eventing.revoke(vcdig=vcdig.decode("utf-8"), regk=regk, dig=iss.said)

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(rev.ked["i"], rev.ked["s"], rev.said)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)
        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        #diger = rotser.saider
        saider = Saider(qb64=rotser.said)

        tev.update(rev, seqner=seqner, saider=saider)
        dgkey = dgKey(pre=vci, dig=rev.said)
        assert bytes(reg.getTvt(dgkey)) == (b'{"v":"KERI10JSON000120_","t":"rev","d":"EGjtu2bIII28dwxA0BH8KeXCN03U7TN3SkLD'
                            b'1KZi77pj","i":"EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU","s":"1","ri":"E'
                            b'CRIn7b_Y6aB-G3x45-fPb_LQgke8CDq0taWGplUj03s","p":"EPlZDm4GgNl2aZNvHyfbk-B8mN'
                            b'6dNMMdJxrRLovbJSCS","dt":"2021-01-01T00:00:00.000000+00:00"}')
        # assert reg.getAnc(dgkey) == b'0AAAAAAAAAAAAAAAAAAAAABAECgc6yHeTRhsKh1M7k65feWZGCf_MG0dWoei5Q6SwgqU'


def test_tever_backers(mockHelpingNowUTC, mockCoringRandomNonce):
    # registry with backer and receipt
    with basing.openDB() as db, keeping.openKS() as kpr, viring.openReger() as reg:
        valSecret = 'ABjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw'

        # create receipt signer prefixer default code is non-transferable
        valSigner = Signer(qb64=valSecret, transferable=False)
        valPrefixer = Prefixer(qb64=valSigner.verfer.qb64)
        valpre = valPrefixer.qb64
        assert valpre == 'BPmRWtx8nwSzRdJ0zTvP5uBb0t3BSjjstDk0gTayFfjV'

        hby, hab = buildHab(db, kpr)

        vcp = eventing.incept(hab.pre,
                              baks=[valpre],
                              toad=1,
                              cnfg=[],
                              code=MtrDex.Blake3_256)
        regk = vcp.pre
        valCigar = valSigner.sign(ser=vcp.raw, index=0)

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(i=regk, s=vcp.ked["s"], d=vcp.said)

        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)

        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        #diger = rotser.saider
        saider = Saider(qb64=rotser.said)

        tev = Tever(serder=vcp, seqner=seqner, saider=saider, bigers=[valCigar], db=db, reger=reg)

        dgkey = dgKey(pre=regk, dig=vcp.said)
        assert bytes(reg.getTvt(dgkey)) == (b'{"v":"KERI10JSON00013d_","t":"vcp","d":"EBgdJt_ASWeq7HjOmut2E8vQL8P1c9VTPDA0'
                                            b'Pdh4KsZX","i":"EBgdJt_ASWeq7HjOmut2E8vQL8P1c9VTPDA0Pdh4KsZX","ii":"EPst_DQ1d'
                                            b'8VCMGHB475dgKWCxO3qX4HlvW_4_lsrVZ9Q","s":"0","c":[],"bt":"1","b":["BPmRWtx8n'
                                            b'wSzRdJ0zTvP5uBb0t3BSjjstDk0gTayFfjV"],"n":"A9XfpxIl1LcIkMhUSCCC8fgvkuX8gG9xK'
                                            b'3SM-S8a8Y_U"}')
        assert bytes(reg.getAnc(dgkey)) == b'0AAAAAAAAAAAAAAAAAAAAAABELUmsgBmQ-OwMp2Zi7NpnRvZPwcWqld49zvTP9r-I4vp'
        assert bytes(reg.getTel(snKey(pre=regk, sn=0))) == b'EBgdJt_ASWeq7HjOmut2E8vQL8P1c9VTPDA0Pdh4KsZX'
        assert [bytes(tib) for tib in reg.getTibs(dgkey)] == [b'AAAzew389hwVg7TzgHucIdznjjgWh9A9w3T2YAe6A1U7mQCG_tEhQ_px7G0ZO39GdtyDx4Z890e0'
                                                              b'WBPKdTyKbqIE']
        assert reg.getTwe(snKey(pre=regk, sn=0)) is None

        debSecret = 'AKUotEE0eAheKdDJh9QvNmSEmO_bjIav8V_GmctGpuCQ'

        # create receipt signer prefixer default code is non-transferable
        debSigner = Signer(qb64=debSecret, transferable=False)
        debPrefixer = Prefixer(qb64=debSigner.verfer.qb64)
        debpre = debPrefixer.qb64
        assert debpre == 'BJLT5kDB54CewL9oqnWdPBC5vxZV30u3i6o9HVcWMhZd'

        vrt = eventing.rotate(regk, dig=vcp.said, baks=[valpre], adds=[debpre])
        valCigar = valSigner.sign(ser=vrt.raw, index=0)
        debCigar = debSigner.sign(ser=vrt.raw, index=1)

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(regk, vrt.ked["s"], vrt.said)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)
        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        #diger = rotser.saider
        saider = Saider(qb64=rotser.said)

        tev.update(serder=vrt, seqner=seqner, saider=saider, bigers=[valCigar, debCigar])

        assert tev.baks == ['BPmRWtx8nwSzRdJ0zTvP5uBb0t3BSjjstDk0gTayFfjV',
                            'BJLT5kDB54CewL9oqnWdPBC5vxZV30u3i6o9HVcWMhZd']

        vcdig = b'EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU'

        bis = eventing.backerIssue(vcdig=vcdig.decode("utf-8"), regk=regk, regsn=tev.sn, regd=tev.serder.said)
        valCigar = valSigner.sign(ser=bis.raw, index=0)
        debCigar = debSigner.sign(ser=bis.raw, index=1)

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(bis.ked["i"], bis.ked["s"], bis.said)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)
        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        #diger = rotser.saider
        saider = Saider(qb64=rotser.said)

        tev.update(bis, seqner=seqner, saider=saider, bigers=[valCigar, debCigar])

        vci = vcdig
        dgkey = dgKey(pre=vci, dig=bis.said)
        assert bytes(reg.getTvt(dgkey)) == (b'{"v":"KERI10JSON000162_","t":"bis","d":"EN01O_jV46iSPtJMFXLNB83OWHtUl0wEDnMT'
                                            b'eHSWXJwf","i":"EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU","ii":"EBgdJt_AS'
                                            b'Weq7HjOmut2E8vQL8P1c9VTPDA0Pdh4KsZX","s":"0","ra":{"i":"EBgdJt_ASWeq7HjOmut2'
                                            b'E8vQL8P1c9VTPDA0Pdh4KsZX","s":"1","d":"EEc1UURU3liIomWOFeDVqCo-3QbZHFZCUorx8'
                                            b'MdZFZvy"},"dt":"2021-01-01T00:00:00.000000+00:00"}')


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
        rseal = keventing.SealEvent(i=regk, s=vcp.ked["s"], d=vcp.said)

        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)

        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        #diger = rotser.saider
        saider = Saider(qb64=rotser.said)

        tvy = Tevery(reger=reg, db=db)

        tvy.processEvent(serder=vcp, seqner=seqner, saider=saider)

        assert regk in tvy.tevers
        tev = tvy.tevers[regk]
        assert tev.prefixer.qb64 == vcp.pre
        assert tev.sn == 0

        # send vcp again, get error
        with pytest.raises(LikelyDuplicitousError):
            tvy.processEvent(serder=vcp, seqner=seqner, saider=saider)

        # process issue vc event
        vcdig = b'EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU'

        iss = eventing.issue(vcdig=vcdig.decode("utf-8"), regk=regk)

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(iss.ked["i"], iss.ked["s"], iss.said)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)
        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        #diger = rotser.saider
        saider = Saider(qb64=rotser.said)

        tvy.processEvent(serder=iss, seqner=seqner, saider=saider)
        status = tev.vcState(vcdig.decode("utf-8"))
        assert status.et == Ilks.iss
        assert status.s == '0'

        # revoke the vc
        rev = eventing.revoke(vcdig=vcdig.decode("utf-8"), regk=regk, dig=iss.said)

        # successfully anchor to a rotation event
        rseal = keventing.SealEvent(rev.ked["i"], rev.ked["s"], rev.said)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)
        seqner = Seqner(sn=int(rotser.ked["s"], 16))
        #diger = rotser.saider
        saider = Saider(qb64=rotser.said)

        tvy.processEvent(serder=rev, seqner=seqner, saider=saider)
        status = tev.vcState(vcdig.decode("utf-8"))
        assert status.et == Ilks.rev
        assert status.s == '1'


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
        rseal = keventing.SealEvent(i=regk, s=vcp.ked["s"], d=vcp.said)

        seqner = Seqner(sn=1)
        # said of rotation
        rotsaid = b'EFEUzOixM-Avz6VPmQoB59eYQ2oan9ltJ1JOSe-QQFRq'
        diger = coring.Diger(qb64b=rotsaid)

        tvy = Tevery(reger=reg, db=db)

        with pytest.raises(MissingAnchorError):  # Process before the Hab rotation event, will escrow
            tvy.processEvent(serder=vcp, seqner=seqner, saider=diger)

        assert regk not in tvy.tevers

        rot = hab.rotate(data=[rseal._asdict()])  # Now rotate so the achoring KEL event gets into the database
        rotser = serdering.SerderKERI(raw=rot)
        assert rotser.saidb == diger.qb64b

        tvy.processEscrows()  # process escrows and now the Tever event is good.
        assert regk in tvy.tevers
        tev = tvy.tevers[regk]
        assert tev.prefixer.qb64 == vcp.pre
        assert tev.sn == 0



if __name__ == "__main__":
    #test_tever_escrow()
    #test_tevery_process_escrow()
    test_prefixer()
