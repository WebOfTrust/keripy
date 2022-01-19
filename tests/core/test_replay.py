# -*- encoding: utf-8 -*-
"""
tests delegation primaily from keri.core.eventing

"""
import os
import datetime

import pytest

from keri import help
from keri.help import helping
from keri.db import dbing, basing
from keri.app import habbing, keeping, directing
from keri.core import coring, eventing, parsing

logger = help.ogler.getLogger()


def test_replay():
    """
    Test disjoint and conjoint replay

    Deb creates series of events.
    Deb replays Deb's events to Cam and collects Cam's receipts
    Deb replays Deb's events with Cam's recepts to Bev and collects Bev's receipts
    Deb replays Deb's events with both Cam's and  Bev's receipts to Cam
    Compare replay of Deb's events with receipts by both Deb and Cam to confirm identical
    """
    artSalt = coring.Salter(raw=b'abcdef0123456789').qb64

    with habbing.openHby(name="deb", base="test") as debHby, \
         habbing.openHby(name="cam", base="test") as camHby, \
         habbing.openHby(name="bev", base="test") as bevHby,  \
         habbing.openHby(name="art", base="test", salt=artSalt) as artHby:

        # setup Deb's habitat using default salt multisig already incepts
        sith = ["1/2", "1/2", "1/2"]  # weighted signing threshold
        debHab = debHby.makeHab(name="deb", isith=sith, icount=3)
        assert debHab.kever.prefixer.transferable

        # setup Cam's habitat using default salt multisig already incepts
        # Cam's receipts will be vrcs with 3 indexed sigantures attached
        sith = '2'  # hex str of threshold int
        camHab = camHby.makeHab(name="cam", isith=sith, icount=3)
        assert camHab.kever.prefixer.transferable

        # setup Bev's habitat using default salt nonstransferable already incepts
        # Bev's receipts will be rcts with a receipt couple attached
        sith = '1'  # hex str of threshold int
        bevHab = bevHby.makeHab(name="bev", isith=sith, icount=1, transferable=False)
        assert not bevHab.kever.prefixer.transferable

        # setup Art's habitat using custom salt nonstransferable so not match Bev
        # already incepts
        # Art's receipts will be rcts with a receipt couple attached
        sith = '1'  # hex str of threshold int
        artHab = artHby.makeHab(name="art", isith=sith, icount=1, transferable=False)
        assert not artHab.kever.prefixer.transferable

        # first setup disjoint replay then conjoint replay
        # Create series of event for Deb
        debMsgs = bytearray()
        debMsgs.extend(debHab.makeOwnInception())
        debMsgs.extend(debHab.interact())
        debMsgs.extend(debHab.rotate())
        debMsgs.extend(debHab.interact())
        debMsgs.extend(debHab.interact())
        debMsgs.extend(debHab.interact())
        debMsgs.extend(debHab.interact())

        assert debMsgs == (b'{"v":"KERI10JSON00018e_","t":"icp","d":"EgmiU27BZtfnJclZw6K_X67h'
                           b'wf6SDT3nJW1dr3Jq9D3s","i":"EgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1dr'
                           b'3Jq9D3s","s":"0","kt":["1/2","1/2","1/2"],"k":["DRxCLERO9eSvG4fl'
                           b'uzOsK52GCWCtKOZClVwA38Oa--MA","DCxzT16ikP6LKVJfr6hv1jmhynm6I4-Ko'
                           b'GYkJtd9uBro","DsDl5xSHnIlcGo13u5jDRr1jJMkQ34nEc5R6NYsdPS2k"],"n"'
                           b':"Eer5S019j0eEFNFLb0R0UDMoNLavlLiQ73fHGU7MUHXg","bt":"0","b":[],'
                           b'"c":[],"a":[]}-AADAAxwDO7vCR4Lxkg1ZCFB7YiCr1I7Cx9CBEYuS8uf5gc0m1'
                           b'n3x5fYylz5Loc-X3-d_4vPgkORVRDlLc9CDnrMekAAABgd5x9CqbFnAQevnZ5oUN'
                           b'UCxOEaW77c6P9lOTFFYL9rmVMHbbxGw4a_hzi3ZaUoU5lG3r_sR9E79Y0Fjv5kde'
                           b'CgACcuVpvt8Z-EHOwb6OSstNvJ4lMWVAowfhOK122xJIga-REzjiyZ5OWgU-c_X9'
                           b'QVesC-dB2ReU8ILaOe7XZuakCQ{"v":"KERI10JSON0000cb_","t":"ixn","d"'
                           b':"Eoy3g6inBwl9tU4XObauVN6HGcrspyJn-8zDHpjRDArQ","i":"EgmiU27BZtf'
                           b'nJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","s":"1","p":"EgmiU27BZtfnJclZ'
                           b'w6K_X67hwf6SDT3nJW1dr3Jq9D3s","a":[]}-AADAASUrG-BrIfFUUtN1X0Rz4m'
                           b'LdfA-ZQM_noyzaaMrBW6DEh2PhKHumi8FPOstrk8pW0Wdkq3FS_ElBnUch0yYOJC'
                           b'gABfWYYABCGm6utumn3svN0nokuHVWI4KeHR71ENgD-UlU9WkL7OCTxSfg2vDf28'
                           b'OMtCxFmTCcJKr4wdBKst2bRBAACacww3k98TR_HE0IcbYN2p1g-1yz9EmbvZJxDD'
                           b'e-ocPcPjkaNmN_9MnTHaMTj_uO6smWexygCHQRv4iJRgR0VCQ{"v":"KERI10JSO'
                           b'N0001c3_","t":"rot","d":"EgRAXqREqw3EvxZsTOGHKU2Aa70IJmd0XC6y7AQ'
                           b'gjwns","i":"EgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","s":"2'
                           b'","p":"Eoy3g6inBwl9tU4XObauVN6HGcrspyJn-8zDHpjRDArQ","kt":["1/2"'
                           b',"1/2","1/2"],"k":["Dj-DUwfCmOrE3ijqucR0I89_fYTFbyotaqeQyDfupkEU'
                           b'","DL-k_8BanjLYaAdm6WWKIpHcHwcbF834vnLPgpW1NL8k","DWG2ZFsWYUsbDI'
                           b'1Kmu8JH22iGaVDGvM7pnuT4y2oR3VI"],"n":"EYd4ha92A2yttnCoLMqFGRzh6n'
                           b'sgduE910LD-scP7C3Q","bt":"0","br":[],"ba":[],"a":[]}-AADAAbw0Nbe'
                           b'6hdYBpeDQq_JspQQRupajov_vF92N1M7XJ1EUMEAoHGpS3wXnT34t5jV6xnoAHxe'
                           b'b3XjQhOingYPQmDwABGuC0zlEg2Efcohgfw-K3_ikX9wnbrWJwKEKe5wz2uLrncJ'
                           b'VokI-s23CEbG8Sdpefm7SABCJS-Xi476T5ebXVBQACdLvWJKf-LraSwpjvCdeEYc'
                           b'3nku8QhrRh7SyUZ4DEr2OX29dfuV2OstTDHc-A52P1vnl-DCVadAoChUm6yfAdBw'
                           b'{"v":"KERI10JSON0000cb_","t":"ixn","d":"EHlKLWTe1lCakBrg-s_sSEbz'
                           b'a24YDvi9rxDQS5Wuph5E","i":"EgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1dr'
                           b'3Jq9D3s","s":"3","p":"EgRAXqREqw3EvxZsTOGHKU2Aa70IJmd0XC6y7AQgjw'
                           b'ns","a":[]}-AADAAKCxcesxrP3Fx0os-p56b4n-8QlLrVJKMiCVJxWZGpfRVFKR'
                           b'DOMEPe6PvwxwwJ3ksF8VwGsxOUZ8BglK1y-EEAQABlTVNnnK717gZGNKKfH2fYji'
                           b'sfaLA5tIvS6Hc79tCwSboFZkljaIiosNbL-ZYCRjR4r_0_kNkUheo3eGxJM3CCQA'
                           b'CCk6sYXHME_4M2__75SCWEQ7q_LAbhhZG5ih5153vbXkY1B_Df44vYRIvo2hVzUK'
                           b't2pHJPgx_XIOinb7qWAFJDw{"v":"KERI10JSON0000cb_","t":"ixn","d":"E'
                           b'JVdSFO631gld44xpJipwzQHqKP4cS_tcoBfrBG07BYI","i":"EgmiU27BZtfnJc'
                           b'lZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","s":"4","p":"EHlKLWTe1lCakBrg-s_'
                           b'sSEbza24YDvi9rxDQS5Wuph5E","a":[]}-AADAAbZOTjHCPR1fG4pVPYYi5_1pT'
                           b'YcE06ZdlvniCNFrk69IU7pc5hg3DUEjRTjqiq6IEp2Y8KcL5Tb4Da8Kzw0bECwAB'
                           b'JBRsCTvAsmjR0B_y2HEnL8lsZ8g6fwBvo8jo6KuRDF7Rosg15ZOBZjSiEq2iHO-H'
                           b'QanM7YJrqcqz3E_NzENJCgACBUy5ZHcYEUq6q02LiCWB8TnnIi0wGIjPjTA9nLX5'
                           b'MWBOYTxYNXKRt8OeQ1pEqZPwpEFLgAsBATDnWJr0xfK_Bg{"v":"KERI10JSON00'
                           b'00cb_","t":"ixn","d":"EYcmtiV1Z__uV7iCSxk5lbcDqMV8lE_zxFGgwc4bRs'
                           b'rg","i":"EgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","s":"5","'
                           b'p":"EJVdSFO631gld44xpJipwzQHqKP4cS_tcoBfrBG07BYI","a":[]}-AADAAO'
                           b'2BfTpTFyMRG_Q3C0SHRLjxRdtblQg_dpNdEPOsAa24-vBtvd5cX34SqmBh7UF2-d'
                           b'LpVkAqXs-i-Sj0krYGPCAABKOYuKg2lPx0v-Z6M-FLaHq_F1381vxi3GIRkeJA6V'
                           b'KBSg9jUQ4mYs7GbNi-kKwbakNAid-9X5EAR-dUNMaAGCwACphP6wVjRAnREENf3y'
                           b'VxYsdiFsUmAI7n0v7kSyvmkhfo64nX5hHga-cTnxspjd3Kk3r2YcSkq6MhUvCG32'
                           b'm28AQ{"v":"KERI10JSON0000cb_","t":"ixn","d":"EQ4_P5u46hGceGpc8hu'
                           b'rR7pTox-VkvkExLj6_CMtVejw","i":"EgmiU27BZtfnJclZw6K_X67hwf6SDT3n'
                           b'JW1dr3Jq9D3s","s":"6","p":"EYcmtiV1Z__uV7iCSxk5lbcDqMV8lE_zxFGgw'
                           b'c4bRsrg","a":[]}-AADAAVlO5R4sIWQXTgkmA5Mlf4_7cvWzxgExYs-yDOV_CAc'
                           b'ipXaSGs34xQh0GXZ6jWon8Hn_KrYtuLAHH_vV8Mq5dBAABJ2anAFF8T4ELwbkG8v'
                           b'-RbYSoUveWu3ir2yyf-6gjGDYAJ03xWpLYAWAmBOZr6ALE5BStOU6Zyd9DR_5Byg'
                           b'fJBwACIs8GWSkGuRqR0Mayo6QBHYax8mIDyBrGYZeZEtim7s51ERVZ3q0_A6YqRk'
                           b'z9Sy_fzFdiQM-GSDD4hEjVpbwkAg')

        # Play debMsgs to Cam
        # create non-local kevery for Cam to process msgs from Deb
        camKevery = eventing.Kevery(db=camHab.db,
                                    lax=False,
                                    local=False)
        parsing.Parser().parse(ims=bytearray(debMsgs), kvy=camKevery)
        # camKevery.process(ims=bytearray(debMsgs))  # give copy to process
        assert debHab.pre in camKevery.kevers
        assert camKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(camKevery.cues) == 7

        # get disjoints receipts (vrcs) from Cam of Deb's events by processing Cam's cues
        camMsgs = camHab.processCues(camKevery.cues)
        assert camMsgs == (b'{"v":"KERI10JSON00017e_","t":"icp","d":"E-kW2C8JK7v59OdT-2Yit5gt'
                           b'sny-4VdoZdYRpszkwkr4","i":"E-kW2C8JK7v59OdT-2Yit5gtsny-4VdoZdYRp'
                           b'szkwkr4","s":"0","kt":"2","k":["DJBtEHHnzNtE-zxH1xeX4wxs9rEfUQ8d'
                           b'1ancgJJ1BLKk","DMu6yPITjrOBoTPfsY-r1Rc0ead8GKmoCxA_BugKehgY","Df'
                           b'hpvbNyYu1fxTBTXy8eCgghMcOYnxkgoGPBr0ZBZPQA"],"n":"EJ85AI0se7UiFB'
                           b'FL1Vl80PnmQ-0dU6q_NXCh6BlSJcKg","bt":"0","b":[],"c":[],"a":[]}-A'
                           b'ADAABX9ffcpdqwmRKypAQ3t7suKTKwkiWH0lrKjenKjRVgkbRxo6yLgLGsPVgfxI'
                           b'hC-ofx-noe4mUdg5UcZ7PFBRDQABcX7FO3nbiMcAIDWOA209Dn1ASvNbV-zB1BF3'
                           b'B2CiQD6pBDnYileVsx2RiR6YvfhkXo-R3B_oUvRk2sahf-XaAgAChzdee55ownrC'
                           b'm-AhVpL3WiGj1a_9N3oeYRZH1hUWDB_Vr3SgahzH6L07PdeNUfmU5o3qTAcqdK3s'
                           b'dvL93tuYCg{"v":"KERI10JSON000091_","t":"rct","d":"EgmiU27BZtfnJc'
                           b'lZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","i":"EgmiU27BZtfnJclZw6K_X67hwf6'
                           b'SDT3nJW1dr3Jq9D3s","s":"0"}-FABE-kW2C8JK7v59OdT-2Yit5gtsny-4VdoZ'
                           b'dYRpszkwkr40AAAAAAAAAAAAAAAAAAAAAAAE-kW2C8JK7v59OdT-2Yit5gtsny-4'
                           b'VdoZdYRpszkwkr4-AADAA70M7un3lxttBK2ig8ZU-RjInM-9IzoXry16g0-K_exO'
                           b'TxBzhZK5Z749n96Q6D0Cw6tDPZ-Op5FrA83-mVOEPDgABdd7yuRAY95sGthqlo5B'
                           b'p3TWS5TYb1BQbO4UZKIowOzW0QzwrPXanUf6Cez63AsLZ_9W4wGQcd4RzzIKuJTW'
                           b'UBAACbg6UWYrfPKEWP42MdgSRrJLk7dXklyoCWhOFrqRRPGLW60s0AD5oB_fZjwa'
                           b'kLqtgiNWq7ERopN2kmCXaUpkTBQ{"v":"KERI10JSON000091_","t":"rct","d'
                           b'":"Eoy3g6inBwl9tU4XObauVN6HGcrspyJn-8zDHpjRDArQ","i":"EgmiU27BZt'
                           b'fnJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","s":"1"}-FABE-kW2C8JK7v59OdT'
                           b'-2Yit5gtsny-4VdoZdYRpszkwkr40AAAAAAAAAAAAAAAAAAAAAAAE-kW2C8JK7v5'
                           b'9OdT-2Yit5gtsny-4VdoZdYRpszkwkr4-AADAALnLgaMzcwy-HD1Q_eRNLyXkskw'
                           b'R8x5veIwy1-ku524iZ-o4pO6HpWlsmkNNCDsIBqzJo03WjYU7Du2cnTBV6BgAB9Z'
                           b'6XXimtVgFVO5g0JRojEg50q_0aWUWOTEHsUQy62gcrDe5sWnY1qtm3-8mo_jRBTV'
                           b'us7hYFK1R63-rt1OFMBQACzr2RoNjy7bj4Dgl1BZZ0qEVYpuZvbdlznXUOB_mvye'
                           b'ZEw9V0bSzgkiw2scfHV0tl4ofltZSREW3uKCmg35BmBA{"v":"KERI10JSON0000'
                           b'91_","t":"rct","d":"EgRAXqREqw3EvxZsTOGHKU2Aa70IJmd0XC6y7AQgjwns'
                           b'","i":"EgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","s":"2"}-FA'
                           b'BE-kW2C8JK7v59OdT-2Yit5gtsny-4VdoZdYRpszkwkr40AAAAAAAAAAAAAAAAAA'
                           b'AAAAAE-kW2C8JK7v59OdT-2Yit5gtsny-4VdoZdYRpszkwkr4-AADAAZqp1jGr-W'
                           b'cIJ8c-1BzNLIYbMtnVGVym3EJYz9sWmMO-6fVzQfJej711kl1Wkiv358vL0jY3Wm'
                           b'4n4SzNaEdJ6CgABWCAIaIGMY8-Sit4vfFhSmut8RRG4cvZtJ4IxyDh0BB5j_DzNZ'
                           b'6Deev_sDLdOO5deSlNB_TvSEYxYV68a-0FdBQAC378zkWXfshbQnJjvonnTr2M2V'
                           b'HwckFwWXYIz13YBiap2EFuDitBAU8p27eKG2qYt4lGERrES_OTIK52upuH0AA{"v'
                           b'":"KERI10JSON000091_","t":"rct","d":"EHlKLWTe1lCakBrg-s_sSEbza24'
                           b'YDvi9rxDQS5Wuph5E","i":"EgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1dr3Jq'
                           b'9D3s","s":"3"}-FABE-kW2C8JK7v59OdT-2Yit5gtsny-4VdoZdYRpszkwkr40A'
                           b'AAAAAAAAAAAAAAAAAAAAAAE-kW2C8JK7v59OdT-2Yit5gtsny-4VdoZdYRpszkwk'
                           b'r4-AADAAy4D-vvwrR2UtRf0-JwgsAphcsuWtaA6JU5VxJtKxdbY0oVQH7kOT6q9K'
                           b'eG4LyS3WM_l4h7HnV1sXFOPuHcnCCgABUpV9oJE7HfAJCkq0MU1_bonwXCcwF6DS'
                           b'nK_PbEvCx0DR3WpjGA9tzgbt7lb27S7_cn5dMQZcQPPTRM18VF8IBwAC6M_rY8eF'
                           b'gneD5j-vylXyRYLkfbUdxASDVhp6n8cyi1wPSKqv8zXnhYnhslsDPJNJkSI52TRM'
                           b'0jDdbMk1zKRWDg{"v":"KERI10JSON000091_","t":"rct","d":"EJVdSFO631'
                           b'gld44xpJipwzQHqKP4cS_tcoBfrBG07BYI","i":"EgmiU27BZtfnJclZw6K_X67'
                           b'hwf6SDT3nJW1dr3Jq9D3s","s":"4"}-FABE-kW2C8JK7v59OdT-2Yit5gtsny-4'
                           b'VdoZdYRpszkwkr40AAAAAAAAAAAAAAAAAAAAAAAE-kW2C8JK7v59OdT-2Yit5gts'
                           b'ny-4VdoZdYRpszkwkr4-AADAATIUtLtJYFRe0Or8d4GeHW-36tkhm010IKqWJoQt'
                           b'U4I5bNFoMbChd6ruxV-EcBFaapjFxl4lX5LOKOIQWHkQbDgABBymHY6_fhjHdhQU'
                           b'tgOJygQC-lmwCohosoxdgax8BOloCs_8irPKYDmj9mjRCOv78B-6eeatuldYm1UH'
                           b'9uk9CDQACPN55PAq6vZUUTlr2snI2G3SvjTXMGE7vpaVclEQOn4tNcBz_ERwCD-p'
                           b'GJbtgS71kk2sDg3L4hUTX6v_GIBZiCQ{"v":"KERI10JSON000091_","t":"rct'
                           b'","d":"EYcmtiV1Z__uV7iCSxk5lbcDqMV8lE_zxFGgwc4bRsrg","i":"EgmiU2'
                           b'7BZtfnJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","s":"5"}-FABE-kW2C8JK7v5'
                           b'9OdT-2Yit5gtsny-4VdoZdYRpszkwkr40AAAAAAAAAAAAAAAAAAAAAAAE-kW2C8J'
                           b'K7v59OdT-2Yit5gtsny-4VdoZdYRpszkwkr4-AADAA6fqo4-7JahfKXF1ZZIHzvf'
                           b'tSJmRfC2qHKAXHVd24La1gBz-jQGHRy3pbuogJ7LuiOfHZ5S-FJ-PHu2LCobfPBA'
                           b'ABDU2RCWxo1Cpt31VSgRROSzH3fKmNDcbpUw0ZEwgMwGwBmA0UW_eD2t75h4tfq_'
                           b'9UznmQ-UWy6vYq9r9fD-jHDgACQfpV88d4OTwNkAkigUyYXDHjhlplaYyucAlDdq'
                           b'0zEFI_QU1hKXbfXabGeiK9L4vGOFDHhEi61RCx-0VyCtsPCQ{"v":"KERI10JSON'
                           b'000091_","t":"rct","d":"EQ4_P5u46hGceGpc8hurR7pTox-VkvkExLj6_CMt'
                           b'Vejw","i":"EgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","s":"6"'
                           b'}-FABE-kW2C8JK7v59OdT-2Yit5gtsny-4VdoZdYRpszkwkr40AAAAAAAAAAAAAA'
                           b'AAAAAAAAAE-kW2C8JK7v59OdT-2Yit5gtsny-4VdoZdYRpszkwkr4-AADAAXyUC9'
                           b'nmRPtqMXG9ci4D1JITFGz7JhzDq0iFtXPHKE2l5jIsDHvm_wNb5CJn_lxCr50qtq'
                           b'LfV6ifPVKFqd0zNCQAB24NytxoFP110Gwcd6O7Rwceq5IhP819pVBAen0ZD_etJa'
                           b'MZE40IVaI_HqX7dULyTMbowfRYGTKLe60j8JpNlCQACe_UgWZTeu_7dE6A90oHu8'
                           b'M4pPWdg8tQumgHKw7refciRJDx87i5nz4UC81Mj6og-UPwaoW_UmBQKMkhEJ48sCw')

        # Play camMsgs to Deb
        # create non-local kevery for Deb to process msgs from Cam
        debKevery = eventing.Kevery(db=debHab.db,
                                    lax=False,
                                    local=False)
        parsing.Parser().parse(ims=bytearray(camMsgs), kvy=debKevery)
        # debKevery.process(ims=bytearray(camMsgs))  # give copy to process
        assert camHab.pre in debKevery.kevers
        assert debKevery.kevers[camHab.pre].sn == camHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Cam's events by processing Deb's cues
        debCamVrcs = debHab.processCues(debKevery.cues)
        assert debCamVrcs == (b'{"v":"KERI10JSON000091_","t":"rct","d":"E-kW2C8JK7v59OdT-2Yit5gt'
                              b'sny-4VdoZdYRpszkwkr4","i":"E-kW2C8JK7v59OdT-2Yit5gtsny-4VdoZdYRp'
                              b'szkwkr4","s":"0"}-FABEgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3'
                              b's0AAAAAAAAAAAAAAAAAAAAAAgEgRAXqREqw3EvxZsTOGHKU2Aa70IJmd0XC6y7AQ'
                              b'gjwns-AADAAEJw4Xod7bMCI6hlKQ-m2XzXj-sT3nuAhX3_SvSZosFfyGQj1hi_3o'
                              b'vDEFCh04QnGf5WbrcECY16QggKsVMMyBAAB4KEEjzcwbWMEry3PsGk8vdrzJ5c0m'
                              b'guNotQQKaRmEIPhazsh9lPJCbAQdJ-X5Nmo15VcYYIOi2RrNWUJ74KMAQACWQSkw'
                              b'Ma_Kqew9GeYDxobaN2aD5rSmIWLbkpj6m2q9inbW7KCbaz9vgWZMu124vIefGRcz'
                              b'oekARWPuCwgSXZfAQ')

        # Play disjoints debCamVrcs to Cam
        parsing.Parser().parseOne(ims=bytearray(debCamVrcs), kvy=camKevery)
        # camKevery.processOne(ims=bytearray(debCamVrcs))  # give copy to process

        # Play debMsgs to Bev
        # create non-local kevery for Bev to process msgs from Deb
        bevKevery = eventing.Kevery(db=bevHab.db,
                                    lax=False,
                                    local=False)
        parsing.Parser().parse(ims=bytearray(debMsgs), kvy=bevKevery)
        # bevKevery.process(ims=bytearray(debMsgs))  # give copy to process
        assert debHab.pre in bevKevery.kevers
        assert bevKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(bevKevery.cues) == 7

        # get disjoints receipts (rcts) from Bev of Deb's events by processing Bevs's cues
        bevMsgs = bevHab.processCues(bevKevery.cues)
        assert bevMsgs == (b'{"v":"KERI10JSON0000f4_","t":"icp","d":"E91pCFGs1Hm_B43_LIi0jCOV'
                           b'7DpPHn-HqHon4uJINaNw","i":"BCqmHiYBZx_uaQiCTVeum-vt1ZPti8chqb-Gp'
                           b'QBPaurA","s":"0","kt":"1","k":["BCqmHiYBZx_uaQiCTVeum-vt1ZPti8ch'
                           b'qb-GpQBPaurA"],"n":"","bt":"0","b":[],"c":[],"a":[]}-AABAA2NToUy'
                           b'43Ua8Ok1UOUTJGWoglnKVQmoEexxjbf9cUqe76Gh4CdeeK2NfT58F-18RWi6WXoP'
                           b'hAhnaKmdKnK2J_Aw{"v":"KERI10JSON000091_","t":"rct","d":"EgmiU27B'
                           b'ZtfnJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","i":"EgmiU27BZtfnJclZw6K_X'
                           b'67hwf6SDT3nJW1dr3Jq9D3s","s":"0"}-CABBCqmHiYBZx_uaQiCTVeum-vt1ZP'
                           b'ti8chqb-GpQBPaurA0BCay0z3y9YFHQO6Z7jy5xh_t74Y_4lJcvTdF46uvAJzV09'
                           b'GGQLXtKK4tplwyKHT58yy9uqAV0_0wOFZGIEG5lBQ{"v":"KERI10JSON000091_'
                           b'","t":"rct","d":"Eoy3g6inBwl9tU4XObauVN6HGcrspyJn-8zDHpjRDArQ","'
                           b'i":"EgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","s":"1"}-CABBC'
                           b'qmHiYBZx_uaQiCTVeum-vt1ZPti8chqb-GpQBPaurA0BRqTp4tQjRgtrJk1Hl_92'
                           b'MHYQonDUnWmjU61Af0zpAFBSGorap6Br5flNdBpTIfCDHPNru_V771ynDi-Rwj2v'
                           b'Bg{"v":"KERI10JSON000091_","t":"rct","d":"EgRAXqREqw3EvxZsTOGHKU'
                           b'2Aa70IJmd0XC6y7AQgjwns","i":"EgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1'
                           b'dr3Jq9D3s","s":"2"}-CABBCqmHiYBZx_uaQiCTVeum-vt1ZPti8chqb-GpQBPa'
                           b'urA0BVjnMzuWPHd_QM9P7OnL4tU7yIENr3K2B2p3KQZRj67b5Wkinv67ro_gltaB'
                           b'FK4PXb8LouUckRL8dgRnsvZtWDQ{"v":"KERI10JSON000091_","t":"rct","d'
                           b'":"EHlKLWTe1lCakBrg-s_sSEbza24YDvi9rxDQS5Wuph5E","i":"EgmiU27BZt'
                           b'fnJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","s":"3"}-CABBCqmHiYBZx_uaQiC'
                           b'TVeum-vt1ZPti8chqb-GpQBPaurA0BSbNEMSxwResaiMT5Al3GyyXIZs4Ya4zI91'
                           b'DsO24iBUgGug7XUo2qSQJ1cbC-ZMphbACYvLonvlfVkFy6Ptx4BA{"v":"KERI10'
                           b'JSON000091_","t":"rct","d":"EJVdSFO631gld44xpJipwzQHqKP4cS_tcoBf'
                           b'rBG07BYI","i":"EgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","s"'
                           b':"4"}-CABBCqmHiYBZx_uaQiCTVeum-vt1ZPti8chqb-GpQBPaurA0B3GwlHrRTK'
                           b'PWw5AF3dIyIc0Csl7WMPbZlmGOlMKbhFdIq8nt-pcCe-wRDrdXk78ese3kGCEPR7'
                           b'5RuPmff_fymBg{"v":"KERI10JSON000091_","t":"rct","d":"EYcmtiV1Z__'
                           b'uV7iCSxk5lbcDqMV8lE_zxFGgwc4bRsrg","i":"EgmiU27BZtfnJclZw6K_X67h'
                           b'wf6SDT3nJW1dr3Jq9D3s","s":"5"}-CABBCqmHiYBZx_uaQiCTVeum-vt1ZPti8'
                           b'chqb-GpQBPaurA0BXOSv2uyENysIcooyC6tys5EWswI1rxNs2ClH3wqlCqGkxr97'
                           b'Rx6vPqbxImrGJ-nKMhYkqS413MkAPNwuWhqFAA{"v":"KERI10JSON000091_","'
                           b't":"rct","d":"EQ4_P5u46hGceGpc8hurR7pTox-VkvkExLj6_CMtVejw","i":'
                           b'"EgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","s":"6"}-CABBCqmH'
                           b'iYBZx_uaQiCTVeum-vt1ZPti8chqb-GpQBPaurA0BXj-h3cIdc5sbMlCpcsxVZx6'
                           b'TaFS11tX0_zttjmlHrPrq5Kk_zPuSSAti47dRmpN_2tSoRYtGByllWGzGnNn2Bw')

        # Play bevMsgs to Deb
        parsing.Parser().parse(ims=bytearray(bevMsgs), kvy=debKevery)
        # debKevery.process(ims=bytearray(bevMsgs))  # give copy to process
        assert bevHab.pre in debKevery.kevers
        assert debKevery.kevers[bevHab.pre].sn == bevHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Bev's events by processing Deb's cues
        debBevVrcs = debHab.processCues(debKevery.cues)
        assert debBevVrcs == (b'{"v":"KERI10JSON000091_","t":"rct","d":"E91pCFGs1Hm_B43_LIi0jCOV'
                              b'7DpPHn-HqHon4uJINaNw","i":"BCqmHiYBZx_uaQiCTVeum-vt1ZPti8chqb-Gp'
                              b'QBPaurA","s":"0"}-FABEgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3'
                              b's0AAAAAAAAAAAAAAAAAAAAAAgEgRAXqREqw3EvxZsTOGHKU2Aa70IJmd0XC6y7AQ'
                              b'gjwns-AADAAolzi_N7g0q792H7aQoB_bVwaNPMQ61UhXDKxrhX5uS6BhCuxHHCIb'
                              b'ELjpyjLUBQvKAs0rMQOgDI0sOGvZa6hBAABfBLZZ60qWfcVVnRx25T4FP8cCg7nH'
                              b'QiF_rowNlbvXjI_sUUgsojVlEm570AwosNockcJr1QLkO-wb0bz59DxBAACQ6gcg'
                              b'0EPlK-VURztqz3IXy_0ASludvqiA2DnV5N918b6fmCTCW01bSrJzEVlo8u1ZazLB'
                              b'ZHWxPUbYUT2FpSrBg')

        # Play disjoints debBevVrcs to Bev
        parsing.Parser().parseOne(ims=bytearray(debBevVrcs), kvy=bevKevery)
        # bevKevery.processOne(ims=bytearray(debBevVrcs))  # give copy to process

        # now setup conjoint replay

        # Replay Deb's First Seen Events with receipts (vrcs and rcts) from both Cam and Bev
        # datetime is different in each run in the fse attachment in clone replay
        # so we either have to force dts in db or we parse in pieces
        debFelMsgs = bytearray()
        fn = 0
        cloner = debHab.db.clonePreIter(pre=debHab.pre, fn=fn)  # create iterator
        msg = next(cloner)  # get zeroth event with attachments
        assert len(msg) == 1474
        debFelMsgs.extend(msg)

        # parse msg
        serder = coring.Serder(raw=msg)
        assert serder.raw == debHab.iserder.raw
        assert serder.sn == fn  # no recovery forks so sn == fn
        assert serder.ked["t"] == coring.Ilks.icp
        del msg[:len(serder.raw)]
        assert len(msg) == 1076

        counter = coring.Counter(qb64b=msg)  # attachment length quadlets counter
        assert counter.code == coring.CtrDex.AttachedMaterialQuadlets
        assert counter.count == (len(msg) - len(counter.qb64b)) // 4 == 268
        del msg[:len(counter.qb64b)]
        assert len(msg) == 1072 == 268 * 4

        counter = coring.Counter(qb64b=msg)  # indexed signatures counter
        assert counter.code == coring.CtrDex.ControllerIdxSigs
        assert counter.count == 3  # multisig deb
        del msg[:len(counter.qb64b)]
        assert len(msg) == 1068

        for i in range(counter.count):  # parse signatures
            siger = coring.Siger(qb64b=msg)
            del msg[:len(siger.qb64b)]
        assert len(msg) == 1068 - 3 * len(siger.qb64b) == 804

        counter = coring.Counter(qb64b=msg)  # trans receipt (vrc) counter
        assert counter.code == coring.CtrDex.TransReceiptQuadruples
        assert counter.count == 3  # multisig cam
        del msg[:len(counter.qb64b)]
        assert len(msg) == 800

        for i in range(counter.count):  # parse receipt quadruples
            prefixer, seqner, diger, siger = eventing.deTransReceiptQuadruple(msg, strip=True)
        assert len(msg) == 800 - 3 * (len(prefixer.qb64b) + len(seqner.qb64b) +
                                      len(diger.qb64b) + len(siger.qb64b)) == 200

        counter = coring.Counter(qb64b=msg)  # nontrans receipt (rct) counter
        assert counter.code == coring.CtrDex.NonTransReceiptCouples
        assert counter.count == 1  # single sig bev
        del msg[:len(counter.qb64b)]
        assert len(msg) == 196

        for i in range(counter.count):  # parse receipt couples
            prefixer, cigar = eventing.deReceiptCouple(msg, strip=True)
        assert len(msg) == 196 - 1 * (len(prefixer.qb64b) + len(cigar.qb64b)) == 64

        counter = coring.Counter(qb64b=msg)  # first seen replay couple counter
        assert counter.code == coring.CtrDex.FirstSeenReplayCouples
        assert counter.count == 1
        del msg[:len(counter.qb64b)]
        assert len(msg) == 60

        seqner = coring.Seqner(qb64b=msg)
        assert seqner.sn == fn == 0
        del msg[:len(seqner.qb64b)]
        assert len(msg) == 36  # 24 less

        dater = coring.Dater(qb64b=msg)
        assert (helping.fromIso8601(helping.nowIso8601()) -
                helping.fromIso8601(dater.dts)) > datetime.timedelta()
        del msg[:len(dater.qb64b)]
        assert len(msg) == 0  # 36 less

        cloner.close()  # must close or get lmdb error upon with exit
        """Exception ignored in: <generator object LMDBer.getAllOrdItemPreIter at 0x106fe1c10>
        Traceback (most recent call last):
        File "/Users/Load/Data/Code/public/keripy/src/keri/db/dbing.py", line 512, in getAllOrdItemPreIter
        yield (cn, bytes(val))  # (on, dig) of event
        lmdb.Error: Attempt to operate on closed/deleted/dropped object.
        """

        fn += 1
        cloner = debHab.db.clonePreIter(pre=debHab.pre, fn=fn)  # create iterator not at 0
        msg = next(cloner)  # next event with attachments
        assert len(msg) == 1279
        serder = coring.Serder(raw=msg)
        assert serder.sn == fn  # no recovery forks so sn == fn
        assert serder.ked["t"] == coring.Ilks.ixn
        debFelMsgs.extend(msg)

        fn += 1
        msg = next(cloner)  # get zeroth event with attachments
        serder = coring.Serder(raw=msg)
        assert serder.sn == fn  # no recovery forks so sn == fn
        assert serder.ked["t"] == coring.Ilks.rot
        assert len(msg) == 1527
        assert ([verfer.qb64 for verfer in serder.verfers] ==
                [verfer.qb64 for verfer in debHab.kever.verfers])
        debFelMsgs.extend(msg)

        fn += 1
        while (fn <= 6):
            msg = next(cloner)  # get zeroth event with attachments
            serder = coring.Serder(raw=msg)
            assert serder.sn == fn  # no recovery forks so sn == fn
            assert serder.ked["t"] == coring.Ilks.ixn
            assert len(msg) == 1279
            debFelMsgs.extend(msg)
            fn += 1

        assert len(debFelMsgs) == 9396
        cloner.close()  # must close or get lmdb error upon with exit

        msgs = debHab.replay()
        assert msgs == debFelMsgs

        # Play Cam's messages to Bev
        parsing.Parser().parse(ims=bytearray(camMsgs), kvy=bevKevery)
        # bevKevery.process(ims=bytearray(camMsgs))  # give copy to process
        assert camHab.pre in bevKevery.kevers
        assert bevKevery.kevers[camHab.pre].sn == camHab.kever.sn == 0
        assert len(bevKevery.cues) == 1

        # Play Bev's messages to Cam
        parsing.Parser().parse(ims=bytearray(bevMsgs), kvy=camKevery)
        # camKevery.process(ims=bytearray(bevMsgs))  # give copy to process
        assert bevHab.pre in camKevery.kevers
        assert camKevery.kevers[bevHab.pre].sn == bevHab.kever.sn == 0
        assert len(camKevery.cues) == 1

        camDebFelMsgs = camHab.replay(pre=debHab.pre)
        bevDebFelMsgs = bevHab.replay(pre=debHab.pre)

        assert len(bevDebFelMsgs) == len(camDebFelMsgs) == len(debFelMsgs) == 9396

        # create non-local kevery for Art to process conjoint replay msgs from Deb
        artKevery = eventing.Kevery(db=artHab.db,
                                    lax=False,
                                    local=False)
        # process Cam's inception so Art will proces Cam's vrcs without escrowing
        camIcpMsg = camHab.makeOwnInception()
        parsing.Parser().parse(ims=bytearray(camIcpMsg), kvy=artKevery)
        # artKevery.process(ims=bytearray(camIcpMsg))
        assert camHab.pre in artKevery.kevers
        assert len(artKevery.cues) == 1

        # process in cloned mode
        artKevery.cloned = True
        parsing.Parser().parse(ims=bytearray(debFelMsgs), kvy=artKevery)
        assert debHab.pre in artKevery.kevers
        assert artKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(artKevery.cues) == 8
        artDebFelMsgs = artHab.replay(pre=debHab.pre)
        assert len(artDebFelMsgs) == 9396

    assert not os.path.exists(artHby.ks.path)
    assert not os.path.exists(artHby.db.path)
    assert not os.path.exists(bevHby.ks.path)
    assert not os.path.exists(bevHby.db.path)
    assert not os.path.exists(camHby.ks.path)
    assert not os.path.exists(camHby.db.path)
    assert not os.path.exists(debHby.ks.path)
    assert not os.path.exists(debHby.db.path)

    """End Test"""


def test_replay_all():
    """
    Test conjoint replay all

    Setup database with events from Deb, Cam, Bev, abd Art
    Replay all the events in database.

    """
    artSalt = coring.Salter(raw=b'abcdef0123456789').qb64


    with habbing.openHby(name="deb", base="test") as debHby, \
         habbing.openHby(name="cam", base="test") as camHby, \
         habbing.openHby(name="bev", base="test") as bevHby,  \
         habbing.openHby(name="art", base="test", salt=artSalt) as artHby:

        # setup Deb's habitat using default salt multisig already incepts
        sith = ["1/2", "1/2", "1/2"]  # weighted signing threshold
        #debHab = habbing.Habitat(ks=debKS, db=debDB, isith=sith, icount=3,
                                 #temp=True)
        debHab = debHby.makeHab(name='test', isith=sith, icount=3)
        #assert debHab.ks == debKS
        #assert debHab.db == debDB
        assert debHab.kever.prefixer.transferable

        # setup Cam's habitat using default salt multisig already incepts
        # Cam's receipts will be vrcs with 3 indexed sigantures attached
        sith = '2'  # hex str of threshold int
        #camHab = habbing.Habitat(ks=camKS, db=camDB, isith=sith, icount=3,
                                 #temp=True)
        camHab = camHby.makeHab(name='test', isith=sith, icount=3)
        #assert camHab.ks == camKS
        #assert camHab.db == camDB
        assert camHab.kever.prefixer.transferable

        # setup Bev's habitat using default salt nonstransferable already incepts
        # Bev's receipts will be rcts with a receipt couple attached
        sith = '1'  # hex str of threshold int
        #bevHab = habbing.Habitat(ks=bevKS, db=bevDB, isith=sith, icount=1,
                                 #transferable=False, temp=True)
        bevHab = bevHby.makeHab(name='test', isith=sith, icount=1, transferable=False)
        #assert bevHab.ks == bevKS
        #assert bevHab.db == bevDB
        assert not bevHab.kever.prefixer.transferable

        # setup Art's habitat using custom salt nonstransferable so not match Bev
        # already incepts
        # Art's receipts will be rcts with a receipt couple attached
        salt = coring.Salter(raw=b'abcdef0123456789').qb64
        sith = '1'  # hex str of threshold int
        #artHab = habbing.Habitat(ks=artKS, db=artDB, isith=sith, icount=1,
                                 #salt=salt, transferable=False, temp=True)
        artHab = artHby.makeHab(name='test', isith=sith, icount=1, transferable=False)
        #assert artHab.ks == artKS
        #assert artHab.db == artDB
        assert not artHab.kever.prefixer.transferable

        # Create series of event for Deb
        debMsgs = bytearray()
        debMsgs.extend(debHab.makeOwnInception())
        debMsgs.extend(debHab.interact())
        debMsgs.extend(debHab.rotate())
        debMsgs.extend(debHab.interact())
        debMsgs.extend(debHab.interact())
        debMsgs.extend(debHab.interact())
        debMsgs.extend(debHab.interact())

        # Play debMsgs to Cam
        # create non-local kevery for Cam to process msgs from Deb
        camKevery = eventing.Kevery(db=camHab.db,
                                    lax=False,
                                    local=False)
        parsing.Parser().parse(ims=bytearray(debMsgs), kvy=camKevery)
        # camKevery.process(ims=bytearray(debMsgs))  # give copy to process
        assert debHab.pre in camKevery.kevers
        assert camKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(camKevery.cues) == 7

        # get disjoints receipts (vrcs) from Cam of Deb's events by processing Cam's cues
        camMsgs = camHab.processCues(camKevery.cues)

        # Play camMsgs to Deb
        # create non-local kevery for Deb to process msgs from Cam
        debKevery = eventing.Kevery(db=debHab.db,
                                    lax=False,
                                    local=False)
        parsing.Parser().parse(ims=bytearray(camMsgs), kvy=debKevery)
        # debKevery.process(ims=bytearray(camMsgs))  # give copy to process
        assert camHab.pre in debKevery.kevers
        assert debKevery.kevers[camHab.pre].sn == camHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Cam's events by processing Deb's cues
        debCamVrcs = debHab.processCues(debKevery.cues)

        # Play disjoints debCamVrcs to Cam
        parsing.Parser().parseOne(ims=bytearray(debCamVrcs), kvy=camKevery)
        # camKevery.processOne(ims=bytearray(debCamVrcs))  # give copy to process

        # Play debMsgs to Bev
        # create non-local kevery for Bev to process msgs from Deb
        bevKevery = eventing.Kevery(db=bevHab.db,
                                    lax=False,
                                    local=False)
        parsing.Parser().parse(ims=bytearray(debMsgs), kvy=bevKevery)
        # bevKevery.process(ims=bytearray(debMsgs))  # give copy to process
        assert debHab.pre in bevKevery.kevers
        assert bevKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(bevKevery.cues) == 7

        # get disjoints receipts (rcts) from Bev of Deb's events by processing Bevs's cues
        bevMsgs = bevHab.processCues(bevKevery.cues)

        # Play bevMsgs to Deb
        parsing.Parser().parse(ims=bytearray(bevMsgs), kvy=debKevery)
        # debKevery.process(ims=bytearray(bevMsgs))  # give copy to process
        assert bevHab.pre in debKevery.kevers
        assert debKevery.kevers[bevHab.pre].sn == bevHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Bev's events by processing Deb's cues
        debBevVrcs = debHab.processCues(debKevery.cues)

        # Play disjoints debBevVrcs to Bev
        parsing.Parser().parseOne(ims=bytearray(debBevVrcs), kvy=bevKevery)
        # bevKevery.processOne(ims=bytearray(debBevVrcs))  # give copy to process

        # now setup replay
        debAllFelMsgs = debHab.replayAll()
        assert len(debAllFelMsgs) == 11726

        # create non-local kevery for Art to process conjoint replay msgs from Deb
        artKevery = eventing.Kevery(db=artHab.db,
                                    lax=False,
                                    local=False)
        # process Cam's inception so Art will proces Cam's vrcs without escrowing
        camIcpMsg = camHab.makeOwnInception()
        parsing.Parser().parse(ims=bytearray(camIcpMsg), kvy=artKevery)
        assert camHab.pre in artKevery.kevers
        assert len(artKevery.cues) == 1
        # give copy to process in cloned mode
        artKevery.cloned = True
        parsing.Parser().parse(ims=bytearray(debAllFelMsgs), kvy=artKevery)
        assert debHab.pre in artKevery.kevers
        assert artKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(artKevery.cues) == 9
        artAllFelMsgs = artHab.replayAll()
        assert len(artAllFelMsgs) == 10922

    assert not os.path.exists(artHby.ks.path)
    assert not os.path.exists(artHby.db.path)
    assert not os.path.exists(bevHby.ks.path)
    assert not os.path.exists(bevHby.db.path)
    assert not os.path.exists(camHby.ks.path)
    assert not os.path.exists(camHby.db.path)
    assert not os.path.exists(debHby.ks.path)
    assert not os.path.exists(debHby.db.path)

    """End Test"""


if __name__ == "__main__":
    test_replay()
