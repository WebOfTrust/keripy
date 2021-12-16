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

    with basing.openDB(name="deb") as debDB, keeping.openKS(name="deb") as debKS, \
            basing.openDB(name="cam") as camDB, keeping.openKS(name="cam") as camKS, \
            basing.openDB(name="bev") as bevDB, keeping.openKS(name="bev") as bevKS, \
            basing.openDB(name="art") as artDB, keeping.openKS(name="art") as artKS:

        # setup Deb's habitat using default salt multisig already incepts
        sith = ["1/2", "1/2", "1/2"]  # weighted signing threshold
        debHab = habbing.Habitat(name='deb', ks=debKS, db=debDB, isith=sith, icount=3,
                                 temp=True)
        assert debHab.ks == debKS
        assert debHab.db == debDB
        assert debHab.kever.prefixer.transferable

        # setup Cam's habitat using default salt multisig already incepts
        # Cam's receipts will be vrcs with 3 indexed sigantures attached
        sith = '2'  # hex str of threshold int
        camHab = habbing.Habitat(name='cam', ks=camKS, db=camDB, isith=sith, icount=3,
                                 temp=True)
        assert camHab.ks == camKS
        assert camHab.db == camDB
        assert camHab.kever.prefixer.transferable

        # setup Bev's habitat using default salt nonstransferable already incepts
        # Bev's receipts will be rcts with a receipt couple attached
        sith = '1'  # hex str of threshold int
        bevHab = habbing.Habitat(name='bev', ks=bevKS, db=bevDB, isith=sith, icount=1,
                                 transferable=False, temp=True)
        assert bevHab.ks == bevKS
        assert bevHab.db == bevDB
        assert not bevHab.kever.prefixer.transferable

        # setup Art's habitat using custom salt nonstransferable so not match Bev
        # already incepts
        # Art's receipts will be rcts with a receipt couple attached
        salt = coring.Salter(raw=b'abcdef0123456789').qb64
        sith = '1'  # hex str of threshold int
        artHab = habbing.Habitat(name='art', ks=artKS, db=artDB, isith=sith, icount=1,
                                 salt=salt, transferable=False, temp=True)
        assert artHab.ks == artKS
        assert artHab.db == artDB
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

        assert debMsgs == (b'{"v":"KERI10JSON00018e_","t":"icp","d":"EbY3caaU2DRWxUkGZ89ZNmEo'
                           b'nFo7cevL36jqXg451epE","i":"EgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1dr'
                           b'3Jq9D3s","s":"0","kt":["1/2","1/2","1/2"],"k":["DRxCLERO9eSvG4fl'
                           b'uzOsK52GCWCtKOZClVwA38Oa--MA","DCxzT16ikP6LKVJfr6hv1jmhynm6I4-Ko'
                           b'GYkJtd9uBro","DsDl5xSHnIlcGo13u5jDRr1jJMkQ34nEc5R6NYsdPS2k"],"n"'
                           b':"Eer5S019j0eEFNFLb0R0UDMoNLavlLiQ73fHGU7MUHXg","bt":"0","b":[],'
                           b'"c":[],"a":[]}-AADAA2tqvvT24XNcwLF1YtcieUmzY1754BLazkxmtJZVngJ73'
                           b'YH3olK8tmF3lFmF_oRy-ccTRsuzuBhmxAl13ap8CAwABYLycLh22xuP1j9yrEObw'
                           b'Zgh_HGVbjxjIRfX0WrK2AQdzUM3LDqXj-m5h1aOpaxw-4qIsNJoeC868szHsP17F'
                           b'CQACpt5-G-bCHvKcWKgcPlO2ZIfTl4Ldr5FKE9MQa8APXV-iyBK2TK0hrFogKONb'
                           b'YkjxmWxpquQBuIcSmQ9Sn3L8Dg{"v":"KERI10JSON0000cb_","t":"ixn","d"'
                           b':"ET7a0bnuCkMp-zPXN7SS1HCcW9Yhatwr5JxzO-K5nwSk","i":"EgmiU27BZtf'
                           b'nJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","s":"1","p":"EbY3caaU2DRWxUkG'
                           b'Z89ZNmEonFo7cevL36jqXg451epE","a":[]}-AADAAq29O5VbrU65tzGdxlwqDa'
                           b'aHo0UbWRHJRc0N5g6wnzPD82dzBrNfMVbU0SGHCaeu1BokdNBeD4xw-MzWaAgBPB'
                           b'wABYUwff1SF0aGyCBXC_hIeEXjeSMA4fQu9W0BYaZKWtXjcAWXkco_6yerYyvXRD'
                           b'7utx1bopyPMoyuQHbf2bjU4BgACJ8LrupuAv0gsCtJT55Ix1AaVKoTWBpJs0V-Lv'
                           b'9B_Nn-6b92UEQkvozsEkPVwCIqslNqEam4EwNaZcFDmhAPvBw{"v":"KERI10JSO'
                           b'N0001c3_","t":"rot","d":"ELv7PoQqtu-0Sfdjt8ccri4rONvU7_YZGLFxgJx'
                           b'PC6dA","i":"EgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","s":"2'
                           b'","p":"ET7a0bnuCkMp-zPXN7SS1HCcW9Yhatwr5JxzO-K5nwSk","kt":["1/2"'
                           b',"1/2","1/2"],"k":["Dj-DUwfCmOrE3ijqucR0I89_fYTFbyotaqeQyDfupkEU'
                           b'","DL-k_8BanjLYaAdm6WWKIpHcHwcbF834vnLPgpW1NL8k","DWG2ZFsWYUsbDI'
                           b'1Kmu8JH22iGaVDGvM7pnuT4y2oR3VI"],"n":"EYd4ha92A2yttnCoLMqFGRzh6n'
                           b'sgduE910LD-scP7C3Q","bt":"0","br":[],"ba":[],"a":[]}-AADAAROo1lA'
                           b'bAvoqSu5M29dPiv42ctX1iAuhX-mn9qx3R2J2gS2dWxDUV7sQXjBBTDtiYIRPhXN'
                           b'er0cLnvtblzVXADQABgtnAobOTTkJ856y998SnM25emuRd6w1oe0YZAew2pX38ao'
                           b'TNnF2MMA9zVe3jrpblYVs9NsdvWGYaOq-ujJ1nAgACIbflIVTrBZbC4iprTo_eXF'
                           b'r9mizWsiIJ9pVAJzWYhPrEl7C5L743UdJJnlfQBIiORJphVgUUJ3hoBJgDICvZDA'
                           b'{"v":"KERI10JSON0000cb_","t":"ixn","d":"EQthDCDk4ripZv0mtnQO3Rou'
                           b'e-25BnJ9IbYgrH4krlzw","i":"EgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1dr'
                           b'3Jq9D3s","s":"3","p":"ELv7PoQqtu-0Sfdjt8ccri4rONvU7_YZGLFxgJxPC6'
                           b'dA","a":[]}-AADAA7uTn8cJjeZSao3gE0liMhglLm8yoERAlSZCbaJfUWsPGtVC'
                           b'gXbq6XMEcUZIigB4SRI-fps7ydgOl9cj-eqMcAQABHJJ__4tG90wG2zv0AgvaSn5'
                           b'SAKcrNKe0NJJVgFLp1ax_ZPUeXIA5zoZ2liziCL9OIbCX7xjv8tZz7BfxURKAAAA'
                           b'CKT3_K_hoTa2OyNF69GsmebOtBEE5FoMlRhb0kyyl6mUE1ctbILVl55KkMYiF7h_'
                           b'rtUe8ZGuaeyeXE1JRP2DfCA{"v":"KERI10JSON0000cb_","t":"ixn","d":"E'
                           b'LLOcsPHfXh2_vrQP8cQVDtf8ul9usY0YwFP4_lsAEec","i":"EgmiU27BZtfnJc'
                           b'lZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","s":"4","p":"EQthDCDk4ripZv0mtnQ'
                           b'O3Roue-25BnJ9IbYgrH4krlzw","a":[]}-AADAAGJxCimtWIC30GfDrfCG_cqsU'
                           b'pF77eV4s5D0qlO_V-VxoqTF2ndKesrBesK8e6gN49SOKiF3FkHL0HrCwaN3bCwAB'
                           b'HPbV7WtX0b_hsB95yEe9GhbLT6XNa0KXcjbPMyRTYWL9DT4bLIBqKKg88YFCF0Z7'
                           b'mnEh6sqZGOOpsv4j2frMAAACqfP1pXXaW81nBtrEYXn_EHsAZdw-G9falDj7u4vz'
                           b'pg0LcLWbXOkzlXaAtVdkZJNC91SUIXSH6O-zsgAwoY1HCQ{"v":"KERI10JSON00'
                           b'00cb_","t":"ixn","d":"EB-U60iiXd1sjDUKyuVq8zVBGNm2Qw0fp_cePYO3wQ'
                           b'ro","i":"EgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","s":"5","'
                           b'p":"ELLOcsPHfXh2_vrQP8cQVDtf8ul9usY0YwFP4_lsAEec","a":[]}-AADAAw'
                           b'Y7XzvFtoSGO5nbGVdUzJv-17JtwhgtyvkyfCxCb6DUcSieDdhbEhKkg5vAW3HCCG'
                           b'bZkte0Rhx2IY5RHjOfqCwABbAF8aERwd_uUmAhY9_i8ruchWkJ9THVSQB39r_sem'
                           b'sVT_zTxbGzNtf1y3xL2EFQkkSGok0a-eSZNjTZSm4gFDAACnWWiOko5d_1Hyrpcp'
                           b'zO-OkislSh5IEaGzw3CKM70egPQW0WArmM0uloOtvwB8Lnoxe2iDBRhwwLPRxUkj'
                           b'6cdAw{"v":"KERI10JSON0000cb_","t":"ixn","d":"E16LczbJQi-5XKgfDYN'
                           b'anLmY8Iu_TTsHl8IpNsk82vvo","i":"EgmiU27BZtfnJclZw6K_X67hwf6SDT3n'
                           b'JW1dr3Jq9D3s","s":"6","p":"EB-U60iiXd1sjDUKyuVq8zVBGNm2Qw0fp_ceP'
                           b'YO3wQro","a":[]}-AADAAN_-tKb7qjpLhPOgjY36tLaJl0Eye8S5UpFG9-WrhXu'
                           b'CFR3cSoHr9T_nqGu1IMPar8cPjzgUtxQluX9bT2gd0AQABqg-Qu9Mwb8jAUgN3Nt'
                           b'uG-ldU-Y1x1f0miXVaWDB5cuty6mD6HcHQO3WD6pvp02aptfe3teVgKJPAAvqGJ4'
                           b'aiCwACehzC7jJeFZsluXxpecmaFaZ-5o4rVinuZaJCS1hL68JOdTuzICUrxpEkE2'
                           b'2JoS01VvwFMSNkmLihR3AX1NfYAQ')

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
        assert camMsgs == (b'{"v":"KERI10JSON00017e_","t":"icp","d":"EBxnCnfhfY9y4aiZ0N5pxfLw'
                           b'-_GDDh0VUsvCUty3G4kE","i":"E-kW2C8JK7v59OdT-2Yit5gtsny-4VdoZdYRp'
                           b'szkwkr4","s":"0","kt":"2","k":["DJBtEHHnzNtE-zxH1xeX4wxs9rEfUQ8d'
                           b'1ancgJJ1BLKk","DMu6yPITjrOBoTPfsY-r1Rc0ead8GKmoCxA_BugKehgY","Df'
                           b'hpvbNyYu1fxTBTXy8eCgghMcOYnxkgoGPBr0ZBZPQA"],"n":"EJ85AI0se7UiFB'
                           b'FL1Vl80PnmQ-0dU6q_NXCh6BlSJcKg","bt":"0","b":[],"c":[],"a":[]}-A'
                           b'ADAAYGQ29NvgXUoeg18oJVy43DnKYp_OJNsHJxS7pja8WNDsvn3ohaLdm7vF0xik'
                           b'ySeiGgM04eDKh7QjS_Bg74c6CgABOBgDANwGSTw94a0eh7Yx3MuAC7_UYENV7NKZ'
                           b'vodDdLV3pnjK0XGtEBrryEqES_QrlK0pA_kMCRs8nI1UUuqJBQACPiv0e4IRRVne'
                           b'odFg0ZJebVe81Ng3wfhGL1EyOJZ1l2jGI6Q3sA9g4qSCC0DTQFovsRIcT16i0-IR'
                           b'T6iVffMYDg{"v":"KERI10JSON000091_","t":"rct","d":"EbY3caaU2DRWxU'
                           b'kGZ89ZNmEonFo7cevL36jqXg451epE","i":"EgmiU27BZtfnJclZw6K_X67hwf6'
                           b'SDT3nJW1dr3Jq9D3s","s":"0"}-FABE-kW2C8JK7v59OdT-2Yit5gtsny-4VdoZ'
                           b'dYRpszkwkr40AAAAAAAAAAAAAAAAAAAAAAAEBxnCnfhfY9y4aiZ0N5pxfLw-_GDD'
                           b'h0VUsvCUty3G4kE-AADAAnv0YuRqlB4sAVPS6CysPuwUJYK_3-BnnrA8lBSsd2xP'
                           b'Xm33EiwhZCbB7kn75nBqauElWYQgWzG5F1A4wjCqhBAABGMPWup3CHCmvZnXzT4L'
                           b'_YlBcnvZQDrtebTFGZ_t9ZeeRXpeETBtsbAdd1ri5-no_jl9YSo2cW-HzCF2V6hr'
                           b'aBAAC5205iYi693KIAv7flGyr1mAqXJfBt3PnHy2g7rD4O5uA_md15s97HDEJRIn'
                           b'c148IZG2hRx70S-yhzFAQzi8gDQ{"v":"KERI10JSON000091_","t":"rct","d'
                           b'":"ET7a0bnuCkMp-zPXN7SS1HCcW9Yhatwr5JxzO-K5nwSk","i":"EgmiU27BZt'
                           b'fnJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","s":"1"}-FABE-kW2C8JK7v59OdT'
                           b'-2Yit5gtsny-4VdoZdYRpszkwkr40AAAAAAAAAAAAAAAAAAAAAAAEBxnCnfhfY9y'
                           b'4aiZ0N5pxfLw-_GDDh0VUsvCUty3G4kE-AADAAn0BrfjeflmYv2lUfdvFofzEjXI'
                           b'mXZt8VgjO0wUnAOEZaDEtcmtB_rneugrNWs1Ba0FURnwBY928LhzG3Vjo_DAABFS'
                           b'xt_Sjl1FbkGH8Klka10utyZm-4DwNqB1q1lkCXCMyqMTqbZy7S_afbUZFzi5bRVP'
                           b'WR0FGOLHT1AeIegFXwDgAC4XshkcNxDOvOsJ9pR3mSCknSaVenuquYcUXkFqrSxl'
                           b'8XxWVc2WprmMehnnfHatRcpNBz_ZYFcHkUqDyn_Qa7AA{"v":"KERI10JSON0000'
                           b'91_","t":"rct","d":"ELv7PoQqtu-0Sfdjt8ccri4rONvU7_YZGLFxgJxPC6dA'
                           b'","i":"EgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","s":"2"}-FA'
                           b'BE-kW2C8JK7v59OdT-2Yit5gtsny-4VdoZdYRpszkwkr40AAAAAAAAAAAAAAAAAA'
                           b'AAAAAEBxnCnfhfY9y4aiZ0N5pxfLw-_GDDh0VUsvCUty3G4kE-AADAArEJ5zaNy9'
                           b'5w6VkkuyWxP24C0yi5Uj-CnUAXRHqAgmdzUUsM9NGneH9cgD9MFWZyO9fLzkCYoE'
                           b'pChqNaIEZk6CAABcY4R7-l38_4izOl9fENuVhnoLr5JuOhunbv3HT_8lQgUCdhVH'
                           b'GzvFG5kgk7-J9yFwcIDktCowRL4eeji9-45BwACNXR9Y4oxbQonImBL0Aia1Mz8r'
                           b'7sxosBTZQGWuX1K21N2cR4iPFnLo3Y3KoQMwGa9raiCGXnyet0QOVG2Pf2TDg{"v'
                           b'":"KERI10JSON000091_","t":"rct","d":"EQthDCDk4ripZv0mtnQO3Roue-2'
                           b'5BnJ9IbYgrH4krlzw","i":"EgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1dr3Jq'
                           b'9D3s","s":"3"}-FABE-kW2C8JK7v59OdT-2Yit5gtsny-4VdoZdYRpszkwkr40A'
                           b'AAAAAAAAAAAAAAAAAAAAAAEBxnCnfhfY9y4aiZ0N5pxfLw-_GDDh0VUsvCUty3G4'
                           b'kE-AADAAKcmIlEArOcS7Gf2jpgp5odjkccGM4kdyHItJHfVYjv3ENC_h1uVsHqil'
                           b'OnZrJD4_xzSMP69nC7WdPm_KpLu_AwABmRu7z1b5nTy6IYpUR9yK9STwyj1jkoOo'
                           b'3Kay2NxL-Zd1rz9F3dDt4KjMlyCl0YEwOMdV9HAnqyIyGGik6uqCDgACW47QIaWN'
                           b'LnDw391-fGmLurS3VJW5Ss2qyZgBA8dBLrClpotiRyaQ58LRU9B4HusLjwLerdH3'
                           b'E5UbZ_laV_0RBg{"v":"KERI10JSON000091_","t":"rct","d":"ELLOcsPHfX'
                           b'h2_vrQP8cQVDtf8ul9usY0YwFP4_lsAEec","i":"EgmiU27BZtfnJclZw6K_X67'
                           b'hwf6SDT3nJW1dr3Jq9D3s","s":"4"}-FABE-kW2C8JK7v59OdT-2Yit5gtsny-4'
                           b'VdoZdYRpszkwkr40AAAAAAAAAAAAAAAAAAAAAAAEBxnCnfhfY9y4aiZ0N5pxfLw-'
                           b'_GDDh0VUsvCUty3G4kE-AADAAX1iMk0OflQ9Zn81WZp9QkT_bKD3LX2_VzBVBrKr'
                           b'7vfbqlopPXRgpvIKIC3COibbH3-EAj1z8DCr6VmLAaOCJBQABHS2x2k8Nw3SO3rH'
                           b'BY396d8jaEkAWu_YtLje3zVf59OiFWozhVtOLz18YeqX9FXHs3Lueu1Ann54iBdQ'
                           b'DYHITBgACiOet3xguVapxc7wgL-GEdQcfnsqOvYps3c-cuNAo9gCAn8k9DTWZtR_'
                           b'EmlEK25kIprsPsLMg0vZhtyTr1wyDCA{"v":"KERI10JSON000091_","t":"rct'
                           b'","d":"EB-U60iiXd1sjDUKyuVq8zVBGNm2Qw0fp_cePYO3wQro","i":"EgmiU2'
                           b'7BZtfnJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","s":"5"}-FABE-kW2C8JK7v5'
                           b'9OdT-2Yit5gtsny-4VdoZdYRpszkwkr40AAAAAAAAAAAAAAAAAAAAAAAEBxnCnfh'
                           b'fY9y4aiZ0N5pxfLw-_GDDh0VUsvCUty3G4kE-AADAAN4Ms7bCOOZRnexep5Ddl3g'
                           b'N75oeWOtIWG9z1RoAX-Plync2qCs-aWJyXX00MnpSx0t_RByNcA26oajAYf9CiDQ'
                           b'AB0hZ7z5BUTIHF0SD_2H8gPlwoiLyiHDemYDzqMnlQ0XTLi6C52Pit9IRvjMy6PP'
                           b'o5SDMxgdGzt2zNSJFBbTJiAAAC5vbpCDUmXtaQg185qa-w52w91TWT34EBWBGwj0'
                           b'38Tc3atHn6uhcT59ZT7I-1cuOPNel0ABguGTIMzt7Ks7HTAQ{"v":"KERI10JSON'
                           b'000091_","t":"rct","d":"E16LczbJQi-5XKgfDYNanLmY8Iu_TTsHl8IpNsk8'
                           b'2vvo","i":"EgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","s":"6"'
                           b'}-FABE-kW2C8JK7v59OdT-2Yit5gtsny-4VdoZdYRpszkwkr40AAAAAAAAAAAAAA'
                           b'AAAAAAAAAEBxnCnfhfY9y4aiZ0N5pxfLw-_GDDh0VUsvCUty3G4kE-AADAAmAlcT'
                           b'I2VQT5r7XbDz6tK47gsLWzFXx99AgfOa-PxU7uV9_Efa2DcEIn6elTQYnc-8K_bW'
                           b'M7UqhFUH3pV-denCQABItrvUCYEqlp341xB8P_nODWC9g8QQQMjF5ThFs5fyPy_g'
                           b'x-BwMwTHV3ik5mGNnayiDW709-TM7Ntlg6AEZjfCQAC1LkwBmbtxR0UrtAMsFi_F'
                           b'UIBMl0L4byJZnFsaqeVvAaqX3I72kNCa2KaBewMVHG7K1AMLu45OyanCgQ1LeiGCA')

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
        assert debCamVrcs == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EBxnCnfhfY9y4aiZ0N5pxfLw'
                              b'-_GDDh0VUsvCUty3G4kE","i":"E-kW2C8JK7v59OdT-2Yit5gtsny-4VdoZdYRp'
                              b'szkwkr4","s":"0"}-FABEgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3'
                              b's0AAAAAAAAAAAAAAAAAAAAAAgELv7PoQqtu-0Sfdjt8ccri4rONvU7_YZGLFxgJx'
                              b'PC6dA-AADAA0kJrsCzmIUBvFNFerMdL5zhQiKLcDn__DVUYgl567J4pVtqhiFL83'
                              b'Zw2FIjWGRCGxTOVJr30SBbuhX4363gJAgABhUw9QnBGYcJdQBhrGUnEOnbhdkbLK'
                              b'LY-7eppke_8SdKhgHFZ-gSmhqVHinme2xJf_gSsG9KdQfcJEFofrjC4CAACSe6MZ'
                              b'_e2CE5vNz7VrOP7n8Y9cCmG4n43Yn9ga-orCCMzT4elaW6xPeYB1nr05G0Tzg0hm'
                              b'OHH7-DqQ35OTHQrBg')

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
                           b'hAhnaKmdKnK2J_Aw{"v":"KERI10JSON000091_","t":"rct","d":"EbY3caaU'
                           b'2DRWxUkGZ89ZNmEonFo7cevL36jqXg451epE","i":"EgmiU27BZtfnJclZw6K_X'
                           b'67hwf6SDT3nJW1dr3Jq9D3s","s":"0"}-CABBCqmHiYBZx_uaQiCTVeum-vt1ZP'
                           b'ti8chqb-GpQBPaurA0BZrPD_S3WkXGYHOHO6j9UKM9eapM8sM_lPHnhZSCR-cX8G'
                           b'OZpMakTaMJe31_Oqd_qkEsoRRTN0J-4da9VbOGbDg{"v":"KERI10JSON000091_'
                           b'","t":"rct","d":"ET7a0bnuCkMp-zPXN7SS1HCcW9Yhatwr5JxzO-K5nwSk","'
                           b'i":"EgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","s":"1"}-CABBC'
                           b'qmHiYBZx_uaQiCTVeum-vt1ZPti8chqb-GpQBPaurA0BKKXXyS6E0PC60pNa0Fj5'
                           b'uH7EvwpxTGEM2o6fy4W8S0oIK4eYsJNQy-EdewcZJ4LKTWjqa3OdgxlL-FxxtkiX'
                           b'AQ{"v":"KERI10JSON000091_","t":"rct","d":"ELv7PoQqtu-0Sfdjt8ccri'
                           b'4rONvU7_YZGLFxgJxPC6dA","i":"EgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1'
                           b'dr3Jq9D3s","s":"2"}-CABBCqmHiYBZx_uaQiCTVeum-vt1ZPti8chqb-GpQBPa'
                           b'urA0BjoWH7weRpUkJ46gF1a-zVjDf7rjRhLwUwTfepX4qDsObPpKvodMdcFyBwNe'
                           b'rcXFU5xZiO958smOLX5CnRzqUDw{"v":"KERI10JSON000091_","t":"rct","d'
                           b'":"EQthDCDk4ripZv0mtnQO3Roue-25BnJ9IbYgrH4krlzw","i":"EgmiU27BZt'
                           b'fnJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","s":"3"}-CABBCqmHiYBZx_uaQiC'
                           b'TVeum-vt1ZPti8chqb-GpQBPaurA0BC9i1T5loKIMVONl7Fs0Rx4kcMtX0qs9ZB1'
                           b'aJv15tIQ2A6kEhAm5lCPf264ncfMKl2Tk-TO-vQY1xMGbh2X5JAQ{"v":"KERI10'
                           b'JSON000091_","t":"rct","d":"ELLOcsPHfXh2_vrQP8cQVDtf8ul9usY0YwFP'
                           b'4_lsAEec","i":"EgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","s"'
                           b':"4"}-CABBCqmHiYBZx_uaQiCTVeum-vt1ZPti8chqb-GpQBPaurA0Biih5fcG4E'
                           b'l_AJ_RN7t-8pcUcCySSPkclygxUpb-X0VjkyA4Y-zW-QQqIlFgY_qv7Wk02O-9Gm'
                           b'--fOnQgHoGaCw{"v":"KERI10JSON000091_","t":"rct","d":"EB-U60iiXd1'
                           b'sjDUKyuVq8zVBGNm2Qw0fp_cePYO3wQro","i":"EgmiU27BZtfnJclZw6K_X67h'
                           b'wf6SDT3nJW1dr3Jq9D3s","s":"5"}-CABBCqmHiYBZx_uaQiCTVeum-vt1ZPti8'
                           b'chqb-GpQBPaurA0BwB1Lr3v2tKBLX6Fetd60M89xaNybUxMCvX93O6709jfi-w5o'
                           b'ogAsApF_eF1kaky6Gf6f3tEWyO3DVQrd3EvKCQ{"v":"KERI10JSON000091_","'
                           b't":"rct","d":"E16LczbJQi-5XKgfDYNanLmY8Iu_TTsHl8IpNsk82vvo","i":'
                           b'"EgmiU27BZtfnJclZw6K_X67hwf6SDT3nJW1dr3Jq9D3s","s":"6"}-CABBCqmH'
                           b'iYBZx_uaQiCTVeum-vt1ZPti8chqb-GpQBPaurA0B08T-WlmE5QbK___AEOpA3_U'
                           b'nLTUoivRI8uRC_CO2gMXVu2VFqCSm9kLygE_6csl7VNs5WtYw1fo0glywYzr1CQ')

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
                              b's0AAAAAAAAAAAAAAAAAAAAAAgELv7PoQqtu-0Sfdjt8ccri4rONvU7_YZGLFxgJx'
                              b'PC6dA-AADAAolzi_N7g0q792H7aQoB_bVwaNPMQ61UhXDKxrhX5uS6BhCuxHHCIb'
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

    assert not os.path.exists(artKS.path)
    assert not os.path.exists(artDB.path)
    assert not os.path.exists(bevKS.path)
    assert not os.path.exists(bevDB.path)
    assert not os.path.exists(camKS.path)
    assert not os.path.exists(camDB.path)
    assert not os.path.exists(debKS.path)
    assert not os.path.exists(debDB.path)

    """End Test"""


def test_replay_all():
    """
    Test conjoint replay all

    Setup database with events from Deb, Cam, Bev, abd Art
    Replay all the events in database.

    """

    with basing.openDB(name="deb") as debDB, keeping.openKS(name="deb") as debKS, \
            basing.openDB(name="cam") as camDB, keeping.openKS(name="cam") as camKS, \
            basing.openDB(name="bev") as bevDB, keeping.openKS(name="bev") as bevKS, \
            basing.openDB(name="art") as artDB, keeping.openKS(name="art") as artKS:
        # setup Deb's habitat using default salt multisig already incepts
        sith = ["1/2", "1/2", "1/2"]  # weighted signing threshold
        debHab = habbing.Habitat(ks=debKS, db=debDB, isith=sith, icount=3,
                                 temp=True)
        assert debHab.ks == debKS
        assert debHab.db == debDB
        assert debHab.kever.prefixer.transferable

        # setup Cam's habitat using default salt multisig already incepts
        # Cam's receipts will be vrcs with 3 indexed sigantures attached
        sith = '2'  # hex str of threshold int
        camHab = habbing.Habitat(ks=camKS, db=camDB, isith=sith, icount=3,
                                 temp=True)
        assert camHab.ks == camKS
        assert camHab.db == camDB
        assert camHab.kever.prefixer.transferable

        # setup Bev's habitat using default salt nonstransferable already incepts
        # Bev's receipts will be rcts with a receipt couple attached
        sith = '1'  # hex str of threshold int
        bevHab = habbing.Habitat(ks=bevKS, db=bevDB, isith=sith, icount=1,
                                 transferable=False, temp=True)
        assert bevHab.ks == bevKS
        assert bevHab.db == bevDB
        assert not bevHab.kever.prefixer.transferable

        # setup Art's habitat using custom salt nonstransferable so not match Bev
        # already incepts
        # Art's receipts will be rcts with a receipt couple attached
        salt = coring.Salter(raw=b'abcdef0123456789').qb64
        sith = '1'  # hex str of threshold int
        artHab = habbing.Habitat(ks=artKS, db=artDB, isith=sith, icount=1,
                                 salt=salt, transferable=False, temp=True)
        assert artHab.ks == artKS
        assert artHab.db == artDB
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

    assert not os.path.exists(artKS.path)
    assert not os.path.exists(artDB.path)
    assert not os.path.exists(bevKS.path)
    assert not os.path.exists(bevDB.path)
    assert not os.path.exists(camKS.path)
    assert not os.path.exists(camDB.path)
    assert not os.path.exists(debKS.path)
    assert not os.path.exists(debDB.path)

    """End Test"""


if __name__ == "__main__":
    test_replay()
