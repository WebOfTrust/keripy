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

        assert debMsgs == (b'{"v":"KERI10JSON00015b_","i":"EeTLHxy5Npa4SQlFABzhu66FUuSl_iJAaf'
                    b'ez-encK314","s":"0","t":"icp","kt":["1/2","1/2","1/2"],"k":["DRx'
                    b'CLERO9eSvG4fluzOsK52GCWCtKOZClVwA38Oa--MA","DCxzT16ikP6LKVJfr6hv'
                    b'1jmhynm6I4-KoGYkJtd9uBro","DsDl5xSHnIlcGo13u5jDRr1jJMkQ34nEc5R6N'
                    b'YsdPS2k"],"n":"Eer5S019j0eEFNFLb0R0UDMoNLavlLiQ73fHGU7MUHXg","bt'
                    b'":"0","b":[],"c":[],"a":[]}-AADAA4HzkCruAhoxet6Vrk_tBCwbwaT78dRw'
                    b'w9RQJb0MR_tmSpEYOYDue-pBQCthsgDJzjyElpSmzNedlY-hVd6rbDwABJnfOgI6'
                    b'teO_3fESnXgiz_9J_F_VfQliLWvLCM8ZnVjrryBuiMYOUmHbfXuNtRC4iZxb-RU0'
                    b'lC55O0r5c5hyrAgACnZEXW7jYpAdrIfmOmH-OEHmhxcwQNu31k-mmzyNTfFvAxmp'
                    b'r7-zLdmzlWKfMBlE6eAbDgCdNr_VL2l8xeJExAA{"v":"KERI10JSON000098_",'
                    b'"i":"EeTLHxy5Npa4SQlFABzhu66FUuSl_iJAafez-encK314","s":"1","t":"'
                    b'ixn","p":"E4gF0E1fkpEPBjeq1Sm-RK_Rvg56KOmtBHGfNe_tPxWc","a":[]}-'
                    b'AADAAvo8lxVzu4YS6nG3BXu7PncYdZO57P4gYY-ikaRepVIOeRnZ10iMdJGcyULm'
                    b'mdXLRaVxtuxI956cJljg3joSMBgABgHtCeHi-UZjnI1IWW9ZF8E7ni6UwerFOvPV'
                    b'7z3i1pI7D3HJCoSx8XkhdXPGzUtrNuAvxVptsJtF17_-rP50bBwACguCjTA2taPP'
                    b'EyhVecWjtpoBJCAiYeTdeDv3Hq0pAJXWa7SWjxlDR2-f1TIIXg8PbBD_tgn4Z6zp'
                    b'LZcPLLHH5Cg{"v":"KERI10JSON000190_","i":"EeTLHxy5Npa4SQlFABzhu66'
                    b'FUuSl_iJAafez-encK314","s":"2","t":"rot","p":"EYROVd3Ho83kEgBkrN'
                    b'v6kqTAG4YeCqyPWYBo2jCPteiw","kt":["1/2","1/2","1/2"],"k":["Dj-DU'
                    b'wfCmOrE3ijqucR0I89_fYTFbyotaqeQyDfupkEU","DL-k_8BanjLYaAdm6WWKIp'
                    b'HcHwcbF834vnLPgpW1NL8k","DWG2ZFsWYUsbDI1Kmu8JH22iGaVDGvM7pnuT4y2'
                    b'oR3VI"],"n":"EYd4ha92A2yttnCoLMqFGRzh6nsgduE910LD-scP7C3Q","bt":'
                    b'"0","br":[],"ba":[],"a":[]}-AADAAspTV94LrwMhYVzZD0xu16aKjf1YQ8nT'
                    b'Ta08ik1Fah545jAoe6n1xdnKSgL9Alucp4F-Yl69ksAttb4hTlnikDwABKspYVa4'
                    b'J3r7ox-gDsPbpI5jiFSTcDCjBJGfU6hWhMXx7zpgG1jt4cTeW83oaILMbW85i_U7'
                    b'RT3x6Sm2z5ytCCQACf157-iV13AXKaIddVaXexNx5K9INhJ44tfpb3OBjuPk5JMj'
                    b'VGIU0iz5LkQlc_rV9D79E1pC5Z--YGplzQMv0Ag{"v":"KERI10JSON000098_",'
                    b'"i":"EeTLHxy5Npa4SQlFABzhu66FUuSl_iJAafez-encK314","s":"3","t":"'
                    b'ixn","p":"EA4mqdTa4RPrUJ3B_lmEPSxQK50tDkxRRVwVlLzcAdb0","a":[]}-'
                    b'AADAAte_OEI-pzZulc4454QS391RR5bPndHIoLG_vLsC4Qmedqz7o04zuisW-7mr'
                    b'TcfU6ZWs7rlMdSHTBZFErsY-FDQABiHkOIixpSaHGZ80--2JzhmR0TCla09WiEJH'
                    b'5gTd9XXmxDfzDVON9FgDqLKf_Tf1nmgRh_eQFXu42jfvQG4Q1AAACp478kKPjbh1'
                    b'pCxlmqa65PplcTa9zG4zsdYz2raYOiregvotKK30LNXm58886gSuSnEWifJvb-zY'
                    b'wvdK8GsgqBg{"v":"KERI10JSON000098_","i":"EeTLHxy5Npa4SQlFABzhu66'
                    b'FUuSl_iJAafez-encK314","s":"4","t":"ixn","p":"Ecw6XFmjIeMiYp1MTG'
                    b'e4KRk9HnygNpnORox6AaCfC44Y","a":[]}-AADAANlbayWV5QQdCTqmh9dSEb13'
                    b'stiK3srIyL9z4FWMZr_nwejoqK9j9Ic6wBQiUVksayOmGVtknUWrDNOY-PzzgBQA'
                    b'B2FONMatheF144ziEB7uJpGZa3vugxedmLFfOD5CcoX7z6eX6ZZ_fIVkOHRVOxmv'
                    b'nfYyVF7uC8G40PeGgkh5eCAACSwyvmjZcik1VBQCCfh5Mq2SQLUvVfFg9plIanMR'
                    b'Trp7bG_OXE5SSqou6VFNon3Ub8IlBA90-dR7DRRDNPQ5UBw{"v":"KERI10JSON0'
                    b'00098_","i":"EeTLHxy5Npa4SQlFABzhu66FUuSl_iJAafez-encK314","s":"'
                    b'5","t":"ixn","p":"EQW9ROsIuNEdKu_ZIm9zDPKIVallegMHz2PVygiZgttc",'
                    b'"a":[]}-AADAAtjUR1rNouk9T92o22qUbNvptIEjrnqKU3eJTiwdDGoWIwhTLY1T'
                    b'UunYYpqtbk55oaCyc_MXkP-6l57YDiOAsCwAB5Fl7CZj1P1-NsYgrf2caXvWTfkg'
                    b'u15C61JRuRpDnjTtevCjxspLQw6hxeJ6-2mTZHqIHC3hzW01Ed2mFOC_eDAACV87'
                    b'jI4scXXRlNfqXmRrsivc0p3vBIO1OLNC6fex-bFbwV6U8zd_pjWTDZLwCnDm3KJq'
                    b'labzAfGxX32trskGpCQ{"v":"KERI10JSON000098_","i":"EeTLHxy5Npa4SQl'
                    b'FABzhu66FUuSl_iJAafez-encK314","s":"6","t":"ixn","p":"E52dhrHeFM'
                    b'AYWsROU3fPEmD8pCsO_Q2MfvLuZufX43o0","a":[]}-AADAAVe6bfQeaR2X8UIB'
                    b'OS1HMVLWho7FETQ17FQly0USMiSVDIWh8KTEeW-ndMDUlDBBeNEf3UiwDIRE62-k'
                    b'ICoofAwABk4ndaxtTYTLmlxWM2Qb38RYtwSRzr7KRRbhLmL_zLXa7KnoAkmCa9LL'
                    b'ZT5o_6rNjuFruYo7eSL4JfFhCEEn_CwACdPvsbvEV30PaDhbDmdVqI9fzGOSp34e'
                    b'oTChNPt_UGq3uvCAAlwJa66g4WndLiTkN_BmKZP8YCgn40mUj5TFnAQ')

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
        assert camMsgs == (b'{"v":"KERI10JSON00014b_","i":"EnjQHu6cA7Mk4gdlnSbhaKtjOh23I2_1ZZ'
                        b'9KYr-ZdNMg","s":"0","t":"icp","kt":"2","k":["DJBtEHHnzNtE-zxH1xe'
                        b'X4wxs9rEfUQ8d1ancgJJ1BLKk","DMu6yPITjrOBoTPfsY-r1Rc0ead8GKmoCxA_'
                        b'BugKehgY","DfhpvbNyYu1fxTBTXy8eCgghMcOYnxkgoGPBr0ZBZPQA"],"n":"E'
                        b'J85AI0se7UiFBFL1Vl80PnmQ-0dU6q_NXCh6BlSJcKg","bt":"0","b":[],"c"'
                        b':[],"a":[]}-AADAAya98TxjoKqXBaXKBKmu0_98hrOSjoq8YeT5HlKBZsBvGPGU'
                        b'NE3Ex9lkhLTl-U_Gx_1JLqEYJJaVrGLaArb5pDAABiYDraSegcRyxe8Syrd3uYqN'
                        b'HTcalW-_hgVqsUDEZcqdsbje2fBxHO4blsODaSDMm2Crvdj5uvaLch-svOBdEDgA'
                        b'CVGMTILr9hF9NHVscjqi5yCvtkwMhtZHEqh_6v7N_flmXKCkN2AXAi9OEmf-pdXj'
                        b'0UlLdab6MkOfbxSRsmrjTDQ{"v":"KERI10JSON000091_","i":"EeTLHxy5Npa'
                        b'4SQlFABzhu66FUuSl_iJAafez-encK314","s":"0","t":"rct","d":"E4gF0E'
                        b'1fkpEPBjeq1Sm-RK_Rvg56KOmtBHGfNe_tPxWc"}-FABEnjQHu6cA7Mk4gdlnSbh'
                        b'aKtjOh23I2_1ZZ9KYr-ZdNMg0AAAAAAAAAAAAAAAAAAAAAAAEZdlVoasgQzvn7mj'
                        b'ai5hTX7JgLyHrRkeo8Mf5SXL10ro-AADAAY7ru97WNltKYXVBeiqSQ2JhCU6W6Uv'
                        b'wSmYQRNAQ7Vk3_VslqnAkQDApZwVY-I5nonPybqxS4riBoN8O2MvH3BwABNvm83-'
                        b'pYo3WR7BAtg13vvHsaX2PfSZn7ajBCRzUXaQ0ZLNr0wJddMywcVtOrgY0myRmiNq'
                        b'YvetEkb0PJwQG4AwACjit5HUQSAeEMyfC5GeAsPHsGqLwbYMJdqxuZrnzfE2xtXe'
                        b'3dEz9iSKEFUbykO0f1ThpMLpjat3SsNtZUtn07CQ{"v":"KERI10JSON000091_"'
                        b',"i":"EeTLHxy5Npa4SQlFABzhu66FUuSl_iJAafez-encK314","s":"1","t":'
                        b'"rct","d":"EYROVd3Ho83kEgBkrNv6kqTAG4YeCqyPWYBo2jCPteiw"}-FABEnj'
                        b'QHu6cA7Mk4gdlnSbhaKtjOh23I2_1ZZ9KYr-ZdNMg0AAAAAAAAAAAAAAAAAAAAAA'
                        b'AEZdlVoasgQzvn7mjai5hTX7JgLyHrRkeo8Mf5SXL10ro-AADAAx2QNu8staqEHq'
                        b'lv3z__tb9wPPuwTqF3uicXv5BAr3npLW541r9RKcDUQ1yMk1TWcs1vO2a_L2rwtC'
                        b'h_pP8kzAgABk1B6jf72NOLhSIbAXTbM5JhxiFatklzqYCkiQw12jGxNOHxmEuKNF'
                        b'0IatvNc3m96hcOb7dc2ZOIQGxX9Ud9nCwAC9LGHfopCtAgtC7OK-aOfYQXN36_Ll'
                        b'RHZu3eeT9E_pFG9I0LYfoRNf0hGVcyPRBpqrIVOTkH1NBWRbVyOMSYhDA{"v":"K'
                        b'ERI10JSON000091_","i":"EeTLHxy5Npa4SQlFABzhu66FUuSl_iJAafez-encK'
                        b'314","s":"2","t":"rct","d":"EA4mqdTa4RPrUJ3B_lmEPSxQK50tDkxRRVwV'
                        b'lLzcAdb0"}-FABEnjQHu6cA7Mk4gdlnSbhaKtjOh23I2_1ZZ9KYr-ZdNMg0AAAAA'
                        b'AAAAAAAAAAAAAAAAAAEZdlVoasgQzvn7mjai5hTX7JgLyHrRkeo8Mf5SXL10ro-A'
                        b'ADAAmMLDAvNgoQ_hnYEfx6uzg0LzRuODZmgwhou-EZv83BNJ9JwNabG9oSuLL15Z'
                        b'Zc0blUm8GJ0BJuBcE4rjNW3-CAABlkXt_qnbOaBjqlfNXbLxZ_Rx2SCy8pVSYSz7'
                        b'-UbB2lHpIfGMApVcTamn4pYhyOnaEVVO47tWZ3vDmXkf3WrKBQAC4MZmfqt3B9SY'
                        b'DROZk8shO6vWxzHfZVBzLtNZAJrJLq8FoZ66q3bG4Pgn1pc0ID0fjkpXSiR5aOF2'
                        b'2QhT06erDA{"v":"KERI10JSON000091_","i":"EeTLHxy5Npa4SQlFABzhu66F'
                        b'UuSl_iJAafez-encK314","s":"3","t":"rct","d":"Ecw6XFmjIeMiYp1MTGe'
                        b'4KRk9HnygNpnORox6AaCfC44Y"}-FABEnjQHu6cA7Mk4gdlnSbhaKtjOh23I2_1Z'
                        b'Z9KYr-ZdNMg0AAAAAAAAAAAAAAAAAAAAAAAEZdlVoasgQzvn7mjai5hTX7JgLyHr'
                        b'Rkeo8Mf5SXL10ro-AADAASQpD32fjD-IJuz9w1CFLXYtHE-9rtVRqSvQPqT8yjHO'
                        b'lKMNG2apDa___svlQSw_OmgsCB-LzQn7dyyv73w3KCQABcbrlJRw3GaM5l5NCq_7'
                        b'czfZBAyXPwvpfjwM3BAMnt-tDmTEoJku4MpruiwpgSWcPw_Xp3SE3nmxPIK6-Q08'
                        b'aCAAC58Bw2io7IEt3ZvfEdaHns97Y4QGCnFovmz9VFfp3c2Mjioa1sDgOf9uybHV'
                        b'MKBhpsUy2_BfpgkVOhmcY6GtzCw{"v":"KERI10JSON000091_","i":"EeTLHxy'
                        b'5Npa4SQlFABzhu66FUuSl_iJAafez-encK314","s":"4","t":"rct","d":"EQ'
                        b'W9ROsIuNEdKu_ZIm9zDPKIVallegMHz2PVygiZgttc"}-FABEnjQHu6cA7Mk4gdl'
                        b'nSbhaKtjOh23I2_1ZZ9KYr-ZdNMg0AAAAAAAAAAAAAAAAAAAAAAAEZdlVoasgQzv'
                        b'n7mjai5hTX7JgLyHrRkeo8Mf5SXL10ro-AADAAsW_khBjW_8JTAMqSmfO719vBlr'
                        b'NVpJu-8bpboWZm8hhYfKEEfUWC40GWoYwSN_Xk-2v6oPVp4_oHVVB4hMavAAABuR'
                        b'VEC014QaDOacru4RchNJBZCa5jKhfK10vt-Mb88mQY-HF-kVywqvGnkFyCZowKPz'
                        b'sLEJbTAa8py3hCKJ-5AQACo4tT9i1sv7JM6zhprqwklVnYKsG6Y1DCfGj6c6vIWz'
                        b'StZeO_ICz9iOZkB8IuwJp8r5AYgqJlNl8cl93sgknZDw{"v":"KERI10JSON0000'
                        b'91_","i":"EeTLHxy5Npa4SQlFABzhu66FUuSl_iJAafez-encK314","s":"5",'
                        b'"t":"rct","d":"E52dhrHeFMAYWsROU3fPEmD8pCsO_Q2MfvLuZufX43o0"}-FA'
                        b'BEnjQHu6cA7Mk4gdlnSbhaKtjOh23I2_1ZZ9KYr-ZdNMg0AAAAAAAAAAAAAAAAAA'
                        b'AAAAAEZdlVoasgQzvn7mjai5hTX7JgLyHrRkeo8Mf5SXL10ro-AADAA_06qSZGjm'
                        b'75-wLDLPBK-p32mM1oeDQAQD2wfdQ75jn-JRkYqGztS2tQDBFlxK4uiceok50-ZJ'
                        b'f64An_oB649AQABZpuMeCzUi0oF98kXROI94G3cWLVrDVdbvxDNe60uE7rQ-qwDq'
                        b'tErr65hMaCgbTO3zD9aumRQMU5-1uWZrIxWDQACyukFA_3zKJQyctI3JER5XO8r_'
                        b'iz9Ga5CXxnZFqSuGmQqQEpA9wMDOZ66hRBRNgImMQh-btX4sqbjO_ycaGmjBg{"v'
                        b'":"KERI10JSON000091_","i":"EeTLHxy5Npa4SQlFABzhu66FUuSl_iJAafez-'
                        b'encK314","s":"6","t":"rct","d":"ENsvgXw3H4VhL3i-eONdu7tgarzrgm9z'
                        b'c2Lj3XlwZ2_4"}-FABEnjQHu6cA7Mk4gdlnSbhaKtjOh23I2_1ZZ9KYr-ZdNMg0A'
                        b'AAAAAAAAAAAAAAAAAAAAAAEZdlVoasgQzvn7mjai5hTX7JgLyHrRkeo8Mf5SXL10'
                        b'ro-AADAAEjRuwX1j8xEYIXjf1cmhLpmF4IwKBGU2fvL0rbbBMN4bA4VTtnAqo6Nh'
                        b'GYK4XKKVL_SKLaL9x9PcFc5ykBqsBwABVwlNGkdx_oScxgYzhLMDmAi-Ro5n85ly'
                        b'LRI6DdtMIRfpgyIa2pPw1BkA2FmmsUkkwdTWxNq77AyfbcQzDKOzDAACSIxniS9R'
                        b'7dsM11Q8uD5qSAxcGyF-CUNYT7NZmQdL52MnszSYy7Mvpwnq9L842jNgL_G8zqif'
                        b'0eizybIVsQj7AQ')

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
        assert debCamVrcs == (b'{"v":"KERI10JSON000091_","i":"EnjQHu6cA7Mk4gdlnSbhaKtjOh23I2_1ZZ'
                        b'9KYr-ZdNMg","s":"0","t":"rct","d":"EZdlVoasgQzvn7mjai5hTX7JgLyHr'
                        b'Rkeo8Mf5SXL10ro"}-FABEeTLHxy5Npa4SQlFABzhu66FUuSl_iJAafez-encK31'
                        b'40AAAAAAAAAAAAAAAAAAAAAAgEA4mqdTa4RPrUJ3B_lmEPSxQK50tDkxRRVwVlLz'
                        b'cAdb0-AADAARwO4P3VantEgLrBs4K7hvStQ_kpN5EiFjklROGNkV19PBtxO0uUU8'
                        b'0RDbWBjuUgIm59v9oJQKe-hdS8neEI2CgABAptixkGIj7UX1PU9Vlr1kZexUaIie'
                        b'AugElzH99gCfQG2MMtOb3EO5ybgMHkWKKr7PaTpi4H2XrQ-me-PT_fGAgACSUTaW'
                        b'0o0XhD0bQn-Qv2TwDj01L8zRyy7dqlGemZSzl2DBnliA_NqGHBQ2QJKIZfuIc6Mc'
                        b'c3n_HpqI6s7xt-jCQ')

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
        assert bevMsgs == (b'{"v":"KERI10JSON0000c1_","i":"BCqmHiYBZx_uaQiCTVeum-vt1ZPti8chqb'
                        b'-GpQBPaurA","s":"0","t":"icp","kt":"1","k":["BCqmHiYBZx_uaQiCTVe'
                        b'um-vt1ZPti8chqb-GpQBPaurA"],"n":"","bt":"0","b":[],"c":[],"a":[]'
                        b'}-AABAAgO3RAPPeeFcl5ZvoIR55jsqjQsfKQNenz9EUITRBtu9Q5Js-Umzd_mvSq'
                        b'ZymNJnwLL656s7P-hTZRtG-8-rhBg{"v":"KERI10JSON000091_","i":"EeTLH'
                        b'xy5Npa4SQlFABzhu66FUuSl_iJAafez-encK314","s":"0","t":"rct","d":"'
                        b'E4gF0E1fkpEPBjeq1Sm-RK_Rvg56KOmtBHGfNe_tPxWc"}-CABBCqmHiYBZx_uaQ'
                        b'iCTVeum-vt1ZPti8chqb-GpQBPaurA0B0VYuHkBtlKSqsXj_0-2mSNzQ9UOiO-iX'
                        b'jG4V74ivokdt9GUYh5OnZ-lW-SfyzGhQv6QlPRcy7nWTyi_mMzOCAg{"v":"KERI'
                        b'10JSON000091_","i":"EeTLHxy5Npa4SQlFABzhu66FUuSl_iJAafez-encK314'
                        b'","s":"1","t":"rct","d":"EYROVd3Ho83kEgBkrNv6kqTAG4YeCqyPWYBo2jC'
                        b'Pteiw"}-CABBCqmHiYBZx_uaQiCTVeum-vt1ZPti8chqb-GpQBPaurA0B_gS89Rl'
                        b'Y4y-YTTgBpjdBiA6l8PbGZkd4ODmA3RQyDGVapnpMB_SLvolQuz7WxyE0NsnpJ-D'
                        b'nVFTt-Dv-dKGADA{"v":"KERI10JSON000091_","i":"EeTLHxy5Npa4SQlFABz'
                        b'hu66FUuSl_iJAafez-encK314","s":"2","t":"rct","d":"EA4mqdTa4RPrUJ'
                        b'3B_lmEPSxQK50tDkxRRVwVlLzcAdb0"}-CABBCqmHiYBZx_uaQiCTVeum-vt1ZPt'
                        b'i8chqb-GpQBPaurA0BcbCV4kKek9oab8MDhzvzf0ucYnTIzNiWHLNh65mpxUa2XL'
                        b'jrEfbWlrjpiDXTyYShlLNt8fZxnnwoAW4aelTyBA{"v":"KERI10JSON000091_"'
                        b',"i":"EeTLHxy5Npa4SQlFABzhu66FUuSl_iJAafez-encK314","s":"3","t":'
                        b'"rct","d":"Ecw6XFmjIeMiYp1MTGe4KRk9HnygNpnORox6AaCfC44Y"}-CABBCq'
                        b'mHiYBZx_uaQiCTVeum-vt1ZPti8chqb-GpQBPaurA0BZSz6DBrS702RsSJ2qhp5V'
                        b'_4UG3u4v9_PZUxZqkTnBmkxkX-dA9Ml5c_2YaZ0_ETfhrbq30r1elT4gXhKJbRAA'
                        b'A{"v":"KERI10JSON000091_","i":"EeTLHxy5Npa4SQlFABzhu66FUuSl_iJAa'
                        b'fez-encK314","s":"4","t":"rct","d":"EQW9ROsIuNEdKu_ZIm9zDPKIVall'
                        b'egMHz2PVygiZgttc"}-CABBCqmHiYBZx_uaQiCTVeum-vt1ZPti8chqb-GpQBPau'
                        b'rA0BFvLdsWHk5oGOZQCnDEVww3dMlXZYo9JzNbuJUdK0IqWaJAQBIMEKOqLvZzMx'
                        b'FIi6xNmJCQYKFu5328ovxtddCg{"v":"KERI10JSON000091_","i":"EeTLHxy5'
                        b'Npa4SQlFABzhu66FUuSl_iJAafez-encK314","s":"5","t":"rct","d":"E52'
                        b'dhrHeFMAYWsROU3fPEmD8pCsO_Q2MfvLuZufX43o0"}-CABBCqmHiYBZx_uaQiCT'
                        b'Veum-vt1ZPti8chqb-GpQBPaurA0BDaF78ajVz3FOsApq_1iBTK2i1PT8F0Fgz4q'
                        b'r4HuboYf5XMWR8IvrYcYvthaaRP5168Ge-npP6UgRUd7t8vwCDw{"v":"KERI10J'
                        b'SON000091_","i":"EeTLHxy5Npa4SQlFABzhu66FUuSl_iJAafez-encK314","'
                        b's":"6","t":"rct","d":"ENsvgXw3H4VhL3i-eONdu7tgarzrgm9zc2Lj3XlwZ2'
                        b'_4"}-CABBCqmHiYBZx_uaQiCTVeum-vt1ZPti8chqb-GpQBPaurA0B9TkOKxh1bS'
                        b'1gwzpNCx5R-AW0D_xHbbBNlVSdyPW4VUJm4PvRCK9UFsHHk2LGv0KbqRe7ftiY6o'
                        b'V7hSkY4rfGAw')


        # Play bevMsgs to Deb
        parsing.Parser().parse(ims=bytearray(bevMsgs), kvy=debKevery)
        # debKevery.process(ims=bytearray(bevMsgs))  # give copy to process
        assert bevHab.pre in debKevery.kevers
        assert debKevery.kevers[bevHab.pre].sn == bevHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Bev's events by processing Deb's cues
        debBevVrcs = debHab.processCues(debKevery.cues)
        assert debBevVrcs == (b'{"v":"KERI10JSON000091_","i":"BCqmHiYBZx_uaQiCTVeum-vt1ZPti8chqb'
                    b'-GpQBPaurA","s":"0","t":"rct","d":"ERejsDJsBCs9b2j0Cd3pIDxNoGEw8'
                    b'zQd94AXMduyyIF8"}-FABEeTLHxy5Npa4SQlFABzhu66FUuSl_iJAafez-encK31'
                    b'40AAAAAAAAAAAAAAAAAAAAAAgEA4mqdTa4RPrUJ3B_lmEPSxQK50tDkxRRVwVlLz'
                    b'cAdb0-AADAApoGcQmhmFQ2tQmovG0aZNxBN3QMgynKdfVA3pNyJQ-UMBnliFkeaC'
                    b'gioFRXuH9SLm3R1XlFjmIJNvZ7hoJ3bBQABLKipRIasV9TRzcoGF7sQs9vfkcneF'
                    b'7y1YqKMw9oWKEzhJKMuk0QUz6E1fse8mUDazKQsXqY1uKnSFhfjuqAhBQACFrF4i'
                    b'Nt4Cm0srlq1QsXwJe3duzNKOEdf4z-WxWSw49dDpYyfllWEIs8Eu65IADEycjZR3'
                    b'q9BTeO9QARuieV_Dw')

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
        assert len(msg) == 1423
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
        assert counter.count == (len(msg) - len(counter.qb64b)) // 4 ==  268
        del msg[:len(counter.qb64b)]
        assert len(msg) == 1072 == 268 *  4

        counter = coring.Counter(qb64b=msg)  # indexed signatures counter
        assert counter.code == coring.CtrDex.ControllerIdxSigs
        assert counter.count == 3  #  multisig deb
        del msg[:len(counter.qb64b)]
        assert len(msg) == 1068

        for i in range(counter.count):  # parse signatures
            siger = coring.Siger(qb64b=msg)
            del msg[:len(siger.qb64b)]
        assert len(msg) == 1068 - 3 * len(siger.qb64b) == 804

        counter = coring.Counter(qb64b=msg)  # trans receipt (vrc) counter
        assert counter.code == coring.CtrDex.TransReceiptQuadruples
        assert counter.count == 3  #  multisig cam
        del msg[:len(counter.qb64b)]
        assert len(msg) == 800

        for i in range(counter.count):  # parse receipt quadruples
            prefixer, seqner, diger, siger = eventing.deTransReceiptQuadruple(msg, strip=True)
        assert len(msg) == 800 - 3 * (len(prefixer.qb64b) + len(seqner.qb64b) +
                                len(diger.qb64b) + len(siger.qb64b)) == 200

        counter = coring.Counter(qb64b=msg)  # nontrans receipt (rct) counter
        assert counter.code == coring.CtrDex.NonTransReceiptCouples
        assert counter.count == 1  #  single sig bev
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
        assert len(msg) == 1228
        serder = coring.Serder(raw=msg)
        assert serder.sn == fn  # no recovery forks so sn == fn
        assert serder.ked["t"] == coring.Ilks.ixn
        debFelMsgs.extend(msg)

        fn += 1
        msg = next(cloner)  # get zeroth event with attachments
        serder = coring.Serder(raw=msg)
        assert serder.sn == fn  # no recovery forks so sn == fn
        assert serder.ked["t"] == coring.Ilks.rot
        assert len(msg) == 1476
        assert ([verfer.qb64 for verfer in serder.verfers] ==
                [verfer.qb64 for verfer in debHab.kever.verfers])
        debFelMsgs.extend(msg)

        fn += 1
        while (fn <= 6 ):
            msg = next(cloner)  # get zeroth event with attachments
            serder = coring.Serder(raw=msg)
            assert serder.sn == fn  # no recovery forks so sn == fn
            assert serder.ked["t"] == coring.Ilks.ixn
            assert len(msg) == 1228
            debFelMsgs.extend(msg)
            fn += 1

        assert len(debFelMsgs) == 9039
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

        assert len(bevDebFelMsgs) == len(camDebFelMsgs) == len(debFelMsgs) == 9039

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
        assert len(artDebFelMsgs) == 9039


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
        assert len(debAllFelMsgs) == 11267

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
        assert len(artAllFelMsgs) == 11016


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
