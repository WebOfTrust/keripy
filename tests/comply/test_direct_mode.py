# -*- encoding: utf-8 -*-

import os

from keri.core.coring import Salter, MtrDex, CtrDex, Counter
from keri.core.coring import Seqner
from keri.base.keeping import Manager, openKS
from keri.core.eventing import incept, rotate, interact, messagize, Nexter, Kevery, SealEvent, chit
from keri.db.dbing import dgKey, snKey, openDB


def test_direct_mode_with_manager():
    """
    Test direct mode with transferable validator event receipts

    """
    # manual process to generate a list of secrets
    # root = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    # secrets = generateSecrets(root=root, count=8)

    # Direct Mode initiated by coe is controller, val is validator
    # but goes both ways once initiated.

    # set of secrets  (seeds for private keys)
    coeSalt = Salter(raw=b'0123456789abcdea').qb64

    # set of secrets (seeds for private keys)
    valSalt = Salter(raw=b'1123456789abcdea').qb64


    with openDB("controller") as coeLogger, openDB("validator") as valLogger, openKS(name="controller") as coeKpr, openKS(name="validator") as valKpr:
        # Init key pair manager
        coeMgr = Manager(keeper=coeKpr, salt=coeSalt)
        coeVerfers, coeDigers = coeMgr.incept(icount=1, ncount=1)

        #  init Keverys
        coeKevery = Kevery(db=coeLogger)
        valKevery = Kevery(db=valLogger)

        coe_event_digs = []  # list of controller's own event log digs to verify against database
        val_event_digs = []  # list of validator's own event log digs to verify against database

        #  init sequence numbers for both controller and validator
        csn = cesn = 0  # sn and last establishment sn = esn
        vsn = vesn = 0  # sn and last establishment sn = esn

        # Controller Event 0  Inception Transferable (nxt digest not empty)
        coeSerder = incept(keys=[coeVerfers[0].qb64],
                           nxt=Nexter(digs=[coeDigers[0].qb64]).qb64,
                           code=MtrDex.Blake3_256)

        assert csn == int(coeSerder.ked["s"], 16) == 0
        coepre = coeSerder.ked["i"]
        assert coepre == 'EsU9ZQwug7DS-GU040Ugj1t7p6Au14VkBOCJnPYabcas'

        coe_event_digs.append(coeSerder.dig)
        # sign serialization
        sigers = coeMgr.sign(ser=coeSerder.raw, verfers=coeVerfers)

        #  create serialized message
        cmsg = messagize(coeSerder, sigers=sigers)
        assert cmsg == bytearray(b'{"v":"KERI10JSON0000e6_","i":"EsU9ZQwug7DS-GU040Ugj1t7p6Au14VkBO'
                                 b'CJnPYabcas","s":"0","t":"icp","kt":"1","k":["Dpt7mGZ3y5UmhT1NLEx'
                                 b'b1IW8vMJ8ylQW3K44LfkTgAqE"],"n":"Erpltchg7BUv21Qz3ZXhOhVu63m7S7Y'
                                 b'bPb21lSeGYd90","wt":"0","w":[],"c":[]}-AABAA2dW-FXhcUiGQZh1JhRrh'
                                 b'_JDqEPU678KT0U8F_a-l8Q3sO25xJAs3Iu2bBonBPZjVo_Zc8FVqrqXjQxxUPt4ICg')

        # create own Controller Kever in  Controller's Kevery
        coeKevery.processOne(ims=bytearray(cmsg))  # send copy of cmsg
        coeKever = coeKevery.kevers[coepre]
        assert coeKever.prefixer.qb64 == coepre

        # Validator Event 0  Inception Transferable (nxt digest not empty)
        # Init key pair manager
        valMgr = Manager(keeper=valKpr, salt=valSalt)
        valVerfers, valDigers = valMgr.incept(icount=1, ncount=1)

        valSerder = incept(keys=[valVerfers[0].qb64],
                           nxt=Nexter(digs=[valDigers[0].qb64]).qb64,
                           code=MtrDex.Blake3_256)

        assert vsn == int(valSerder.ked["s"], 16) == 0
        valpre = valSerder.ked["i"]
        assert valpre == 'EBiIFxr_o1b4x1YR21PblAFpFG61qDghqFBDyVSOXYW0'

        val_event_digs.append(valSerder.dig)

        # sign serialization
        sigers = valMgr.sign(valSerder.raw, verfers=valVerfers)  # return Siger if index

        #  create serialized message
        vmsg = messagize(valSerder, sigers=sigers)
        assert vmsg == bytearray(b'{"v":"KERI10JSON0000e6_","i":"EBiIFxr_o1b4x1YR21PblAFpFG61qDghqF'
                                 b'BDyVSOXYW0","s":"0","t":"icp","kt":"1","k":["DLSBUmklGu6eLqnA5DA'
                                 b'gj41jetAJYkyn34crqejwXxVw"],"n":"EwmUJaS6DSPRQprlGp_3CIg8BZwmaJl'
                                 b'KPlE4LHcx0Zms","wt":"0","w":[],"c":[]}-AABAAxvl1581mKQME95XZrjsy'
                                 b'CXxJ3fCnmNSG_Bc1I4FcxEoeQbgdLAQ8sudwb0FHOYXfqRE6Z7PraaU82YQDyVShDw')

        # create own Validator Kever in  Validator's Kevery
        valKevery.processOne(ims=bytearray(vmsg))  # send copy of vmsg
        valKever = valKevery.kevers[valpre]
        assert valKever.prefixer.qb64 == valpre

        # simulate sending of controller's inception message to validator
        valKevery.process(ims=bytearray(cmsg))  # make copy of msg
        assert coepre in valKevery.kevers  # creates Kever for controller in validator's .kevers

        # create receipt of controller's inception
        # create seal of validator's last establishment event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        coeK = valKevery.kevers[coepre]  # lookup coeKever from validator's .kevers
        # create validator receipt
        reserder = chit(pre=coeK.prefixer.qb64,
                        sn=coeK.sn,
                        dig=coeK.serder.diger.qb64,
                        seal=seal)
        # Validate receipt
        assert reserder.raw == (b'{"v":"KERI10JSON000105_","i":"EsU9ZQwug7DS-GU040Ugj1t7p6Au14VkBOCJnPYabcas",'
                                b'"s":"0","t":"vrc","d":"Ey2pXEnaoQVwxA4jB6k0QH5G2Us-0juFL5hOAHAwIEkc","a":{"i'
                                b'":"EBiIFxr_o1b4x1YR21PblAFpFG61qDghqFBDyVSOXYW0","s":"0","d":"ElsHFkbZQjRb7x'
                                b'HnuE-wyiarIZ9j-1CEQ89I0E3WevcE"}}')

        # sign controller's event not receipt
        # look up event to sign from validator's kever for coe
        coeIcpDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeIcpDig == coeK.serder.diger.qb64b == b'Ey2pXEnaoQVwxA4jB6k0QH5G2Us-0juFL5hOAHAwIEkc'
        coeIcpRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeIcpDig)))
        assert coeIcpRaw == (b'{"v":"KERI10JSON0000e6_","i":"EsU9ZQwug7DS-GU040Ugj1t7p6Au14VkBOCJnPYabcas",'
                             b'"s":"0","t":"icp","kt":"1","k":["Dpt7mGZ3y5UmhT1NLExb1IW8vMJ8ylQW3K44LfkTgAq'
                             b'E"],"n":"Erpltchg7BUv21Qz3ZXhOhVu63m7S7YbPb21lSeGYd90","wt":"0","w":[],"c":['
                             b']}')
        counter = Counter(CtrDex.ControllerIdxSigs)
        assert counter.qb64 == '-AAB'
        sigers = valMgr.sign(ser=coeIcpRaw, verfers=valVerfers)  # return Siger if index

        # process own validator receipt in validator's Kevery so have copy in own log
        rmsg = messagize(reserder, sigers=sigers)
        assert rmsg == bytearray(b'{"v":"KERI10JSON000105_","i":"EsU9ZQwug7DS-GU040Ugj1t7p6Au14VkBOCJnPYabcas",'
                                 b'"s":"0","t":"vrc","d":"Ey2pXEnaoQVwxA4jB6k0QH5G2Us-0juFL5hOAHAwIEkc","a":{"i'
                                 b'":"EBiIFxr_o1b4x1YR21PblAFpFG61qDghqFBDyVSOXYW0","s":"0","d":"ElsHFkbZQjRb7x'
                                 b'HnuE-wyiarIZ9j-1CEQ89I0E3WevcE"}}-AABAARG0my55RTX81fFzUbbcfygZXfz04VglNA8Zwy'
                                 b'qst_ZvLo05jau9GsF0IS9Vm6yGr8QQPdB7M4oVkrd9IEZ8PDA')

        valKevery.processOne(ims=bytearray(rmsg))  # process copy of rmsg

        # attach receipt message to existing message with validators inception message
        # simulate streaming. validator first sends it's inception event, then sends a receipt to controller
        vmsg.extend(rmsg)
        assert vmsg == bytearray(b'{"v":"KERI10JSON0000e6_","i":"EBiIFxr_o1b4x1YR21PblAFpFG61qDghqF'
                                 b'BDyVSOXYW0","s":"0","t":"icp","kt":"1","k":["DLSBUmklGu6eLqnA5DA'
                                 b'gj41jetAJYkyn34crqejwXxVw"],"n":"EwmUJaS6DSPRQprlGp_3CIg8BZwmaJl'
                                 b'KPlE4LHcx0Zms","wt":"0","w":[],"c":[]}-AABAAxvl1581mKQME95XZrjsy'
                                 b'CXxJ3fCnmNSG_Bc1I4FcxEoeQbgdLAQ8sudwb0FHOYXfqRE6Z7PraaU82YQDyVSh'
                                 b'Dw{"v":"KERI10JSON000105_","i":"EsU9ZQwug7DS-GU040Ugj1t7p6Au14Vk'
                                 b'BOCJnPYabcas","s":"0","t":"vrc","d":"Ey2pXEnaoQVwxA4jB6k0QH5G2Us'
                                 b'-0juFL5hOAHAwIEkc","a":{"i":"EBiIFxr_o1b4x1YR21PblAFpFG61qDghqFB'
                                 b'DyVSOXYW0","s":"0","d":"ElsHFkbZQjRb7xHnuE-wyiarIZ9j-1CEQ89I0E3W'
                                 b'evcE"}}-AABAARG0my55RTX81fFzUbbcfygZXfz04VglNA8Zwyqst_ZvLo05jau9'
                                 b'GsF0IS9Vm6yGr8QQPdB7M4oVkrd9IEZ8PDA')

        # Simulate sending validator's inception event and receipt of controller's inception message to controller
        coeKevery.process(ims=vmsg)  # controller process validator's inception and receipt

        # check if validator's Kever in controller's .kevers
        assert valpre in coeKevery.kevers
        #  check if receipt quadruple from validator in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                   dig=coeKever.serder.diger.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.diger.qb64b +
                                    sigers[0].qb64b)

        assert bytes(result[0]) == (b'EBiIFxr_o1b4x1YR21PblAFpFG61qDghqFBDyVSOXYW00AAAAAAAAAAAAAAAAAAAAAAAElsHFkbZ'
                                    b'QjRb7xHnuE-wyiarIZ9j-1CEQ89I0E3WevcEAARG0my55RTX81fFzUbbcfygZXfz04VglNA8Zwyq'
                                    b'st_ZvLo05jau9GsF0IS9Vm6yGr8QQPdB7M4oVkrd9IEZ8PDA')

        # create receipt to escrow use invalid digest and sequence number so not in controller's db
        fake = reserder.dig  # some other digest
        reserder = chit(pre=coeK.prefixer.qb64,
                        sn=10,
                        dig=fake,
                        seal=seal)
        # sign event not receipt
        sigers = valMgr.sign(ser=coeIcpRaw, verfers=valVerfers)  # return Siger if index

        # create receipt message
        vmsg = messagize(reserder, sigers=sigers)
        assert vmsg == bytearray(b'{"v":"KERI10JSON000105_","i":"EsU9ZQwug7DS-GU040Ugj1t7p6Au14VkBO'
                                 b'CJnPYabcas","s":"a","t":"vrc","d":"EwxY7Vhkeyr7LBnLAzdGXZzSmTmJV'
                                 b'RctQfNUO0YUqeOU","a":{"i":"EBiIFxr_o1b4x1YR21PblAFpFG61qDghqFBDy'
                                 b'VSOXYW0","s":"0","d":"ElsHFkbZQjRb7xHnuE-wyiarIZ9j-1CEQ89I0E3Wev'
                                 b'cE"}}-AABAARG0my55RTX81fFzUbbcfygZXfz04VglNA8Zwyqst_ZvLo05jau9Gs'
                                 b'F0IS9Vm6yGr8QQPdB7M4oVkrd9IEZ8PDA')

        coeKevery.process(ims=vmsg)  # controller process the escrow receipt from validator
        #  check if receipt quadruple in escrow database
        result = coeKevery.db.getVres(key=snKey(pre=coeKever.prefixer.qb64,
                                                   sn=10))
        assert bytes(result[0]) == (fake.encode("utf-8") +
                                    valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.diger.qb64b +
                                    sigers[0].qb64b)

        # Send receipt from controller to validator
        # create receipt of validator's inception
        # create seal of controller's last establishment event
        seal = SealEvent(i=coepre,
                         s="{:x}".format(coeKever.lastEst.s),
                         d=coeKever.lastEst.d)
        valK = coeKevery.kevers[valpre]  # lookup valKever from controller's .kevers
        # create validator receipt
        reserder = chit(pre=valK.prefixer.qb64,
                        sn=valK.sn,
                        dig=valK.serder.diger.qb64,
                        seal=seal)
        # sign validator's event not receipt
        # look up event to sign from controller's kever for validator
        valIcpDig = bytes(coeKevery.db.getKeLast(key=snKey(pre=valpre, sn=vsn)))
        assert valIcpDig == valK.serder.diger.qb64b == b'ElsHFkbZQjRb7xHnuE-wyiarIZ9j-1CEQ89I0E3WevcE'
        valIcpRaw = bytes(coeKevery.db.getEvt(key=dgKey(pre=valpre, dig=valIcpDig)))
        assert valIcpRaw == (b'{"v":"KERI10JSON0000e6_","i":"EBiIFxr_o1b4x1YR21PblAFpFG61qDghqF'
                             b'BDyVSOXYW0","s":"0","t":"icp","kt":"1","k":["DLSBUmklGu6eLqnA5DA'
                             b'gj41jetAJYkyn34crqejwXxVw"],"n":"EwmUJaS6DSPRQprlGp_3CIg8BZwmaJl'
                             b'KPlE4LHcx0Zms","wt":"0","w":[],"c":[]}')

        counter = Counter(CtrDex.ControllerIdxSigs)
        assert counter.qb64 == '-AAB'
        sigers = coeMgr.sign(ser=valIcpRaw, verfers=coeVerfers)  # return Siger if index

        # create receipt message
        cmsg = messagize(reserder, sigers=sigers)
        assert cmsg == bytearray(b'{"v":"KERI10JSON000105_","i":"EBiIFxr_o1b4x1YR21PblAFpFG61qDghqF'
                                 b'BDyVSOXYW0","s":"0","t":"vrc","d":"ElsHFkbZQjRb7xHnuE-wyiarIZ9j-'
                                 b'1CEQ89I0E3WevcE","a":{"i":"EsU9ZQwug7DS-GU040Ugj1t7p6Au14VkBOCJn'
                                 b'PYabcas","s":"0","d":"Ey2pXEnaoQVwxA4jB6k0QH5G2Us-0juFL5hOAHAwIE'
                                 b'kc"}}-AABAAKXFMBGw559YHoxyeDrmpilQo5JMbr5WSfYTn1IXV_rMtg23_GHrNQ'
                                 b'Ua7y45UkNftT48O0MekxT7geRBU84dACA')

        # controller process own receipt in own Kevery so have copy in own log
        coeKevery.processOne(ims=bytearray(cmsg))  # make copy

        # Simulate sending controller's receipt of validator's inception message to validator
        valKevery.process(ims=cmsg)  # controller process validator's inception and receipt

        #  check if receipt quadruple from controller in validator's receipt database
        result = valKevery.db.getVrcs(key=dgKey(pre=valKever.prefixer.qb64,
                                                   dig=valKever.serder.diger.qb64))
        assert bytes(result[0]) == (coeKever.prefixer.qb64b +
                                    Seqner(sn=coeKever.sn).qb64b +
                                    coeKever.serder.diger.qb64b +
                                    sigers[0].qb64b)
        assert bytes(result[0]) == (b'EsU9ZQwug7DS-GU040Ugj1t7p6Au14VkBOCJnPYabcas0AAAAAAAAAAAAAAAAAAAAAAAEy2pXEna'
                                    b'oQVwxA4jB6k0QH5G2Us-0juFL5hOAHAwIEkcAAKXFMBGw559YHoxyeDrmpilQo5JMbr5WSfYTn1I'
                                    b'XV_rMtg23_GHrNQUa7y45UkNftT48O0MekxT7geRBU84dACA')

        # Controller Event 1 Rotation Transferable
        csn += 1
        cesn += 1
        assert csn == cesn == 1
        coeVerfers, coeDigers = coeMgr.rotate(coeVerfers[0].qb64)
        coeSerder = rotate(pre=coeKever.prefixer.qb64,
                           keys=[coeVerfers[0].qb64],
                           dig=coeKever.serder.diger.qb64,
                           nxt=Nexter(digs=[coeDigers[0].qb64]).qb64,
                           sn=csn)
        coe_event_digs.append(coeSerder.dig)

        # sign serialization
        sigers = coeMgr.sign(coeSerder.raw, verfers=coeVerfers)  # returns sigers

        #  create serialized message
        cmsg = messagize(coeSerder, sigers=sigers)

        assert cmsg == bytearray(b'{"v":"KERI10JSON000122_","i":"EsU9ZQwug7DS-GU040Ugj1t7p6Au14VkBO'
                                 b'CJnPYabcas","s":"1","t":"rot","p":"Ey2pXEnaoQVwxA4jB6k0QH5G2Us-0'
                                 b'juFL5hOAHAwIEkc","kt":"1","k":["D-HwiqmaETxls3vAVSh0xpXYTs94NUJX'
                                 b'6juupWj_EgsA"],"n":"ED6lKZwg-BWl_jlCrjosQkOEhqKD4BJnlqYqWmhqPhaU'
                                 b'","wt":"0","wr":[],"wa":[],"a":[]}-AABAAsDhyw43CAo29zyTZ7WIuztBG'
                                 b'L3WELM78qSwaEYh8NzwNAPqDtiuL-QmKd22om1qYGDU7cuFM-AlTKaFjsVOzBg')

        # update controller's key event verifier state
        coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify controller's copy of controller's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.serder.diger.qb64 == coeSerder.dig

        # simulate send message from controller to validator
        valKevery.process(ims=cmsg)
        # verify validator's copy of controller's event stream is updated
        assert coeK.sn == csn
        assert coeK.serder.diger.qb64 == coeSerder.dig

        # create receipt of controller's rotation
        # create seal of validator's last establishment event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        # create validator receipt
        reserder = chit(pre=coeK.prefixer.qb64,
                        sn=coeK.sn,
                        dig=coeK.serder.diger.qb64,
                        seal=seal)
        # sign controller's event not receipt
        # look up event to sign from validator's kever for controller
        coeRotDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeRotDig == coeK.serder.diger.qb64b == b'EO7V6wDClWWiN_7sfGDTD8KsfRQaHyap6fz_O4CYvsek'
        coeRotRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeRotDig)))
        assert coeRotRaw == (b'{"v":"KERI10JSON000122_","i":"EsU9ZQwug7DS-GU040Ugj1t7p6Au14VkBOCJnPYabcas",'
                             b'"s":"1","t":"rot","p":"Ey2pXEnaoQVwxA4jB6k0QH5G2Us-0juFL5hOAHAwIEkc","kt":"1'
                             b'","k":["D-HwiqmaETxls3vAVSh0xpXYTs94NUJX6juupWj_EgsA"],"n":"ED6lKZwg-BWl_jlC'
                             b'rjosQkOEhqKD4BJnlqYqWmhqPhaU","wt":"0","wr":[],"wa":[],"a":[]}')

        sigers = valMgr.sign(ser=coeRotRaw, verfers=valVerfers)

        # validator create receipt message
        vmsg = messagize(reserder, sigers=sigers)
        assert vmsg == bytearray(b'{"v":"KERI10JSON000105_","i":"EsU9ZQwug7DS-GU040Ugj1t7p6Au14VkBO'
                                 b'CJnPYabcas","s":"1","t":"vrc","d":"EO7V6wDClWWiN_7sfGDTD8KsfRQaH'
                                 b'yap6fz_O4CYvsek","a":{"i":"EBiIFxr_o1b4x1YR21PblAFpFG61qDghqFBDy'
                                 b'VSOXYW0","s":"0","d":"ElsHFkbZQjRb7xHnuE-wyiarIZ9j-1CEQ89I0E3Wev'
                                 b'cE"}}-AABAAjVFBjhbM2RdHKEk2rtHA0tXMe0iswn6IS5ShALtR3JHMz-NePCN_f'
                                 b'lUEUbV2F22CGRgmnCe71n42ywWyzsFmDg')

        # validator process own receipt in own kevery so have copy in own log
        valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to controller of validator's receipt of controller's rotation message
        coeKevery.process(ims=vmsg)  # controller process validator's incept and receipt

        # check if receipt quadruple from validator in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                   dig=coeKever.serder.diger.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.diger.qb64b +
                                    sigers[0].qb64b)

        assert bytes(result[0]) == (b'EBiIFxr_o1b4x1YR21PblAFpFG61qDghqFBDyVSOXYW00AAAAAAAAAAAAAAAAAAAAAAAElsHFkbZ'
                                    b'QjRb7xHnuE-wyiarIZ9j-1CEQ89I0E3WevcEAAjVFBjhbM2RdHKEk2rtHA0tXMe0iswn6IS5ShAL'
                                    b'tR3JHMz-NePCN_flUEUbV2F22CGRgmnCe71n42ywWyzsFmDg')

        # Next Event 2 Controller Interaction
        csn += 1  # do not increment esn
        assert csn == 2
        assert cesn == 1
        coeSerder = interact(pre=coeKever.prefixer.qb64,
                             dig=coeKever.serder.diger.qb64,
                             sn=csn)
        coe_event_digs.append(coeSerder.dig)

        # sign serialization
        sigers = coeMgr.sign(coeSerder.raw, verfers=coeVerfers)

        # create msg
        cmsg = messagize(coeSerder, sigers=sigers)
        assert cmsg == bytearray(b'{"v":"KERI10JSON000098_","i":"EsU9ZQwug7DS-GU040Ugj1t7p6Au14VkBO'
                                 b'CJnPYabcas","s":"2","t":"ixn","p":"EO7V6wDClWWiN_7sfGDTD8KsfRQaH'
                                 b'yap6fz_O4CYvsek","a":[]}-AABAAstaU9Hu1ti8erlnFwEdCrXWkkkW_ydYgrr'
                                 b'ryB6EtEOrWY_tQh5jZLGRWrClefeX6AfDDw7JS5JY15n8_ueJWBQ')

        # update controller's key event verifier state
        coeKevery.processOne(ims=bytearray(cmsg))  # make copy
        # verify controller's copy of controller's event stream is updated
        assert coeKever.sn == csn
        assert coeKever.serder.diger.qb64 == coeSerder.dig

        # simulate send message from controller to validator
        valKevery.process(ims=cmsg)
        # verify validator's copy of controller's event stream is updated
        assert coeK.sn == csn
        assert coeK.serder.diger.qb64 == coeSerder.dig

        # create receipt of controller's interaction
        # create seal of validator's last est event
        seal = SealEvent(i=valpre,
                         s="{:x}".format(valKever.lastEst.s),
                         d=valKever.lastEst.d)
        # create validator receipt
        reserder = chit(pre=coeK.prefixer.qb64,
                        sn=coeK.sn,
                        dig=coeK.serder.diger.qb64,
                        seal=seal)
        # sign controller's event not receipt
        # look up event to sign from validator's kever for controller
        coeIxnDig = bytes(valKevery.db.getKeLast(key=snKey(pre=coepre, sn=csn)))
        assert coeIxnDig == coeK.serder.diger.qb64b == b'EuCLxtdKdRgzzgBnPhTwFKz36u58DqQyMqhX5CUrurPE'
        coeIxnRaw = bytes(valKevery.db.getEvt(key=dgKey(pre=coepre, dig=coeIxnDig)))
        assert coeIxnRaw == (b'{"v":"KERI10JSON000098_","i":"EsU9ZQwug7DS-GU040Ugj1t7p6Au14VkBOCJnPYabcas",'
                             b'"s":"2","t":"ixn","p":"EO7V6wDClWWiN_7sfGDTD8KsfRQaHyap6fz_O4CYvsek","a":[]}')

        sigers = valMgr.sign(ser=coeIxnRaw, verfers=valVerfers)

        # create receipt message
        vmsg = messagize(reserder, sigers=sigers)
        assert vmsg == bytearray(b'{"v":"KERI10JSON000105_","i":"EsU9ZQwug7DS-GU040Ugj1t7p6Au14VkBO'
                                 b'CJnPYabcas","s":"2","t":"vrc","d":"EuCLxtdKdRgzzgBnPhTwFKz36u58D'
                                 b'qQyMqhX5CUrurPE","a":{"i":"EBiIFxr_o1b4x1YR21PblAFpFG61qDghqFBDy'
                                 b'VSOXYW0","s":"0","d":"ElsHFkbZQjRb7xHnuE-wyiarIZ9j-1CEQ89I0E3Wev'
                                 b'cE"}}-AABAAboeSfNNgX04wuUrQp-3eY0oUzcLYnLUmtqYETBZqXEL97pjSjmm81'
                                 b'1KzCRu2cnSHVlKqzIaEBaXyBpWBDexLBQ')

        # ------------------------------END CONVERTED CODE------------------------------

        # validator process own receipt in own kevery so have copy in own log
        valKevery.processOne(ims=bytearray(vmsg))  # make copy

        # Simulate send to controller of validator's receipt of controller's rotation message
        coeKevery.process(ims=vmsg)  # controller process validator's incept and receipt

        #  check if receipt quadruple from validator in receipt database
        result = coeKevery.db.getVrcs(key=dgKey(pre=coeKever.prefixer.qb64,
                                                   dig=coeKever.serder.diger.qb64))
        assert bytes(result[0]) == (valKever.prefixer.qb64b +
                                    Seqner(sn=valKever.sn).qb64b +
                                    valKever.serder.diger.qb64b +
                                    sigers[0].qb64b)

        assert bytes(result[0]) == (b'EBiIFxr_o1b4x1YR21PblAFpFG61qDghqFBDyVSOXYW00AAAAAAAAAAAAAAAAAAAAAAAElsHFkbZ'
                                    b'QjRb7xHnuE-wyiarIZ9j-1CEQ89I0E3WevcEAAboeSfNNgX04wuUrQp-3eY0oUzcLYnLUmtqYETB'
                                    b'ZqXEL97pjSjmm811KzCRu2cnSHVlKqzIaEBaXyBpWBDexLBQ')

        #  verify final controller event state
        assert coeKever.sn == coeK.sn == csn

        db_digs = [bytes(v).decode("utf-8") for v in coeKever.baser.getKelIter(coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn + 1
        assert db_digs == coe_event_digs == ['Ey2pXEnaoQVwxA4jB6k0QH5G2Us-0juFL5hOAHAwIEkc',
                                             'EO7V6wDClWWiN_7sfGDTD8KsfRQaHyap6fz_O4CYvsek',
                                             'EuCLxtdKdRgzzgBnPhTwFKz36u58DqQyMqhX5CUrurPE']

        db_digs = [bytes(v).decode("utf-8") for v in valKever.baser.getKelIter(coepre)]
        assert len(db_digs) == len(coe_event_digs) == csn + 1
        assert db_digs == coe_event_digs

        #  verify final validator event state
        assert valKever.sn == valK.sn == vsn

        db_digs = [bytes(v).decode("utf-8") for v in valKever.baser.getKelIter(valpre)]
        assert len(db_digs) == len(val_event_digs) == vsn + 1
        assert db_digs == val_event_digs == ['ElsHFkbZQjRb7xHnuE-wyiarIZ9j-1CEQ89I0E3WevcE']

        db_digs = [bytes(v).decode("utf-8") for v in coeKever.baser.getKelIter(valpre)]
        assert len(db_digs) == len(val_event_digs) == vsn + 1
        assert db_digs == val_event_digs

    assert not os.path.exists(valKevery.db.path)
    assert not os.path.exists(coeKever.baser.path)


if __name__ == "__main__":
    test_direct_mode_with_manager()
