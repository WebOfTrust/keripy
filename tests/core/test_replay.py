# -*- encoding: utf-8 -*-
"""
tests delegation primaily from keri.core.eventing

"""
import datetime
import os

from hio.help import ogler


from keri.kering import Version, Vrsn_1_0, Vrsn_2_0, Ilks, Kinds
from keri.help import helping
from keri.core import (Salter, Counter, Seqner, Dater, Prefixer, Number, Diger,
                        Siger, Kevery, Parser, SerderKERI, CtrDex_1_0, CtrDex_2_0,
                       deTransReceiptQuadruple, deReceiptCouple)

from keri.app import openHby


logger = ogler.getLogger()


def test_replay_v1():
    """
    Test disjoint and conjoint replay

    Deb creates series of events.
    Deb replays Deb's events to Cam and collects Cam's receipts
    Deb replays Deb's events with Cam's recepts to Bev and collects Bev's receipts
    Deb replays Deb's events with both Cam's and  Bev's receipts to Cam
    Compare replay of Deb's events with receipts by both Deb and Cam to confirm identical
    """
    artSalt = Salter(raw=b'abcdef0123456789').qb64
    default_salt = Salter(raw=b'0123456789abcdef').qb64

    with (openHby(name="deb", base="test", salt=default_salt, version=Vrsn_1_0) as debHby,
         openHby(name="cam", base="test", salt=default_salt, version=Vrsn_1_0) as camHby,
         openHby(name="bev", base="test", salt=default_salt, version=Vrsn_1_0) as bevHby,
         openHby(name="art", base="test", salt=artSalt, version=Vrsn_1_0) as artHby):

        # setup Deb's habitat using default salt multisig already incepts
        sith = ["1/2", "1/2", "1/2"]  # weighted signing threshold
        debHab = debHby.makeHab(name="deb", isith=sith, icount=3, version=Vrsn_1_0, kind=Kinds.json)
        assert debHab.kever.prefixer.transferable

        # setup Cam's habitat using default salt multisig already incepts
        # Cam's receipts will be vrcs with 3 indexed sigantures attached
        sith = '2'  # hex str of threshold int
        camHab = camHby.makeHab(name="cam", isith=sith, icount=3, version=Vrsn_1_0, kind=Kinds.json)
        assert camHab.kever.prefixer.transferable

        # setup Bev's habitat using default salt nonstransferable already incepts
        # Bev's receipts will be rcts with a receipt couple attached
        sith = '1'  # hex str of threshold int
        bevHab = bevHby.makeHab(name="bev", isith=sith, icount=1, transferable=False, version=Vrsn_1_0, kind=Kinds.json)
        assert not bevHab.kever.prefixer.transferable

        # setup Art's habitat using custom salt nonstransferable so not match Bev
        # already incepts
        # Art's receipts will be rcts with a receipt couple attached
        sith = '1'  # hex str of threshold int
        artHab = artHby.makeHab(name="art", isith=sith, icount=1, transferable=False, version=Vrsn_1_0, kind=Kinds.json)
        assert not artHab.kever.prefixer.transferable

        # Create series of event for Deb
        debMsgs = bytearray()
        debMsgs.extend(debHab.msgOwnInception(framed=True, gvrsn=Vrsn_1_0))
        debMsgs.extend(debHab.interact(framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0))
        debMsgs.extend(debHab.rotate(framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0))
        debMsgs.extend(debHab.interact(framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0))
        debMsgs.extend(debHab.interact(framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0))
        debMsgs.extend(debHab.interact(framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0))
        debMsgs.extend(debHab.interact(framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0))

        assert debMsgs == (b'{"v":"KERI10JSON000207_","t":"icp","d":"ELfp9ZhqQCGov3wPRLa6vn5V'
            b'kIQjug2sb2QD17T-TIpY","i":"ELfp9ZhqQCGov3wPRLa6vn5VkIQjug2sb2QD1'
            b'7T-TIpY","s":"0","kt":["1/2","1/2","1/2"],"k":["DEcQixETvXkrxuH5'
            b'bszrCudhglgrSjmQpVcAN_DmvvjA","DAsc09eopD-iylSX6-ob9Y5ocp5uiOPiq'
            b'BmJCbXfbga6","DLA5ecUh5yJXBqNd7uYw0a9YyTJEN-JxHOUejWLHT0tp"],"nt'
            b'":["1/2","1/2","1/2"],"n":["EHi61HDu9euzY_8aa5iSmrTlXxme5Qy3oY6i'
            b'XucSEeGh","EB6NxkyXMBgDPthCtbx_f1UFW1pUMTh3B5wd3wuNX2WJ","EDjOUD'
            b'gp2ft49_bqxmhW5mhCISsHxm0UZPjhUeGJWytb"],"bt":"0","b":[],"c":[],'
            b'"a":[]}-AADAADqkN1IwOepXk5LYPaLBCoHWnZpdWZ2qmhLQKY9I-ape8cTqwHKP'
            b'g5EP98ybxgYDhAzpOkv9BzE2dhVeac0l7cKABBJhNtfZG642LFbrRurILy0iKMoT'
            b'8bc1OlkcFYDpmCUwIYlH_jNk-7WlxtgunEMMcBvvGl_E5xuZ_Il6YLSUY4JACAIr'
            b'MoryRkispZKXWabmx2aBrTgTaGBvysk7B3-mcF0Mg1riSikRar5d70gBZIQjAUuE'
            b'6KYWLd1Sa0CTMzaTZAO{"v":"KERI10JSON0000cb_","t":"ixn","d":"EFECU'
            b'zlLZ3IKG9Kvkj51a0RYPYXnUeZ5SIpw8x3SPS1E","i":"ELfp9ZhqQCGov3wPRL'
            b'a6vn5VkIQjug2sb2QD17T-TIpY","s":"1","p":"ELfp9ZhqQCGov3wPRLa6vn5'
            b'VkIQjug2sb2QD17T-TIpY","a":[]}-AADAAA9aT5vgzKjSVl_xcCXiLIUIqYl9_'
            b'__1Gll8Sj6dDIAygsBQ-lVATd1ifTe_DcsKTwY6sCr1a29f1LNOY_tngoLABCUcE'
            b'NmDJH_Xeh7Pc5q8Nwww5FcTJtpHkBTwdeJ-v6aSPUMaTdkXI7n_3r-8ogrDlKddj'
            b'gYiOTt2V7f53g-JbYCACAVG_IWtYZpVns4bYI_Acce2HMFjrM26cB_OuyHdYHx7S'
            b'5SDrJmnKeQvSnMGGq_MiBGf3RhW7szQw1zFwSHKEMI{"v":"KERI10JSON00023c'
            b'_","t":"rot","d":"EELHnIwzGaJ-twKTfXtsPMteqsIVmDpiwVO574h6LRXD",'
            b'"i":"ELfp9ZhqQCGov3wPRLa6vn5VkIQjug2sb2QD17T-TIpY","s":"2","p":"'
            b'EFECUzlLZ3IKG9Kvkj51a0RYPYXnUeZ5SIpw8x3SPS1E","kt":["1/2","1/2",'
            b'"1/2"],"k":["DI_g1MHwpjqxN4o6rnEdCPPf32ExW8qLWqnkMg37qZBF","DC_p'
            b'P_AWp4y2GgHZulliiKR3B8HGxfN-L5yz4KVtTS_J","DFhtmRbFmFLGwyNSprvCR'
            b'9tohmlQxrzO6Z7k-MtqEd1S"],"nt":["1/2","1/2","1/2"],"n":["ELFzlp0'
            b'ShKZ35PElySBc2l-Mol2RwmjuMIvfmwP2IwMN","EM64JMyn8UliE8JY7zBEGyou'
            b'dykA8ql52WkviIWs86ov","EAbVsTzKbdx9mHkxNlxfT_-1bz9tWGkpSc9d5rA_G'
            b'UsI"],"bt":"0","br":[],"ba":[],"a":[]}-AADAAD6u5uRxC8VLgzXddS3-g'
            b'WBbvsFiR9yxr9LVMDDlIg_52PSbdlyXzyna8eWtRNP45qP-eczRmX4ynFfaTW4r0'
            b'kJABD-UKXmYnHwvxbdzkXHWNMaHOi4Up2HD4PGDn_O6Fg426wA7d8RFbWoyXQ25V'
            b'yYHBEu3rlgtmyzhHX1ltrwufUJACApEq33UecImxkmkFtzgOS2O84hIc97aMsXrR'
            b'ong2datCM2Ip2odY-GTRSLLOhdzg1SejBBlyT7oBmM-qdCqioP{"v":"KERI10JS'
            b'ON0000cb_","t":"ixn","d":"ECWvVQFFqxmAW-vpSLwWj4yPO04nGA-6l8cifN'
            b'Blc3gK","i":"ELfp9ZhqQCGov3wPRLa6vn5VkIQjug2sb2QD17T-TIpY","s":"'
            b'3","p":"EELHnIwzGaJ-twKTfXtsPMteqsIVmDpiwVO574h6LRXD","a":[]}-AA'
            b'DAABgIkfny2TLxsBNx0Jy7qOas75QgqcmyovkDOU57YlHXIYSSKqTAkwZ3tkVifx'
            b'2bCHkg14xl16Zl1WAnqOx8wMEABBFUmop2zG5IJRUsacdqJB9jIcUrlFN-oq53rA'
            b'9JlC8UJCMbR7sF4Yb6xy88XowWMdcZKv-pDbNRM_mDAoCi_sPACCVCBxDNcthRLk'
            b'eYNvww2DIYDS-X8EFzY4zI7w7eT0N-noe9qxljWf6EMxU2o3ZCVy9iODnpUKAa9E'
            b'b6k3hGB0H{"v":"KERI10JSON0000cb_","t":"ixn","d":"EFcoQIrpd4_NMcn'
            b'L7SvVqUSLfPZOzkAGbtQcE3JVMn7D","i":"ELfp9ZhqQCGov3wPRLa6vn5VkIQj'
            b'ug2sb2QD17T-TIpY","s":"4","p":"ECWvVQFFqxmAW-vpSLwWj4yPO04nGA-6l'
            b'8cifNBlc3gK","a":[]}-AADAADmTY74mWFG2UQ1UfIU7n_2fmZZL7BIl0bPCxIG'
            b'EmdxpZhib8WGE2V7oC5Lal11V95nP3CgAtkZRf1ig7jUGbEHABCyPH2D6oVXrP1r'
            b'e8wRKMzfJHNt1BS8pfBa7DtfJ1vUSWhCGNxzo2F0Jby_pu9VU6G93hBQb9o2M86C'
            b't-WRpMAMACAnqyD8jWyGOpkeK27Jp9YYOt96e_gmUY03CtDqM5g27fHcqZ6wbsku'
            b'4j3lnbxyIoKmi0eaz4sNzzvRe07gKPkG{"v":"KERI10JSON0000cb_","t":"ix'
            b'n","d":"ELVXLfglCimN6Y-HkpoLoLiQkR1v65rrg7JRDhcToXVn","i":"ELfp9'
            b'ZhqQCGov3wPRLa6vn5VkIQjug2sb2QD17T-TIpY","s":"5","p":"EFcoQIrpd4'
            b'_NMcnL7SvVqUSLfPZOzkAGbtQcE3JVMn7D","a":[]}-AADAADgJwA-ury9T7UMg'
            b'4CcsFHzpnWYWrP6Tv2NTtFTIuyjr8sXVk5wIHUqPdChxdSty_dqZsCQ55VxT5IxV'
            b'vsnr74NABAei1rsp4wsNNOIx6UlUn4IywK58IVxMA4wbTpHMSE1c0MLKo4I6yzEi'
            b'uWCLwe_BdfZIab1t0AkFMOtDzxjfq8GACDVbQ0xyKXxVuQ5nn42KCsGy86rYrAyc'
            b'slgoiyTNvPdeHBiohV418sAmy5HD46ia_d9xDpM6dSldOo-ejC1w7EC{"v":"KER'
            b'I10JSON0000cb_","t":"ixn","d":"ECSAoB-QcY3Vnia2G80NLVMkiGssUV70J'
            b'oWxwJbqx9gL","i":"ELfp9ZhqQCGov3wPRLa6vn5VkIQjug2sb2QD17T-TIpY",'
            b'"s":"6","p":"ELVXLfglCimN6Y-HkpoLoLiQkR1v65rrg7JRDhcToXVn","a":['
            b']}-AADAADV-VPXI9US25isPB1E_FjxcsuOTn15zZ6xlAVGQxVcDkvP0JzTR76zPm'
            b'lkKNJR6XX8XgfYFXix_6Ew5clfUQkOABAWG25ZG2uXl6jksn0xl7-SWuFTI6ZUuC'
            b'1GKkeaTbP1DT8hitwTrbcVZj1p_WOAyGzPGr5MCVG7TeQLGGzHu2sMACDwQlEJV6'
            b'OOJVAAAjEg-3N4cNT_yot5wWlcKaz-1xPAgteGCsYZhq9dax3sQPD5HFI7M13Bhp'
            b'kRttBEq92pAaIG')

        assert debHab.kever.sn == 6
        msgs = next(debHab.db.clonePreIter(debHab.pre, fn=4, version=Vrsn_1_0))
        serder = SerderKERI(raw=msgs)
        assert serder.ilk == Ilks.ixn
        assert serder.sn == 4

        # Play debMsgs to Cam
        # create non-local kevery for Cam to process msgs from Deb
        camKevery = Kevery(db=camHab.db,
                                    lax=False,
                                    local=False)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(debMsgs), kvy=camKevery)
        # camKevery.process(ims=bytearray(debMsgs))  # give copy to process
        assert debHab.pre in camKevery.kevers
        assert camKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(camKevery.cues) == 7
        # get disjoints receipts (vrcs) from Cam of Deb's events by processing Cam's cues
        camMsgs = camHab.processCues(camKevery.cues, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        assert camMsgs == (b'{"v":"KERI10JSON0001e7_","t":"icp","d":"EBp-SQb9fTgeoQkIkOd2xegv'
                        b'Xy3epjOskiPrf6JDIEuj","i":"EBp-SQb9fTgeoQkIkOd2xegvXy3epjOskiPrf'
                        b'6JDIEuj","s":"0","kt":"2","k":["DCQbRBx58zbRPs8R9cXl-MMbPaxH1EPH'
                        b'dWp3ICSdQSyp","DDLusjyE46zgaEz37GPq9UXNHmnfBipqAsQPwboCnoYG","DH'
                        b'4ab2zcmLtX8UwU18vHgoIITHDmJ8ZIKBjwa9GQWT0A"],"nt":"2","n":["EGSF'
                        b'aY2-o3mAVN1iq23SovuMY34VCNcsot4WhS-JXGgf","EOHL9prk6Um5CxeoofhVV'
                        b'Nik0DRhrHZQWX3k_whUf49Y","EID2f_sJoa-DJSmOlYvxuofE0Zzp_qningHCJ5'
                        b'X-gZIG"],"bt":"0","b":[],"c":[],"a":[]}-AADAACLbBvicsgapBJU2I7gJ'
                        b'iqY_h4X-zTu61aUl-qBMxKoFYPP_YX2Cl94ck580dD0T1uVj8s_qxtCm1LAEa5bG'
                        b'Z0FABAbmupsT6XzfUNWO3B0jQFbVppgyfvEwLERSnw6XKQZKoH7EqQdIQN3GF7U9'
                        b'Bk6yWCGjTcsSvpiKXi3Bnw1CiYCACD50cKv4w8L14pJSVCKPrMO5EOqZo3dQan5j'
                        b'-GY8LfZ_z441iTzf53acNZQXEMXhS4fStYgz0RY3DT9r0rtth4I{"v":"KERI10J'
                        b'SON000091_","t":"rct","d":"ELfp9ZhqQCGov3wPRLa6vn5VkIQjug2sb2QD1'
                        b'7T-TIpY","i":"ELfp9ZhqQCGov3wPRLa6vn5VkIQjug2sb2QD17T-TIpY","s":'
                        b'"0"}-FABEBp-SQb9fTgeoQkIkOd2xegvXy3epjOskiPrf6JDIEujMAAAEBp-SQb9'
                        b'fTgeoQkIkOd2xegvXy3epjOskiPrf6JDIEuj-AADAADLQfvb0b5TiD4Y-4wjaTMJ'
                        b'GTYW4CyEL2tPhwgvbuWt3JV7e_qsaPszYE17QqR3WiOLlQ1mCCAzsYuIT2CGvYoM'
                        b'ABCc4h6BKn6u-FODICsn7JhhIv16bdWjPRLZ_wpvlpsGYQE8_hNebpOyKMeeqbkm'
                        b'NimbQUbyBZAO2-3w9dVFDXUBACCVRnaFk5BTNKXD8HpeIVIEgpnu6BJLZ9C5VYAc'
                        b'1-kS7HTuSCc5ZMZRRFid8Ugt8SWLTbDYpLSMFVYy0VQqIcYB{"v":"KERI10JSON'
                        b'000091_","t":"rct","d":"EFECUzlLZ3IKG9Kvkj51a0RYPYXnUeZ5SIpw8x3S'
                        b'PS1E","i":"ELfp9ZhqQCGov3wPRLa6vn5VkIQjug2sb2QD17T-TIpY","s":"1"'
                        b'}-FABEBp-SQb9fTgeoQkIkOd2xegvXy3epjOskiPrf6JDIEujMAAAEBp-SQb9fTg'
                        b'eoQkIkOd2xegvXy3epjOskiPrf6JDIEuj-AADAABGTRtvtT_fwczryJNP8wVxFog'
                        b'46GK_aM2PV2BKrx6NnXKcG400u_0RtWmf4HfcbIgShjLciuD8-8prdczzLKoLABB'
                        b'wRzBuX1yXl7gqGBuw9vmfx2cnLEfnNnuF6KlgvGrGuaaNvMWtMC4jAyPFYdrcGwS'
                        b'G_Akg3zXW3GSrVgossNAEACA6LncYgxQiJ_HTAQARynrd4H53gf4VvLYVI4XZaEg'
                        b'iQi_HA3QV-CxTA2uNLTYo-j84CtpUxrmA23NY3JPgmUMJ{"v":"KERI10JSON000'
                        b'091_","t":"rct","d":"EELHnIwzGaJ-twKTfXtsPMteqsIVmDpiwVO574h6LRX'
                        b'D","i":"ELfp9ZhqQCGov3wPRLa6vn5VkIQjug2sb2QD17T-TIpY","s":"2"}-F'
                        b'ABEBp-SQb9fTgeoQkIkOd2xegvXy3epjOskiPrf6JDIEujMAAAEBp-SQb9fTgeoQ'
                        b'kIkOd2xegvXy3epjOskiPrf6JDIEuj-AADAAC8ionj_ZwUG9TVkLEtvamimUtttk'
                        b'yPWJYziFgppcJo0D7NqrI68irp5t1Jx6tHhXnYdp6p_MySoFdHphInUQENABAC9G'
                        b'bBibt14SbKyzktfn0xurSNHwhV1D61rgKPjoM6HIhJ7J171SZpIyT9ppraWJEMcR'
                        b'I4cDWkC3FWFLoVXo4HACAvxzyZMpnEVzxt56SZhDwE_aa2jma4ge_Lw3fODzT0Vq'
                        b'La6WDBn5ChZwExXaTm3DtH0bCai0WdBX4_SLT2qS0O{"v":"KERI10JSON000091'
                        b'_","t":"rct","d":"ECWvVQFFqxmAW-vpSLwWj4yPO04nGA-6l8cifNBlc3gK",'
                        b'"i":"ELfp9ZhqQCGov3wPRLa6vn5VkIQjug2sb2QD17T-TIpY","s":"3"}-FABE'
                        b'Bp-SQb9fTgeoQkIkOd2xegvXy3epjOskiPrf6JDIEujMAAAEBp-SQb9fTgeoQkIk'
                        b'Od2xegvXy3epjOskiPrf6JDIEuj-AADAAATkvw3JirYUej9yP58hEu0mb5klkMAH'
                        b'XHnVocUInjkJe2dY-TQi0LsmRdA4-Atr0Ys4iT0uqyEsOoHkDch4EMBABCRvib0d'
                        b'z7KqpOS17MbWixJHxeLt0shgNBuXFXyFP5NrZdXRWuJ-z6jbH4hlO_hXrBdfK4CX'
                        b'TegUuBxqZiT3g8PACDWPPS-lBg7PvPcfus4ahRYCEWK-kNyaRCJ3BiFDbEb1YTV2'
                        b'sFJliZ3Rnt7-_YBHUtLIS-ScgBG_HanGwQV9JEM{"v":"KERI10JSON000091_",'
                        b'"t":"rct","d":"EFcoQIrpd4_NMcnL7SvVqUSLfPZOzkAGbtQcE3JVMn7D","i"'
                        b':"ELfp9ZhqQCGov3wPRLa6vn5VkIQjug2sb2QD17T-TIpY","s":"4"}-FABEBp-'
                        b'SQb9fTgeoQkIkOd2xegvXy3epjOskiPrf6JDIEujMAAAEBp-SQb9fTgeoQkIkOd2'
                        b'xegvXy3epjOskiPrf6JDIEuj-AADAAATnbaIYocPQWSwn26FGE9gLLxybf_kYLlM'
                        b'38itDL_udjJ1tYICFzdfUj_n7rEs_e2gz72NHSpfFCdmSbTafXUDABCMcU34uYKj'
                        b'h3USDhllvTTTl-QXzbf7o5OITfaUZEMnPXssMi6XbV1Oifu7JS-nZGpkXAPM2HqQ'
                        b'd3Nzgx9WV8AHACCbzy5FlSMUjWm7mfCK_2Eo-scJNXdcncjeNNcr3I_CbZlOukmY'
                        b'3vPZzydQyMxEKzgMyUwjKlx5QsChtl_Z6J0N{"v":"KERI10JSON000091_","t"'
                        b':"rct","d":"ELVXLfglCimN6Y-HkpoLoLiQkR1v65rrg7JRDhcToXVn","i":"E'
                        b'Lfp9ZhqQCGov3wPRLa6vn5VkIQjug2sb2QD17T-TIpY","s":"5"}-FABEBp-SQb'
                        b'9fTgeoQkIkOd2xegvXy3epjOskiPrf6JDIEujMAAAEBp-SQb9fTgeoQkIkOd2xeg'
                        b'vXy3epjOskiPrf6JDIEuj-AADAACs4ZBIRuqeLb89OzIA-yVqvYdgwT5d5MZ7T-c'
                        b'hrjkKKKrG2-93TqJv5DQoQ1H4Co18CvLjy0vj0odggJby5N4NABB6sAy89h4uU9v'
                        b'iuDSzKBw88SYCy1OiiTPqV6kpucYIVcKkF_yYGfB-QXPuwCrQr-xN572CyRE0Pxe'
                        b'cMFa-YogIACCKOoOQex0AUWu4YmlLo4RF2-hkaNsuVyP8aviudTV4Io7fYLnpV5h'
                        b'd3X9_7P46lZJSvDMll30AVq8sAtiLp4sJ{"v":"KERI10JSON000091_","t":"r'
                        b'ct","d":"ECSAoB-QcY3Vnia2G80NLVMkiGssUV70JoWxwJbqx9gL","i":"ELfp'
                        b'9ZhqQCGov3wPRLa6vn5VkIQjug2sb2QD17T-TIpY","s":"6"}-FABEBp-SQb9fT'
                        b'geoQkIkOd2xegvXy3epjOskiPrf6JDIEujMAAAEBp-SQb9fTgeoQkIkOd2xegvXy'
                        b'3epjOskiPrf6JDIEuj-AADAAANnzuJ_wzxPKRggIpkqC9LFCZ-ARAB_JzKcuFh26'
                        b'1zS-1uUmyoAEH6tKeG2dWv5xfLhjziVaeip4cMmvwrC5EIABC_5losjcTe4ka6aG'
                        b'ks_xt1q3qv5hIJzwluyqwBtRDK-oCDnsHfJiZCFi6Fd4OnYkW5tg9F85etul09Es'
                        b'qbQ60NACA4ZILmT9YYliUbdNivmu8AeXFzSN5T5sDSrOT79J5RcbP6oJidhYCNIh'
                        b'UB5bKmsuEnWda_NXXwJCsklQbQDGUL')

        # Play camMsgs to Deb
        # create non-local kevery for Deb to process msgs from Cam
        debKevery = Kevery(db=debHab.db,
                                    lax=False,
                                    local=False)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(camMsgs), kvy=debKevery)
        # debKevery.process(ims=bytearray(camMsgs))  # give copy to process
        assert camHab.pre in debKevery.kevers
        assert debKevery.kevers[camHab.pre].sn == camHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Cam's events by processing Deb's cues
        debCamVrcs = debHab.processCues(debKevery.cues, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        assert len(debKevery.cues) == 0
        assert debCamVrcs == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EBp-SQb9fTgeoQkIkOd2xegv'
                            b'Xy3epjOskiPrf6JDIEuj","i":"EBp-SQb9fTgeoQkIkOd2xegvXy3epjOskiPrf'
                            b'6JDIEuj","s":"0"}-FABELfp9ZhqQCGov3wPRLa6vn5VkIQjug2sb2QD17T-TIp'
                            b'YMAACEELHnIwzGaJ-twKTfXtsPMteqsIVmDpiwVO574h6LRXD-AADAAA_RaT3MzW'
                            b'-uI6Y7CTpooCRyvVV9LIDCjTGw8Nz1EqRmR_dvjIQwoNQklDujYn1eTxVAc9-fTY'
                            b'Mlpk7ZWWOSDYBABA9QRnuSlET3mU45BtJm9HY655bt8ZsEUUw5Ke8l5KHn4hl5Gf'
                            b'ZH8aHDnVY1SiQnZrKu7W4MeOsazhF8waHZbcHACCFEDA_jO-u0WccqVdffVc_xmr'
                            b'l9LYAinzPLJNx_XxVlf2Z5DHFBZM-Usq9Wb5-dvlDaR8GhGTKOxFbTcCwnnkL')


        # Play disjoints debCamVrcs to Cam
        Parser(version=Vrsn_1_0).parseOne(ims=bytearray(debCamVrcs), kvy=camKevery)
        # camKevery.processOne(ims=bytearray(debCamVrcs))  # give copy to process

        # Play debMsgs to Bev
        # create non-local kevery for Bev to process msgs from Deb
        bevKevery = Kevery(db=bevHab.db,
                                    lax=False,
                                    local=False)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(debMsgs), kvy=bevKevery)
        # bevKevery.process(ims=bytearray(debMsgs))  # give copy to process
        assert debHab.pre in bevKevery.kevers
        assert bevKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(bevKevery.cues) == 7

        # get disjoints receipts (rcts) from Bev of Deb's events by processing Bevs's cues
        bevMsgs = bevHab.processCues(bevKevery.cues, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        assert len(bevKevery.cues) == 0
        assert bevMsgs == (b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EBXqe7Xzsw2aolT09Ouh5Zw9'
                        b'kNn2sgoHmo4zCn7Q7ZSC","i":"BAqph4mAWcf7mkIgk1Xrpvr7dWT7YvHIam_hq'
                        b'UAT2rqw","s":"0","kt":"1","k":["BAqph4mAWcf7mkIgk1Xrpvr7dWT7YvHI'
                        b'am_hqUAT2rqw"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-AA'
                        b'BAAB7WHPA5UPHhV5DRKUU93pXnwp4bPGDQ-DIrFsVr6kPIpHByaM2WPC7SgHXVn3'
                        b'MMGjsdJc1Ul8LrvUc1VrV46cL{"v":"KERI10JSON000091_","t":"rct","d":'
                        b'"ELfp9ZhqQCGov3wPRLa6vn5VkIQjug2sb2QD17T-TIpY","i":"ELfp9ZhqQCGo'
                        b'v3wPRLa6vn5VkIQjug2sb2QD17T-TIpY","s":"0"}-CABBAqph4mAWcf7mkIgk1'
                        b'Xrpvr7dWT7YvHIam_hqUAT2rqw0BDaa9nAkQ2-M2_Mr4Kecfa9Y-rR9WD3IKDV3A'
                        b'G4USGCP-wA2rIAzw6vBABM9eCIs6mETGykfX04DCWavJsrfjMK{"v":"KERI10JS'
                        b'ON000091_","t":"rct","d":"EFECUzlLZ3IKG9Kvkj51a0RYPYXnUeZ5SIpw8x'
                        b'3SPS1E","i":"ELfp9ZhqQCGov3wPRLa6vn5VkIQjug2sb2QD17T-TIpY","s":"'
                        b'1"}-CABBAqph4mAWcf7mkIgk1Xrpvr7dWT7YvHIam_hqUAT2rqw0BAEUr8d1CAe9'
                        b'HYGOXeqbgBPf9IFM0L1iNw6ZgMlfJ4djVvZ8Fl250sAh4thrsOFaaNqYCVg8uWRS'
                        b'3YtpEu5yfEE{"v":"KERI10JSON000091_","t":"rct","d":"EELHnIwzGaJ-t'
                        b'wKTfXtsPMteqsIVmDpiwVO574h6LRXD","i":"ELfp9ZhqQCGov3wPRLa6vn5VkI'
                        b'Qjug2sb2QD17T-TIpY","s":"2"}-CABBAqph4mAWcf7mkIgk1Xrpvr7dWT7YvHI'
                        b'am_hqUAT2rqw0BCt52hAdsQw3LONIIzelwVZpGZX6vqxZEFp3nxtz657xS8Y92ng'
                        b'cGhYK30Wc1_-y8baTDb-NAsL3pLJyn_czSUJ{"v":"KERI10JSON000091_","t"'
                        b':"rct","d":"ECWvVQFFqxmAW-vpSLwWj4yPO04nGA-6l8cifNBlc3gK","i":"E'
                        b'Lfp9ZhqQCGov3wPRLa6vn5VkIQjug2sb2QD17T-TIpY","s":"3"}-CABBAqph4m'
                        b'AWcf7mkIgk1Xrpvr7dWT7YvHIam_hqUAT2rqw0BCc8xIDPi9H1kpSMjELYByC51U'
                        b'Lre7Y0m_9Ftti23NtrRmbOV8RwgLE4mzrbwwSOksKhzNoqX3QXZsDjXU5N1UL{"v'
                        b'":"KERI10JSON000091_","t":"rct","d":"EFcoQIrpd4_NMcnL7SvVqUSLfPZ'
                        b'OzkAGbtQcE3JVMn7D","i":"ELfp9ZhqQCGov3wPRLa6vn5VkIQjug2sb2QD17T-'
                        b'TIpY","s":"4"}-CABBAqph4mAWcf7mkIgk1Xrpvr7dWT7YvHIam_hqUAT2rqw0B'
                        b'BeLpMLawI0J7ZzESvU4M86mTCGPcuYlGux9en-6PBIO7xZGMuVMCFwqWFmkMlhJ_'
                        b'ZEIUVm9ZgSp-P8jtTU4yUL{"v":"KERI10JSON000091_","t":"rct","d":"EL'
                        b'VXLfglCimN6Y-HkpoLoLiQkR1v65rrg7JRDhcToXVn","i":"ELfp9ZhqQCGov3w'
                        b'PRLa6vn5VkIQjug2sb2QD17T-TIpY","s":"5"}-CABBAqph4mAWcf7mkIgk1Xrp'
                        b'vr7dWT7YvHIam_hqUAT2rqw0BCUPQtStUkkvgVW-Aq4mNzVpT0PNvSjrLjR02498'
                        b'Z4AiM7lbmkJTDPL1gU4yuu_G_Lc7q6V_EWsZUxfMyw3HysP{"v":"KERI10JSON0'
                        b'00091_","t":"rct","d":"ECSAoB-QcY3Vnia2G80NLVMkiGssUV70JoWxwJbqx'
                        b'9gL","i":"ELfp9ZhqQCGov3wPRLa6vn5VkIQjug2sb2QD17T-TIpY","s":"6"}'
                        b'-CABBAqph4mAWcf7mkIgk1Xrpvr7dWT7YvHIam_hqUAT2rqw0BAdms9s96PcHz-h'
                        b'spbH5eZUfO6qUSTRoQjc0FI3CylhL2fyp9M97dpKo0Rp3x1PtubRxIBVn1V3qfra'
                        b'uro0ISwG')

        # Play bevMsgs to Deb
        Parser(version=Vrsn_1_0).parse(ims=bytearray(bevMsgs), kvy=debKevery)
        # debKevery.process(ims=bytearray(bevMsgs))  # give copy to process
        assert bevHab.pre in debKevery.kevers
        assert debKevery.kevers[bevHab.pre].sn == bevHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Bev's events by processing Deb's cues
        debBevVrcs = debHab.processCues(debKevery.cues, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        assert len(debKevery.cues) == 0
        assert debBevVrcs == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EBXqe7Xzsw2aolT09Ouh5Zw9'
                        b'kNn2sgoHmo4zCn7Q7ZSC","i":"BAqph4mAWcf7mkIgk1Xrpvr7dWT7YvHIam_hq'
                        b'UAT2rqw","s":"0"}-FABELfp9ZhqQCGov3wPRLa6vn5VkIQjug2sb2QD17T-TIp'
                        b'YMAACEELHnIwzGaJ-twKTfXtsPMteqsIVmDpiwVO574h6LRXD-AADAABjgf8tiPV'
                        b'fvviaQ60CY9rJR-Nigj4paeIrFr87mnU-3Z2VKHFo6rpFyQfd5Za_M3gEbcjf3Ot'
                        b'B718M7M6WFf4CABCz83_zL8bZM8wxQB4kQrJ4GatYSOg5UpphulR3lhkbV3imD4Z'
                        b'XJJF_v6D-Zcq0I1PluxUTMYsHYGoaXvLSWpkFACBdhdPiqPfy30Oxt_LshbISGHx'
                        b'PCyOBucKLfhkFqvTd21GhJQZ_LlUy0q-mGUtM_PAStYW00VuA1RMj1p6COtQC')

        # Play disjoints debBevVrcs to Bev
        Parser(version=Vrsn_1_0).parseOne(ims=bytearray(debBevVrcs), kvy=bevKevery)
        # bevKevery.processOne(ims=bytearray(debBevVrcs))  # give copy to process

        # now setup conjoint replay

        # Replay Deb's First Seen Events with receipts (vrcs and rcts) from both Cam and Bev
        # datetime is different in each run in the fse attachment in clone replay
        # so we either have to force dts in db or we parse in pieces
        debFelMsgs = bytearray()
        fn = 0
        cloner = debHab.db.clonePreIter(pre=debHab.pre, fn=fn, version=Vrsn_1_0)  # create iterator
        msg = next(cloner)  # get zeroth event with attachments
        assert len(msg) == 1335 # 1355 # 1535
        debFelMsgs.extend(msg)

        # parse msg
        serder = SerderKERI(raw=msg)
        assert serder.raw == debHab.iserder.raw
        assert serder.sn == fn  # no recovery forks so sn == fn
        assert serder.ked["t"] == Ilks.icp
        del msg[:len(serder.raw)]
        assert len(msg) == 816  # 836 # 1016

        counter = Counter(qb64b=msg, version=Vrsn_1_0)  # attachment length quadlets counter
        assert counter.code == CtrDex_1_0.AttachmentGroup
        assert counter.count == 203 # (len(msg) - len(counter.qb64b)) // 4 == 208 # 253
        del msg[:len(counter.qb64b)]
        assert len(msg) == 812 # 832 == 208 * 4

        counter = Counter(qb64b=msg, version=Vrsn_1_0)  # indexed signatures counter
        assert counter.code == CtrDex_1_0.ControllerIdxSigs
        assert counter.count == 3  # multisig deb
        del msg[:len(counter.qb64b)]
        assert len(msg) == 808  # 828  # 1008

        for i in range(counter.count):  # parse signatures
            siger = Siger(qb64b=msg)
            del msg[:len(siger.qb64b)]
        assert len(msg) == 544 # 828 - 3 * len(siger.qb64b) == 564 # 744

        counter = Counter(qb64b=msg, version=Vrsn_1_0)  # nontrans receipt (rct) counter
        assert counter.code == CtrDex_1_0.NonTransReceiptCouples
        assert counter.count == 1  # single sig bev
        del msg[:len(counter.qb64b)]
        assert len(msg) == 540

        for i in range(counter.count):  # parse receipt couples
            prefixer, cigar = deReceiptCouple(msg, strip=True)
        assert len(msg) == 408 # 196 - 1 * (len(prefixer.qb64b) + len(cigar.qb64b)) == 64

        # extract trans receipt counters (quadlet)
        counter = Counter(qb64b=msg, version=Vrsn_1_0)  # trans receipt (vrc) counter
        assert counter.code == CtrDex_1_0.TransReceiptIdxSigGroups
        assert counter.count == 90 # now quadlet counter not 3  multisig cam
        del msg[:len(counter.qb64b)]
        assert len(msg) == 404 # 560

        # extract receipt triple
        prefixer = Prefixer(qb64b=msg, strip=True)
        number = Number(qb64b=msg, strip=True)
        diger = Diger(qb64b=msg, strip=True)
        assert len(msg) == 312 # 468 == 560 - (len(prefixer.qb64b) + len(number.qb64b) + len(diger.qb64b))
        #extract sigs
        counter = Counter(qb64b=msg, strip=True, version=Vrsn_1_0)
        sigers = []
        for i in range(counter.count):  # extract idx sig group ctr non-quadlet
            sigers.append(Siger(qb64b=msg, strip=True))
        assert len(msg) == 44 # 200 == 468 - 4 - 3 * len(sigers[0].qb64b)

        counter = Counter(qb64b=msg, version=Vrsn_1_0)  # first seen replay couple counter
        assert counter.code == CtrDex_1_0.FirstSeenReplayCouples
        assert counter.count == 1
        del msg[:len(counter.qb64b)]
        assert len(msg) == 40

        number = Number(qb64b=msg)
        assert number.sn == fn == 0
        del msg[:len(number.qb64b)]
        assert len(msg) == 36  # 24 less

        dater = Dater(qb64b=msg)
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
        cloner = debHab.db.clonePreIter(pre=debHab.pre, fn=fn, version=Vrsn_1_0)  # create iterator not at 0
        msg = next(cloner)  # next event with attachments
        assert len(msg) == 1019  # 1039  # 1219
        serder = SerderKERI(raw=msg)
        assert serder.sn == fn  # no recovery forks so sn == fn
        assert serder.ked["t"] == Ilks.ixn
        debFelMsgs.extend(msg)

        fn += 1
        msg = next(cloner)  # get zeroth event with attachments
        serder = SerderKERI(raw=msg)
        assert serder.sn == fn  # no recovery forks so sn == fn
        assert serder.ked["t"] == Ilks.rot
        assert len(msg) == 1388 # 1408 # 1588
        assert ([verfer.qb64 for verfer in serder.verfers] ==
                [verfer.qb64 for verfer in debHab.kever.verfers])
        debFelMsgs.extend(msg)

        fn += 1
        while (fn <= 6):
            msg = next(cloner)  # get zeroth event with attachments
            serder = SerderKERI(raw=msg)
            assert serder.sn == fn  # no recovery forks so sn == fn
            assert serder.ked["t"] == Ilks.ixn
            assert len(msg) == 1019 # 1039 # 1219
            debFelMsgs.extend(msg)
            fn += 1

        assert len(debFelMsgs) == 7818 # 7958  # 9218
        cloner.close()  # must close or get lmdb error upon with exit

        msgs = debHab.replay(version=Vrsn_1_0)
        assert msgs == debFelMsgs

        # Play Cam's messages to Bev
        Parser(version=Vrsn_1_0).parse(ims=bytearray(camMsgs), kvy=bevKevery)
        # bevKevery.process(ims=bytearray(camMsgs))  # give copy to process
        assert camHab.pre in bevKevery.kevers
        assert bevKevery.kevers[camHab.pre].sn == camHab.kever.sn == 0
        assert len(bevKevery.cues) == 1

        # Play Bev's messages to Cam
        Parser(version=Vrsn_1_0).parse(ims=bytearray(bevMsgs), kvy=camKevery)
        # camKevery.process(ims=bytearray(bevMsgs))  # give copy to process
        assert bevHab.pre in camKevery.kevers
        assert camKevery.kevers[bevHab.pre].sn == bevHab.kever.sn == 0
        assert len(camKevery.cues) == 1

        camDebFelMsgs = camHab.replay(pre=debHab.pre, version=Vrsn_1_0)
        bevDebFelMsgs = bevHab.replay(pre=debHab.pre, version=Vrsn_1_0)

        assert len(bevDebFelMsgs) == len(camDebFelMsgs) == len(debFelMsgs) == 7818 # 7958 # 9218

        # create non-local kevery for Art to process conjoint replay msgs from Deb
        artKevery = Kevery(db=artHab.db,
                                    lax=False,
                                    local=False)
        # process Cam's inception so Art will proces Cam's vrcs without escrowing
        camIcpMsg = camHab.msgOwnInception(framed=True, gvrsn=Vrsn_1_0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(camIcpMsg), kvy=artKevery)
        # artKevery.process(ims=bytearray(camIcpMsg))
        assert camHab.pre in artKevery.kevers
        assert len(artKevery.cues) == 1

        # process in cloned mode
        artKevery.cloned = True
        Parser(version=Vrsn_1_0).parse(ims=bytearray(debFelMsgs), kvy=artKevery)
        assert debHab.pre in artKevery.kevers
        assert artKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(artKevery.cues) == 8
        # Explicit receipt+firner path: clone replay receipt processing uses
        # fels.getOn(keys=pre, on=firner.sn) to look up the event digest.
        assert artHab.db.fels.get(keys=debHab.pre, on=0) == debHab.iserder.said
        artDebFelMsgs = artHab.replay(pre=debHab.pre, version=Vrsn_1_0)
        assert len(artDebFelMsgs) == 7818  # 7958 # 9218

    assert not os.path.exists(artHby.ks.path)
    assert not os.path.exists(artHby.db.path)
    assert not os.path.exists(bevHby.ks.path)
    assert not os.path.exists(bevHby.db.path)
    assert not os.path.exists(camHby.ks.path)
    assert not os.path.exists(camHby.db.path)
    assert not os.path.exists(debHby.ks.path)
    assert not os.path.exists(debHby.db.path)

    """End Test"""

def test_replay_v2():
    """
    Test disjoint and conjoint replay

    Deb creates series of events.
    Deb replays Deb's events to Cam and collects Cam's receipts
    Deb replays Deb's events with Cam's recepts to Bev and collects Bev's receipts
    Deb replays Deb's events with both Cam's and  Bev's receipts to Cam
    Compare replay of Deb's events with receipts by both Deb and Cam to confirm identical
    """
    artSalt = Salter(raw=b'abcdef0123456789').qb64
    default_salt = Salter(raw=b'0123456789abcdef').qb64

    with (openHby(name="deb", base="test", salt=default_salt, version=Vrsn_2_0) as debHby,
         openHby(name="cam", base="test", salt=default_salt, version=Vrsn_2_0) as camHby,
         openHby(name="bev", base="test", salt=default_salt, version=Vrsn_2_0) as bevHby,
         openHby(name="art", base="test", salt=artSalt, version=Vrsn_2_0) as artHby):

        # setup Deb's habitat using default salt multisig already incepts
        sith = ["1/2", "1/2", "1/2"]  # weighted signing threshold
        debHab = debHby.makeHab(name="deb", isith=sith, icount=3, version=Vrsn_2_0, kind=Kinds.json)
        assert debHab.kever.prefixer.transferable

        # setup Cam's habitat using default salt multisig already incepts
        # Cam's receipts will be vrcs with 3 indexed sigantures attached
        sith = '2'  # hex str of threshold int
        camHab = camHby.makeHab(name="cam", isith=sith, icount=3, version=Vrsn_2_0, kind=Kinds.json)
        assert camHab.kever.prefixer.transferable

        # setup Bev's habitat using default salt nonstransferable already incepts
        # Bev's receipts will be rcts with a receipt couple attached
        sith = '1'  # hex str of threshold int
        bevHab = bevHby.makeHab(name="bev", isith=sith, icount=1, transferable=False, version=Vrsn_2_0, kind=Kinds.json)
        assert not bevHab.kever.prefixer.transferable

        # setup Art's habitat using custom salt nonstransferable so not match Bev
        # already incepts
        # Art's receipts will be rcts with a receipt couple attached
        sith = '1'  # hex str of threshold int
        artHab = artHby.makeHab(name="art", isith=sith, icount=1, transferable=False, version=Vrsn_2_0, kind=Kinds.json)
        assert not artHab.kever.prefixer.transferable

        # Create series of event for Deb
        debMsgs = bytearray()
        debMsgs.extend(debHab.msgOwnInception(framed=True, gvrsn=Vrsn_2_0))
        debMsgs.extend(debHab.interact(framed=True, version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0))
        debMsgs.extend(debHab.rotate(framed=True, version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0))
        debMsgs.extend(debHab.interact(framed=True, version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0))
        debMsgs.extend(debHab.interact(framed=True, version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0))
        debMsgs.extend(debHab.interact(framed=True, version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0))
        debMsgs.extend(debHab.interact(framed=True, version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0))

        assert debMsgs == (b'{"v":"KERICAACAAJSONAAIJ.","t":"icp","d":"EMClOv48MJabMgSKYty-iV'
                    b'fpEImA1gaawtofFXk5VVPT","i":"EMClOv48MJabMgSKYty-iVfpEImA1gaawto'
                    b'fFXk5VVPT","s":"0","kt":["1/2","1/2","1/2"],"k":["DEcQixETvXkrxu'
                    b'H5bszrCudhglgrSjmQpVcAN_DmvvjA","DAsc09eopD-iylSX6-ob9Y5ocp5uiOP'
                    b'iqBmJCbXfbga6","DLA5ecUh5yJXBqNd7uYw0a9YyTJEN-JxHOUejWLHT0tp"],"'
                    b'nt":["1/2","1/2","1/2"],"n":["EHi61HDu9euzY_8aa5iSmrTlXxme5Qy3oY'
                    b'6iXucSEeGh","EB6NxkyXMBgDPthCtbx_f1UFW1pUMTh3B5wd3wuNX2WJ","EDjO'
                    b'UDgp2ft49_bqxmhW5mhCISsHxm0UZPjhUeGJWytb"],"bt":"0","b":[],"c":['
                    b'],"a":[]}-KBCAAB72479-alzTT8voU2kZrzlKzRksp-kESzdSTJq8MzCFcHryC7'
                    b'M6d_49zfFUcAP7kj2maT74abPgS_f2ZjnEOsOABAI4ReqWZuYpInaMkNDIfB-J-N'
                    b'08Hejy0QfAWRY6mnvC4yKG4GWGYHA8LoHgTMGHmkeYfUvrw2qVMIxJ7-IXpENACB'
                    b'MhkvXU4ch2fWCzm1VAlQ2CY1tM5bi3K_2lokWl20NeAW8sqGMAIExKmLE5quZWAn'
                    b'wAPzmlwSt6njKgoyWn4YH{"v":"KERICAACAAJSONAADN.","t":"ixn","d":"E'
                    b'HzNGRf2LrWqtBA14pg-j0jiihLMq5JFfNi3Gbk8-5J1","i":"EMClOv48MJabMg'
                    b'SKYty-iVfpEImA1gaawtofFXk5VVPT","s":"1","p":"EMClOv48MJabMgSKYty'
                    b'-iVfpEImA1gaawtofFXk5VVPT","a":[]}-KBCAACjXBSLLglIehUyYtsuH1QHK6'
                    b'f_ZwhthCUbgaAZKGezaSgngWw81U2mCr2_Tg0az2UWMShy6Cxl3Zh8od8az30MAB'
                    b'BQWZG-c3sOPkd2uMBRrgyXFtNlUH_2AaCg21a8gepVUO8EAfEQroN4fZW9dAMy-1'
                    b'nyLmd4P0Lgma9cPsADD08NACBhYg26_yzhPm3HIarB9qmWvKQdk3UbU5_KSYnvKA'
                    b'anev-bxR_rcI7-Qk0N2IDr8TywtHr9YeZyNfiPJ47poCgE{"v":"KERICAACAAJS'
                    b'ONAAJF.","t":"rot","d":"EGzk7gjEPIoBfsCj2xIr74rw2pICSYT4SY-jRrOJ'
                    b'WUDE","i":"EMClOv48MJabMgSKYty-iVfpEImA1gaawtofFXk5VVPT","s":"2"'
                    b',"p":"EHzNGRf2LrWqtBA14pg-j0jiihLMq5JFfNi3Gbk8-5J1","kt":["1/2",'
                    b'"1/2","1/2"],"k":["DI_g1MHwpjqxN4o6rnEdCPPf32ExW8qLWqnkMg37qZBF"'
                    b',"DC_pP_AWp4y2GgHZulliiKR3B8HGxfN-L5yz4KVtTS_J","DFhtmRbFmFLGwyN'
                    b'SprvCR9tohmlQxrzO6Z7k-MtqEd1S"],"nt":["1/2","1/2","1/2"],"n":["E'
                    b'LFzlp0ShKZ35PElySBc2l-Mol2RwmjuMIvfmwP2IwMN","EM64JMyn8UliE8JY7z'
                    b'BEGyoudykA8ql52WkviIWs86ov","EAbVsTzKbdx9mHkxNlxfT_-1bz9tWGkpSc9'
                    b'd5rA_GUsI"],"bt":"0","br":[],"ba":[],"c":[],"a":[]}-KBCAAAnZp4G4'
                    b'cKPEy080wxBSHf4yAT3AiKdIHW3zvNYewJxeYrS4ab1vx231H_tKwh92I2oiozdE'
                    b'FyxJ9sllo5dAkgGABDwpWUBolQ0US1oamtYgImWVik07DuIHuf0lagG1ObSsbBY7'
                    b'EKhbeLaPXXA7REXBaAQp3s8kTB-yB9SNbUfVZAMACC3w_gmpUGglggrvRyJa7l0r'
                    b'Vh_s1FdRyJpoZKT-8uA3q66UGbOOUafp9IN7qnwoHeaoUI4rNZIWzQReUNu0kIH{'
                    b'"v":"KERICAACAAJSONAADN.","t":"ixn","d":"EFRjgfaQAHIb_-7e6WWOJUk'
                    b'cdjjBd67Yve78HZWSn-9M","i":"EMClOv48MJabMgSKYty-iVfpEImA1gaawtof'
                    b'FXk5VVPT","s":"3","p":"EGzk7gjEPIoBfsCj2xIr74rw2pICSYT4SY-jRrOJW'
                    b'UDE","a":[]}-KBCAAAm7gmyuSbuDh5Sz9bjRd4HChEs63-eriz6Z73Z_HbJRKcT'
                    b'tlWoN1PtAaqTiSiEybkE7USDxIr--Be-c1957PYAABAsHR0nrL0n9bQnRYkM2GYN'
                    b'DuLHdy2SbcyYR5ALazBRc1V-3ZZdndooz-6ns-k8Z3JmziJbg5SUQQHiTg6AL90E'
                    b'ACDxuxb3AryQ0yub5ftVF8HWGh-BNipLYMcHYOP2EmVU90Yo3UaiCLQUnUutPqdx'
                    b'hWJy6FkNWtqJxnO7N_yh-ncH{"v":"KERICAACAAJSONAADN.","t":"ixn","d"'
                    b':"EO2FFKL-ckYs5jQHgG_AI8ZN5Ltnmmm2Zocdp3kVmnFX","i":"EMClOv48MJa'
                    b'bMgSKYty-iVfpEImA1gaawtofFXk5VVPT","s":"4","p":"EFRjgfaQAHIb_-7e'
                    b'6WWOJUkcdjjBd67Yve78HZWSn-9M","a":[]}-KBCAABgCWCBN7-k86SDAEtSJJS'
                    b'ZZcP7ibiDeKomYgEWUwwHjF0BnvQFxLrUo7N1HJNL_yf2q0cCJnDxad_WAhzzfpQ'
                    b'IABDaGNfCXz-IflcBIiQfdY6kFPk4qQhT1N7WjZ0pIyuyb7JGzcQ020UklK3bpwJ'
                    b'JWfKWhUMLNDL2Nlq6So5xA70HACAHHMhxr117kZkJ6t_Q5fEroUYpXfVcLB7WpzI'
                    b'quoy7rSYe9zEIVE0uKRnQRXKLVbhU_5447V2Hfqz_MbCztA0A{"v":"KERICAACA'
                    b'AJSONAADN.","t":"ixn","d":"EJ6JQ0VuKyaoxVy0N0N6vgb6gS6QDHHyyhEhp'
                    b'DJIQaXJ","i":"EMClOv48MJabMgSKYty-iVfpEImA1gaawtofFXk5VVPT","s":'
                    b'"5","p":"EO2FFKL-ckYs5jQHgG_AI8ZN5Ltnmmm2Zocdp3kVmnFX","a":[]}-K'
                    b'BCAAA0n3xCI1ItYpyXuZfU3GCSdiDrJuUkbkNMl3cvZY9nDBxmZBGswk4m7gRgks'
                    b'gmTzyFAK50a4RcIRulyYE7hBgGABBUQL-doamiug9PqmLVs-eq_fIbRNkNFczKkI'
                    b'Ywq-ntINkiMzTCFElXJJTh-6ufrHfnRk5ZAxZUtbdegNlS36sNACAsukHl8a-lRg'
                    b'PHnISVJzhceTjMtWaUdsDi98xkc51QNUGsn4Ch5DtgzZAjcX-Pv3_1IfO0_3Xbg5'
                    b'jOG0FUftgG{"v":"KERICAACAAJSONAADN.","t":"ixn","d":"ELLXmDHjPA-K'
                    b'1MoVBqOfLTrRRo_GJosVi8mIPS6zsAkw","i":"EMClOv48MJabMgSKYty-iVfpE'
                    b'ImA1gaawtofFXk5VVPT","s":"6","p":"EJ6JQ0VuKyaoxVy0N0N6vgb6gS6QDH'
                    b'HyyhEhpDJIQaXJ","a":[]}-KBCAAD5iN1jjWCTBybmwS43_SSAdsC3qqtXM_VFV'
                    b'_rYPSZg0vNa8nV2Wu-p3U9YGv3jmJ-Eq5O8V-46WUbtewZhHSgOABAhkhp70Ks76'
                    b'94hk7mR4Tg6yTUKMYEbWc9Zsxy8ZUYgmfT-5QehPxu2iRjUhnr-gfAiCeUq1inEq'
                    b'qaC-GhPrGwGACCVjU1IrkdL14L5u_VA7DAq4PiMW-g25CX2Z0Z7T2ya0gju63n1k'
                    b'ypAKmAXc3oDjBC7IJFGE9qI7agOnA-o3QYK')


        assert debHab.kever.sn == 6
        msgs = next(debHab.db.clonePreIter(debHab.pre, fn=4, version=Vrsn_2_0))
        serder = SerderKERI(raw=msgs)
        assert serder.ilk == Ilks.ixn
        assert serder.sn == 4

        # Play debMsgs to Cam
        # create non-local kevery for Cam to process msgs from Deb
        camKevery = Kevery(db=camHab.db,
                                    lax=False,
                                    local=False)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(debMsgs), kvy=camKevery)
        # camKevery.process(ims=bytearray(debMsgs))  # give copy to process
        assert debHab.pre in camKevery.kevers
        assert camKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(camKevery.cues) == 7
        # get disjoints receipts (vrcs) from Cam of Deb's events by processing Cam's cues
        camMsgs = camHab.processCues(camKevery.cues, version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)
        assert camMsgs == (b'{"v":"KERICAACAAJSONAAHp.","t":"icp","d":"EGcI8FG4uEn1Pu8ak3ghec'
                        b'-iMWpfR6h3vGGloIzWEUZB","i":"EGcI8FG4uEn1Pu8ak3ghec-iMWpfR6h3vGG'
                        b'loIzWEUZB","s":"0","kt":"2","k":["DCQbRBx58zbRPs8R9cXl-MMbPaxH1E'
                        b'PHdWp3ICSdQSyp","DDLusjyE46zgaEz37GPq9UXNHmnfBipqAsQPwboCnoYG","'
                        b'DH4ab2zcmLtX8UwU18vHgoIITHDmJ8ZIKBjwa9GQWT0A"],"nt":"2","n":["EG'
                        b'SFaY2-o3mAVN1iq23SovuMY34VCNcsot4WhS-JXGgf","EOHL9prk6Um5Cxeoofh'
                        b'VVNik0DRhrHZQWX3k_whUf49Y","EID2f_sJoa-DJSmOlYvxuofE0Zzp_qningHC'
                        b'J5X-gZIG"],"bt":"0","b":[],"c":[],"a":[]}-KBCAAC0J4DPahS495manSO'
                        b'QbhtC6A3gQ5DFNvvwoMhwHb2CRUVYptrn7PuRgeHdWGWH0XgLmpCIj1g0zuKMwiH'
                        b'MoMQPABA1H_BTaqGanw-celc4byDoog0CtceUR1WcU9GGW6GZQ6CfKe0XzbJbHdy'
                        b'AZ7mrq1eIV9l2qM7lHxKxbDDtQo0EACBrFuA5l47SBhSDwfzQ314hZx9IO7gClK9'
                        b'Inf0OYkkFsf0B2zXOHhHS5lMtuN4MjGLjK_QXKGcVMGDHzvgh7R8A{"v":"KERIC'
                        b'AACAAJSONAACT.","t":"rct","d":"EMClOv48MJabMgSKYty-iVfpEImA1gaaw'
                        b'tofFXk5VVPT","i":"EMClOv48MJabMgSKYty-iVfpEImA1gaawtofFXk5VVPT",'
                        b'"s":"0"}-XBaEGcI8FG4uEn1Pu8ak3ghec-iMWpfR6h3vGGloIzWEUZBMAAAEGcI'
                        b'8FG4uEn1Pu8ak3ghec-iMWpfR6h3vGGloIzWEUZB-KBCAABjJ7B5KIUlFCz7COh0'
                        b'fx_mvSxjKX3-a1trSMr3tbJi7aDrMwE55YSrHDc4wOfeou4kLuv0x1W2CaQUIg-M'
                        b'OkkAABAONy1QieGeTRPIReI7VFtG_1WPT0qAf91fS_dlKsmY9IGTULDKgr8IiOjZ'
                        b'H2kAVswtKG_O-izPmTHkfTKeN30JACDBL3a0qBk3lPp7bcpcX6ruUDlYK46_sDWl'
                        b'cWQq7ip7le57i_6iPPkK2DNWtSUY8qqisOtIPAHqRNRqvXjPdQ8E{"v":"KERICA'
                        b'ACAAJSONAACT.","t":"rct","d":"EHzNGRf2LrWqtBA14pg-j0jiihLMq5JFfN'
                        b'i3Gbk8-5J1","i":"EMClOv48MJabMgSKYty-iVfpEImA1gaawtofFXk5VVPT","'
                        b's":"1"}-XBaEGcI8FG4uEn1Pu8ak3ghec-iMWpfR6h3vGGloIzWEUZBMAAAEGcI8'
                        b'FG4uEn1Pu8ak3ghec-iMWpfR6h3vGGloIzWEUZB-KBCAAAITZEH75Z2hBh0uWPBG'
                        b'1ILvjdvE7w0126K6Cyo4j3t8xxMjRHmNYGVFRzFuL7FOPgB_dylmA5w3HdIU4pyg'
                        b'NELABBuez1gOB0LmM3I7ubpnNTGsPy9bVGJEHH6wH9k21OJ4zEHYozPRtBdmxBpL'
                        b'mWDBG-CeBvWcQudG2XEGtVp9ygGACDfXSSpBWWMmCojk41uAGgESnYRhAhi7rLJc'
                        b's3kJDpmVYQtMiR6QMIbMqF9UuZbQUl3uPXVEXn-0O6Yog6knSUI{"v":"KERICAA'
                        b'CAAJSONAACT.","t":"rct","d":"EGzk7gjEPIoBfsCj2xIr74rw2pICSYT4SY-'
                        b'jRrOJWUDE","i":"EMClOv48MJabMgSKYty-iVfpEImA1gaawtofFXk5VVPT","s'
                        b'":"2"}-XBaEGcI8FG4uEn1Pu8ak3ghec-iMWpfR6h3vGGloIzWEUZBMAAAEGcI8F'
                        b'G4uEn1Pu8ak3ghec-iMWpfR6h3vGGloIzWEUZB-KBCAABVgVzOIzDAOBSiU6Cejd'
                        b'2dNBG7eC1s1qHEFpQihU_4RIlR1C0YUYY7TslbA6dAltR84DV9pNnnT-xq3GINEl'
                        b'sLABBM9X8k0MBrEIj_r9C_1Fjwt0dX3_MZxhEqMK4VnzwH1HEsLRMwBrHGf3GHJT'
                        b'JSxzr7iEhrM5zD0fgPTd3m6RAFACAQwuE0e3sMCM6CTZIxHbRK_FoSbc-oRSQRtf'
                        b'kJ1aiTi6sMkKyzvxU5oPGXGQ1WsbWh5WAxuRGRMT9D3amxf7kP{"v":"KERICAAC'
                        b'AAJSONAACT.","t":"rct","d":"EFRjgfaQAHIb_-7e6WWOJUkcdjjBd67Yve78'
                        b'HZWSn-9M","i":"EMClOv48MJabMgSKYty-iVfpEImA1gaawtofFXk5VVPT","s"'
                        b':"3"}-XBaEGcI8FG4uEn1Pu8ak3ghec-iMWpfR6h3vGGloIzWEUZBMAAAEGcI8FG'
                        b'4uEn1Pu8ak3ghec-iMWpfR6h3vGGloIzWEUZB-KBCAAAH982cksGu4VfgAKl6CMb'
                        b'PEc1gJHf74uHXr2OCQ6D_rURJJuxUFGhjA4zBOcsUzWakDpYTXUbMjLm83j6TG7o'
                        b'NABDvAw6m_oD0DcLLxCZvm56_mfDQnfgX2DyAtknjnbc1lLV56yaENNwqB43zGWx'
                        b'jw1sBU3NiHt-wXdcnO7I208AAACB-I0fE3uwJJPe2URnh1mYaO69pvMe7tNTSOus'
                        b'iH7mCClTPDIhlz_lptFEd28q3aucn6Rt1EKTSqaKAFLk5RPoD{"v":"KERICAACA'
                        b'AJSONAACT.","t":"rct","d":"EO2FFKL-ckYs5jQHgG_AI8ZN5Ltnmmm2Zocdp'
                        b'3kVmnFX","i":"EMClOv48MJabMgSKYty-iVfpEImA1gaawtofFXk5VVPT","s":'
                        b'"4"}-XBaEGcI8FG4uEn1Pu8ak3ghec-iMWpfR6h3vGGloIzWEUZBMAAAEGcI8FG4'
                        b'uEn1Pu8ak3ghec-iMWpfR6h3vGGloIzWEUZB-KBCAAD6zArQLvM6vlzzmTjdJJZN'
                        b'WBWGzEkL0lHyBZ9Tb-72OkPI5_GJbLfpaOYt0XTkJuDvPyIP9Lm15_mglRaTfO8D'
                        b'ABAM4q-5vmUMN25C7766MXRLjlQmBdgDF7qX4eFs1bJqQRxkY2zB7MNLhflOa5eY'
                        b'ewRkErYO-lgEf2UchEKXxeIAACBUih9XtNHWbCRuGY0RbSHDqixdMb8UK91gB-zM'
                        b'0FpimjB9mYBpukV1Z9taHPgOXqjtejR-ZnlXFKwUVv6ogOMK{"v":"KERICAACAA'
                        b'JSONAACT.","t":"rct","d":"EJ6JQ0VuKyaoxVy0N0N6vgb6gS6QDHHyyhEhpD'
                        b'JIQaXJ","i":"EMClOv48MJabMgSKYty-iVfpEImA1gaawtofFXk5VVPT","s":"'
                        b'5"}-XBaEGcI8FG4uEn1Pu8ak3ghec-iMWpfR6h3vGGloIzWEUZBMAAAEGcI8FG4u'
                        b'En1Pu8ak3ghec-iMWpfR6h3vGGloIzWEUZB-KBCAAD5wgGbLHznvPXlzIyHMAATk'
                        b'0-vNIr-8j8ebauAIDGyS7H52g-nkda490z-McB7I6WDu3CCB68gEAsk2_7X0BUBA'
                        b'BBseYFahIalgyhDRbI6iZ1WkQuelvdGs3Z_QTSlVC1jkpPX6nyXIZ8sD191HiOQh'
                        b'Y4MeEF2IEPbybqMQx74pkcJACBvQTGdtQAeb8RFUOph8Ak2TrJ-d1-kR8RF1uixW'
                        b'qEN27m71wOfoYluwjN8xtzCsp8maUYdRLizAON0jcn_pSwN{"v":"KERICAACAAJ'
                        b'SONAACT.","t":"rct","d":"ELLXmDHjPA-K1MoVBqOfLTrRRo_GJosVi8mIPS6'
                        b'zsAkw","i":"EMClOv48MJabMgSKYty-iVfpEImA1gaawtofFXk5VVPT","s":"6'
                        b'"}-XBaEGcI8FG4uEn1Pu8ak3ghec-iMWpfR6h3vGGloIzWEUZBMAAAEGcI8FG4uE'
                        b'n1Pu8ak3ghec-iMWpfR6h3vGGloIzWEUZB-KBCAACjHzYfNkDYM5pGD5vsONz6yX'
                        b'Zmt0oztyXabaidTU3zTiLNA5cfxODOZPuZGWdQyAIKQGyT_SBWbQ9N8gzndAcOAB'
                        b'B7PFLmjKSRHa0q9ltcM2ph3K4hE9SlGsKnyaK4NZWINE0XYRTSoKtFe_liA0tREj'
                        b'6TONgeiJ6fpqRNB2Wlh2UHACAmIjEcUKEyWHoS9kJ6SR9HekdXZGMRpGqDejgTqm'
                        b'UmFR93-xpyeXXg9Ma9rwx_H2M8m_G6w1tbZGnZv6DYoW8G')


        # Play camMsgs to Deb
        # create non-local kevery for Deb to process msgs from Cam
        debKevery = Kevery(db=debHab.db,
                                    lax=False,
                                    local=False)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(camMsgs), kvy=debKevery)
        # debKevery.process(ims=bytearray(camMsgs))  # give copy to process
        assert camHab.pre in debKevery.kevers
        assert debKevery.kevers[camHab.pre].sn == camHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Cam's events by processing Deb's cues
        debCamVrcs = debHab.processCues(debKevery.cues, version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)
        assert len(debKevery.cues) == 0
        assert debCamVrcs == (b'{"v":"KERICAACAAJSONAACT.","t":"rct","d":"EGcI8FG4uEn1Pu8ak3ghec'
                        b'-iMWpfR6h3vGGloIzWEUZB","i":"EGcI8FG4uEn1Pu8ak3ghec-iMWpfR6h3vGG'
                        b'loIzWEUZB","s":"0"}-XBaEMClOv48MJabMgSKYty-iVfpEImA1gaawtofFXk5V'
                        b'VPTMAACEGzk7gjEPIoBfsCj2xIr74rw2pICSYT4SY-jRrOJWUDE-KBCAAB7ANgAO'
                        b'AZa_MC3Gdf6z84akhjTFZz0byKyxPhbufN9a96WkJYbOfoLFmSzDSFlNj2G1kiuh'
                        b'aXiZqHJVK3dVggFABAhYdbs3tIQNJcEDCvwIOPFq4-OBnGEDjPTFLIUvS4xOBe9b'
                        b'kQnirXUZphjNkCmOX3kNIF1uP7XaCelRaxW9N8KACCGBXKdA1GS2ucADdJiu8xna'
                        b'lLIbKtMO-zqCVH-E24jIW4-Oj7AeI04Wz3V-eO0l7FTptKJvUSJ1LxVEFjQ594G')


        # Play disjoints debCamVrcs to Cam
        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(debCamVrcs), kvy=camKevery)
        # camKevery.processOne(ims=bytearray(debCamVrcs))  # give copy to process

        # Play debMsgs to Bev
        # create non-local kevery for Bev to process msgs from Deb
        bevKevery = Kevery(db=bevHab.db,
                                    lax=False,
                                    local=False)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(debMsgs), kvy=bevKevery)
        # bevKevery.process(ims=bytearray(debMsgs))  # give copy to process
        assert debHab.pre in bevKevery.kevers
        assert bevKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(bevKevery.cues) == 7

        # get disjoints receipts (rcts) from Bev of Deb's events by processing Bevs's cues
        bevMsgs = bevHab.processCues(bevKevery.cues, version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)
        assert len(bevKevery.cues) == 0
        assert bevMsgs == (b'{"v":"KERICAACAAJSONAAD_.","t":"icp","d":"EDMq5XKszE3xAoMN-gPfti'
                        b'O0DizoUzFWlIfcXTgaQGrq","i":"BAqph4mAWcf7mkIgk1Xrpvr7dWT7YvHIam_'
                        b'hqUAT2rqw","s":"0","kt":"1","k":["BAqph4mAWcf7mkIgk1Xrpvr7dWT7Yv'
                        b'HIam_hqUAT2rqw"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-'
                        b'KAWAACUKyv0KgardrD-JVe7MaRbhpOA046bRdyGxZ5iHtnq_jq_LvUNjf9dqUCsW'
                        b'PyujqquYAzYtho4ws9FGimJdWYF{"v":"KERICAACAAJSONAACT.","t":"rct",'
                        b'"d":"EMClOv48MJabMgSKYty-iVfpEImA1gaawtofFXk5VVPT","i":"EMClOv48'
                        b'MJabMgSKYty-iVfpEImA1gaawtofFXk5VVPT","s":"0"}-MAhBAqph4mAWcf7mk'
                        b'Igk1Xrpvr7dWT7YvHIam_hqUAT2rqw0BCDiwbGRAdvkza1aVfHUVRpKfrDn-Pxmp'
                        b'XdayaKsnv9kcAn8XPTko68EMEPaS7KFA1Lavxkru5x-tEKtV7dPAAG{"v":"KERI'
                        b'CAACAAJSONAACT.","t":"rct","d":"EHzNGRf2LrWqtBA14pg-j0jiihLMq5JF'
                        b'fNi3Gbk8-5J1","i":"EMClOv48MJabMgSKYty-iVfpEImA1gaawtofFXk5VVPT"'
                        b',"s":"1"}-MAhBAqph4mAWcf7mkIgk1Xrpvr7dWT7YvHIam_hqUAT2rqw0BCjL43'
                        b'Uek4FnbjK89r9UN7y4W0-osGEMuY8CyD8W9uHbDegN34Qy9588VGd_uNsM2H4No5'
                        b'JmJHWsSP-okb_pusJ{"v":"KERICAACAAJSONAACT.","t":"rct","d":"EGzk7'
                        b'gjEPIoBfsCj2xIr74rw2pICSYT4SY-jRrOJWUDE","i":"EMClOv48MJabMgSKYt'
                        b'y-iVfpEImA1gaawtofFXk5VVPT","s":"2"}-MAhBAqph4mAWcf7mkIgk1Xrpvr7'
                        b'dWT7YvHIam_hqUAT2rqw0BC60hVo888t3pt1el16HCb1SrdCusOD9gVMnExS0_dc'
                        b'_n6Bt9chK903MKBRn7H5WD-Yo9hukk08RkN0sC8xNGMO{"v":"KERICAACAAJSON'
                        b'AACT.","t":"rct","d":"EFRjgfaQAHIb_-7e6WWOJUkcdjjBd67Yve78HZWSn-'
                        b'9M","i":"EMClOv48MJabMgSKYty-iVfpEImA1gaawtofFXk5VVPT","s":"3"}-'
                        b'MAhBAqph4mAWcf7mkIgk1Xrpvr7dWT7YvHIam_hqUAT2rqw0BDwSLQjI5MFWAjkJ'
                        b'C53qyopcQwMlK6THrq9WmB-tLEkqlKRoZ_6ChbcbTRY_Ikiiq41yW9k73mZiN8En'
                        b'KwCJ-MK{"v":"KERICAACAAJSONAACT.","t":"rct","d":"EO2FFKL-ckYs5jQ'
                        b'HgG_AI8ZN5Ltnmmm2Zocdp3kVmnFX","i":"EMClOv48MJabMgSKYty-iVfpEImA'
                        b'1gaawtofFXk5VVPT","s":"4"}-MAhBAqph4mAWcf7mkIgk1Xrpvr7dWT7YvHIam'
                        b'_hqUAT2rqw0BAuWeJG1eGvglHUaGA75NZcn4jFc-IqexbCp89YPV9IO3kcyPvfwU'
                        b'yALaASZehnqH5QKenMRUhJdOwlzuIZW2gG{"v":"KERICAACAAJSONAACT.","t"'
                        b':"rct","d":"EJ6JQ0VuKyaoxVy0N0N6vgb6gS6QDHHyyhEhpDJIQaXJ","i":"E'
                        b'MClOv48MJabMgSKYty-iVfpEImA1gaawtofFXk5VVPT","s":"5"}-MAhBAqph4m'
                        b'AWcf7mkIgk1Xrpvr7dWT7YvHIam_hqUAT2rqw0BBbD-JVG4XjfwuH8j38IkrPZ_T'
                        b'CL2e1-arJhPHoFi4JTuH2xyMLy73nAIk3Q_LTx4ktQqwIglrylf8cu4qG7pYF{"v'
                        b'":"KERICAACAAJSONAACT.","t":"rct","d":"ELLXmDHjPA-K1MoVBqOfLTrRR'
                        b'o_GJosVi8mIPS6zsAkw","i":"EMClOv48MJabMgSKYty-iVfpEImA1gaawtofFX'
                        b'k5VVPT","s":"6"}-MAhBAqph4mAWcf7mkIgk1Xrpvr7dWT7YvHIam_hqUAT2rqw'
                        b'0BCuc2iG2zfkqbKgNEf1M1XeQUyMN8JsG3v1PSzZo6joXV-kUGVe60FcFnKsJvt3'
                        b'HJFXSS-yT48HYYQw7-C8Jq0J')

        # Play bevMsgs to Deb
        Parser(version=Vrsn_2_0).parse(ims=bytearray(bevMsgs), kvy=debKevery)
        # debKevery.process(ims=bytearray(bevMsgs))  # give copy to process
        assert bevHab.pre in debKevery.kevers
        assert debKevery.kevers[bevHab.pre].sn == bevHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Bev's events by processing Deb's cues
        debBevVrcs = debHab.processCues(debKevery.cues, version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)
        assert len(debKevery.cues) == 0
        assert debBevVrcs == (b'{"v":"KERICAACAAJSONAACT.","t":"rct","d":"EDMq5XKszE3xAoMN-gPfti'
                        b'O0DizoUzFWlIfcXTgaQGrq","i":"BAqph4mAWcf7mkIgk1Xrpvr7dWT7YvHIam_'
                        b'hqUAT2rqw","s":"0"}-XBaEMClOv48MJabMgSKYty-iVfpEImA1gaawtofFXk5V'
                        b'VPTMAACEGzk7gjEPIoBfsCj2xIr74rw2pICSYT4SY-jRrOJWUDE-KBCAAAb_tTh7'
                        b'wMPrHZW3Dpjz5lNdulFhEi9kvyuYfLKj8Gv5LtAnR_K--MSL0qLPZPSbMY02P1Q_'
                        b'B0LdaUQCi3_I28AABCjcOt30nCgrDrSOAIRY-1qYukv5nmsboWCBr4YFHuTQwKfP'
                        b'R3qX38-B3z67Tk3eDY_yDXsZVB-WYimolzpHNABACCVn8vFScLnE4DJh0AErxDqk'
                        b'0BCOUhgBO17loLA-MCWUGdfTVEvO4FoVIk8bJNXbZ2U0euM1NHO_yi5_xrgpb4M')

        # Play disjoints debBevVrcs to Bev
        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(debBevVrcs), kvy=bevKevery)
        # bevKevery.processOne(ims=bytearray(debBevVrcs))  # give copy to process

        # now setup conjoint replay

        # Replay Deb's First Seen Events with receipts (vrcs and rcts) from both Cam and Bev
        # datetime is different in each run in the fse attachment in clone replay
        # so we either have to force dts in db or we parse in pieces
        debFelMsgs = bytearray()
        fn = 0
        cloner = debHab.db.clonePreIter(pre=debHab.pre, fn=fn, version=Vrsn_2_0)  # create iterator
        msg = next(cloner)  # get zeroth event with attachments
        assert len(msg) == 1337
        debFelMsgs.extend(msg)

        # parse msg
        serder = SerderKERI(raw=msg)
        assert serder.raw == debHab.iserder.raw
        assert serder.sn == fn  # no recovery forks so sn == fn
        assert serder.ked["t"] == Ilks.icp
        del msg[:len(serder.raw)]
        assert len(msg) == 816  # 836 # 1016

        counter = Counter(qb64b=msg, version=Vrsn_2_0)  # attachment length quadlets counter
        assert counter.code == CtrDex_2_0.AttachmentGroup
        assert counter.count == 203 # (len(msg) - len(counter.qb64b)) // 4 == 208 # 253
        del msg[:len(counter.qb64b)]
        assert len(msg) == 812 # 832 == 208 * 4

        counter = Counter(qb64b=msg, version=Vrsn_2_0)  # indexed signatures counter
        assert counter.code == CtrDex_2_0.ControllerIdxSigs
        del msg[:len(counter.qb64b)]
        assert len(msg) == 808

        for i in range(3):  # parse signatures multisig 3
            siger = Siger(qb64b=msg)
            del msg[:len(siger.qb64b)]
        assert len(msg) == 544

        counter = Counter(qb64b=msg, version=Vrsn_2_0)  # nontrans receipt (rct) counter
        assert counter.code == CtrDex_2_0.NonTransReceiptCouples
        del msg[:len(counter.qb64b)]
        assert len(msg) == 540

        for i in range(1):  # parse receipt couples single sig
            prefixer, cigar = deReceiptCouple(msg, strip=True)
        assert len(msg) == 408 # 196 - 1 * (len(prefixer.qb64b) + len(cigar.qb64b)) == 64

        # extract trans receipt counters (quadlet)
        counter = Counter(qb64b=msg, version=Vrsn_2_0)  # trans receipt (vrc) counter
        assert counter.code == CtrDex_2_0.TransReceiptIdxSigGroups
        assert counter.count == 90 # now quadlet counter not 3  multisig cam
        del msg[:len(counter.qb64b)]
        assert len(msg) == 404 # 560

        # extract receipt triple
        prefixer = Prefixer(qb64b=msg, strip=True)
        number = Number(qb64b=msg, strip=True)
        diger = Diger(qb64b=msg, strip=True)
        assert len(msg) == 312 # 468 == 560 - (len(prefixer.qb64b) + len(number.qb64b) + len(diger.qb64b))
        #extract sigs
        counter = Counter(qb64b=msg, strip=True, version=Vrsn_2_0)
        sigers = []
        for i in range(3):  # extract idx sig group ctr quadlet
            sigers.append(Siger(qb64b=msg, strip=True))
        assert len(msg) == 44

        counter = Counter(qb64b=msg, version=Vrsn_2_0)  # first seen replay couple counter
        assert counter.code == CtrDex_2_0.FirstSeenReplayCouples
        del msg[:len(counter.qb64b)]
        assert len(msg) == 40

        number = Number(qb64b=msg)
        assert number.sn == fn == 0
        del msg[:len(number.qb64b)]
        assert len(msg) == 36  # 24 less

        dater = Dater(qb64b=msg)
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
        cloner = debHab.db.clonePreIter(pre=debHab.pre, fn=fn, version=Vrsn_2_0)  # create iterator not at 0
        msg = next(cloner)  # next event with attachments
        assert len(msg) == 1021
        serder = SerderKERI(raw=msg)
        assert serder.sn == fn  # no recovery forks so sn == fn
        assert serder.ked["t"] == Ilks.ixn
        debFelMsgs.extend(msg)

        fn += 1
        msg = next(cloner)  # get zeroth event with attachments
        serder = SerderKERI(raw=msg)
        assert serder.sn == fn  # no recovery forks so sn == fn
        assert serder.ked["t"] == Ilks.rot
        assert len(msg) == 1397
        assert ([verfer.qb64 for verfer in serder.verfers] ==
                [verfer.qb64 for verfer in debHab.kever.verfers])
        debFelMsgs.extend(msg)

        fn += 1
        while (fn <= 6):
            msg = next(cloner)  # get zeroth event with attachments
            serder = SerderKERI(raw=msg)
            assert serder.sn == fn  # no recovery forks so sn == fn
            assert serder.ked["t"] == Ilks.ixn
            assert len(msg) == 1021
            debFelMsgs.extend(msg)
            fn += 1

        assert len(debFelMsgs) == 7839
        cloner.close()  # must close or get lmdb error upon with exit

        msgs = debHab.replay(version=Vrsn_2_0)
        assert msgs == debFelMsgs

        # Play Cam's messages to Bev
        Parser(version=Vrsn_2_0).parse(ims=bytearray(camMsgs), kvy=bevKevery)
        # bevKevery.process(ims=bytearray(camMsgs))  # give copy to process
        assert camHab.pre in bevKevery.kevers
        assert bevKevery.kevers[camHab.pre].sn == camHab.kever.sn == 0
        assert len(bevKevery.cues) == 1

        # Play Bev's messages to Cam
        Parser(version=Vrsn_2_0).parse(ims=bytearray(bevMsgs), kvy=camKevery)
        # camKevery.process(ims=bytearray(bevMsgs))  # give copy to process
        assert bevHab.pre in camKevery.kevers
        assert camKevery.kevers[bevHab.pre].sn == bevHab.kever.sn == 0
        assert len(camKevery.cues) == 1

        camDebFelMsgs = camHab.replay(pre=debHab.pre, version=Vrsn_2_0)
        bevDebFelMsgs = bevHab.replay(pre=debHab.pre, version=Vrsn_2_0)

        assert len(bevDebFelMsgs) == len(camDebFelMsgs) == len(debFelMsgs) == 7839

        # create non-local kevery for Art to process conjoint replay msgs from Deb
        artKevery = Kevery(db=artHab.db,
                                    lax=False,
                                    local=False)
        # process Cam's inception so Art will proces Cam's vrcs without escrowing
        camIcpMsg = camHab.msgOwnInception(framed=True, gvrsn=Vrsn_2_0)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(camIcpMsg), kvy=artKevery)
        # artKevery.process(ims=bytearray(camIcpMsg))
        assert camHab.pre in artKevery.kevers
        assert len(artKevery.cues) == 1

        # process in cloned mode
        artKevery.cloned = True
        Parser(version=Vrsn_2_0).parse(ims=bytearray(debFelMsgs), kvy=artKevery)
        assert debHab.pre in artKevery.kevers
        assert artKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(artKevery.cues) == 8
        # Explicit receipt+firner path: clone replay receipt processing uses
        # fels.getOn(keys=pre, on=firner.sn) to look up the event digest.
        assert artHab.db.fels.get(keys=debHab.pre, on=0) == debHab.iserder.said
        artDebFelMsgs = artHab.replay(pre=debHab.pre, version=Vrsn_2_0)
        assert len(artDebFelMsgs) == 7839

    assert not os.path.exists(artHby.ks.path)
    assert not os.path.exists(artHby.db.path)
    assert not os.path.exists(bevHby.ks.path)
    assert not os.path.exists(bevHby.db.path)
    assert not os.path.exists(camHby.ks.path)
    assert not os.path.exists(camHby.db.path)
    assert not os.path.exists(debHby.ks.path)
    assert not os.path.exists(debHby.db.path)

    """End Test"""


def test_replay_all_v1():
    """
    Test conjoint replay all

    Setup database with events from Deb, Cam, Bev, abd Art
    Replay all the events in database.

    """
    artSalt = Salter(raw=b'abcdef0123456789').qb64
    default_salt = Salter(raw=b'0123456789abcdef').qb64

    with (openHby(name="deb", base="test", salt=default_salt, version=Vrsn_1_0) as debHby,
         openHby(name="cam", base="test", salt=default_salt, version=Vrsn_1_0) as camHby,
         openHby(name="bev", base="test", salt=default_salt, version=Vrsn_1_0) as bevHby,
         openHby(name="art", base="test", salt=artSalt, version=Vrsn_1_0) as artHby):

        # setup Deb's habitat using default salt multisig already incepts
        sith = ["1/2", "1/2", "1/2"]  # weighted signing threshold
        debHab = debHby.makeHab(name='test', isith=sith, icount=3, version=Vrsn_1_0, kind=Kinds.json)
        assert debHab.kever.prefixer.transferable

        # setup Cam's habitat using default salt multisig already incepts
        # Cam's receipts will be vrcs with 3 indexed sigantures attached
        sith = '2'  # hex str of threshold int
        camHab = camHby.makeHab(name='test', isith=sith, icount=3, version=Vrsn_1_0, kind=Kinds.json)
        assert camHab.kever.prefixer.transferable

        # setup Bev's habitat using default salt nonstransferable already incepts
        # Bev's receipts will be rcts with a receipt couple attached
        sith = '1'  # hex str of threshold int
        bevHab = bevHby.makeHab(name='test', isith=sith, icount=1,
                                transferable=False, version=Vrsn_1_0, kind=Kinds.json)
        assert not bevHab.kever.prefixer.transferable

        # setup Art's habitat using custom salt nonstransferable so not match Bev
        # already incepts
        # Art's receipts will be rcts with a receipt couple attached
        sith = '1'  # hex str of threshold int
        artHab = artHby.makeHab(name='test', isith=sith, icount=1,
                                transferable=False, version=Vrsn_1_0, kind=Kinds.json)
        assert not artHab.kever.prefixer.transferable

        # Create series of event for Deb
        debMsgs = bytearray()
        debMsgs.extend(debHab.msgOwnInception(framed=True, gvrsn=Vrsn_1_0))
        debMsgs.extend(debHab.interact(framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0))
        debMsgs.extend(debHab.rotate(framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0))
        debMsgs.extend(debHab.interact(framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0))
        debMsgs.extend(debHab.interact(framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0))
        debMsgs.extend(debHab.interact(framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0))
        debMsgs.extend(debHab.interact(framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0))

        # Play debMsgs to Cam
        # create non-local kevery for Cam to process msgs from Deb
        camKevery = Kevery(db=camHab.db,
                                    lax=False,
                                    local=False)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(debMsgs), kvy=camKevery)
        # camKevery.process(ims=bytearray(debMsgs))  # give copy to process
        assert debHab.pre in camKevery.kevers
        assert camKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(camKevery.cues) == 7

        # get disjoints receipts (vrcs) from Cam of Deb's events by processing Cam's cues
        camMsgs = camHab.processCues(camKevery.cues, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        assert len(camKevery.cues) == 0

        # Play camMsgs to Deb
        # create non-local kevery for Deb to process msgs from Cam
        debKevery = Kevery(db=debHab.db,
                                    lax=False,
                                    local=False)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(camMsgs), kvy=debKevery)
        # debKevery.process(ims=bytearray(camMsgs))  # give copy to process
        assert camHab.pre in debKevery.kevers
        assert debKevery.kevers[camHab.pre].sn == camHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Cam's events by processing Deb's cues
        debCamVrcs = debHab.processCues(debKevery.cues, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        assert len(debKevery.cues) == 0

        # Play disjoints debCamVrcs to Cam
        Parser(version=Vrsn_1_0).parseOne(ims=bytearray(debCamVrcs), kvy=camKevery)
        # camKevery.processOne(ims=bytearray(debCamVrcs))  # give copy to process

        # Play debMsgs to Bev
        # create non-local kevery for Bev to process msgs from Deb
        bevKevery = Kevery(db=bevHab.db,
                                    lax=False,
                                    local=False)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(debMsgs), kvy=bevKevery)
        # bevKevery.process(ims=bytearray(debMsgs))  # give copy to process
        assert debHab.pre in bevKevery.kevers
        assert bevKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(bevKevery.cues) == 7

        # get disjoints receipts (rcts) from Bev of Deb's events by processing Bevs's cues
        bevMsgs = bevHab.processCues(bevKevery.cues, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        assert len(bevKevery.cues) == 0

        # Play bevMsgs to Deb
        Parser(version=Vrsn_1_0).parse(ims=bytearray(bevMsgs), kvy=debKevery)
        # debKevery.process(ims=bytearray(bevMsgs))  # give copy to process
        assert bevHab.pre in debKevery.kevers
        assert debKevery.kevers[bevHab.pre].sn == bevHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Bev's events by processing Deb's cues
        debBevVrcs = debHab.processCues(debKevery.cues, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        assert len(debKevery.cues) == 0

        # Play disjoints debBevVrcs to Bev
        Parser(version=Vrsn_1_0).parseOne(ims=bytearray(debBevVrcs), kvy=bevKevery)
        # bevKevery.processOne(ims=bytearray(debBevVrcs))  # give copy to process

        # now setup replay
        debAllFelMsgs = debHab.replayAll(version=Vrsn_1_0)
        # assert len(debAllFelMsgs) == 12495

        # create non-local kevery for Art to process conjoint replay msgs from Deb
        artKevery = Kevery(db=artHab.db,
                                    lax=False,
                                    local=False)
        # process Cam's inception so Art will proces Cam's vrcs without escrowing
        camIcpMsg = camHab.msgOwnInception(framed=True, gvrsn=Vrsn_1_0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(camIcpMsg), kvy=artKevery)
        assert camHab.pre in artKevery.kevers
        assert len(artKevery.cues) == 1
        # give copy to process in cloned mode
        artKevery.cloned = True
        Parser(version=Vrsn_1_0).parse(ims=bytearray(debAllFelMsgs), kvy=artKevery)
        assert debHab.pre in artKevery.kevers
        assert artKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(artKevery.cues) == 10
        # Explicit receipt+firner path: fels.getOn(keys=pre, on=firner.sn) in clone replay
        assert artHab.db.fels.get(keys=debHab.pre, on=0) == debHab.iserder.said
        artAllFelMsgs = artHab.replayAll(version=Vrsn_1_0)
        assert len(artAllFelMsgs) == 10557 # 10797 # 12237

    assert not os.path.exists(artHby.ks.path)
    assert not os.path.exists(artHby.db.path)
    assert not os.path.exists(bevHby.ks.path)
    assert not os.path.exists(bevHby.db.path)
    assert not os.path.exists(camHby.ks.path)
    assert not os.path.exists(camHby.db.path)
    assert not os.path.exists(debHby.ks.path)
    assert not os.path.exists(debHby.db.path)

    """End Test"""

def test_replay_all_v2():
    """
    Test conjoint replay all

    Setup database with events from Deb, Cam, Bev, abd Art
    Replay all the events in database.

    """
    artSalt = Salter(raw=b'abcdef0123456789').qb64
    default_salt = Salter(raw=b'0123456789abcdef').qb64

    with (openHby(name="deb", base="test", salt=default_salt, version=Vrsn_2_0) as debHby,
         openHby(name="cam", base="test", salt=default_salt, version=Vrsn_2_0) as camHby,
         openHby(name="bev", base="test", salt=default_salt, version=Vrsn_2_0) as bevHby,
         openHby(name="art", base="test", salt=artSalt, version=Vrsn_2_0) as artHby):

        # setup Deb's habitat using default salt multisig already incepts
        sith = ["1/2", "1/2", "1/2"]  # weighted signing threshold
        debHab = debHby.makeHab(name='test', isith=sith, icount=3, version=Vrsn_2_0, kind=Kinds.json)
        assert debHab.kever.prefixer.transferable

        # setup Cam's habitat using default salt multisig already incepts
        # Cam's receipts will be vrcs with 3 indexed sigantures attached
        sith = '2'  # hex str of threshold int
        camHab = camHby.makeHab(name='test', isith=sith, icount=3, version=Vrsn_2_0, kind=Kinds.json)
        assert camHab.kever.prefixer.transferable

        # setup Bev's habitat using default salt nonstransferable already incepts
        # Bev's receipts will be rcts with a receipt couple attached
        sith = '1'  # hex str of threshold int
        bevHab = bevHby.makeHab(name='test', isith=sith, icount=1,
                                transferable=False, version=Vrsn_2_0, kind=Kinds.json)
        assert not bevHab.kever.prefixer.transferable

        # setup Art's habitat using custom salt nonstransferable so not match Bev
        # already incepts
        # Art's receipts will be rcts with a receipt couple attached
        sith = '1'  # hex str of threshold int
        artHab = artHby.makeHab(name='test', isith=sith, icount=1,
                                transferable=False, version=Vrsn_2_0, kind=Kinds.json)
        assert not artHab.kever.prefixer.transferable

        # Create series of event for Deb
        debMsgs = bytearray()
        debMsgs.extend(debHab.msgOwnInception(framed=True, gvrsn=Vrsn_2_0))
        debMsgs.extend(debHab.interact(framed=True, version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0))
        debMsgs.extend(debHab.rotate(framed=True, version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0))
        debMsgs.extend(debHab.interact(framed=True, version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0))
        debMsgs.extend(debHab.interact(framed=True, version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0))
        debMsgs.extend(debHab.interact(framed=True, version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0))
        debMsgs.extend(debHab.interact(framed=True, version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0))

        # Play debMsgs to Cam
        # create non-local kevery for Cam to process msgs from Deb
        camKevery = Kevery(db=camHab.db,
                                    lax=False,
                                    local=False)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(debMsgs), kvy=camKevery)
        # camKevery.process(ims=bytearray(debMsgs))  # give copy to process
        assert debHab.pre in camKevery.kevers
        assert camKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(camKevery.cues) == 7

        # get disjoints receipts (vrcs) from Cam of Deb's events by processing Cam's cues
        camMsgs = camHab.processCues(camKevery.cues, version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)
        assert len(camKevery.cues) == 0

        # Play camMsgs to Deb
        # create non-local kevery for Deb to process msgs from Cam
        debKevery = Kevery(db=debHab.db,
                                    lax=False,
                                    local=False)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(camMsgs), kvy=debKevery)
        # debKevery.process(ims=bytearray(camMsgs))  # give copy to process
        assert camHab.pre in debKevery.kevers
        assert debKevery.kevers[camHab.pre].sn == camHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Cam's events by processing Deb's cues
        debCamVrcs = debHab.processCues(debKevery.cues, version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)
        assert len(debKevery.cues) == 0

        # Play disjoints debCamVrcs to Cam
        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(debCamVrcs), kvy=camKevery)
        # camKevery.processOne(ims=bytearray(debCamVrcs))  # give copy to process

        # Play debMsgs to Bev
        # create non-local kevery for Bev to process msgs from Deb
        bevKevery = Kevery(db=bevHab.db,
                                    lax=False,
                                    local=False)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(debMsgs), kvy=bevKevery)
        # bevKevery.process(ims=bytearray(debMsgs))  # give copy to process
        assert debHab.pre in bevKevery.kevers
        assert bevKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(bevKevery.cues) == 7

        # get disjoints receipts (rcts) from Bev of Deb's events by processing Bevs's cues
        bevMsgs = bevHab.processCues(bevKevery.cues, version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)
        assert len(bevKevery.cues) == 0

        # Play bevMsgs to Deb
        Parser(version=Vrsn_2_0).parse(ims=bytearray(bevMsgs), kvy=debKevery)
        # debKevery.process(ims=bytearray(bevMsgs))  # give copy to process
        assert bevHab.pre in debKevery.kevers
        assert debKevery.kevers[bevHab.pre].sn == bevHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Bev's events by processing Deb's cues
        debBevVrcs = debHab.processCues(debKevery.cues, version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)
        assert len(debKevery.cues) == 0

        # Play disjoints debBevVrcs to Bev
        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(debBevVrcs), kvy=bevKevery)
        # bevKevery.processOne(ims=bytearray(debBevVrcs))  # give copy to process

        # now setup replay
        debAllFelMsgs = debHab.replayAll(version=Vrsn_2_0)
        # assert len(debAllFelMsgs) == 12495

        # create non-local kevery for Art to process conjoint replay msgs from Deb
        artKevery = Kevery(db=artHab.db,
                                    lax=False,
                                    local=False)
        # process Cam's inception so Art will proces Cam's vrcs without escrowing
        camIcpMsg = camHab.msgOwnInception(framed=True, gvrsn=Vrsn_2_0)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(camIcpMsg), kvy=artKevery)
        assert camHab.pre in artKevery.kevers
        assert len(artKevery.cues) == 1
        # give copy to process in cloned mode
        artKevery.cloned = True
        Parser(version=Vrsn_2_0).parse(ims=bytearray(debAllFelMsgs), kvy=artKevery)
        assert debHab.pre in artKevery.kevers
        assert artKevery.kevers[debHab.pre].sn == debHab.kever.sn == 6
        assert len(artKevery.cues) == 10
        # Explicit receipt+firner path: fels.getOn(keys=pre, on=firner.sn) in clone replay
        assert artHab.db.fels.get(keys=debHab.pre, on=0) == debHab.iserder.said
        artAllFelMsgs = artHab.replayAll(version=Vrsn_2_0)
        assert len(artAllFelMsgs) == 10588 # 10557 # 10797 # 12237

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
    test_replay_v1()
    test_replay_v2()
    test_replay_all_v1()
    test_replay_all_v2()
