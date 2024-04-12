# -*- encoding: utf-8 -*-
"""
tests delegation primaily from keri.core.eventing

"""
import datetime
import os

from keri import help
from keri.help import helping

from keri import core
from keri.core import coring, eventing, parsing, serdering, indexing

from keri.app import habbing


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
    artSalt = core.Salter(raw=b'abcdef0123456789').qb64
    default_salt = core.Salter(raw=b'0123456789abcdef').qb64

    with (habbing.openHby(name="deb", base="test", salt=default_salt) as debHby,
         habbing.openHby(name="cam", base="test", salt=default_salt) as camHby,
         habbing.openHby(name="bev", base="test", salt=default_salt) as bevHby,
         habbing.openHby(name="art", base="test", salt=artSalt) as artHby):

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
                    b'"0"}-FABEBp-SQb9fTgeoQkIkOd2xegvXy3epjOskiPrf6JDIEuj0AAAAAAAAAAA'
                    b'AAAAAAAAAAAAEBp-SQb9fTgeoQkIkOd2xegvXy3epjOskiPrf6JDIEuj-AADAADL'
                    b'Qfvb0b5TiD4Y-4wjaTMJGTYW4CyEL2tPhwgvbuWt3JV7e_qsaPszYE17QqR3WiOL'
                    b'lQ1mCCAzsYuIT2CGvYoMABCc4h6BKn6u-FODICsn7JhhIv16bdWjPRLZ_wpvlpsG'
                    b'YQE8_hNebpOyKMeeqbkmNimbQUbyBZAO2-3w9dVFDXUBACCVRnaFk5BTNKXD8Hpe'
                    b'IVIEgpnu6BJLZ9C5VYAc1-kS7HTuSCc5ZMZRRFid8Ugt8SWLTbDYpLSMFVYy0VQq'
                    b'IcYB{"v":"KERI10JSON000091_","t":"rct","d":"EFECUzlLZ3IKG9Kvkj51'
                    b'a0RYPYXnUeZ5SIpw8x3SPS1E","i":"ELfp9ZhqQCGov3wPRLa6vn5VkIQjug2sb'
                    b'2QD17T-TIpY","s":"1"}-FABEBp-SQb9fTgeoQkIkOd2xegvXy3epjOskiPrf6J'
                    b'DIEuj0AAAAAAAAAAAAAAAAAAAAAAAEBp-SQb9fTgeoQkIkOd2xegvXy3epjOskiP'
                    b'rf6JDIEuj-AADAABGTRtvtT_fwczryJNP8wVxFog46GK_aM2PV2BKrx6NnXKcG40'
                    b'0u_0RtWmf4HfcbIgShjLciuD8-8prdczzLKoLABBwRzBuX1yXl7gqGBuw9vmfx2c'
                    b'nLEfnNnuF6KlgvGrGuaaNvMWtMC4jAyPFYdrcGwSG_Akg3zXW3GSrVgossNAEACA'
                    b'6LncYgxQiJ_HTAQARynrd4H53gf4VvLYVI4XZaEgiQi_HA3QV-CxTA2uNLTYo-j8'
                    b'4CtpUxrmA23NY3JPgmUMJ{"v":"KERI10JSON000091_","t":"rct","d":"EEL'
                    b'HnIwzGaJ-twKTfXtsPMteqsIVmDpiwVO574h6LRXD","i":"ELfp9ZhqQCGov3wP'
                    b'RLa6vn5VkIQjug2sb2QD17T-TIpY","s":"2"}-FABEBp-SQb9fTgeoQkIkOd2xe'
                    b'gvXy3epjOskiPrf6JDIEuj0AAAAAAAAAAAAAAAAAAAAAAAEBp-SQb9fTgeoQkIkO'
                    b'd2xegvXy3epjOskiPrf6JDIEuj-AADAAC8ionj_ZwUG9TVkLEtvamimUtttkyPWJ'
                    b'YziFgppcJo0D7NqrI68irp5t1Jx6tHhXnYdp6p_MySoFdHphInUQENABAC9GbBib'
                    b't14SbKyzktfn0xurSNHwhV1D61rgKPjoM6HIhJ7J171SZpIyT9ppraWJEMcRI4cD'
                    b'WkC3FWFLoVXo4HACAvxzyZMpnEVzxt56SZhDwE_aa2jma4ge_Lw3fODzT0VqLa6W'
                    b'DBn5ChZwExXaTm3DtH0bCai0WdBX4_SLT2qS0O{"v":"KERI10JSON000091_","'
                    b't":"rct","d":"ECWvVQFFqxmAW-vpSLwWj4yPO04nGA-6l8cifNBlc3gK","i":'
                    b'"ELfp9ZhqQCGov3wPRLa6vn5VkIQjug2sb2QD17T-TIpY","s":"3"}-FABEBp-S'
                    b'Qb9fTgeoQkIkOd2xegvXy3epjOskiPrf6JDIEuj0AAAAAAAAAAAAAAAAAAAAAAAE'
                    b'Bp-SQb9fTgeoQkIkOd2xegvXy3epjOskiPrf6JDIEuj-AADAAATkvw3JirYUej9y'
                    b'P58hEu0mb5klkMAHXHnVocUInjkJe2dY-TQi0LsmRdA4-Atr0Ys4iT0uqyEsOoHk'
                    b'Dch4EMBABCRvib0dz7KqpOS17MbWixJHxeLt0shgNBuXFXyFP5NrZdXRWuJ-z6jb'
                    b'H4hlO_hXrBdfK4CXTegUuBxqZiT3g8PACDWPPS-lBg7PvPcfus4ahRYCEWK-kNya'
                    b'RCJ3BiFDbEb1YTV2sFJliZ3Rnt7-_YBHUtLIS-ScgBG_HanGwQV9JEM{"v":"KER'
                    b'I10JSON000091_","t":"rct","d":"EFcoQIrpd4_NMcnL7SvVqUSLfPZOzkAGb'
                    b'tQcE3JVMn7D","i":"ELfp9ZhqQCGov3wPRLa6vn5VkIQjug2sb2QD17T-TIpY",'
                    b'"s":"4"}-FABEBp-SQb9fTgeoQkIkOd2xegvXy3epjOskiPrf6JDIEuj0AAAAAAA'
                    b'AAAAAAAAAAAAAAAAEBp-SQb9fTgeoQkIkOd2xegvXy3epjOskiPrf6JDIEuj-AAD'
                    b'AAATnbaIYocPQWSwn26FGE9gLLxybf_kYLlM38itDL_udjJ1tYICFzdfUj_n7rEs'
                    b'_e2gz72NHSpfFCdmSbTafXUDABCMcU34uYKjh3USDhllvTTTl-QXzbf7o5OITfaU'
                    b'ZEMnPXssMi6XbV1Oifu7JS-nZGpkXAPM2HqQd3Nzgx9WV8AHACCbzy5FlSMUjWm7'
                    b'mfCK_2Eo-scJNXdcncjeNNcr3I_CbZlOukmY3vPZzydQyMxEKzgMyUwjKlx5QsCh'
                    b'tl_Z6J0N{"v":"KERI10JSON000091_","t":"rct","d":"ELVXLfglCimN6Y-H'
                    b'kpoLoLiQkR1v65rrg7JRDhcToXVn","i":"ELfp9ZhqQCGov3wPRLa6vn5VkIQju'
                    b'g2sb2QD17T-TIpY","s":"5"}-FABEBp-SQb9fTgeoQkIkOd2xegvXy3epjOskiP'
                    b'rf6JDIEuj0AAAAAAAAAAAAAAAAAAAAAAAEBp-SQb9fTgeoQkIkOd2xegvXy3epjO'
                    b'skiPrf6JDIEuj-AADAACs4ZBIRuqeLb89OzIA-yVqvYdgwT5d5MZ7T-chrjkKKKr'
                    b'G2-93TqJv5DQoQ1H4Co18CvLjy0vj0odggJby5N4NABB6sAy89h4uU9viuDSzKBw'
                    b'88SYCy1OiiTPqV6kpucYIVcKkF_yYGfB-QXPuwCrQr-xN572CyRE0PxecMFa-Yog'
                    b'IACCKOoOQex0AUWu4YmlLo4RF2-hkaNsuVyP8aviudTV4Io7fYLnpV5hd3X9_7P4'
                    b'6lZJSvDMll30AVq8sAtiLp4sJ{"v":"KERI10JSON000091_","t":"rct","d":'
                    b'"ECSAoB-QcY3Vnia2G80NLVMkiGssUV70JoWxwJbqx9gL","i":"ELfp9ZhqQCGo'
                    b'v3wPRLa6vn5VkIQjug2sb2QD17T-TIpY","s":"6"}-FABEBp-SQb9fTgeoQkIkO'
                    b'd2xegvXy3epjOskiPrf6JDIEuj0AAAAAAAAAAAAAAAAAAAAAAAEBp-SQb9fTgeoQ'
                    b'kIkOd2xegvXy3epjOskiPrf6JDIEuj-AADAAANnzuJ_wzxPKRggIpkqC9LFCZ-AR'
                    b'AB_JzKcuFh261zS-1uUmyoAEH6tKeG2dWv5xfLhjziVaeip4cMmvwrC5EIABC_5l'
                    b'osjcTe4ka6aGks_xt1q3qv5hIJzwluyqwBtRDK-oCDnsHfJiZCFi6Fd4OnYkW5tg'
                    b'9F85etul09EsqbQ60NACA4ZILmT9YYliUbdNivmu8AeXFzSN5T5sDSrOT79J5Rcb'
                    b'P6oJidhYCNIhUB5bKmsuEnWda_NXXwJCsklQbQDGUL')

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
        assert debCamVrcs == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EBp-SQb9fTgeoQkIkOd2xegv'
                        b'Xy3epjOskiPrf6JDIEuj","i":"EBp-SQb9fTgeoQkIkOd2xegvXy3epjOskiPrf'
                        b'6JDIEuj","s":"0"}-FABELfp9ZhqQCGov3wPRLa6vn5VkIQjug2sb2QD17T-TIp'
                        b'Y0AAAAAAAAAAAAAAAAAAAAAACEELHnIwzGaJ-twKTfXtsPMteqsIVmDpiwVO574h'
                        b'6LRXD-AADAAA_RaT3MzW-uI6Y7CTpooCRyvVV9LIDCjTGw8Nz1EqRmR_dvjIQwoN'
                        b'QklDujYn1eTxVAc9-fTYMlpk7ZWWOSDYBABA9QRnuSlET3mU45BtJm9HY655bt8Z'
                        b'sEUUw5Ke8l5KHn4hl5GfZH8aHDnVY1SiQnZrKu7W4MeOsazhF8waHZbcHACCFEDA'
                        b'_jO-u0WccqVdffVc_xmrl9LYAinzPLJNx_XxVlf2Z5DHFBZM-Usq9Wb5-dvlDaR8'
                        b'GhGTKOxFbTcCwnnkL')

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
        parsing.Parser().parse(ims=bytearray(bevMsgs), kvy=debKevery)
        # debKevery.process(ims=bytearray(bevMsgs))  # give copy to process
        assert bevHab.pre in debKevery.kevers
        assert debKevery.kevers[bevHab.pre].sn == bevHab.kever.sn == 0
        assert len(debKevery.cues) == 1

        # get disjoints receipts (vrcs) from Deb of Bev's events by processing Deb's cues
        debBevVrcs = debHab.processCues(debKevery.cues)
        assert debBevVrcs == (b'{"v":"KERI10JSON000091_","t":"rct","d":"EBXqe7Xzsw2aolT09Ouh5Zw9'
                        b'kNn2sgoHmo4zCn7Q7ZSC","i":"BAqph4mAWcf7mkIgk1Xrpvr7dWT7YvHIam_hq'
                        b'UAT2rqw","s":"0"}-FABELfp9ZhqQCGov3wPRLa6vn5VkIQjug2sb2QD17T-TIp'
                        b'Y0AAAAAAAAAAAAAAAAAAAAAACEELHnIwzGaJ-twKTfXtsPMteqsIVmDpiwVO574h'
                        b'6LRXD-AADAABjgf8tiPVfvviaQ60CY9rJR-Nigj4paeIrFr87mnU-3Z2VKHFo6rp'
                        b'FyQfd5Za_M3gEbcjf3OtB718M7M6WFf4CABCz83_zL8bZM8wxQB4kQrJ4GatYSOg'
                        b'5UpphulR3lhkbV3imD4ZXJJF_v6D-Zcq0I1PluxUTMYsHYGoaXvLSWpkFACBdhdP'
                        b'iqPfy30Oxt_LshbISGHxPCyOBucKLfhkFqvTd21GhJQZ_LlUy0q-mGUtM_PAStYW'
                        b'00VuA1RMj1p6COtQC')

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
        assert len(msg) == 1595
        debFelMsgs.extend(msg)

        # parse msg
        serder = serdering.SerderKERI(raw=msg)
        assert serder.raw == debHab.iserder.raw
        assert serder.sn == fn  # no recovery forks so sn == fn
        assert serder.ked["t"] == coring.Ilks.icp
        del msg[:len(serder.raw)]
        assert len(msg) == 1076

        counter = coring.Counter(qb64b=msg)  # attachment length quadlets counter
        assert counter.code == coring.CtrDex.AttachmentGroup
        assert counter.count == (len(msg) - len(counter.qb64b)) // 4 == 268
        del msg[:len(counter.qb64b)]
        assert len(msg) == 1072 == 268 * 4

        counter = coring.Counter(qb64b=msg)  # indexed signatures counter
        assert counter.code == coring.CtrDex.ControllerIdxSigs
        assert counter.count == 3  # multisig deb
        del msg[:len(counter.qb64b)]
        assert len(msg) == 1068

        for i in range(counter.count):  # parse signatures
            siger = indexing.Siger(qb64b=msg)
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
        serder = serdering.SerderKERI(raw=msg)
        assert serder.sn == fn  # no recovery forks so sn == fn
        assert serder.ked["t"] == coring.Ilks.ixn
        debFelMsgs.extend(msg)

        fn += 1
        msg = next(cloner)  # get zeroth event with attachments
        serder = serdering.SerderKERI(raw=msg)
        assert serder.sn == fn  # no recovery forks so sn == fn
        assert serder.ked["t"] == coring.Ilks.rot
        assert len(msg) == 1648
        assert ([verfer.qb64 for verfer in serder.verfers] ==
                [verfer.qb64 for verfer in debHab.kever.verfers])
        debFelMsgs.extend(msg)

        fn += 1
        while (fn <= 6):
            msg = next(cloner)  # get zeroth event with attachments
            serder = serdering.SerderKERI(raw=msg)
            assert serder.sn == fn  # no recovery forks so sn == fn
            assert serder.ked["t"] == coring.Ilks.ixn
            assert len(msg) == 1279
            debFelMsgs.extend(msg)
            fn += 1

        assert len(debFelMsgs) == 9638
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

        assert len(bevDebFelMsgs) == len(camDebFelMsgs) == len(debFelMsgs) == 9638

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
        assert len(artDebFelMsgs) == 9638

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
    artSalt = core.Salter(raw=b'abcdef0123456789').qb64
    default_salt = core.Salter(raw=b'0123456789abcdef').qb64

    with (habbing.openHby(name="deb", base="test", salt=default_salt) as debHby,
         habbing.openHby(name="cam", base="test", salt=default_salt) as camHby,
         habbing.openHby(name="bev", base="test", salt=default_salt) as bevHby,
         habbing.openHby(name="art", base="test", salt=artSalt) as artHby):

        # setup Deb's habitat using default salt multisig already incepts
        sith = ["1/2", "1/2", "1/2"]  # weighted signing threshold
        debHab = debHby.makeHab(name='test', isith=sith, icount=3)
        assert debHab.kever.prefixer.transferable

        # setup Cam's habitat using default salt multisig already incepts
        # Cam's receipts will be vrcs with 3 indexed sigantures attached
        sith = '2'  # hex str of threshold int
        camHab = camHby.makeHab(name='test', isith=sith, icount=3)
        assert camHab.kever.prefixer.transferable

        # setup Bev's habitat using default salt nonstransferable already incepts
        # Bev's receipts will be rcts with a receipt couple attached
        sith = '1'  # hex str of threshold int
        bevHab = bevHby.makeHab(name='test', isith=sith, icount=1, transferable=False)
        assert not bevHab.kever.prefixer.transferable

        # setup Art's habitat using custom salt nonstransferable so not match Bev
        # already incepts
        # Art's receipts will be rcts with a receipt couple attached
        sith = '1'  # hex str of threshold int
        artHab = artHby.makeHab(name='test', isith=sith, icount=1, transferable=False)
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
        assert len(debAllFelMsgs) == 12495

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
        assert len(artKevery.cues) == 10
        artAllFelMsgs = artHab.replayAll()
        assert len(artAllFelMsgs) == 12717 #12113

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
    test_replay_all()
