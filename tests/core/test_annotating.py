# -*- coding: utf-8 -*-
"""
tests.core.test_annotating module

"""
from binascii import unhexlify

import pytest


from keri import kering

from keri.help import helping

from keri.core import (Matter,)
from keri.core.coring import dumps


from keri.core.annotating import (annot, denot)



def test_annot():
    """Test annot function  Annotate"""

    # simple Inception
    ims = (b'-FAtYKERICAAXicpEAXi2ueSrATBdAYAey6hA9LOS6WuITh90eq4L_SM0C4oDG9X'
            b'hvcVryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQMAAAMAAB-JALDG9XhvcVryHj'
            b'oIGcj5nK4sAE3oslQHWi4fBJre3NGwTQMAAA-JAAMAAA-JAA-JAA-JAA')

    bms = bytearray(ims)  # make copy
    print(f"incoming = \n{ims}\n")
    ams = annot(bms)  # annotated message dream
    assert not bms
    print(f"annotated = \n{ams}\n")
    dms = denot(ams)
    assert dms == ims

    # complex inception
    ims = (b'-FDD0OKERICAACAAXicpEOB71mX8FTP7bqJzbODmicKqK491WfIDopCCHjdHSU71EOB71mX8FTP7'
            b'bqJzbODmicKqK491WfIDopCCHjdHSU71MAAAMAAC-JAhDG9XhvcVryHjoIGcj5nK4sAE3oslQHWi'
            b'4fBJre3NGwTQDK58m521o6nwgcluK8Mu2ULvScXM9kB1bSORrxNSS9cnDMOmBoddcrRHShSajb4d'
            b'60S6RK34gXZ2WYbr3AiPY1M0MAAC-JAhEB9O4V-zUteZJJFubu1h0xMtzt0wuGpLMVj1sKVsElA_'
            b'EMrowWRk6u1imR32ZNHnTPUtc7uSAvrchIPN3I8S6vUGEEbufBpvagqe9kijKISOoQPYFEOpy22C'
            b'ZJGJqQZpZEyPMAAD-JAhBG9XhvcVryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQBK58m521o6nw'
            b'gcluK8Mu2ULvScXM9kB1bSORrxNSS9cnBMOmBoddcrRHShSajb4d60S6RK34gXZ2WYbr3AiPY1M0'
            b'-JABXDND-JA8-TAuDG9XhvcVryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQMAAAEB9O4V-zUteZ'
            b'JJFubu1h0xMtzt0wuGpLMVj1sKVsElA_DK58m521o6nwgcluK8Mu2ULvScXM9kB1bSORrxNSS9cn'
            b'MAABEMrowWRk6u1imR32ZNHnTPUtc7uSAvrchIPN3I8S6vUG-SAMMAAPEEbufBpvagqe9kijKISO'
            b'oQPYFEOpy22CZJGJqQZpZEyP')


    bms = bytearray(ims)  # make copy
    print(f"incoming = \n{ims}\n")
    ams = annot(bms)  # annotated message dream
    assert not bms
    print(f"annotated = \n{ams}\n")
    dms = denot(ams)
    assert dms == ims


    # interaction
    ims = (b'-FB70OKERICAACAAXixnEHSEI2ByWoUtCw9VHEGRelNBkHaMq_XsCl1TjQ4RhitFEOB71mX8FTP7'
            b'bqJzbODmicKqK491WfIDopCCHjdHSU71MAABEOB71mX8FTP7bqJzbODmicKqK491WfIDopCCHjdH'
            b'SU71-JBU-TAuDG9XhvcVryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQMAACEB9O4V-zUteZJJFu'
            b'bu1h0xMtzt0wuGpLMVj1sKVsElA_DK58m521o6nwgcluK8Mu2ULvScXM9kB1bSORrxNSS9cnMAAi'
            b'EMrowWRk6u1imR32ZNHnTPUtc7uSAvrchIPN3I8S6vUG-SAMMABDEEbufBpvagqe9kijKISOoQPY'
            b'FEOpy22CZJGJqQZpZEyP-TAXDMOmBoddcrRHShSajb4d60S6RK34gXZ2WYbr3AiPY1M0MACAEB9O'
            b'4V-zUteZJJFubu1h0xMtzt0wuGpLMVj1sKVsElA_')



    bms = bytearray(ims)  # make copy
    print(f"incoming = \n{ims}\n")
    ams = annot(bms)  # annotated message dream
    assert not bms
    print(f"annotated = \n{ams}\n")
    dms = denot(ams)
    assert dms == ims


    # Rotation
    ims = (b'-FCH0OKERICAACAAXrotEFQSJ-Z4yDa8uRNy1UiDdo7ONH4jB0a5AEgvPYsswn5OEOB71mX8FTP7'
        b'bqJzbODmicKqK491WfIDopCCHjdHSU71MAACEHSEI2ByWoUtCw9VHEGRelNBkHaMq_XsCl1TjQ4R'
        b'hitFMAAC-JAhDH7p14xo09rob5cEupmo8jSDi35ZOGt1k4t2nm1C1A68DIAdqJzLWEwQbhXEMOFj'
        b'vFVZ7oMCJP4XXDP_ILaTEBAQDKhYdMBeP6FoH3ajGJTf_4fH229rm_lTZXfYkfwGTMERMAAC-JAh'
        b'EBvDSpcj3y0y9W2-1GzYJ85KEkDIPxu4y_TxAK49k7ciEEb97lh2oOd_yM3meBaRX5xSs8mIeBoP'
        b'dhOTgVkd31jbECQTrhKHgrOXJS4kdvifvOqoJ7RjfJSsN3nshclYStgaMAAD-JALBG9XhvcVryHj'
        b'oIGcj5nK4sAE3oslQHWi4fBJre3NGwTQ-JALBH7p14xo09rob5cEupmo8jSDi35ZOGt1k4t2nm1C'
        b'1A68-JAA-JAA')


    bms = bytearray(ims)  # make copy
    print(f"incoming = \n{ims}\n")
    ams = annot(bms)  # annotated message dream
    assert not bms
    print(f"annotated = \n{ams}\n")
    dms = denot(ams)
    assert dms == ims


    # Delegated Inception
    ims = (b'-FDf0OKERICAACAAXdipEFGt_YP4f5yS3xBGMWxa-GO1QGcmpIvqZykClz03oKaEEFGt_YP4f5yS'
        b'3xBGMWxa-GO1QGcmpIvqZykClz03oKaEMAAA4AADA1s2c1s2c1s2-JAhDIR8GACw4z2GC5_XoReU'
        b'4DMKbqi6-EdbgDZUAobRb8uVDN7WiKyjLLBTK92xayCuddZsBuwPmD2BKrl83h1xEUtiDOE5jmI9'
        b'ktNSAddEke1rH2cGMDq4uYmyagDkAzHl5nfY4AADA1s2c1s2c1s2-JAhEKFoJ9Conb37zSn8zHLK'
        b'P3YwHbeQiD1D9Qx0MagJ44DSEC7sCVf_rYJ_khIj7UdlzrtemP31TuHTPUsGjvWni8GZEHgewy_y'
        b'mPxtSFwuX2KaI_mPmoIUkxClviX3f-M38kCDMAAD-JAhBIR8GACw4z2GC5_XoReU4DMKbqi6-Edb'
        b'gDZUAobRb8uVBN7WiKyjLLBTK92xayCuddZsBuwPmD2BKrl83h1xEUtiBOE5jmI9ktNSAddEke1r'
        b'H2cGMDq4uYmyagDkAzHl5nfY-JAA-JBI-TAuDIR8GACw4z2GC5_XoReU4DMKbqi6-EdbgDZUAobR'
        b'b8uVMAADEKFoJ9Conb37zSn8zHLKP3YwHbeQiD1D9Qx0MagJ44DSDN7WiKyjLLBTK92xayCuddZs'
        b'BuwPmD2BKrl83h1xEUtiMAAEEC7sCVf_rYJ_khIj7UdlzrtemP31TuHTPUsGjvWni8GZ-SAYMAAV'
        b'EHgewy_ymPxtSFwuX2KaI_mPmoIUkxClviX3f-M38kCDMD4SEKFoJ9Conb37zSn8zHLKP3YwHbeQ'
        b'iD1D9Qx0MagJ44DSEOB71mX8FTP7bqJzbODmicKqK491WfIDopCCHjdHSU71')

    bms = bytearray(ims)  # make copy
    print(f"incoming = \n{ims}\n")
    ams = annot(bms)  # annotated message dream
    assert not bms
    print(f"annotated = \n{ams}\n")
    dms = denot(ams)
    assert dms == ims


    # Delegated Rotatation
    ims = (b'-FBb0OKERICAACAAXdrtEOTktOZADw2Ll3zwGdAIfSIByyKOhpET-wQPN6BBozfvEFGt_YP4f5yS'
            b'3xBGMWxa-GO1QGcmpIvqZykClz03oKaEMAABEFGt_YP4f5yS3xBGMWxa-GO1QGcmpIvqZykClz03'
            b'oKaEMAAB-JALDJ0pLe3f2zGus0Va1dqWAnukWdZHGNWlK9NciJop9N4fMAAB-JALENX_LTL97uOS'
            b'OkA1PEzam9vtmCLPprnbcpi71wXpmhFFMAAD-JALBIR8GACw4z2GC5_XoReU4DMKbqi6-EdbgDZU'
            b'AobRb8uV-JALBJ0pLe3f2zGus0Va1dqWAnukWdZHGNWlK9NciJop9N4f-JAA-JAA')


    bms = bytearray(ims)  # make copy
    print(f"incoming = \n{ims}\n")
    ams = annot(bms)  # annotated message dream
    assert not bms
    print(f"annotated = \n{ams}\n")
    dms = denot(ams)
    assert dms == ims

    # JWK  https://connect2id.com/products/nimbus-jose-jwt/examples/jwk-generation#okp
    # ED25519 EDDSA
    djwk = {
            "kty" : "OKP",
            "crv" : "Ed25519",
            "x"   : "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "d"   : "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
            "use" : "sig",
            "kid" : "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ"
          }

    jwk = dumps(djwk, kering.Kinds.json)
    assert jwk == (b'{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHUR'
                   b'o","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","use":"sig","kid":"FdFY'
                   b'FzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ"}')

    assert len(jwk) == 193
    assert 193 - 44 == 149

    # ECDSA Example
    # https://pycose.readthedocs.io/en/latest/pycose/keys/ec2.html

    ckat = {
             'KTY': 'EC2',
             'CURVE': 'P_256',
             'ALG': 'ES256',
             'D': unhexlify(b'57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3')
           }


    ck = (b'\xa6\x01\x02\x03&\x01!X\xba\xc5\xb1\x1c\xad\x8f\x99\xf9\xc7+\x05\xcfK\x9e&\xd2D\xdc\x18\x9ftR(%Z!\x9a\x86\xd6\xa0\x9e\xffX\x13\x8b\xf8-\xc1\xb6\xd5b\xbe\x0f\xa5J\xb7\x80J:d\xb6\xd7,\xcf\xedko\xb6\xed(\xbb\xfc\x11~#XW\xc9 wfAF\xe8vv\x0c\x95\xd0T\xaa\x93\xc3\xaf\xb0N0g\x05\xdb`\x900\x85\x07\xb4\xd3')
    assert len(ck) == 105
    assert 105 - 36 == 69


    # From keri spec examples
    ims = (b'-FCS0OKERICAACAAXicpEDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYsEDZOA3y_b_0L'
                    b'G4_cfpKTbWU-_3eeYNM0w9iTkT7frTYsMAAAMAAC-JAhDBFiIgoCOpJ_zW_OO0GdffhHfEvJWb1H'
                    b'xpDx95bFvufuDG-YwInLUxzVDD5z8SqZmS2FppXSB-ZX_f2bJC_ZnsM5DGIAk2jkC3xuLIe-DI9r'
                    b'cA0naevtZiKuU9wz91L_qBAVMAAC-JAhELeFYMmuJb0hevKjhv97joA5bTfuA8E697cMzi8eoaZB'
                    b'ENY9GYShOjeh7qZUpIipKRHgrWcoR2WkJ7Wgj4wZx1YTEGyJ7y3TlewCW97dgBN-4pckhCqsni-z'
                    b'HNZ_G8zVerPGMAAD-JAsBGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3BBJfueFAYc7N_'
                    b'V-zmDEn2SPCoVFx3H20alWsNZKgsS1vtBAPv2MnoiCsgOnklmFyfU07QDK_93NeH9iKfOy8V22aH'
                    b'BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB-JABXDID-JAA')

    bms = bytearray(ims)
    print(f"KERI spec icp incoming = \n{ims}\n")
    ams = annot(bms)  # annotated message stream see terminal output
    assert not bms
    print(f"annotated = \n{ams}\n")
    dms = denot(ams)
    assert dms == ims

    ann = \
    """
    -FCS # Key Event Counter FixBodyGroup count=146 quadlets
      0OKERICAACAA # 'v' version  Verser Tag10 proto=KERI vrsn=2.00
      Xicp # 't' message type Ilker Tag3 Ilk=icp
      EDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs # 'd' SAID Diger Blake3_256
      EDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs # 'i' AID Prefixer Blake3_256
      MAAA # 's' Number Short sn=0
      MAAC # 'kt' Tholder signing threshold=2
      -JAh # 'k' Signing Key List Counter GenericListGroup count=33 quadlets
        DBFiIgoCOpJ_zW_OO0GdffhHfEvJWb1HxpDx95bFvufu # key Verfer Ed25519
        DG-YwInLUxzVDD5z8SqZmS2FppXSB-ZX_f2bJC_ZnsM5 # key Verfer Ed25519
        DGIAk2jkC3xuLIe-DI9rcA0naevtZiKuU9wz91L_qBAV # key Verfer Ed25519
      MAAC # 'nt' Tholder rotation threshold=2
      -JAh # 'n' Rotation Key Digest List Counter GenericListGroup count=33 quadlets
        ELeFYMmuJb0hevKjhv97joA5bTfuA8E697cMzi8eoaZB # key digest Diger Blake3_256
        ENY9GYShOjeh7qZUpIipKRHgrWcoR2WkJ7Wgj4wZx1YT # key digest Diger Blake3_256
        EGyJ7y3TlewCW97dgBN-4pckhCqsni-zHNZ_G8zVerPG # key digest Diger Blake3_256
      MAAD # 'bt' Tholder Backer (witness) threshold=3
      -JAs # 'b' Backer (witness)List Counter GenericListGroup count=44 quadlets
        BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B # AID Prefixer Ed25519N
        BJfueFAYc7N_V-zmDEn2SPCoVFx3H20alWsNZKgsS1vt # AID Prefixer Ed25519N
        BAPv2MnoiCsgOnklmFyfU07QDK_93NeH9iKfOy8V22aH # AID Prefixer Ed25519N
        BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB # AID Prefixer Ed25519N
      -JAB # 'c' Config Trait List Counter GenericListGroup count=1 quadlets
        XDID # trait Traitor Tag3 trait=DID
      -JAA # 'a' Seal List Counter GenericListGroup count=0 quadlets
      """

    """End Test"""



if __name__ == "__main__":
    test_annot()



