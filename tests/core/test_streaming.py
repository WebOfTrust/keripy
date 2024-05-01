# -*- coding: utf-8 -*-
"""
tests.core.test_streaming module

"""
from binascii import unhexlify

import pytest


from keri import kering

from keri.help import helping

from keri.core import (Matter,)
from keri.core.coring import dumps


from keri.core import streaming
from keri.core.streaming import (annot, denot, Streamer)


def test_streamer():
    """Test streamer instance"""
    pass

    """End Test"""


def test_annot():
    """Test annot function  Annotate"""

    # simple Inception
    ims = (b'-FAtYKERICAAXicpEEx4oxGYbNrd6nZsdGu2KdN4MSDGD5IWS7hXjST7r8ewDG9X'
            b'hvcVryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQMAAAMAAB-IALDG9XhvcVryHj'
            b'oIGcj5nK4sAE3oslQHWi4fBJre3NGwTQMAAA-IAAMAAA-IAA-IAA-IAA')

    bms = bytearray(ims)  # make copy
    print(f"incoming = \n{ims}\n")
    ams = annot(bms)  # annotated message dream
    assert not bms
    print(f"annotated = \n{ams}\n")
    dms = denot(ams)
    assert dms == ims

    # complex inception
    ims = (b'-FDCYKERICAAXicpEKIuA20I5q6IrgAHrX-gkAt4Og17Ebu5CDBrRvh8RToiEKIu'
          b'A20I5q6IrgAHrX-gkAt4Og17Ebu5CDBrRvh8RToiMAAAMAAC-IAhDG9XhvcVryHj'
          b'oIGcj5nK4sAE3oslQHWi4fBJre3NGwTQDK58m521o6nwgcluK8Mu2ULvScXM9kB1'
          b'bSORrxNSS9cnDMOmBoddcrRHShSajb4d60S6RK34gXZ2WYbr3AiPY1M0MAAC-IAh'
          b'EB9O4V-zUteZJJFubu1h0xMtzt0wuGpLMVj1sKVsElA_EMrowWRk6u1imR32ZNHn'
          b'TPUtc7uSAvrchIPN3I8S6vUGEEbufBpvagqe9kijKISOoQPYFEOpy22CZJGJqQZp'
          b'ZEyPMAAD-IAhBG9XhvcVryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQBK58m521'
          b'o6nwgcluK8Mu2ULvScXM9kB1bSORrxNSS9cnBMOmBoddcrRHShSajb4d60S6RK34'
          b'gXZ2WYbr3AiPY1M0-IABXDND-IA8-RAuDG9XhvcVryHjoIGcj5nK4sAE3oslQHWi'
          b'4fBJre3NGwTQMAAAEB9O4V-zUteZJJFubu1h0xMtzt0wuGpLMVj1sKVsElA_DK58'
          b'm521o6nwgcluK8Mu2ULvScXM9kB1bSORrxNSS9cnMAABEMrowWRk6u1imR32ZNHn'
          b'TPUtc7uSAvrchIPN3I8S6vUG-QAMMAAPEEbufBpvagqe9kijKISOoQPYFEOpy22C'
          b'ZJGJqQZpZEyP')


    bms = bytearray(ims)  # make copy
    print(f"incoming = \n{ims}\n")
    ams = annot(bms)  # annotated message dream
    assert not bms
    print(f"annotated = \n{ams}\n")
    dms = denot(ams)
    assert dms == ims


    # interaction
    ims = (b'-FB6YKERICAAXixnEHXLwMJsZLyG643VW8Do1cqqiMxD_E65Mc3Z1we6vTaREKIu'
          b'A20I5q6IrgAHrX-gkAt4Og17Ebu5CDBrRvh8RToiMAABEKIuA20I5q6IrgAHrX-g'
          b'kAt4Og17Ebu5CDBrRvh8RToi-IBU-RAuDG9XhvcVryHjoIGcj5nK4sAE3oslQHWi'
          b'4fBJre3NGwTQMAACEB9O4V-zUteZJJFubu1h0xMtzt0wuGpLMVj1sKVsElA_DK58'
          b'm521o6nwgcluK8Mu2ULvScXM9kB1bSORrxNSS9cnMAAiEMrowWRk6u1imR32ZNHn'
          b'TPUtc7uSAvrchIPN3I8S6vUG-QAMMABDEEbufBpvagqe9kijKISOoQPYFEOpy22C'
          b'ZJGJqQZpZEyP-RAXDMOmBoddcrRHShSajb4d60S6RK34gXZ2WYbr3AiPY1M0MACA'
          b'EB9O4V-zUteZJJFubu1h0xMtzt0wuGpLMVj1sKVsElA_')


    bms = bytearray(ims)  # make copy
    print(f"incoming = \n{ims}\n")
    ams = annot(bms)  # annotated message dream
    assert not bms
    print(f"annotated = \n{ams}\n")
    dms = denot(ams)
    assert dms == ims


    # Rotation
    ims = (b'-FCGYKERICAAXrotEDHlTlOcSXZInbTE4iXzb1iFjZcxJZn3C3UXhckb3uQmEKIu'
          b'A20I5q6IrgAHrX-gkAt4Og17Ebu5CDBrRvh8RToiMAACEHXLwMJsZLyG643VW8Do'
          b'1cqqiMxD_E65Mc3Z1we6vTaRMAAC-IAhDH7p14xo09rob5cEupmo8jSDi35ZOGt1'
          b'k4t2nm1C1A68DIAdqJzLWEwQbhXEMOFjvFVZ7oMCJP4XXDP_ILaTEBAQDKhYdMBe'
          b'P6FoH3ajGJTf_4fH229rm_lTZXfYkfwGTMERMAAC-IAhEBvDSpcj3y0y9W2-1GzY'
          b'J85KEkDIPxu4y_TxAK49k7ciEEb97lh2oOd_yM3meBaRX5xSs8mIeBoPdhOTgVkd'
          b'31jbECQTrhKHgrOXJS4kdvifvOqoJ7RjfJSsN3nshclYStgaMAAD-IALBG9XhvcV'
          b'ryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQ-IALBH7p14xo09rob5cEupmo8jSD'
          b'i35ZOGt1k4t2nm1C1A68-IAA-IAA')


    bms = bytearray(ims)  # make copy
    print(f"incoming = \n{ims}\n")
    ams = annot(bms)  # annotated message dream
    assert not bms
    print(f"annotated = \n{ams}\n")
    dms = denot(ams)
    assert dms == ims


    # Delegated Inception
    ims = (b'-FDeYKERICAAXdipEKCFMk4nmn3t8jdC1pB_-Qmp7w8EROvdYaxgru7vHOjCEKCF'
          b'Mk4nmn3t8jdC1pB_-Qmp7w8EROvdYaxgru7vHOjCMAAA4AADA1s2c1s2c1s2-IAh'
          b'DIR8GACw4z2GC5_XoReU4DMKbqi6-EdbgDZUAobRb8uVDN7WiKyjLLBTK92xayCu'
          b'ddZsBuwPmD2BKrl83h1xEUtiDOE5jmI9ktNSAddEke1rH2cGMDq4uYmyagDkAzHl'
          b'5nfY4AADA1s2c1s2c1s2-IAhEKFoJ9Conb37zSn8zHLKP3YwHbeQiD1D9Qx0MagJ'
          b'44DSEC7sCVf_rYJ_khIj7UdlzrtemP31TuHTPUsGjvWni8GZEHgewy_ymPxtSFwu'
          b'X2KaI_mPmoIUkxClviX3f-M38kCDMAAD-IAhBIR8GACw4z2GC5_XoReU4DMKbqi6'
          b'-EdbgDZUAobRb8uVBN7WiKyjLLBTK92xayCuddZsBuwPmD2BKrl83h1xEUtiBOE5'
          b'jmI9ktNSAddEke1rH2cGMDq4uYmyagDkAzHl5nfY-IAA-IBI-RAuDIR8GACw4z2G'
          b'C5_XoReU4DMKbqi6-EdbgDZUAobRb8uVMAADEKFoJ9Conb37zSn8zHLKP3YwHbeQ'
          b'iD1D9Qx0MagJ44DSDN7WiKyjLLBTK92xayCuddZsBuwPmD2BKrl83h1xEUtiMAAE'
          b'EC7sCVf_rYJ_khIj7UdlzrtemP31TuHTPUsGjvWni8GZ-QAYMAAVEHgewy_ymPxt'
          b'SFwuX2KaI_mPmoIUkxClviX3f-M38kCDMD4SEKFoJ9Conb37zSn8zHLKP3YwHbeQ'
          b'iD1D9Qx0MagJ44DSEKIuA20I5q6IrgAHrX-gkAt4Og17Ebu5CDBrRvh8RToi')

    bms = bytearray(ims)  # make copy
    print(f"incoming = \n{ims}\n")
    ams = annot(bms)  # annotated message dream
    assert not bms
    print(f"annotated = \n{ams}\n")
    dms = denot(ams)
    assert dms == ims


    # Delegated Rotatation
    ims = (b'-FBaYKERICAAXdrtEKfRY6YrpqUU0HyKWMGvNtzuZCaeMcIBrdKzHAqpmtTAEKCF'
          b'Mk4nmn3t8jdC1pB_-Qmp7w8EROvdYaxgru7vHOjCMAABEKCFMk4nmn3t8jdC1pB_'
          b'-Qmp7w8EROvdYaxgru7vHOjCMAAB-IALDJ0pLe3f2zGus0Va1dqWAnukWdZHGNWl'
          b'K9NciJop9N4fMAAB-IALENX_LTL97uOSOkA1PEzam9vtmCLPprnbcpi71wXpmhFF'
          b'MAAD-IALBIR8GACw4z2GC5_XoReU4DMKbqi6-EdbgDZUAobRb8uV-IALBJ0pLe3f'
          b'2zGus0Va1dqWAnukWdZHGNWlK9NciJop9N4f-IAA-IAA')


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

    jwk = dumps(djwk, kering.Serials.json)
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




    """End Test"""



if __name__ == "__main__":
    test_streamer()
    test_annot()



