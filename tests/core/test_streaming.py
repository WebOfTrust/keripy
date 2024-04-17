# -*- coding: utf-8 -*-
"""
tests.core.test_streaming module

"""


import pytest


from keri import kering

from keri.help import helping

from keri.core import (Matter, )


from keri.core import streaming
from keri.core.streaming import (annot, denot, Streamer)


def test_streamer():
    """Test streamer instance"""
    pass

    """End Test"""


def test_annot():
    """Test annot function  Annotate"""

    # simple Inception
    ims = bytearray(
        b'-FAtYKERICAAXicpEO6lMLcTbUhdpbQVXCh78MShuT_69th6tiZhEbAfPCj4DG9X'
        b'hvcVryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQMAAAMAAB-LALDG9XhvcVryHj'
        b'oIGcj5nK4sAE3oslQHWi4fBJre3NGwTQMAAA-LAAMAAA-LAA-LAA-LAA')

    print(f"incoming = \n{bytes(ims)}\n")
    ams = annot(ims)  # annotated message dream
    assert not ims
    print(f"annotated = \n{ams}\n")

    # complex inception
    ims = bytearray(
        b'-FDCYKERICAAXicpEMEvSn0o6Iv2-3gInTDMMDTV0qQEfooM-yTzkj6Kynn6EMEv'
        b'Sn0o6Iv2-3gInTDMMDTV0qQEfooM-yTzkj6Kynn6MAAAMAAC-LAhDG9XhvcVryHj'
        b'oIGcj5nK4sAE3oslQHWi4fBJre3NGwTQDK58m521o6nwgcluK8Mu2ULvScXM9kB1'
        b'bSORrxNSS9cnDMOmBoddcrRHShSajb4d60S6RK34gXZ2WYbr3AiPY1M0MAAC-LAh'
        b'EB9O4V-zUteZJJFubu1h0xMtzt0wuGpLMVj1sKVsElA_EMrowWRk6u1imR32ZNHn'
        b'TPUtc7uSAvrchIPN3I8S6vUGEEbufBpvagqe9kijKISOoQPYFEOpy22CZJGJqQZp'
        b'ZEyPMAAD-LAhBG9XhvcVryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQBK58m521'
        b'o6nwgcluK8Mu2ULvScXM9kB1bSORrxNSS9cnBMOmBoddcrRHShSajb4d60S6RK34'
        b'gXZ2WYbr3AiPY1M0-LABXDND-LA8-RAuDG9XhvcVryHjoIGcj5nK4sAE3oslQHWi'
        b'4fBJre3NGwTQMAAAEB9O4V-zUteZJJFubu1h0xMtzt0wuGpLMVj1sKVsElA_DK58'
        b'm521o6nwgcluK8Mu2ULvScXM9kB1bSORrxNSS9cnMAABEMrowWRk6u1imR32ZNHn'
        b'TPUtc7uSAvrchIPN3I8S6vUG-QAMMAAPEEbufBpvagqe9kijKISOoQPYFEOpy22C'
        b'ZJGJqQZpZEyP')

    print(f"incoming = \n{bytes(ims)}\n")
    ams = annot(ims)  # annotated message dream
    assert not ims
    print(f"annotated = \n{ams}\n")


    # interaction
    ims = bytearray(
        b'-FB6YKERICAAXixnEHeLJVa4LLNRRYVkLQsXHIDvllcmhDaahe5a_oMvXKePEMEv'
        b'Sn0o6Iv2-3gInTDMMDTV0qQEfooM-yTzkj6Kynn6MAABEMEvSn0o6Iv2-3gInTDM'
        b'MDTV0qQEfooM-yTzkj6Kynn6-LBU-RAuDG9XhvcVryHjoIGcj5nK4sAE3oslQHWi'
        b'4fBJre3NGwTQMAACEB9O4V-zUteZJJFubu1h0xMtzt0wuGpLMVj1sKVsElA_DK58'
        b'm521o6nwgcluK8Mu2ULvScXM9kB1bSORrxNSS9cnMAAiEMrowWRk6u1imR32ZNHn'
        b'TPUtc7uSAvrchIPN3I8S6vUG-QAMMABDEEbufBpvagqe9kijKISOoQPYFEOpy22C'
        b'ZJGJqQZpZEyP-RAXDMOmBoddcrRHShSajb4d60S6RK34gXZ2WYbr3AiPY1M0MACA'
        b'EB9O4V-zUteZJJFubu1h0xMtzt0wuGpLMVj1sKVsElA_')

    print(f"incoming = \n{bytes(ims)}\n")
    ams = annot(ims)  # annotated message dream
    assert not ims
    print(f"annotated = \n{ams}\n")


    # Rotation
    ims = bytearray(
        b'-FCGYKERICAAXrotEDtBwgOB0uGrSMBJhOmnkRoCupjg-4sJApvOx04ujhKsEMEv'
        b'Sn0o6Iv2-3gInTDMMDTV0qQEfooM-yTzkj6Kynn6MAACEHeLJVa4LLNRRYVkLQsX'
        b'HIDvllcmhDaahe5a_oMvXKePMAAC-LAhDH7p14xo09rob5cEupmo8jSDi35ZOGt1'
        b'k4t2nm1C1A68DIAdqJzLWEwQbhXEMOFjvFVZ7oMCJP4XXDP_ILaTEBAQDKhYdMBe'
        b'P6FoH3ajGJTf_4fH229rm_lTZXfYkfwGTMERMAAC-LAhEBvDSpcj3y0y9W2-1GzY'
        b'J85KEkDIPxu4y_TxAK49k7ciEEb97lh2oOd_yM3meBaRX5xSs8mIeBoPdhOTgVkd'
        b'31jbECQTrhKHgrOXJS4kdvifvOqoJ7RjfJSsN3nshclYStgaMAAD-LALBG9XhvcV'
        b'ryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQ-LALBH7p14xo09rob5cEupmo8jSD'
        b'i35ZOGt1k4t2nm1C1A68-LAA-LAA')

    print(f"incoming = \n{bytes(ims)}\n")
    ams = annot(ims)  # annotated message dream
    assert not ims
    print(f"annotated = \n{ams}\n")

    # Delegated Inception
    ims = bytearray(
        b'-FDeYKERICAAXdipECQs0t3_GL7-B3q4kMU-qLeRCugTFjrxR15mxUwYWp8TECQs'
        b'0t3_GL7-B3q4kMU-qLeRCugTFjrxR15mxUwYWp8TMAAA4AADA1s2c1s2c1s2-LAh'
        b'DIR8GACw4z2GC5_XoReU4DMKbqi6-EdbgDZUAobRb8uVDN7WiKyjLLBTK92xayCu'
        b'ddZsBuwPmD2BKrl83h1xEUtiDOE5jmI9ktNSAddEke1rH2cGMDq4uYmyagDkAzHl'
        b'5nfY4AADA1s2c1s2c1s2-LAhEKFoJ9Conb37zSn8zHLKP3YwHbeQiD1D9Qx0MagJ'
        b'44DSEC7sCVf_rYJ_khIj7UdlzrtemP31TuHTPUsGjvWni8GZEHgewy_ymPxtSFwu'
        b'X2KaI_mPmoIUkxClviX3f-M38kCDMAAD-LAhBIR8GACw4z2GC5_XoReU4DMKbqi6'
        b'-EdbgDZUAobRb8uVBN7WiKyjLLBTK92xayCuddZsBuwPmD2BKrl83h1xEUtiBOE5'
        b'jmI9ktNSAddEke1rH2cGMDq4uYmyagDkAzHl5nfY-LAA-LBI-RAuDIR8GACw4z2G'
        b'C5_XoReU4DMKbqi6-EdbgDZUAobRb8uVMAADEKFoJ9Conb37zSn8zHLKP3YwHbeQ'
        b'iD1D9Qx0MagJ44DSDN7WiKyjLLBTK92xayCuddZsBuwPmD2BKrl83h1xEUtiMAAE'
        b'EC7sCVf_rYJ_khIj7UdlzrtemP31TuHTPUsGjvWni8GZ-QAYMAAVEHgewy_ymPxt'
        b'SFwuX2KaI_mPmoIUkxClviX3f-M38kCDMD4SEKFoJ9Conb37zSn8zHLKP3YwHbeQ'
        b'iD1D9Qx0MagJ44DSEMEvSn0o6Iv2-3gInTDMMDTV0qQEfooM-yTzkj6Kynn6')

    print(f"incoming = \n{bytes(ims)}\n")
    ams = annot(ims)  # annotated message dream
    assert not ims
    print(f"annotated = \n{ams}\n")

    # Delegated Rotatation
    ims = bytearray(
        b'-FBaYKERICAAXdrtEKwDKG0L9pAMbzV2e31-I5ObiEfkptfs8VqXYiHGCL1vECQs'
        b'0t3_GL7-B3q4kMU-qLeRCugTFjrxR15mxUwYWp8TMAABECQs0t3_GL7-B3q4kMU-'
        b'qLeRCugTFjrxR15mxUwYWp8TMAAB-LALDJ0pLe3f2zGus0Va1dqWAnukWdZHGNWl'
        b'K9NciJop9N4fMAAB-LALENX_LTL97uOSOkA1PEzam9vtmCLPprnbcpi71wXpmhFF'
        b'MAAD-LALBIR8GACw4z2GC5_XoReU4DMKbqi6-EdbgDZUAobRb8uV-LALBJ0pLe3f'
        b'2zGus0Va1dqWAnukWdZHGNWlK9NciJop9N4f-LAA-LAA')

    print(f"incoming = \n{bytes(ims)}\n")
    ams = annot(ims)  # annotated message dream
    assert not ims
    print(f"annotated = \n{ams}\n")



    """End Test"""



if __name__ == "__main__":
    test_streamer()
    test_annot()



