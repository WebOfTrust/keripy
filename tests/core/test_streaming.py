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
    ims = bytearray(
        b'-FAtYKERICAAXicpEO6lMLcTbUhdpbQVXCh78MShuT_69th6tiZhEbAfPCj4DG9X'
        b'hvcVryHjoIGcj5nK4sAE3oslQHWi4fBJre3NGwTQMAAAMAAB-LALDG9XhvcVryHj'
        b'oIGcj5nK4sAE3oslQHWi4fBJre3NGwTQMAAA-LAAMAAA-LAA-LAA-LAA')

    print(f"incoming = \n{ims}\n")
    ams = annot(ims)  # annotated message dream
    assert not ims
    print(f"annotated = \n{ams}\n")

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

    print(f"incoming = \n{ims}\n")
    ams = annot(ims)  # annotated message dream
    assert not ims
    print(f"annotated = \n{ams}\n")



    """End Test"""



if __name__ == "__main__":
    test_streamer()
    test_annot()



