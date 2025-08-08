# -*- coding: utf-8 -*-
"""
tests.spec.cesr.test_cesr_example module

"""
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64

import pytest

from ordered_set import OrderedSet as oset

from keri import Vrsn_2_0, Kinds, Protocols, Ilks, TraitDex
from keri.core import (MtrDex, Salter, Signer, Diger, Noncer, Number, Structor,
                       SealEvent, SealSource, Counter, Codens, Seqner)
from keri.core import (incept, interact, rotate, delcept, deltate, receipt,
                       query, reply, prod, bare, exchept, exchange)

def test_cesr_examples():
    """ Working examples for CESR specification """

    # Trans Indexed Sig Group
    # Ean inception taken from keri examples
    raw = (b'{"v":"KERICAACAAJSONAAKp.","t":"icp","d":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXj'
                        b'BUcMVtvhmB","i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","s":"0","kt":'
                        b'"2","k":["DBFiIgoCOpJ_zW_OO0GdffhHfEvJWb1HxpDx95bFvufu","DG-YwInLUxzVDD5z8Sq'
                        b'ZmS2FppXSB-ZX_f2bJC_ZnsM5","DGIAk2jkC3xuLIe-DI9rcA0naevtZiKuU9wz91L_qBAV"],"'
                        b'nt":"2","n":["ELeFYMmuJb0hevKjhv97joA5bTfuA8E697cMzi8eoaZB","ENY9GYShOjeh7qZ'
                        b'UpIipKRHgrWcoR2WkJ7Wgj4wZx1YT","EGyJ7y3TlewCW97dgBN-4pckhCqsni-zHNZ_G8zVerPG'
                        b'"],"bt":"3","b":["BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B","BJfueFAYc7N'
                        b'_V-zmDEn2SPCoVFx3H20alWsNZKgsS1vt","BAPv2MnoiCsgOnklmFyfU07QDK_93NeH9iKfOy8V'
                        b'22aH","BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB"],"c":["DID"],"a":[]}')

    pre = 'EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB'
    said = 'EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB'
    snh = '0'

    salt = b'kerispecworkexam'  # for example
    salter = Salter(raw=salt)
    assert salter.qb64 == '0ABrZXJpc3BlY3dvcmtleGFt'  # CESR encoded for example

    # create set of signers each with private signing key and trans public
    # verification key
    signers = salter.signers(count=3, transferable=True, temp=True)

    msgs = bytearray()
    buf = bytearray()
    sigs = bytearray()

    buf.extend(pre.encode())
    buf.extend(Seqner(snh=snh).qb64b)
    buf.extend(said.encode())

    for i, signer in enumerate(signers):
        siger = signer.sign(raw, index=i)  # return siger
        sigs.extend(siger.qb64b)

    buf.extend(Counter.enclose(qb64=sigs, code=Codens.ControllerIdxSigs))
    msgs.extend(Counter.enclose(qb64=buf, code=Codens.TransIdxSigGroups))

    assert msgs == bytearray(b'-XBfEPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB0AAAAAAAAAAAAAAA'
          b'AAAAAAAAEPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB-KBCAADQ-rNV'
          b'53XEXW1mI24X6uK3LlSMxqQxzM3HuWv_rbEkGP8kVjEYjzrBg8o5hRCxXPnoO2zp'
          b'Hmh52OdUdog7xb0BABCD_iSjAJvu9JsXHBAnCCTGCA-YSTKiRG-y6gUV42tzkL11'
          b'OSEqRztXZOq4yCBHcf4WTPT8fsMoaJGbW1a5JFkPACBcPS0C_QwGdJUZTKXvC_qC'
          b's6069pqV8rdQymrJTdcmJAEYJDJXuHUc6sjgdb0_VlPYIPtVZ9ypbRhkkuXJOykL')

    # Said computation


    """Done Test"""

if __name__ == "__main__":
    test_cesr_examples()

