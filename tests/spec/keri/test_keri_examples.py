# -*- coding: utf-8 -*-
"""
tests.spec.keri.test_keri_examples module

"""
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64

import pytest

from ordered_set import OrderedSet as oset

from keri import Vrsn_2_0, Kinds, Protocols, Ilks, TraitDex
from keri.core import (MtrDex, Salter, Signer, Diger, Noncer, Number, Structor,
                       SealEvent, SealSource)
from keri.core import (incept, interact, rotate, delcept, deltate, receipt,
                       query, reply, prod, bare, exchept, exchange)


def test_keri_examples_json():
    """Working examples for KERI Specification """
    # Create incepting key states
    # use same salter for all but different path
    # salt = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    salt = b'kerispecworkexam'  # for example
    salter = Salter(raw=salt)
    assert salter.qb64 == '0ABrZXJpc3BlY3dvcmtleGFt'  # CESR encoded for example

    # create set of signers each with private signing key and trans public
    # verification key
    signers = salter.signers(count=18, transferable=True, temp=True)

    # create witness signers as nontransferable
    walt = b'kerispecworkwits'
    walter = Salter(raw=walt)
    assert walter.qb64 == '0ABrZXJpc3BlY3dvcmt3aXRz'  # CESR encoded for example

    # creat set of witness signers each with private signing key and nontrans
    # public verificaiton key
    wigners = walter.signers(count=16, transferable=False, temp=True)


    # from ACDC examples
    bobaid = "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf"   # bob's AID
    bobreg = "ECOWJI9kAjpCFYJ7RenpJx2w66-GsGlhyKLO-Or3qOIQ"  # bob's acdc registry
    bobacdc = 'EMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M'  # bob's project report ACDC
    bobbup = "EBdytzDC4dnatn-6mrCWLSGuM62LM0BgS31YnAg5NTeW" # issued blindable update said
    bobblid = "EOtWw6X_aoOJlkzNaLj23IC6MXHl7ZSYSWVulFW_Hr_t"  # issued blid said
    bobbupsn = '2' # sn of issuing bup

    debaid = "EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW"   # deb's AID
    debreg = "EJl5EUxL23p_pqgN3IyM-pzru89Nb7NzOM8ijH644xSU"  # deb's Registry
    debacdc = 'EAU5dUws4ffM9jZjWs0QfXTnhJ1qk2u3IUhBwFVbFnt5'  # deb's research report ACDC
    debupd = "EJFxtbr9WioIkzTfVX4iC6Axxyg8jjKSX0ZrJgoNHiB-"  # deb's update said
    debupdsn = '1' # sn of issuing upd


    # UUIDs
    raws = [b'kerispecworkraw' + b'%0x'%(i, ) for i in range(16)]
    uuids = [Noncer(raw=raw).qb64 for raw in raws]
    assert uuids == \
    [
        '0ABrZXJpc3BlY3dvcmtyYXcw',
        '0ABrZXJpc3BlY3dvcmtyYXcx',
        '0ABrZXJpc3BlY3dvcmtyYXcy',
        '0ABrZXJpc3BlY3dvcmtyYXcz',
        '0ABrZXJpc3BlY3dvcmtyYXc0',
        '0ABrZXJpc3BlY3dvcmtyYXc1',
        '0ABrZXJpc3BlY3dvcmtyYXc2',
        '0ABrZXJpc3BlY3dvcmtyYXc3',
        '0ABrZXJpc3BlY3dvcmtyYXc4',
        '0ABrZXJpc3BlY3dvcmtyYXc5',
        '0ABrZXJpc3BlY3dvcmtyYXdh',
        '0ABrZXJpc3BlY3dvcmtyYXdi',
        '0ABrZXJpc3BlY3dvcmtyYXdj',
        '0ABrZXJpc3BlY3dvcmtyYXdk',
        '0ABrZXJpc3BlY3dvcmtyYXdl',
        '0ABrZXJpc3BlY3dvcmtyYXdm'
    ]


    # multi-sig inception for Ean

    keys = [signer.verfer.qb64 for signer in signers][:3]
    assert keys == \
    [
        'DBFiIgoCOpJ_zW_OO0GdffhHfEvJWb1HxpDx95bFvufu',
        'DG-YwInLUxzVDD5z8SqZmS2FppXSB-ZX_f2bJC_ZnsM5',
        'DGIAk2jkC3xuLIe-DI9rcA0naevtZiKuU9wz91L_qBAV'
    ]
    nkeys = [signer.verfer.qb64 for signer in signers][3:6]
    assert nkeys == \
    [
        "DLv9BlDvjcZWkfPfWcYhNK-xQxz89h82_wA184Vxk8dj",
        "DCx3WypeBym3fCkVizTg18qEThSrVnB63dFq2oX5c3mz",
        "DO0PG_ww4PbF2jUIxQnlb4DluJu5ndNehp0BTGWXErXf"
    ]
    nxts = [Diger(ser=key.encode()).qb64 for key in nkeys]
    assert nxts == \
    [
        'ELeFYMmuJb0hevKjhv97joA5bTfuA8E697cMzi8eoaZB',
        'ENY9GYShOjeh7qZUpIipKRHgrWcoR2WkJ7Wgj4wZx1YT',
        'EGyJ7y3TlewCW97dgBN-4pckhCqsni-zHNZ_G8zVerPG'
    ]
    wits = [wigner.verfer.qb64 for wigner in wigners][:4]
    assert wits == \
    [
        'BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B',
        'BJfueFAYc7N_V-zmDEn2SPCoVFx3H20alWsNZKgsS1vt',
        'BAPv2MnoiCsgOnklmFyfU07QDK_93NeH9iKfOy8V22aH',
        'BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB'
    ]
    eanwits = wits

    cnfg = [TraitDex.DelegateIsDelegator]
    data = []
    code = MtrDex.Blake3_256
    kind = Kinds.json

    serder = incept(keys,
                    ndigs=nxts,
                    wits=wits,
                    cnfg=cnfg,
                    data=data,
                    code=code,
                    pvrsn=Vrsn_2_0,
                    gvrsn=Vrsn_2_0,
                    kind=kind)

    assert serder.pre == serder.said
    eanaid = serder.pre
    assert eanaid == 'EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB'
    eanprior = serder.said
    eansn = serder.sn
    assert eansn == 0
    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAKp.",
        "t": "icp",
        "d": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
        "i": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
        "s": "0",
        "kt": "2",
        "k":
        [
            "DBFiIgoCOpJ_zW_OO0GdffhHfEvJWb1HxpDx95bFvufu",
            "DG-YwInLUxzVDD5z8SqZmS2FppXSB-ZX_f2bJC_ZnsM5",
            "DGIAk2jkC3xuLIe-DI9rcA0naevtZiKuU9wz91L_qBAV"
        ],
        "nt": "2",
        "n":
        [
            "ELeFYMmuJb0hevKjhv97joA5bTfuA8E697cMzi8eoaZB",
            "ENY9GYShOjeh7qZUpIipKRHgrWcoR2WkJ7Wgj4wZx1YT",
            "EGyJ7y3TlewCW97dgBN-4pckhCqsni-zHNZ_G8zVerPG"
        ],
        "bt": "3",
        "b":
        [
            "BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B",
            "BJfueFAYc7N_V-zmDEn2SPCoVFx3H20alWsNZKgsS1vt",
            "BAPv2MnoiCsgOnklmFyfU07QDK_93NeH9iKfOy8V22aH",
            "BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB"
        ],
        "c": ["DID"],
        "a": []
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAKp.","t":"icp","d":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXj'
                        b'BUcMVtvhmB","i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","s":"0","kt":'
                        b'"2","k":["DBFiIgoCOpJ_zW_OO0GdffhHfEvJWb1HxpDx95bFvufu","DG-YwInLUxzVDD5z8Sq'
                        b'ZmS2FppXSB-ZX_f2bJC_ZnsM5","DGIAk2jkC3xuLIe-DI9rcA0naevtZiKuU9wz91L_qBAV"],"'
                        b'nt":"2","n":["ELeFYMmuJb0hevKjhv97joA5bTfuA8E697cMzi8eoaZB","ENY9GYShOjeh7qZ'
                        b'UpIipKRHgrWcoR2WkJ7Wgj4wZx1YT","EGyJ7y3TlewCW97dgBN-4pckhCqsni-zHNZ_G8zVerPG'
                        b'"],"bt":"3","b":["BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B","BJfueFAYc7N'
                        b'_V-zmDEn2SPCoVFx3H20alWsNZKgsS1vt","BAPv2MnoiCsgOnklmFyfU07QDK_93NeH9iKfOy8V'
                        b'22aH","BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB"],"c":["DID"],"a":[]}')


    # Delegatee Fay
    keys = [signer.verfer.qb64 for signer in signers][9:12]
    assert keys == \
    [
        'DEE-HCMSwqMDkEBzlmUNmVBAGIinGu7wZ5_hfY6bSMz3',
        'DHyJFyFzuD5vvUWv5jy6nwWI3wZmSnoePu29tBR-jXkv',
        'DN3JXVEvIjTbisPC4maYQWy6eQIRNdJsxqGFXYUm_ygr'
    ]
    isith = ["1/2", "1/2", "1/2"]
    nkeys = [signer.verfer.qb64 for signer in signers][12:15]
    assert nkeys == \
    [
        "DB1S8zOh4_qdFhxVHn7BDZb1ErWbBFvcVJX1suKSBctR",
        "DDCDFlbG4dCAX6oIbNffB1mkZqLAS_eHnYUUIPH7BeXB",
        "DP3GAMcSx7eCApzk1N7DceV42o1dZemAe0s3r_-Z0zs1"
    ]
    nxts = [Diger(ser=key.encode()).qb64 for key in nkeys]
    assert nxts == \
    [
        'EFzr1nnfHpT-nkSfd6vQvbPC-Kq6zy8vbVvUmwxcM1e-',
        'EIXFsLk9kmESy0ZsoHMUaDyK_g3DVRiJQYiAlyeCeYJM',
        'EGVvq4Njkki3EZv838rJrYShBtwXY9o8RUrG2w3nbujn'
    ]
    nsith = ["1/2", "1/2", "1/2"]
    wits = [wigner.verfer.qb64 for wigner in wigners][8:12]
    assert wits == \
    [
        'BFATArhqG_ktVCRLWt2Knbc7JDpaPAFJ4npNEmIW_gPX',
        'BOtF-I9geAUjX9NW1kLIq5qDRNgEXCuwpE4mKHkYuWsF',
        'BEzZUvashpXh_nfPoR6aiqvag0a8E_tbhpeJIgHhOXzl',
        'BCE6biH4a-Zg8LI3cMSx7JRoOvb8rRD62xbyl9N4M2g6'
    ]
    faywits = wits

    cnfg = []
    data = []
    delpre = eanaid  # delegator is Ean
    code = MtrDex.Blake3_256
    kind = Kinds.json

    serder = delcept(keys,
                    isith=isith,
                    ndigs=nxts,
                    nsith=nsith,
                    wits=wits,
                    cnfg=cnfg,
                    data=data,
                    delpre=delpre,
                    code=code,
                    pvrsn=Vrsn_2_0,
                    gvrsn=Vrsn_2_0,
                    kind=kind)
    assert serder.pre == serder.said
    fayaid = serder.pre
    assert fayaid == 'EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur'
    fayprior = serder.said
    faysn = serder.sn
    assert faysn == 0
    assert serder.delpre == eanaid
    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAL4.",
        "t": "dip",
        "d": "EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur",
        "i": "EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur",
        "s": "0",
        "kt": ["1/2", "1/2", "1/2"],
        'k':
        [
            'DEE-HCMSwqMDkEBzlmUNmVBAGIinGu7wZ5_hfY6bSMz3',
            'DHyJFyFzuD5vvUWv5jy6nwWI3wZmSnoePu29tBR-jXkv',
            'DN3JXVEvIjTbisPC4maYQWy6eQIRNdJsxqGFXYUm_ygr'
        ],
        "nt": ["1/2", "1/2", "1/2"],
        "n":
        [
            "EFzr1nnfHpT-nkSfd6vQvbPC-Kq6zy8vbVvUmwxcM1e-",
            "EIXFsLk9kmESy0ZsoHMUaDyK_g3DVRiJQYiAlyeCeYJM",
            "EGVvq4Njkki3EZv838rJrYShBtwXY9o8RUrG2w3nbujn"
        ],
        "bt": "3",
        "b":
        [
            "BFATArhqG_ktVCRLWt2Knbc7JDpaPAFJ4npNEmIW_gPX",
            "BOtF-I9geAUjX9NW1kLIq5qDRNgEXCuwpE4mKHkYuWsF",
            "BEzZUvashpXh_nfPoR6aiqvag0a8E_tbhpeJIgHhOXzl",
            "BCE6biH4a-Zg8LI3cMSx7JRoOvb8rRD62xbyl9N4M2g6"
        ],
        "c": [],
        "a": [],
        "di": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB"
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAL4.","t":"dip","d":"EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2'
                        b'GRc2SG3aur","i":"EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur","s":"0","kt":'
                        b'["1/2","1/2","1/2"],"k":["DEE-HCMSwqMDkEBzlmUNmVBAGIinGu7wZ5_hfY6bSMz3","DHy'
                        b'JFyFzuD5vvUWv5jy6nwWI3wZmSnoePu29tBR-jXkv","DN3JXVEvIjTbisPC4maYQWy6eQIRNdJs'
                        b'xqGFXYUm_ygr"],"nt":["1/2","1/2","1/2"],"n":["EFzr1nnfHpT-nkSfd6vQvbPC-Kq6zy'
                        b'8vbVvUmwxcM1e-","EIXFsLk9kmESy0ZsoHMUaDyK_g3DVRiJQYiAlyeCeYJM","EGVvq4Njkki3'
                        b'EZv838rJrYShBtwXY9o8RUrG2w3nbujn"],"bt":"3","b":["BFATArhqG_ktVCRLWt2Knbc7JD'
                        b'paPAFJ4npNEmIW_gPX","BOtF-I9geAUjX9NW1kLIq5qDRNgEXCuwpE4mKHkYuWsF","BEzZUvas'
                        b'hpXh_nfPoR6aiqvag0a8E_tbhpeJIgHhOXzl","BCE6biH4a-Zg8LI3cMSx7JRoOvb8rRD62xbyl'
                        b'9N4M2g6"],"c":[],"a":[],"di":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB"}')

    # Ean interaction event with delegation seal to delegatee Fay's delcept
    pre = eanaid
    prior = eanprior
    sn = eansn + 1
    sealtuple = SealEvent(i=fayaid,
                     s=Number(num=faysn).numh,
                     d=fayaid)
    eseal = sealtuple._asdict()
    assert eseal == \
    {
        'i': 'EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur',
        's': '0',
        'd': 'EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur'
    }
    data = [eseal]
    kind = Kinds.json

    serder = interact(pre=pre,
                      dig=prior,
                      sn=sn,
                      data=data,
                      pvrsn=Vrsn_2_0,
                      gvrsn=Vrsn_2_0,
                      kind=kind)

    eanprior = serder.said
    assert eanprior == 'EDeCPBTHAt75Acgi9PfEciHFnc1r2DKAno3s9_QIYrXk'
    eansn = serder.sn
    assert eansn == 1
    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAE8.",
        "t": "ixn",
        "d": "EDeCPBTHAt75Acgi9PfEciHFnc1r2DKAno3s9_QIYrXk",
        "i": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
        "s": "1",
        "p": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
        "a":
        [
            {
                "i": "EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur",
                "s": "0",
                "d": "EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur"
            }
        ]
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAE8.","t":"ixn","d":"EDeCPBTHAt75Acgi9PfEciHFnc1r2DKAno'
                            b'3s9_QIYrXk","i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","s":"1","p":"'
                            b'EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","a":[{"i":"EHqSsH1Imc2MEcgzEor'
                            b'dBUFqJKWTcRyTz2GRc2SG3aur","s":"0","d":"EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GR'
                            b'c2SG3aur"}]}')

    # Fay Rotation Event
    pre = fayaid
    keys = [signer.verfer.qb64 for signer in signers][12:15]
    assert keys == \
    [
        'DB1S8zOh4_qdFhxVHn7BDZb1ErWbBFvcVJX1suKSBctR',
        'DDCDFlbG4dCAX6oIbNffB1mkZqLAS_eHnYUUIPH7BeXB',
        'DP3GAMcSx7eCApzk1N7DceV42o1dZemAe0s3r_-Z0zs1'
    ]
    isith = ["1/2", "1/2", "1/2"]
    nkeys = [signer.verfer.qb64 for signer in signers][15:18]
    assert nkeys == \
    [
        "DCcN7BGPo6c47EWOTvcIUCpzvetDN5E-7EPMprN6tqVI",
        "DAaAPS7IpPe9nPrgF6eGkA9hIphUIeZE0zLkGHCS1BBD",
        "DONoZ4RumKezgod8xoAtRQvmhPRe4LZm8QP-BVEN-MW_"
    ]
    nxts = [Diger(ser=key.encode()).qb64 for key in nkeys]
    assert nxts == \
    [
        'EKUlc5Ml4HLSvdk39k_vh0m6rc061mfM1a4qoEuiBwXW',
        'EJdqHiijmjII-ZtlhFAM5D7myuNeESQkzHoqeWJMMHzW',
        'EDyk8pj0YPHjGNfrG2qZI866WwevwlHEbWYMsKGTGqj2'
    ]
    nsith = ["1/2", "1/2", "1/2"]
    cuts = [wigner.verfer.qb64 for wigner in wigners][9:10]
    assert cuts == \
    ['BOtF-I9geAUjX9NW1kLIq5qDRNgEXCuwpE4mKHkYuWsF']
    assert cuts[0] in faywits
    adds = [wigner.verfer.qb64 for wigner in wigners][12:13]
    assert adds == \
    ['BOMrYd5izsqbqaq1WZYa3nbEeTYLPwccfqfhirybKKqx']
    assert adds[0] not in faywits

    prior = fayprior
    sn = faysn + 1
    cnfg = []
    data = []
    code = MtrDex.Blake3_256
    kind = Kinds.json

    serder = deltate(pre=pre,
                    keys=keys,
                    isith=isith,
                    dig=prior,
                    sn=sn,
                    ndigs=nxts,
                    nsith=nsith,
                    wits=faywits, #prior
                    cuts=cuts,
                    adds=adds,
                    cnfg=cnfg,
                    data=data,
                    pvrsn=Vrsn_2_0,
                    gvrsn=Vrsn_2_0,
                    kind=kind)

    fayprior = serder.said
    assert fayprior == 'ENl9GdcDY-4hlg5GtVwOg2E9X7JHw-7Dr5Zq5KNirISF'
    faysn = serder.sn
    assert faysn == 1
    # set math for new faywits
    faywitset = oset(faywits) - oset(cuts) | oset(adds)
    faywits = list(faywitset)
    assert faywits == \
    [
        'BFATArhqG_ktVCRLWt2Knbc7JDpaPAFJ4npNEmIW_gPX',
        'BEzZUvashpXh_nfPoR6aiqvag0a8E_tbhpeJIgHhOXzl',
        'BCE6biH4a-Zg8LI3cMSx7JRoOvb8rRD62xbyl9N4M2g6',
        'BOMrYd5izsqbqaq1WZYa3nbEeTYLPwccfqfhirybKKqx'
    ]

    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAKh.",
        "t": "drt",
        "d": "ENl9GdcDY-4hlg5GtVwOg2E9X7JHw-7Dr5Zq5KNirISF",
        "i": "EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur",
        "s": "1",
        "p": "EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur",
        "kt": ["1/2", "1/2", "1/2"],
        "k":
        [
            "DB1S8zOh4_qdFhxVHn7BDZb1ErWbBFvcVJX1suKSBctR",
            "DDCDFlbG4dCAX6oIbNffB1mkZqLAS_eHnYUUIPH7BeXB",
            "DP3GAMcSx7eCApzk1N7DceV42o1dZemAe0s3r_-Z0zs1"
        ],
        "nt": ["1/2", "1/2", "1/2"],
        "n":
        [
            "EKUlc5Ml4HLSvdk39k_vh0m6rc061mfM1a4qoEuiBwXW",
            "EJdqHiijmjII-ZtlhFAM5D7myuNeESQkzHoqeWJMMHzW",
            "EDyk8pj0YPHjGNfrG2qZI866WwevwlHEbWYMsKGTGqj2"
        ],
        "bt": "3",
        "br": ["BOtF-I9geAUjX9NW1kLIq5qDRNgEXCuwpE4mKHkYuWsF"],
        "ba": ["BOMrYd5izsqbqaq1WZYa3nbEeTYLPwccfqfhirybKKqx"],
        "c": [],
        "a": []
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAKh.","t":"drt","d":"ENl9GdcDY-4hlg5GtVwOg2E9X7JHw-7Dr5'
                            b'Zq5KNirISF","i":"EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur","s":"1","p":"'
                            b'EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur","kt":["1/2","1/2","1/2"],"k":['
                            b'"DB1S8zOh4_qdFhxVHn7BDZb1ErWbBFvcVJX1suKSBctR","DDCDFlbG4dCAX6oIbNffB1mkZqLA'
                            b'S_eHnYUUIPH7BeXB","DP3GAMcSx7eCApzk1N7DceV42o1dZemAe0s3r_-Z0zs1"],"nt":["1/2'
                            b'","1/2","1/2"],"n":["EKUlc5Ml4HLSvdk39k_vh0m6rc061mfM1a4qoEuiBwXW","EJdqHiij'
                            b'mjII-ZtlhFAM5D7myuNeESQkzHoqeWJMMHzW","EDyk8pj0YPHjGNfrG2qZI866WwevwlHEbWYMs'
                            b'KGTGqj2"],"bt":"3","br":["BOtF-I9geAUjX9NW1kLIq5qDRNgEXCuwpE4mKHkYuWsF"],"ba'
                            b'":["BOMrYd5izsqbqaq1WZYa3nbEeTYLPwccfqfhirybKKqx"],"c":[],"a":[]}')


    # Ean rotate with seal to Fay rotate
    pre = eanaid
    keys = [signer.verfer.qb64 for signer in signers][3:6]
    assert keys == \
    [
        'DLv9BlDvjcZWkfPfWcYhNK-xQxz89h82_wA184Vxk8dj',
        'DCx3WypeBym3fCkVizTg18qEThSrVnB63dFq2oX5c3mz',
        'DO0PG_ww4PbF2jUIxQnlb4DluJu5ndNehp0BTGWXErXf'
    ]
    nkeys = [signer.verfer.qb64 for signer in signers][6:9]
    assert nkeys == \
    [
        "DHODGNuxeW2JTKn3S7keooAjVw582puHoK_zDflPflZg",
        "DImP4vghHKJIgzBxt1HrTLrNLOMy07_gFV0_IekdzAQh",
        "DNlPrQ9T7G71BDgRSpB0coMFANpw_QPVEUosPep1JC79"
    ]
    nxts = [Diger(ser=key.encode()).qb64 for key in nkeys]
    assert nxts == \
    [
        'EA8_fj-Ezin_Us_gUcg5JQJkIIBnrcZt3HEIuH-E1lpe',
        'EERS8udHp2FW89nmaHweQWnZz7I8v9FTQdA-LZ_amqGh',
        'EAEzmrPusrj4CDKnSFQvhCEW6T95C7hBeFtZtRD7rOTg'
    ]
    cuts = [wigner.verfer.qb64 for wigner in wigners][3:4]
    assert cuts == \
    ['BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB']
    assert cuts[0] in eanwits
    adds = [wigner.verfer.qb64 for wigner in wigners][4:6]
    assert adds == \
    [
        'BO3cCAfQiqndZBBxwNk6RGkyA-OA1XbZhBj3s4-VIsCo',
        'BPowpltoeF14nMbU1ng89JSoYf3AmWhZ50KaCaVO6SIW'
    ]
    assert adds[0] not in eanwits
    assert adds[1] not in eanwits

    prior = eanprior
    sn = eansn + 1
    cnfg = []
    sealtuple = SealEvent(i=fayaid,
                          s=Number(num=faysn).numh,
                          d=fayprior)
    eseal = sealtuple._asdict()
    assert eseal == \
    {
        'i': 'EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur',
        's': '1',
        'd': 'ENl9GdcDY-4hlg5GtVwOg2E9X7JHw-7Dr5Zq5KNirISF'
    }
    data = [eseal]
    code = MtrDex.Blake3_256
    kind = Kinds.json

    serder = rotate(pre=pre,
                    keys=keys,
                    dig=prior,
                    sn=sn,
                    ndigs=nxts,
                    wits=eanwits, #prior
                    cuts=cuts,
                    cnfg=cnfg,
                    adds=adds,
                    data=data,
                    pvrsn=Vrsn_2_0,
                    gvrsn=Vrsn_2_0,
                    kind=kind)

    eanprior = serder.said
    assert eanprior == 'EJOnAKXGaSyJ_43kit0V806NNeGWS07lfjybB1UcfWsv'
    eansn = serder.sn
    assert eansn == 2
    # set math for new eanwits
    eanwitset = oset(eanwits) - oset(cuts) | oset(adds)
    eanwits = list(eanwitset)
    assert eanwits == \
    [
        'BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B',
        'BJfueFAYc7N_V-zmDEn2SPCoVFx3H20alWsNZKgsS1vt',
        'BAPv2MnoiCsgOnklmFyfU07QDK_93NeH9iKfOy8V22aH',
        'BO3cCAfQiqndZBBxwNk6RGkyA-OA1XbZhBj3s4-VIsCo',
        'BPowpltoeF14nMbU1ng89JSoYf3AmWhZ50KaCaVO6SIW'
    ]
    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAMf.",
        "t": "rot",
        "d": "EJOnAKXGaSyJ_43kit0V806NNeGWS07lfjybB1UcfWsv",
        "i": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
        "s": "2",
        "p": "EDeCPBTHAt75Acgi9PfEciHFnc1r2DKAno3s9_QIYrXk",
        "kt": "2",
        "k":
        [
            "DLv9BlDvjcZWkfPfWcYhNK-xQxz89h82_wA184Vxk8dj",
            "DCx3WypeBym3fCkVizTg18qEThSrVnB63dFq2oX5c3mz",
            "DO0PG_ww4PbF2jUIxQnlb4DluJu5ndNehp0BTGWXErXf"
        ],
        "nt": "2",
        "n":
        [
            "EA8_fj-Ezin_Us_gUcg5JQJkIIBnrcZt3HEIuH-E1lpe",
            "EERS8udHp2FW89nmaHweQWnZz7I8v9FTQdA-LZ_amqGh",
            "EAEzmrPusrj4CDKnSFQvhCEW6T95C7hBeFtZtRD7rOTg"
        ],
        "bt": "4",
        "br":
        [
            "BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB"
        ],
        "ba":
        [
            "BO3cCAfQiqndZBBxwNk6RGkyA-OA1XbZhBj3s4-VIsCo",
            "BPowpltoeF14nMbU1ng89JSoYf3AmWhZ50KaCaVO6SIW"
        ],
        "c": [],
        "a":
        [
            {
                "i": "EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur",
                "s": "1",
                "d": "ENl9GdcDY-4hlg5GtVwOg2E9X7JHw-7Dr5Zq5KNirISF"
            }
        ]
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAMf.","t":"rot","d":"EJOnAKXGaSyJ_43kit0V806NNeGWS07lfj'
                        b'ybB1UcfWsv","i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","s":"2","p":"'
                        b'EDeCPBTHAt75Acgi9PfEciHFnc1r2DKAno3s9_QIYrXk","kt":"2","k":["DLv9BlDvjcZWkfP'
                        b'fWcYhNK-xQxz89h82_wA184Vxk8dj","DCx3WypeBym3fCkVizTg18qEThSrVnB63dFq2oX5c3mz'
                        b'","DO0PG_ww4PbF2jUIxQnlb4DluJu5ndNehp0BTGWXErXf"],"nt":"2","n":["EA8_fj-Ezin'
                        b'_Us_gUcg5JQJkIIBnrcZt3HEIuH-E1lpe","EERS8udHp2FW89nmaHweQWnZz7I8v9FTQdA-LZ_a'
                        b'mqGh","EAEzmrPusrj4CDKnSFQvhCEW6T95C7hBeFtZtRD7rOTg"],"bt":"4","br":["BA4PSa'
                        b'tfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB"],"ba":["BO3cCAfQiqndZBBxwNk6RGkyA-OA'
                        b'1XbZhBj3s4-VIsCo","BPowpltoeF14nMbU1ng89JSoYf3AmWhZ50KaCaVO6SIW"],"c":[],"a"'
                        b':[{"i":"EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur","s":"1","d":"ENl9GdcDY'
                        b'-4hlg5GtVwOg2E9X7JHw-7Dr5Zq5KNirISF"}]}')

    # Test receipt
    rctpre = eanaid
    rctsaid = eanprior
    rctsn = eansn
    serder = receipt(pre=rctpre,
                      sn=rctsn,
                      said=rctsaid,
                      pvrsn=Vrsn_2_0,
                      gvrsn=Vrsn_2_0,
                      kind=kind)

    assert serder.said == rctsaid  # note said of receipt is not computed but refernced
    assert serder.pre == rctpre
    assert serder.sn == rctsn

    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAACT.",
        "t": "rct",
        "d": "EJOnAKXGaSyJ_43kit0V806NNeGWS07lfjybB1UcfWsv",
        "i": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
        "s": "2"
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAACT.","t":"rct","d":"EJOnAKXGaSyJ_43kit0V806NNeGWS07lfj'
                          b'ybB1UcfWsv","i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","s":"2"}')


    # Routed Messages
    # Query Message Body
    # Test query
    pre = fayaid
    route = "/oobi"
    replyRoute = "/oobi/process"
    q = dict(i=eanaid, role="witness")
    dts = '2025-08-21T17:50:00.000000+00:00'

    serder = query(pre=pre,
                   route=route,
                   replyRoute=replyRoute,
                   query=q,
                   stamp=dts,
                   pvrsn=Vrsn_2_0,
                   gvrsn=Vrsn_2_0,
                   kind=kind)

    said = serder.said
    assert said == 'EEiUK4cVgcyA1Dk6g2jFzqc5JerkaSnJi3IosutVCyYO'

    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAEe.",
        "t": "qry",
        "d": "EEiUK4cVgcyA1Dk6g2jFzqc5JerkaSnJi3IosutVCyYO",
        "i": "EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur",
        "dt": "2025-08-21T17:50:00.000000+00:00",
        "r": "/oobi",
        "rr": "/oobi/process",
        "q":
        {
            "i": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
            "role": "witness"
        }
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAEe.","t":"qry","d":"EEiUK4cVgcyA1Dk6g2jFzqc5JerkaSnJi3'
                        b'IosutVCyYO","i":"EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur","dt":"2025-08'
                        b'-21T17:50:00.000000+00:00","r":"/oobi","rr":"/oobi/process","q":{"i":"EPR7FW'
                        b'sN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","role":"witness"}}')

    # Reply states
    pre = eanaid
    raid = eanaid
    route = '/oobi/process'
    url = "https://example.com/witness/BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B"
    data = dict(i=raid, url=url)
    dts = '2020-08-21T17:52:00.000000+00:00'

    serder = reply(pre=pre,
                   route=route,
                    data=data,
                    stamp=dts,
                    pvrsn=Vrsn_2_0,
                    gvrsn=Vrsn_2_0,
                    kind=kind)

    said = serder.said
    assert said == 'EPdgmUkvx5o_KRg3elBqj_vSZOFgWI9hCVWO-FfGZz8U'

    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAFR.",
        "t": "rpy",
        "d": "EPdgmUkvx5o_KRg3elBqj_vSZOFgWI9hCVWO-FfGZz8U",
        "i": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
        "dt": "2020-08-21T17:52:00.000000+00:00",
        "r": "/oobi/process",
        "a":
        {
            "i": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
            "url": "https://example.com/witness/BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B"
        }
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAFR.","t":"rpy","d":"EPdgmUkvx5o_KRg3elBqj_vSZOFgWI9hCV'
                        b'WO-FfGZz8U","i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","dt":"2020-08'
                        b'-21T17:52:00.000000+00:00","r":"/oobi/process","a":{"i":"EPR7FWsN3tOM8PqfMap'
                        b'2FRfF4MFQ4v3ZXjBUcMVtvhmB","url":"https://example.com/witness/BGKV6v93ue5L5w'
                        b'sgk75t6j8TcdgABMN9x-eIyPi96J3B"}}')

    # Test prod
    pre = fayaid
    route = "/confidential"
    replyRoute = "/confidential/process"
    q = dict(i=eanaid, name=True)
    dts = '2025-08-21T17:50:00.000000+00:00'

    serder = prod(pre=pre,
                   route=route,
                   replyRoute=replyRoute,
                   query=q,
                   stamp=dts,
                   pvrsn=Vrsn_2_0,
                   gvrsn=Vrsn_2_0,
                   kind=kind)

    said = serder.said
    assert said == 'EHNqhJXgUdYHFzNiuO7Ue06QWRnOMjhTrVt_QGOfZjH_'

    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAEp.",
        "t": "pro",
        "d": "EHNqhJXgUdYHFzNiuO7Ue06QWRnOMjhTrVt_QGOfZjH_",
        "i": "EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur",
        "dt": "2025-08-21T17:50:00.000000+00:00",
        "r": "/confidential",
        "rr": "/confidential/process",
        "q":
        {
            "i": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
            "name": True
        }
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAEp.","t":"pro","d":"EHNqhJXgUdYHFzNiuO7Ue06QWRnOMjhTrV'
                        b't_QGOfZjH_","i":"EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur","dt":"2025-08'
                        b'-21T17:50:00.000000+00:00","r":"/confidential","rr":"/confidential/process",'
                        b'"q":{"i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","name":true}}')


    # Test bare
    pre = eanaid
    raid = eanaid
    route = "/confidential/process"
    data = dict(i=raid, name="Ean")
    dts = '2020-08-22T17:52:00.000000+00:00'

    serder = bare(pre=pre,
                   route=route,
                    data=data,
                    stamp=dts,
                    pvrsn=Vrsn_2_0,
                    gvrsn=Vrsn_2_0,
                    kind=kind)

    said = serder.said
    assert said == 'EMSlSHIe04CuAqhz55nAnBpE_0T65Sqs2fmaPpsNIbnn'

    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAEV.",
        "t": "bar",
        "d": "EMSlSHIe04CuAqhz55nAnBpE_0T65Sqs2fmaPpsNIbnn",
        "i": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
        "dt": "2020-08-22T17:52:00.000000+00:00",
        "r": "/confidential/process",
        "a":
        {
            "i": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
            "name": "Ean"
        }
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAEV.","t":"bar","d":"EMSlSHIe04CuAqhz55nAnBpE_0T65Sqs2f'
                        b'maPpsNIbnn","i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","dt":"2020-08'
                        b'-22T17:52:00.000000+00:00","r":"/confidential/process","a":{"i":"EPR7FWsN3tO'
                        b'M8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","name":"Ean"}}')

    # Test exchange
    # Test exchept xip from eventing
    sender = fayaid
    receiver = eanaid
    route = "/offer"
    modifiers = dict(timing="immediate")
    attributes = dict(action="sell", item="Rembrant", price=300000.00)
    nonce = uuids[0]
    dts = '2020-08-30T13:30:10.123456+00:00'

    serder = exchept(sender=sender,
                     receiver=receiver,
                     route=route,
                     modifiers=modifiers,
                     attributes=attributes,
                     nonce=nonce,
                     stamp=dts,
                     pvrsn=Vrsn_2_0,
                     gvrsn=Vrsn_2_0,
                     kind=kind)

    said = serder.said
    assert said == 'EJbE2agA3239Iusld1lNvFAxRuhv1SX0mAxxUm67gWOU'
    xid = said  # exchange ID
    prior = said

    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAFn.",
        "t": "xip",
        "d": "EJbE2agA3239Iusld1lNvFAxRuhv1SX0mAxxUm67gWOU",
        "u": "0ABrZXJpc3BlY3dvcmtyYXcw",
        "i": "EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur",
        "ri": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
        "dt": "2020-08-30T13:30:10.123456+00:00",
        "r": "/offer",
        "q":
        {
            "timing": "immediate"
        },
        "a":
        {
            "action": "sell",
            "item": "Rembrant",
            "price": 300000.0
        }
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAFn.","t":"xip","d":"EJbE2agA3239Iusld1lNvFAxRuhv1SX0mA'
                        b'xxUm67gWOU","u":"0ABrZXJpc3BlY3dvcmtyYXcw","i":"EHqSsH1Imc2MEcgzEordBUFqJKWT'
                        b'cRyTz2GRc2SG3aur","ri":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","dt":"'
                        b'2020-08-30T13:30:10.123456+00:00","r":"/offer","q":{"timing":"immediate"},"a'
                        b'":{"action":"sell","item":"Rembrant","price":300000.0}}')


    # Test exchange exn from eventing
    sender = eanaid
    receiver =  fayaid
    route = "/agree"
    modifiers = dict(timing="immediate")
    attributes = dict(action="buy", item="Rembrant", price=300000.0)
    dts = '2020-08-30T13:42:11.123456+00:00'

    serder = exchange(sender=sender,
                      receiver=receiver,
                     xid=xid,
                     prior=prior,
                     route=route,
                     modifiers=modifiers,
                     attributes=attributes,
                     stamp=dts,
                     pvrsn=Vrsn_2_0,
                     gvrsn=Vrsn_2_0,
                     kind=kind)

    said = serder.said
    assert said == 'EEIp1e5v4L6rt7cp1nRsn4mN6bJVUDyIQEATIzxR8UnE'

    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAGt.",
        "t": "exn",
        "d": "EEIp1e5v4L6rt7cp1nRsn4mN6bJVUDyIQEATIzxR8UnE",
        "i": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
        "ri": "EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur",
        "x": "EJbE2agA3239Iusld1lNvFAxRuhv1SX0mAxxUm67gWOU",
        "p": "EJbE2agA3239Iusld1lNvFAxRuhv1SX0mAxxUm67gWOU",
        "dt": "2020-08-30T13:42:11.123456+00:00",
        "r": "/agree",
        "q":
        {
            "timing": "immediate"
        },
        "a":
        {
            "action": "buy",
            "item": "Rembrant",
            "price": 300000.0
        }
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAGt.","t":"exn","d":"EEIp1e5v4L6rt7cp1nRsn4mN6bJVUDyIQE'
                    b'ATIzxR8UnE","i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","ri":"EHqSsH1'
                    b'Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur","x":"EJbE2agA3239Iusld1lNvFAxRuhv1SX0'
                    b'mAxxUm67gWOU","p":"EJbE2agA3239Iusld1lNvFAxRuhv1SX0mAxxUm67gWOU","dt":"2020-'
                    b'08-30T13:42:11.123456+00:00","r":"/agree","q":{"timing":"immediate"},"a":{"a'
                    b'ction":"buy","item":"Rembrant","price":300000.0}}')

    # OOBI section Reply examples
    # MOOBI
    wilma = "BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B"
    watson = "BAPv2MnoiCsgOnklmFyfU07QDK_93NeH9iKfOy8V22aH"
    winona = "BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB"
    pre = eanaid
    route = '/oobi/witness'
    url0 = "https://example.com/witness/wilma/" + wilma
    url1 = "https://example.com/witness/watson/" + watson
    url2 = "https://example.com/witness/winona/" + winona
    dts = '2020-08-21T17:52:00.000000+00:00'
    data = dict(cid=eanaid, urls=[url0, url1, url2])

    serder = reply(pre=pre,
                   route=route,
                    data=data,
                    stamp=dts,
                    pvrsn=Vrsn_2_0,
                    gvrsn=Vrsn_2_0,
                    kind=kind)

    said = serder.said
    assert said == 'ELtIQ71PMr9m5a8eYiC39hikuU8yTWoFw1vWjtqbVUX4'

    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAIA.",
        "t": "rpy",
        "d": "ELtIQ71PMr9m5a8eYiC39hikuU8yTWoFw1vWjtqbVUX4",
        "i": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
        "dt": "2020-08-21T17:52:00.000000+00:00",
        "r": "/oobi/witness",
        "a":
        {
            "cid": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
            "urls":
            [
                "https://example.com/witness/wilma/BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B",
                "https://example.com/witness/watson/BAPv2MnoiCsgOnklmFyfU07QDK_93NeH9iKfOy8V22aH",
                "https://example.com/witness/winona/BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB"
            ]
        }
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAIA.","t":"rpy","d":"ELtIQ71PMr9m5a8eYiC39hikuU8yTWoFw1'
                    b'vWjtqbVUX4","i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","dt":"2020-08'
                    b'-21T17:52:00.000000+00:00","r":"/oobi/witness","a":{"cid":"EPR7FWsN3tOM8PqfM'
                    b'ap2FRfF4MFQ4v3ZXjBUcMVtvhmB","urls":["https://example.com/witness/wilma/BGKV'
                    b'6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B","https://example.com/witness/watso'
                    b'n/BAPv2MnoiCsgOnklmFyfU07QDK_93NeH9iKfOy8V22aH","https://example.com/witness'
                    b'/winona/BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB"]}}')

    # service endpoint OOBI example
    pre = eanaid
    route = '/oobi/' + eanaid + '/witness'
    eid = wilma
    scheme = 'https'
    url = "https://example.com/witness/wilma"

    dts = '2020-08-21T17:52:00.000000+00:00'
    data = dict(eid=eid, scheme=scheme, url=url)

    serder = reply(pre=pre,
                   route=route,
                    data=data,
                    stamp=dts,
                    pvrsn=Vrsn_2_0,
                    gvrsn=Vrsn_2_0,
                    kind=kind)

    said = serder.said
    assert said == 'EFMQh0w5-AHw-H01DtqEFhAIC6KXbjYvUSOEX6kSPY4j'

    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAFq.",
        "t": "rpy",
        "d": "EFMQh0w5-AHw-H01DtqEFhAIC6KXbjYvUSOEX6kSPY4j",
        "i": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
        "dt": "2020-08-21T17:52:00.000000+00:00",
        "r": "/oobi/EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB/witness",
        "a":
        {
            "eid": "BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B",
            "scheme": "https",
            "url": "https://example.com/witness/wilma"
        }
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAFq.","t":"rpy","d":"EFMQh0w5-AHw-H01DtqEFhAIC6KXbjYvUS'
                        b'OEX6kSPY4j","i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","dt":"2020-08'
                        b'-21T17:52:00.000000+00:00","r":"/oobi/EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcM'
                        b'VtvhmB/witness","a":{"eid":"BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B","s'
                        b'cheme":"https","url":"https://example.com/witness/wilma"}}')


    # BADA Run Examples
    pre = eanaid
    route = '/end/role/add'
    cid = eanaid
    role = 'witness'
    eid = wilma
    scheme = 'https'

    dts = '2020-08-21T17:52:00.000000+00:00'
    data = dict(cid=cid, role=role, eid=eid)

    serder = reply(pre=pre,
                   route=route,
                    data=data,
                    stamp=dts,
                    pvrsn=Vrsn_2_0,
                    gvrsn=Vrsn_2_0,
                    kind=kind)

    said = serder.said
    assert said == 'EBcL5FQ2cHPcLmGb7AKk-ORtq0_A-m-mQTygGxTrqTBb'

    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAFI.",
        "t": "rpy",
        "d": "EBcL5FQ2cHPcLmGb7AKk-ORtq0_A-m-mQTygGxTrqTBb",
        "i": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
        "dt": "2020-08-21T17:52:00.000000+00:00",
        "r": "/end/role/add",
        "a":
        {
            "cid": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
            "role": "witness",
            "eid": "BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B"
        }
    }


    assert serder.raw == (b'{"v":"KERICAACAAJSONAAFI.","t":"rpy","d":"EBcL5FQ2cHPcLmGb7AKk-ORtq0_A-m-mQT'
                    b'ygGxTrqTBb","i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","dt":"2020-08'
                    b'-21T17:52:00.000000+00:00","r":"/end/role/add","a":{"cid":"EPR7FWsN3tOM8PqfM'
                    b'ap2FRfF4MFQ4v3ZXjBUcMVtvhmB","role":"witness","eid":"BGKV6v93ue5L5wsgk75t6j8'
                    b'TcdgABMN9x-eIyPi96J3B"}}')

    pre = eanaid
    route = '/end/role/cut'
    cid = eanaid
    role = 'witness'
    eid = wilma
    scheme = 'https'

    dts = '2020-08-21T17:52:10.000000+00:00'
    data = dict(cid=cid, role=role, eid=eid)

    serder = reply(pre=pre,
                   route=route,
                    data=data,
                    stamp=dts,
                    pvrsn=Vrsn_2_0,
                    gvrsn=Vrsn_2_0,
                    kind=kind)

    said = serder.said
    assert said == 'EH4uEDQHtCxoJ-RXbvmIjl-NE3JoPJ26fN7sZm9dsqPv'
    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAFI.",
        "t": "rpy",
        "d": "EH4uEDQHtCxoJ-RXbvmIjl-NE3JoPJ26fN7sZm9dsqPv",
        "i": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
        "dt": "2020-08-21T17:52:10.000000+00:00",
        "r": "/end/role/cut",
        "a":
        {
            "cid": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
            "role": "witness",
            "eid": "BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B"
        }
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAFI.","t":"rpy","d":"EH4uEDQHtCxoJ-RXbvmIjl-NE3JoPJ26fN'
                        b'7sZm9dsqPv","i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","dt":"2020-08'
                        b'-21T17:52:10.000000+00:00","r":"/end/role/cut","a":{"cid":"EPR7FWsN3tOM8PqfM'
                        b'ap2FRfF4MFQ4v3ZXjBUcMVtvhmB","role":"witness","eid":"BGKV6v93ue5L5wsgk75t6j8'
                        b'TcdgABMN9x-eIyPi96J3B"}}')

    pre = eanaid
    route = '/loc/scheme'
    eid = wilma
    scheme = 'https'
    url = "https//example.com/witness/wilma"

    dts = '2020-08-21T17:52:11.000000+00:00'
    data = dict(eid=eid, scheme=scheme, url=url)

    serder = reply(pre=pre,
                   route=route,
                    data=data,
                    stamp=dts,
                    pvrsn=Vrsn_2_0,
                    gvrsn=Vrsn_2_0,
                    kind=kind)

    said = serder.said
    assert said == 'ELH2kZK9QXgV9utSqRE-jf2Xwk4rgca6xk35Mpo4EeZP'
    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAE6.",
        "t": "rpy",
        "d": "ELH2kZK9QXgV9utSqRE-jf2Xwk4rgca6xk35Mpo4EeZP",
        "i": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
        "dt": "2020-08-21T17:52:11.000000+00:00",
        "r": "/loc/scheme",
        "a":
        {
            "eid": "BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B",
            "scheme": "https",
            "url": "https//example.com/witness/wilma"
        }
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAE6.","t":"rpy","d":"ELH2kZK9QXgV9utSqRE-jf2Xwk4rgca6xk'
                    b'35Mpo4EeZP","i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","dt":"2020-08'
                    b'-21T17:52:11.000000+00:00","r":"/loc/scheme","a":{"eid":"BGKV6v93ue5L5wsgk75'
                    b't6j8TcdgABMN9x-eIyPi96J3B","scheme":"https","url":"https//example.com/witnes'
                    b's/wilma"}}')

    pre = eanaid
    route = '/loc/scheme'
    eid = wilma
    scheme = 'https'
    url = ""

    dts = '2020-08-21T17:52:12.000000+00:00'
    data = dict(eid=eid, scheme=scheme, url=url)

    serder = reply(pre=pre,
                   route=route,
                    data=data,
                    stamp=dts,
                    pvrsn=Vrsn_2_0,
                    gvrsn=Vrsn_2_0,
                    kind=kind)

    said = serder.said
    assert said == 'EGWrf4ve6Nlec3iC7ba0-f6YBIHXKRzrGG-bWE-gcHY_'
    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAEa.",
        "t": "rpy",
        "d": "EGWrf4ve6Nlec3iC7ba0-f6YBIHXKRzrGG-bWE-gcHY_",
        "i": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
        "dt": "2020-08-21T17:52:12.000000+00:00",
        "r": "/loc/scheme",
        "a":
        {
            "eid": "BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B",
            "scheme": "https",
            "url": ""
        }
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAEa.","t":"rpy","d":"EGWrf4ve6Nlec3iC7ba0-f6YBIHXKRzrGG'
                        b'-bWE-gcHY_","i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","dt":"2020-08'
                        b'-21T17:52:12.000000+00:00","r":"/loc/scheme","a":{"eid":"BGKV6v93ue5L5wsgk75'
                        b't6j8TcdgABMN9x-eIyPi96J3B","scheme":"https","url":""}}')



    """Done Test"""


def test_keri_examples_cesr():
    """Working examples for KERI Specification CESR serialization"""
    # Create incepting key states
    # use same salter for all but different path
    # salt = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    salt = b'kerispecworkexam'  # for example
    salter = Salter(raw=salt)
    assert salter.qb64 == '0ABrZXJpc3BlY3dvcmtleGFt'  # CESR encoded for example

    # create set of signers each with private signing key and trans public
    # verification key
    signers = salter.signers(count=18, transferable=True, temp=True)

    # create witness signers as nontransferable
    walt = b'kerispecworkwits'
    walter = Salter(raw=walt)
    assert walter.qb64 == '0ABrZXJpc3BlY3dvcmt3aXRz'  # CESR encoded for example

    # creat set of witness signers each with private signing key and nontrans
    # public verificaiton key
    wigners = walter.signers(count=16, transferable=False, temp=True)


    # from ACDC examples
    bobaid = "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf"   # bob's AID
    bobreg = "ECOWJI9kAjpCFYJ7RenpJx2w66-GsGlhyKLO-Or3qOIQ"  # bob's acdc registry
    bobacdc = 'EMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M'  # bob's project report ACDC
    bobbup = "EBdytzDC4dnatn-6mrCWLSGuM62LM0BgS31YnAg5NTeW" # issued blindable update said
    bobblid = "EOtWw6X_aoOJlkzNaLj23IC6MXHl7ZSYSWVulFW_Hr_t"  # issued blid said
    bobbupsn = '2' # sn of issuing bup

    debaid = "EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW"   # deb's AID
    debreg = "EJl5EUxL23p_pqgN3IyM-pzru89Nb7NzOM8ijH644xSU"  # deb's Registry
    debacdc = 'EAU5dUws4ffM9jZjWs0QfXTnhJ1qk2u3IUhBwFVbFnt5'  # deb's research report ACDC
    debupd = "EJFxtbr9WioIkzTfVX4iC6Axxyg8jjKSX0ZrJgoNHiB-"  # deb's update said
    debupdsn = '1' # sn of issuing upd


    # UUIDs
    raws = [b'kerispecworkraw' + b'%0x'%(i, ) for i in range(16)]
    uuids = [Noncer(raw=raw).qb64 for raw in raws]
    assert uuids == \
    [
        '0ABrZXJpc3BlY3dvcmtyYXcw',
        '0ABrZXJpc3BlY3dvcmtyYXcx',
        '0ABrZXJpc3BlY3dvcmtyYXcy',
        '0ABrZXJpc3BlY3dvcmtyYXcz',
        '0ABrZXJpc3BlY3dvcmtyYXc0',
        '0ABrZXJpc3BlY3dvcmtyYXc1',
        '0ABrZXJpc3BlY3dvcmtyYXc2',
        '0ABrZXJpc3BlY3dvcmtyYXc3',
        '0ABrZXJpc3BlY3dvcmtyYXc4',
        '0ABrZXJpc3BlY3dvcmtyYXc5',
        '0ABrZXJpc3BlY3dvcmtyYXdh',
        '0ABrZXJpc3BlY3dvcmtyYXdi',
        '0ABrZXJpc3BlY3dvcmtyYXdj',
        '0ABrZXJpc3BlY3dvcmtyYXdk',
        '0ABrZXJpc3BlY3dvcmtyYXdl',
        '0ABrZXJpc3BlY3dvcmtyYXdm'
    ]


    # multi-sig inception for Ean

    keys = [signer.verfer.qb64 for signer in signers][:3]
    assert keys == \
    [
        'DBFiIgoCOpJ_zW_OO0GdffhHfEvJWb1HxpDx95bFvufu',
        'DG-YwInLUxzVDD5z8SqZmS2FppXSB-ZX_f2bJC_ZnsM5',
        'DGIAk2jkC3xuLIe-DI9rcA0naevtZiKuU9wz91L_qBAV'
    ]
    nkeys = [signer.verfer.qb64 for signer in signers][3:6]
    assert nkeys == \
    [
        "DLv9BlDvjcZWkfPfWcYhNK-xQxz89h82_wA184Vxk8dj",
        "DCx3WypeBym3fCkVizTg18qEThSrVnB63dFq2oX5c3mz",
        "DO0PG_ww4PbF2jUIxQnlb4DluJu5ndNehp0BTGWXErXf"
    ]
    nxts = [Diger(ser=key.encode()).qb64 for key in nkeys]
    assert nxts == \
    [
        'ELeFYMmuJb0hevKjhv97joA5bTfuA8E697cMzi8eoaZB',
        'ENY9GYShOjeh7qZUpIipKRHgrWcoR2WkJ7Wgj4wZx1YT',
        'EGyJ7y3TlewCW97dgBN-4pckhCqsni-zHNZ_G8zVerPG'
    ]
    wits = [wigner.verfer.qb64 for wigner in wigners][:4]
    assert wits == \
    [
        'BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B',
        'BJfueFAYc7N_V-zmDEn2SPCoVFx3H20alWsNZKgsS1vt',
        'BAPv2MnoiCsgOnklmFyfU07QDK_93NeH9iKfOy8V22aH',
        'BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB'
    ]
    eanwits = wits

    cnfg = [TraitDex.DelegateIsDelegator]
    data = []
    code = MtrDex.Blake3_256
    kind = Kinds.cesr

    serder = incept(keys,
                    ndigs=nxts,
                    wits=wits,
                    cnfg=cnfg,
                    data=data,
                    code=code,
                    pvrsn=Vrsn_2_0,
                    gvrsn=Vrsn_2_0,
                    kind=kind)

    assert serder.pre == serder.said
    eanaid = serder.pre
    assert eanaid == 'EDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs'
    eanprior = serder.said
    eansn = serder.sn
    assert eansn == 0
    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAAJM.',
        't': 'icp',
        'd': 'EDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs',
        'i': 'EDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs',
        's': '0',
        'kt': '2',
        'k':
        [
            'DBFiIgoCOpJ_zW_OO0GdffhHfEvJWb1HxpDx95bFvufu',
            'DG-YwInLUxzVDD5z8SqZmS2FppXSB-ZX_f2bJC_ZnsM5',
            'DGIAk2jkC3xuLIe-DI9rcA0naevtZiKuU9wz91L_qBAV'
        ],
        'nt': '2',
        'n':
        [
            'ELeFYMmuJb0hevKjhv97joA5bTfuA8E697cMzi8eoaZB',
            'ENY9GYShOjeh7qZUpIipKRHgrWcoR2WkJ7Wgj4wZx1YT',
            'EGyJ7y3TlewCW97dgBN-4pckhCqsni-zHNZ_G8zVerPG'
        ],
        'bt': '3',
        'b':
        [
            'BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B',
            'BJfueFAYc7N_V-zmDEn2SPCoVFx3H20alWsNZKgsS1vt',
            'BAPv2MnoiCsgOnklmFyfU07QDK_93NeH9iKfOy8V22aH',
            'BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB'
        ],
        'c': ['DID'],
        'a': []
    }


    assert serder.raw == (b'-FCS0OKERICAACAAXicpEDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYsEDZOA3y_b_0L'
                        b'G4_cfpKTbWU-_3eeYNM0w9iTkT7frTYsMAAAMAAC-JAhDBFiIgoCOpJ_zW_OO0GdffhHfEvJWb1H'
                        b'xpDx95bFvufuDG-YwInLUxzVDD5z8SqZmS2FppXSB-ZX_f2bJC_ZnsM5DGIAk2jkC3xuLIe-DI9r'
                        b'cA0naevtZiKuU9wz91L_qBAVMAAC-JAhELeFYMmuJb0hevKjhv97joA5bTfuA8E697cMzi8eoaZB'
                        b'ENY9GYShOjeh7qZUpIipKRHgrWcoR2WkJ7Wgj4wZx1YTEGyJ7y3TlewCW97dgBN-4pckhCqsni-z'
                        b'HNZ_G8zVerPGMAAD-JAsBGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3BBJfueFAYc7N_'
                        b'V-zmDEn2SPCoVFx3H20alWsNZKgsS1vtBAPv2MnoiCsgOnklmFyfU07QDK_93NeH9iKfOy8V22aH'
                        b'BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB-JABXDID-JAA')


    # Delegatee Fay
    keys = [signer.verfer.qb64 for signer in signers][9:12]
    assert keys == \
    [
        'DEE-HCMSwqMDkEBzlmUNmVBAGIinGu7wZ5_hfY6bSMz3',
        'DHyJFyFzuD5vvUWv5jy6nwWI3wZmSnoePu29tBR-jXkv',
        'DN3JXVEvIjTbisPC4maYQWy6eQIRNdJsxqGFXYUm_ygr'
    ]
    isith = ["1/2", "1/2", "1/2"]
    nkeys = [signer.verfer.qb64 for signer in signers][12:15]
    assert nkeys == \
    [
        "DB1S8zOh4_qdFhxVHn7BDZb1ErWbBFvcVJX1suKSBctR",
        "DDCDFlbG4dCAX6oIbNffB1mkZqLAS_eHnYUUIPH7BeXB",
        "DP3GAMcSx7eCApzk1N7DceV42o1dZemAe0s3r_-Z0zs1"
    ]
    nxts = [Diger(ser=key.encode()).qb64 for key in nkeys]
    assert nxts == \
    [
        'EFzr1nnfHpT-nkSfd6vQvbPC-Kq6zy8vbVvUmwxcM1e-',
        'EIXFsLk9kmESy0ZsoHMUaDyK_g3DVRiJQYiAlyeCeYJM',
        'EGVvq4Njkki3EZv838rJrYShBtwXY9o8RUrG2w3nbujn'
    ]
    nsith = ["1/2", "1/2", "1/2"]
    wits = [wigner.verfer.qb64 for wigner in wigners][8:12]
    assert wits == \
    [
        'BFATArhqG_ktVCRLWt2Knbc7JDpaPAFJ4npNEmIW_gPX',
        'BOtF-I9geAUjX9NW1kLIq5qDRNgEXCuwpE4mKHkYuWsF',
        'BEzZUvashpXh_nfPoR6aiqvag0a8E_tbhpeJIgHhOXzl',
        'BCE6biH4a-Zg8LI3cMSx7JRoOvb8rRD62xbyl9N4M2g6'
    ]
    faywits = wits

    cnfg = []
    data = []
    delpre = eanaid  # delegator is Ean
    code = MtrDex.Blake3_256
    kind = Kinds.cesr

    serder = delcept(keys,
                    isith=isith,
                    ndigs=nxts,
                    nsith=nsith,
                    wits=wits,
                    cnfg=cnfg,
                    data=data,
                    delpre=delpre,
                    code=code,
                    pvrsn=Vrsn_2_0,
                    gvrsn=Vrsn_2_0,
                    kind=kind)
    assert serder.pre == serder.said
    fayaid = serder.pre
    assert fayaid == 'EF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3'
    fayprior = serder.said
    faysn = serder.sn
    assert faysn == 0
    assert serder.delpre == eanaid
    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAAKM.',
        't': 'dip',
        'd': 'EF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3',
        'i': 'EF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3',
        's': '0',
        'kt': ['1/2', '1/2', '1/2'],
        'k':
        [
            'DEE-HCMSwqMDkEBzlmUNmVBAGIinGu7wZ5_hfY6bSMz3',
            'DHyJFyFzuD5vvUWv5jy6nwWI3wZmSnoePu29tBR-jXkv',
            'DN3JXVEvIjTbisPC4maYQWy6eQIRNdJsxqGFXYUm_ygr'
        ],
        'nt': ['1/2', '1/2', '1/2'],
        'n':
        [
            'EFzr1nnfHpT-nkSfd6vQvbPC-Kq6zy8vbVvUmwxcM1e-',
            'EIXFsLk9kmESy0ZsoHMUaDyK_g3DVRiJQYiAlyeCeYJM',
            'EGVvq4Njkki3EZv838rJrYShBtwXY9o8RUrG2w3nbujn'
        ],
        'bt': '3',
        'b':
        [
            'BFATArhqG_ktVCRLWt2Knbc7JDpaPAFJ4npNEmIW_gPX',
            'BOtF-I9geAUjX9NW1kLIq5qDRNgEXCuwpE4mKHkYuWsF',
            'BEzZUvashpXh_nfPoR6aiqvag0a8E_tbhpeJIgHhOXzl',
            'BCE6biH4a-Zg8LI3cMSx7JRoOvb8rRD62xbyl9N4M2g6'
        ],
        'c': [],
        'a': [],
        'di': 'EDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs'
    }

    assert serder.raw == (b'-FCi0OKERICAACAAXdipEF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3EF-jViYoBr8p'
                        b'3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3MAAA4AADA1s2c1s2c1s2-JAhDEE-HCMSwqMDkEBzlmUN'
                        b'mVBAGIinGu7wZ5_hfY6bSMz3DHyJFyFzuD5vvUWv5jy6nwWI3wZmSnoePu29tBR-jXkvDN3JXVEv'
                        b'IjTbisPC4maYQWy6eQIRNdJsxqGFXYUm_ygr4AADA1s2c1s2c1s2-JAhEFzr1nnfHpT-nkSfd6vQ'
                        b'vbPC-Kq6zy8vbVvUmwxcM1e-EIXFsLk9kmESy0ZsoHMUaDyK_g3DVRiJQYiAlyeCeYJMEGVvq4Nj'
                        b'kki3EZv838rJrYShBtwXY9o8RUrG2w3nbujnMAAD-JAsBFATArhqG_ktVCRLWt2Knbc7JDpaPAFJ'
                        b'4npNEmIW_gPXBOtF-I9geAUjX9NW1kLIq5qDRNgEXCuwpE4mKHkYuWsFBEzZUvashpXh_nfPoR6a'
                        b'iqvag0a8E_tbhpeJIgHhOXzlBCE6biH4a-Zg8LI3cMSx7JRoOvb8rRD62xbyl9N4M2g6-JAA-JAA'
                        b'EDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs')

    # Ean interaction event with delegation seal to delegatee Fay's delcept
    pre = eanaid
    prior = eanprior
    sn = eansn + 1
    sealtuple = SealEvent(i=fayaid,
                     s=Number(num=faysn).numh,
                     d=fayaid)
    eseal = sealtuple._asdict()
    assert eseal == \
    {
        'i': 'EF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3',
        's': '0',
        'd': 'EF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3'
    }
    data = [eseal]
    kind = Kinds.cesr

    serder = interact(pre=pre,
                      dig=prior,
                      sn=sn,
                      data=data,
                      pvrsn=Vrsn_2_0,
                      gvrsn=Vrsn_2_0,
                      kind=kind)

    eanprior = serder.said
    assert eanprior == 'EDmgVuwPOXDjIW3reg4_k8SeJoQEKJKP24fGzeMV4uKD'
    eansn = serder.sn
    assert eansn == 1
    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAAEA.',
        't': 'ixn',
        'd': 'EDmgVuwPOXDjIW3reg4_k8SeJoQEKJKP24fGzeMV4uKD',
        'i': 'EDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs',
        's': '1',
        'p': 'EDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs',
        'a':
        [
            {
                'i': 'EF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3',
                's': '0',
                'd': 'EF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3'
            }
        ]
    }

    assert serder.raw == (b'-FA_0OKERICAACAAXixnEDmgVuwPOXDjIW3reg4_k8SeJoQEKJKP24fGzeMV4uKDEDZOA3y_b_0L'
                        b'G4_cfpKTbWU-_3eeYNM0w9iTkT7frTYsMAABEDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7f'
                        b'rTYs-JAY-TAXEF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3MAAAEF-jViYoBr8p3vkp'
                        b'ZuHlkvxAAY5GZkmQ0QaaHfiE0kg3')

    # Fay Rotation Event
    pre = fayaid
    keys = [signer.verfer.qb64 for signer in signers][12:15]
    assert keys == \
    [
        'DB1S8zOh4_qdFhxVHn7BDZb1ErWbBFvcVJX1suKSBctR',
        'DDCDFlbG4dCAX6oIbNffB1mkZqLAS_eHnYUUIPH7BeXB',
        'DP3GAMcSx7eCApzk1N7DceV42o1dZemAe0s3r_-Z0zs1'
    ]
    isith = ["1/2", "1/2", "1/2"]
    nkeys = [signer.verfer.qb64 for signer in signers][15:18]
    assert nkeys == \
    [
        "DCcN7BGPo6c47EWOTvcIUCpzvetDN5E-7EPMprN6tqVI",
        "DAaAPS7IpPe9nPrgF6eGkA9hIphUIeZE0zLkGHCS1BBD",
        "DONoZ4RumKezgod8xoAtRQvmhPRe4LZm8QP-BVEN-MW_"
    ]
    nxts = [Diger(ser=key.encode()).qb64 for key in nkeys]
    assert nxts == \
    [
        'EKUlc5Ml4HLSvdk39k_vh0m6rc061mfM1a4qoEuiBwXW',
        'EJdqHiijmjII-ZtlhFAM5D7myuNeESQkzHoqeWJMMHzW',
        'EDyk8pj0YPHjGNfrG2qZI866WwevwlHEbWYMsKGTGqj2'
    ]
    nsith = ["1/2", "1/2", "1/2"]
    cuts = [wigner.verfer.qb64 for wigner in wigners][9:10]
    assert cuts == \
    ['BOtF-I9geAUjX9NW1kLIq5qDRNgEXCuwpE4mKHkYuWsF']
    assert cuts[0] in faywits
    adds = [wigner.verfer.qb64 for wigner in wigners][12:13]
    assert adds == \
    ['BOMrYd5izsqbqaq1WZYa3nbEeTYLPwccfqfhirybKKqx']
    assert adds[0] not in faywits

    prior = fayprior
    sn = faysn + 1
    cnfg = []
    data = []
    code = MtrDex.Blake3_256
    kind = Kinds.cesr

    serder = deltate(pre=pre,
                    keys=keys,
                    isith=isith,
                    dig=prior,
                    sn=sn,
                    ndigs=nxts,
                    nsith=nsith,
                    wits=faywits, #prior
                    cuts=cuts,
                    adds=adds,
                    cnfg=cnfg,
                    data=data,
                    pvrsn=Vrsn_2_0,
                    gvrsn=Vrsn_2_0,
                    kind=kind)

    fayprior = serder.said
    assert fayprior == 'EFzRkEIXetj-ojZaj0U6P9OqroqZzV0kYwoHGqnlUOwv'
    faysn = serder.sn
    assert faysn == 1
    # set math for new faywits
    faywitset = oset(faywits) - oset(cuts) | oset(adds)
    faywits = list(faywitset)
    assert faywits == \
    [
        'BFATArhqG_ktVCRLWt2Knbc7JDpaPAFJ4npNEmIW_gPX',
        'BEzZUvashpXh_nfPoR6aiqvag0a8E_tbhpeJIgHhOXzl',
        'BCE6biH4a-Zg8LI3cMSx7JRoOvb8rRD62xbyl9N4M2g6',
        'BOMrYd5izsqbqaq1WZYa3nbEeTYLPwccfqfhirybKKqx'
    ]

    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAAI4.',
        't': 'drt',
        'd': 'EFzRkEIXetj-ojZaj0U6P9OqroqZzV0kYwoHGqnlUOwv',
        'i': 'EF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3',
        's': '1',
        'p': 'EF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3',
        'kt': ['1/2', '1/2', '1/2'],
        'k':
        [
            'DB1S8zOh4_qdFhxVHn7BDZb1ErWbBFvcVJX1suKSBctR',
            'DDCDFlbG4dCAX6oIbNffB1mkZqLAS_eHnYUUIPH7BeXB',
            'DP3GAMcSx7eCApzk1N7DceV42o1dZemAe0s3r_-Z0zs1'
        ],
        'nt': ['1/2', '1/2', '1/2'],
        'n':
        [
            'EKUlc5Ml4HLSvdk39k_vh0m6rc061mfM1a4qoEuiBwXW',
            'EJdqHiijmjII-ZtlhFAM5D7myuNeESQkzHoqeWJMMHzW',
            'EDyk8pj0YPHjGNfrG2qZI866WwevwlHEbWYMsKGTGqj2'
        ],
        'bt': '3',
        'br': ['BOtF-I9geAUjX9NW1kLIq5qDRNgEXCuwpE4mKHkYuWsF'],
        'ba': ['BOMrYd5izsqbqaq1WZYa3nbEeTYLPwccfqfhirybKKqx'],
        'c': [],
        'a': []
    }

    assert serder.raw == (b'-FCN0OKERICAACAAXdrtEFzRkEIXetj-ojZaj0U6P9OqroqZzV0kYwoHGqnlUOwvEF-jViYoBr8p'
                        b'3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3MAABEF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE'
                        b'0kg34AADA1s2c1s2c1s2-JAhDB1S8zOh4_qdFhxVHn7BDZb1ErWbBFvcVJX1suKSBctRDDCDFlbG'
                        b'4dCAX6oIbNffB1mkZqLAS_eHnYUUIPH7BeXBDP3GAMcSx7eCApzk1N7DceV42o1dZemAe0s3r_-Z'
                        b'0zs14AADA1s2c1s2c1s2-JAhEKUlc5Ml4HLSvdk39k_vh0m6rc061mfM1a4qoEuiBwXWEJdqHiij'
                        b'mjII-ZtlhFAM5D7myuNeESQkzHoqeWJMMHzWEDyk8pj0YPHjGNfrG2qZI866WwevwlHEbWYMsKGT'
                        b'Gqj2MAAD-JALBOtF-I9geAUjX9NW1kLIq5qDRNgEXCuwpE4mKHkYuWsF-JALBOMrYd5izsqbqaq1'
                        b'WZYa3nbEeTYLPwccfqfhirybKKqx-JAA-JAA')


    # Ean rotate with seal to Fay rotate
    pre = eanaid
    keys = [signer.verfer.qb64 for signer in signers][3:6]
    assert keys == \
    [
        'DLv9BlDvjcZWkfPfWcYhNK-xQxz89h82_wA184Vxk8dj',
        'DCx3WypeBym3fCkVizTg18qEThSrVnB63dFq2oX5c3mz',
        'DO0PG_ww4PbF2jUIxQnlb4DluJu5ndNehp0BTGWXErXf'
    ]
    nkeys = [signer.verfer.qb64 for signer in signers][6:9]
    assert nkeys == \
    [
        "DHODGNuxeW2JTKn3S7keooAjVw582puHoK_zDflPflZg",
        "DImP4vghHKJIgzBxt1HrTLrNLOMy07_gFV0_IekdzAQh",
        "DNlPrQ9T7G71BDgRSpB0coMFANpw_QPVEUosPep1JC79"
    ]
    nxts = [Diger(ser=key.encode()).qb64 for key in nkeys]
    assert nxts == \
    [
        'EA8_fj-Ezin_Us_gUcg5JQJkIIBnrcZt3HEIuH-E1lpe',
        'EERS8udHp2FW89nmaHweQWnZz7I8v9FTQdA-LZ_amqGh',
        'EAEzmrPusrj4CDKnSFQvhCEW6T95C7hBeFtZtRD7rOTg'
    ]
    cuts = [wigner.verfer.qb64 for wigner in wigners][3:4]
    assert cuts == \
    ['BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB']
    assert cuts[0] in eanwits
    adds = [wigner.verfer.qb64 for wigner in wigners][4:6]
    assert adds == \
    [
        'BO3cCAfQiqndZBBxwNk6RGkyA-OA1XbZhBj3s4-VIsCo',
        'BPowpltoeF14nMbU1ng89JSoYf3AmWhZ50KaCaVO6SIW'
    ]
    assert adds[0] not in eanwits
    assert adds[1] not in eanwits

    prior = eanprior
    sn = eansn + 1
    cnfg = []
    sealtuple = SealEvent(i=fayaid,
                          s=Number(num=faysn).numh,
                          d=fayprior)
    eseal = sealtuple._asdict()
    assert eseal == \
    {
        'i': 'EF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3',
        's': '1',
        'd': 'EFzRkEIXetj-ojZaj0U6P9OqroqZzV0kYwoHGqnlUOwv'
    }

    data = [eseal]
    code = MtrDex.Blake3_256
    kind = Kinds.cesr

    serder = rotate(pre=pre,
                    keys=keys,
                    dig=prior,
                    sn=sn,
                    ndigs=nxts,
                    wits=eanwits, #prior
                    cuts=cuts,
                    cnfg=cnfg,
                    adds=adds,
                    data=data,
                    pvrsn=Vrsn_2_0,
                    gvrsn=Vrsn_2_0,
                    kind=kind)

    eanprior = serder.said
    assert eanprior == 'EADBM_Gjzv1_mImlJPPD0bzYmUXmXmCiFIncRYfZMaFc'
    eansn = serder.sn
    assert eansn == 2
    # set math for new eanwits
    eanwitset = oset(eanwits) - oset(cuts) | oset(adds)
    eanwits = list(eanwitset)
    assert eanwits == \
    [
        'BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B',
        'BJfueFAYc7N_V-zmDEn2SPCoVFx3H20alWsNZKgsS1vt',
        'BAPv2MnoiCsgOnklmFyfU07QDK_93NeH9iKfOy8V22aH',
        'BO3cCAfQiqndZBBxwNk6RGkyA-OA1XbZhBj3s4-VIsCo',
        'BPowpltoeF14nMbU1ng89JSoYf3AmWhZ50KaCaVO6SIW'
    ]

    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAAKs.',
        't': 'rot',
        'd': 'EADBM_Gjzv1_mImlJPPD0bzYmUXmXmCiFIncRYfZMaFc',
        'i': 'EDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs',
        's': '2',
        'p': 'EDmgVuwPOXDjIW3reg4_k8SeJoQEKJKP24fGzeMV4uKD',
        'kt': '2',
        'k':
        [
            'DLv9BlDvjcZWkfPfWcYhNK-xQxz89h82_wA184Vxk8dj',
            'DCx3WypeBym3fCkVizTg18qEThSrVnB63dFq2oX5c3mz',
            'DO0PG_ww4PbF2jUIxQnlb4DluJu5ndNehp0BTGWXErXf'
        ],
        'nt': '2',
        'n':
        [
            'EA8_fj-Ezin_Us_gUcg5JQJkIIBnrcZt3HEIuH-E1lpe',
            'EERS8udHp2FW89nmaHweQWnZz7I8v9FTQdA-LZ_amqGh',
            'EAEzmrPusrj4CDKnSFQvhCEW6T95C7hBeFtZtRD7rOTg'
        ],
        'bt': '4',
        'br': ['BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB'],
        'ba':
        [
            'BO3cCAfQiqndZBBxwNk6RGkyA-OA1XbZhBj3s4-VIsCo',
            'BPowpltoeF14nMbU1ng89JSoYf3AmWhZ50KaCaVO6SIW'
        ],
        'c': [],
        'a':
        [
            {
                'i': 'EF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3',
                's': '1',
                'd': 'EFzRkEIXetj-ojZaj0U6P9OqroqZzV0kYwoHGqnlUOwv'
            }
        ]
    }

    assert serder.raw == (b'-FCq0OKERICAACAAXrotEADBM_Gjzv1_mImlJPPD0bzYmUXmXmCiFIncRYfZMaFcEDZOA3y_b_0L'
                        b'G4_cfpKTbWU-_3eeYNM0w9iTkT7frTYsMAACEDmgVuwPOXDjIW3reg4_k8SeJoQEKJKP24fGzeMV'
                        b'4uKDMAAC-JAhDLv9BlDvjcZWkfPfWcYhNK-xQxz89h82_wA184Vxk8djDCx3WypeBym3fCkVizTg'
                        b'18qEThSrVnB63dFq2oX5c3mzDO0PG_ww4PbF2jUIxQnlb4DluJu5ndNehp0BTGWXErXfMAAC-JAh'
                        b'EA8_fj-Ezin_Us_gUcg5JQJkIIBnrcZt3HEIuH-E1lpeEERS8udHp2FW89nmaHweQWnZz7I8v9FT'
                        b'QdA-LZ_amqGhEAEzmrPusrj4CDKnSFQvhCEW6T95C7hBeFtZtRD7rOTgMAAE-JALBA4PSatfQMw1'
                        b'lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB-JAWBO3cCAfQiqndZBBxwNk6RGkyA-OA1XbZhBj3s4-V'
                        b'IsCoBPowpltoeF14nMbU1ng89JSoYf3AmWhZ50KaCaVO6SIW-JAA-JAY-TAXEF-jViYoBr8p3vkp'
                        b'ZuHlkvxAAY5GZkmQ0QaaHfiE0kg3MAABEFzRkEIXetj-ojZaj0U6P9OqroqZzV0kYwoHGqnlUOwv')

    # Test receipt
    rctpre = eanaid
    rctsaid = eanprior
    rctsn = eansn
    serder = receipt(pre=rctpre,
                     sn=rctsn,
                      said=rctsaid,
                      pvrsn=Vrsn_2_0,
                      gvrsn=Vrsn_2_0,
                      kind=kind)

    assert serder.said == rctsaid  # note said of receipt is not computed but refernced
    assert serder.pre == rctpre
    assert serder.sn == rctsn

    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAABw.',
        't': 'rct',
        'd': 'EADBM_Gjzv1_mImlJPPD0bzYmUXmXmCiFIncRYfZMaFc',
        'i': 'EDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs',
        's': '2'
    }


    assert serder.raw == (b'-FAb0OKERICAACAAXrctEADBM_Gjzv1_mImlJPPD0bzYmUXmXmCiFIncRYfZMaFcEDZOA3y_b_0L'
                          b'G4_cfpKTbWU-_3eeYNM0w9iTkT7frTYsMAAC')


    # Routed Messages
    # Query Message Body
    # Test query
    pre = fayaid
    route = "/oobi"
    replyRoute = "/oobi/process"
    q = dict(i=eanaid, role="witness")
    dts = '2025-08-21T17:50:00.000000+00:00'

    serder = query(pre=pre,
                   route=route,
                   replyRoute=replyRoute,
                   query=q,
                   stamp=dts,
                   pvrsn=Vrsn_2_0,
                   gvrsn=Vrsn_2_0,
                   kind=kind)

    said = serder.said
    assert said == 'EF6usM5fNtZWF33E_EQTo9cgU-5f2DH7iBK2V0RPexSe'

    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAAD0.',
        't': 'qry',
        'd': 'EF6usM5fNtZWF33E_EQTo9cgU-5f2DH7iBK2V0RPexSe',
        'i': 'EF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3',
        'dt': '2025-08-21T17:50:00.000000+00:00',
        'r': '/oobi',
        'rr': '/oobi/process',
        'q':
        {
            'i': 'EDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs',
            'role': 'witness'
        }
    }

    assert serder.raw == (b'-FA80OKERICAACAAXqryEF6usM5fNtZWF33E_EQTo9cgU-5f2DH7iBK2V0RPexSeEF-jViYoBr8p'
                            b'3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg31AAG2025-08-21T17c50c00d000000p00c006AACAAA-'
                            b'oobi6AAEAAA-oobi-process-IAQ0J_iEDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs'
                            b'1AAFroleYwitness')

    # Reply states
    pre = eanaid
    raid = eanaid
    route = '/oobi/process'
    url = "https://example.com/witness/BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B"
    data = dict(i=raid, url=url)
    dts = '2020-08-21T17:52:00.000000+00:00'

    serder = reply(pre=pre,
                   route=route,
                    data=data,
                    stamp=dts,
                    pvrsn=Vrsn_2_0,
                    gvrsn=Vrsn_2_0,
                    kind=kind)

    said = serder.said
    assert said == 'EPvuKFb4DpBKOA-HPJHKXf3mHFokUcYnBE3tjBougM9S'

    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAAFA.',
        't': 'rpy',
        'd': 'EPvuKFb4DpBKOA-HPJHKXf3mHFokUcYnBE3tjBougM9S',
        'i': 'EDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs',
        'dt': '2020-08-21T17:52:00.000000+00:00',
        'r': '/oobi/process',
        'a':
        {
            'i': 'EDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs',
            'url': 'https://example.com/witness/BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B'
        }
    }

    assert serder.raw == (b'-FBP0OKERICAACAAXrpyEPvuKFb4DpBKOA-HPJHKXf3mHFokUcYnBE3tjBougM9SEDZOA3y_b_0L'
                        b'G4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs1AAG2020-08-21T17c52c00d000000p00c006AAEAAA-'
                        b'oobi-process-IAm0J_iEDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYsXurl4BAYaHR0'
                        b'cHM6Ly9leGFtcGxlLmNvbS93aXRuZXNzL0JHS1Y2djkzdWU1TDV3c2drNzV0Nmo4VGNkZ0FCTU45'
                        b'eC1lSXlQaTk2SjNC')


    # Test prod
    pre = fayaid
    route = "/confidential"
    replyRoute = "/confidential/process"
    q = dict(i=eanaid, name=True)
    dts = '2025-08-21T17:50:00.000000+00:00'

    serder = prod(pre=pre,
                   route=route,
                   replyRoute=replyRoute,
                   query=q,
                   stamp=dts,
                   pvrsn=Vrsn_2_0,
                   gvrsn=Vrsn_2_0,
                   kind=kind)

    said = serder.said
    assert said == 'EJRa0zYQjeupTLGMJxdLBkxZP175elZFCI_Ddg0IjKI1'

    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAAEA.',
        't': 'pro',
        'd': 'EJRa0zYQjeupTLGMJxdLBkxZP175elZFCI_Ddg0IjKI1',
        'i': 'EF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3',
        'dt': '2025-08-21T17:50:00.000000+00:00',
        'r': '/confidential',
        'rr': '/confidential/process',
        'q':
        {
            'i': 'EDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs',
            'name': True
        }
    }

    assert serder.raw == (b'-FA_0OKERICAACAAXproEJRa0zYQjeupTLGMJxdLBkxZP175elZFCI_Ddg0IjKI1EF-jViYoBr8p'
                        b'3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg31AAG2025-08-21T17c50c00d000000p00c006AAEAAA-'
                        b'confidential6AAGAAA-confidential-process-IAP0J_iEDZOA3y_b_0LG4_cfpKTbWU-_3ee'
                        b'YNM0w9iTkT7frTYs1AAFname1AAM')


    # Test bare
    pre = eanaid
    raid = eanaid
    route = "/confidential/process"
    data = dict(i=raid, name="Ean")
    dts = '2020-08-22T17:52:00.000000+00:00'

    serder = bare(pre=pre,
                   route=route,
                    data=data,
                    stamp=dts,
                    pvrsn=Vrsn_2_0,
                    gvrsn=Vrsn_2_0,
                    kind=kind)

    said = serder.said
    assert said == 'EMaAeoTKrRTGIhJeSp-WhwIMSQMvdf13fChMWV6IL6fa'

    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAADs.',
        't': 'bar',
        'd': 'EMaAeoTKrRTGIhJeSp-WhwIMSQMvdf13fChMWV6IL6fa',
        'i': 'EDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs',
        'dt': '2020-08-22T17:52:00.000000+00:00',
        'r': '/confidential/process',
        'a':
        {
            'i': 'EDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs',
            'name': 'Ean'
        }
    }

    assert serder.raw == (b'-FA60OKERICAACAAXbarEMaAeoTKrRTGIhJeSp-WhwIMSQMvdf13fChMWV6IL6faEDZOA3y_b_0L'
                        b'G4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs1AAG2020-08-22T17c52c00d000000p00c006AAGAAA-'
                        b'confidential-process-IAP0J_iEDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs1AAF'
                        b'nameXEan')

    # Test exchange
    # Test exchept xip from eventing
    sender = fayaid
    receiver = eanaid
    route = "/offer"
    modifiers = dict(timing="immediate")
    attributes = dict(action="sell", item="Rembrant", price=300000.00)
    nonce = uuids[0]
    dts = '2020-08-30T13:30:10.123456+00:00'

    serder = exchept(sender=sender,
                     receiver=receiver,
                     route=route,
                     modifiers=modifiers,
                     attributes=attributes,
                     nonce=nonce,
                     stamp=dts,
                     pvrsn=Vrsn_2_0,
                     gvrsn=Vrsn_2_0,
                     kind=kind)

    said = serder.said
    assert said == 'EISX00jpyZ1_XZBubJghQ2MSxAEgbuBPSoNIKT-4EdwU'
    xid = said  # exchange ID
    prior = said

    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAAE0.',
        't': 'xip',
        'd': 'EISX00jpyZ1_XZBubJghQ2MSxAEgbuBPSoNIKT-4EdwU',
        'u': '0ABrZXJpc3BlY3dvcmtyYXcw',
        'i': 'EF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3',
        'ri': 'EDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs',
        'dt': '2020-08-30T13:30:10.123456+00:00',
        'r': '/offer',
        'q':
        {
            'timing': 'immediate'
        },
        'a':
        {
            'action': 'sell',
            'item': 'Rembrant',
            'price': 300000.0
        }
    }

    assert serder.raw == (b'-FBM0OKERICAACAAXxipEISX00jpyZ1_XZBubJghQ2MSxAEgbuBPSoNIKT-4EdwU0ABrZXJpc3Bl'
                        b'Y3dvcmtyYXcwEF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3EDZOA3y_b_0LG4_cfpKT'
                        b'bWU-_3eeYNM0w9iTkT7frTYs1AAG2020-08-30T13c30c10d123456p00c005AACAA-offer-IAF'
                        b'0Mtiming0N_immediate-IAO0Maction1AAFsell1AAFitem1AANRembrant0L_price4HAC3000'
                        b'00p0')


    # Test exchange exn from eventing
    sender = eanaid
    receiver =  fayaid
    route = "/agree"
    modifiers = dict(timing="immediate")
    attributes = dict(action="buy", item="Rembrant", price=300000.0)
    dts = '2020-08-30T13:42:11.123456+00:00'

    serder = exchange(sender=sender,
                      receiver=receiver,
                     xid=xid,
                     prior=prior,
                     route=route,
                     modifiers=modifiers,
                     attributes=attributes,
                     stamp=dts,
                     pvrsn=Vrsn_2_0,
                     gvrsn=Vrsn_2_0,
                     kind=kind)

    said = serder.said
    assert said == 'ELG8gjElCt6Q53u0m6QuvVRle32EJz0quZkWITml8BMb'

    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAAFw.',
        't': 'exn',
        'd': 'ELG8gjElCt6Q53u0m6QuvVRle32EJz0quZkWITml8BMb',
        'i': 'EDZOA3y_b_0LG4_cfpKTbWU-_3eeYNM0w9iTkT7frTYs',
        'ri': 'EF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3',
        'x': 'EISX00jpyZ1_XZBubJghQ2MSxAEgbuBPSoNIKT-4EdwU',
        'p': 'EISX00jpyZ1_XZBubJghQ2MSxAEgbuBPSoNIKT-4EdwU',
        'dt': '2020-08-30T13:42:11.123456+00:00',
        'r': '/agree',
        'q':
        {
            'timing': 'immediate'
        },
        'a':
        {
            'action': 'buy',
            'item': 'Rembrant',
            'price': 300000.0
        }
    }

    assert serder.raw == (b'-FBb0OKERICAACAAXexnELG8gjElCt6Q53u0m6QuvVRle32EJz0quZkWITml8BMbEDZOA3y_b_0L'
                    b'G4_cfpKTbWU-_3eeYNM0w9iTkT7frTYsEF-jViYoBr8p3vkpZuHlkvxAAY5GZkmQ0QaaHfiE0kg3'
                    b'EISX00jpyZ1_XZBubJghQ2MSxAEgbuBPSoNIKT-4EdwUEISX00jpyZ1_XZBubJghQ2MSxAEgbuBP'
                    b'SoNIKT-4EdwU1AAG2020-08-30T13c42c11d123456p00c005AACAA-agree-IAF0Mtiming0N_i'
                    b'mmediate-IAN0MactionXbuy1AAFitem1AANRembrant0L_price4HAC300000p0')



    """Done Test"""


if __name__ == "__main__":
    test_keri_examples_json()
    test_keri_examples_cesr()

