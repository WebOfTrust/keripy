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
from keri.core import (incept, interact, rotate, delcept, deltate, receipt)


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



    """Done Test"""


if __name__ == "__main__":
    test_keri_examples_json()
    test_keri_examples_cesr()

