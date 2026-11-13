# -*- coding: utf-8 -*-
"""
tests.spec.keri.test_keri_examples module

"""
from ordered_set import OrderedSet as oset

from keri import Vrsn_2_0, Kinds,TraitDex
from keri.core import (MtrDex, Salter, Diger, Noncer,
                       Number, SealEvent,
                       incept, interact, rotate, delcept, deltate, receipt,
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
    bobacdc = 'EP-iKGmXD-iZu3RhVA2FTI-dOdX50bRBV3VDCy-peOtv'  # bob's project report ACDC
    bobbup = "EHdCoOs5P-xwHWjXuJOe8SWgTKVj_Vx_YbbDSYxJ6fK3" # issued blindable update said
    bobblid = "EItpXDP26bvHIRZ0GrJwhOIR5lLEaviFcIxFodP6IJ8N"  # issued blid said
    bobbupsn = '2' # sn of issuing bup

    debaid = "EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW"   # deb's AID
    debreg = "EJl5EUxL23p_pqgN3IyM-pzru89Nb7NzOM8ijH644xSU"  # deb's Registry
    debacdc = 'ELCZRc2VlaDv0mdooNQ_Y_MGiaBS0YQ2OaSpV97Y-wrt'  # deb's research report ACDC
    debupd = "EH_7mAMBpQ21f3nHSy8B6yCD_jdMYiZ__Je1Hac-c-Kc"  # deb's update said
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

    cnfg = []
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
    assert eanaid == 'EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN'
    eanprior = serder.said
    eansn = serder.sn
    assert eansn == 0
    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAKk.",
        "t": "icp",
        "d": "EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN",
        "i": "EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN",
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
        "c": [],
        "a": []
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAKk.","t":"icp","d":"EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuV'
                        b'SUslB-8uRN","i":"EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN","s":"0","kt":'
                        b'"2","k":["DBFiIgoCOpJ_zW_OO0GdffhHfEvJWb1HxpDx95bFvufu","DG-YwInLUxzVDD5z8Sq'
                        b'ZmS2FppXSB-ZX_f2bJC_ZnsM5","DGIAk2jkC3xuLIe-DI9rcA0naevtZiKuU9wz91L_qBAV"],"'
                        b'nt":"2","n":["ELeFYMmuJb0hevKjhv97joA5bTfuA8E697cMzi8eoaZB","ENY9GYShOjeh7qZ'
                        b'UpIipKRHgrWcoR2WkJ7Wgj4wZx1YT","EGyJ7y3TlewCW97dgBN-4pckhCqsni-zHNZ_G8zVerPG'
                        b'"],"bt":"3","b":["BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B","BJfueFAYc7N'
                        b'_V-zmDEn2SPCoVFx3H20alWsNZKgsS1vt","BAPv2MnoiCsgOnklmFyfU07QDK_93NeH9iKfOy8V'
                        b'22aH","BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB"],"c":[],"a":[]}')


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
    assert fayaid == 'EJync0CSV0HLN4zdVgCyIUHIG_KiZTRFByXJcOclFbaC'
    fayprior = serder.said
    faysn = serder.sn
    assert faysn == 0
    assert serder.delpre == eanaid
    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAL4.",
        "t": "dip",
        "d": "EJync0CSV0HLN4zdVgCyIUHIG_KiZTRFByXJcOclFbaC",
        "i": "EJync0CSV0HLN4zdVgCyIUHIG_KiZTRFByXJcOclFbaC",
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
        "di": "EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN"
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAL4.","t":"dip","d":"EJync0CSV0HLN4zdVgCyIUHIG_KiZTRFBy'
                        b'XJcOclFbaC","i":"EJync0CSV0HLN4zdVgCyIUHIG_KiZTRFByXJcOclFbaC","s":"0","kt":'
                        b'["1/2","1/2","1/2"],"k":["DEE-HCMSwqMDkEBzlmUNmVBAGIinGu7wZ5_hfY6bSMz3","DHy'
                        b'JFyFzuD5vvUWv5jy6nwWI3wZmSnoePu29tBR-jXkv","DN3JXVEvIjTbisPC4maYQWy6eQIRNdJs'
                        b'xqGFXYUm_ygr"],"nt":["1/2","1/2","1/2"],"n":["EFzr1nnfHpT-nkSfd6vQvbPC-Kq6zy'
                        b'8vbVvUmwxcM1e-","EIXFsLk9kmESy0ZsoHMUaDyK_g3DVRiJQYiAlyeCeYJM","EGVvq4Njkki3'
                        b'EZv838rJrYShBtwXY9o8RUrG2w3nbujn"],"bt":"3","b":["BFATArhqG_ktVCRLWt2Knbc7JD'
                        b'paPAFJ4npNEmIW_gPX","BOtF-I9geAUjX9NW1kLIq5qDRNgEXCuwpE4mKHkYuWsF","BEzZUvas'
                        b'hpXh_nfPoR6aiqvag0a8E_tbhpeJIgHhOXzl","BCE6biH4a-Zg8LI3cMSx7JRoOvb8rRD62xbyl'
                        b'9N4M2g6"],"c":[],"a":[],"di":"EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN"}')

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
        'i': 'EJync0CSV0HLN4zdVgCyIUHIG_KiZTRFByXJcOclFbaC',
        's': '0',
        'd': 'EJync0CSV0HLN4zdVgCyIUHIG_KiZTRFByXJcOclFbaC'
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
    assert eanprior == 'EHTLoDjCFXSEHnOJiwdwyeHGqRsRRMlwMuggAGigSsXx'
    eansn = serder.sn
    assert eansn == 1
    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAE8.",
        "t": "ixn",
        "d": "EHTLoDjCFXSEHnOJiwdwyeHGqRsRRMlwMuggAGigSsXx",
        "i": "EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN",
        "s": "1",
        "p": "EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN",
        "a":
        [
            {
                "i": "EJync0CSV0HLN4zdVgCyIUHIG_KiZTRFByXJcOclFbaC",
                "s": "0",
                "d": "EJync0CSV0HLN4zdVgCyIUHIG_KiZTRFByXJcOclFbaC"
            }
        ]
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAE8.","t":"ixn","d":"EHTLoDjCFXSEHnOJiwdwyeHGqRsRRMlwMu'
                            b'ggAGigSsXx","i":"EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN","s":"1","p":"'
                            b'EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN","a":[{"i":"EJync0CSV0HLN4zdVgC'
                            b'yIUHIG_KiZTRFByXJcOclFbaC","s":"0","d":"EJync0CSV0HLN4zdVgCyIUHIG_KiZTRFByXJ'
                            b'cOclFbaC"}]}')

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
    assert fayprior == 'EEaJrM-0HPs4hATSqSpvotRBAjKuJO6ri5Uh7KBoLYbV'
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
        "d": "EEaJrM-0HPs4hATSqSpvotRBAjKuJO6ri5Uh7KBoLYbV",
        "i": "EJync0CSV0HLN4zdVgCyIUHIG_KiZTRFByXJcOclFbaC",
        "s": "1",
        "p": "EJync0CSV0HLN4zdVgCyIUHIG_KiZTRFByXJcOclFbaC",
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

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAKh.","t":"drt","d":"EEaJrM-0HPs4hATSqSpvotRBAjKuJO6ri5'
                            b'Uh7KBoLYbV","i":"EJync0CSV0HLN4zdVgCyIUHIG_KiZTRFByXJcOclFbaC","s":"1","p":"'
                            b'EJync0CSV0HLN4zdVgCyIUHIG_KiZTRFByXJcOclFbaC","kt":["1/2","1/2","1/2"],"k":['
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
        'i': 'EJync0CSV0HLN4zdVgCyIUHIG_KiZTRFByXJcOclFbaC',
        's': '1',
        'd': 'EEaJrM-0HPs4hATSqSpvotRBAjKuJO6ri5Uh7KBoLYbV'
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
    assert eanprior == 'EDB2wjbby-xefglmIDinyPpp3cFO6ZG8CpnERMvLMh9z'
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
        "d": "EDB2wjbby-xefglmIDinyPpp3cFO6ZG8CpnERMvLMh9z",
        "i": "EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN",
        "s": "2",
        "p": "EHTLoDjCFXSEHnOJiwdwyeHGqRsRRMlwMuggAGigSsXx",
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
                "i": "EJync0CSV0HLN4zdVgCyIUHIG_KiZTRFByXJcOclFbaC",
                "s": "1",
                "d": "EEaJrM-0HPs4hATSqSpvotRBAjKuJO6ri5Uh7KBoLYbV"
            }
        ]
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAMf.","t":"rot","d":"EDB2wjbby-xefglmIDinyPpp3cFO6ZG8Cp'
                        b'nERMvLMh9z","i":"EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN","s":"2","p":"'
                        b'EHTLoDjCFXSEHnOJiwdwyeHGqRsRRMlwMuggAGigSsXx","kt":"2","k":["DLv9BlDvjcZWkfP'
                        b'fWcYhNK-xQxz89h82_wA184Vxk8dj","DCx3WypeBym3fCkVizTg18qEThSrVnB63dFq2oX5c3mz'
                        b'","DO0PG_ww4PbF2jUIxQnlb4DluJu5ndNehp0BTGWXErXf"],"nt":"2","n":["EA8_fj-Ezin'
                        b'_Us_gUcg5JQJkIIBnrcZt3HEIuH-E1lpe","EERS8udHp2FW89nmaHweQWnZz7I8v9FTQdA-LZ_a'
                        b'mqGh","EAEzmrPusrj4CDKnSFQvhCEW6T95C7hBeFtZtRD7rOTg"],"bt":"4","br":["BA4PSa'
                        b'tfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB"],"ba":["BO3cCAfQiqndZBBxwNk6RGkyA-OA'
                        b'1XbZhBj3s4-VIsCo","BPowpltoeF14nMbU1ng89JSoYf3AmWhZ50KaCaVO6SIW"],"c":[],"a"'
                        b':[{"i":"EJync0CSV0HLN4zdVgCyIUHIG_KiZTRFByXJcOclFbaC","s":"1","d":"EEaJrM-0H'
                        b'Ps4hATSqSpvotRBAjKuJO6ri5Uh7KBoLYbV"}]}')

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
        "d": "EDB2wjbby-xefglmIDinyPpp3cFO6ZG8CpnERMvLMh9z",
        "i": "EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN",
        "s": "2"
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAACT.","t":"rct","d":"EDB2wjbby-xefglmIDinyPpp3cFO6ZG8Cp'
                          b'nERMvLMh9z","i":"EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN","s":"2"}')


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
    assert said == 'EDH-jhkIhzSg24dEuawgvwrG5NmaGuFpcLq3_jt69Gi6'

    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAEe.",
        "t": "qry",
        "d": "EDH-jhkIhzSg24dEuawgvwrG5NmaGuFpcLq3_jt69Gi6",
        "i": "EJync0CSV0HLN4zdVgCyIUHIG_KiZTRFByXJcOclFbaC",
        "dt": "2025-08-21T17:50:00.000000+00:00",
        "r": "/oobi",
        "rr": "/oobi/process",
        "q":
        {
            "i": "EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN",
            "role": "witness"
        }
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAEe.","t":"qry","d":"EDH-jhkIhzSg24dEuawgvwrG5NmaGuFpcL'
                        b'q3_jt69Gi6","i":"EJync0CSV0HLN4zdVgCyIUHIG_KiZTRFByXJcOclFbaC","dt":"2025-08'
                        b'-21T17:50:00.000000+00:00","r":"/oobi","rr":"/oobi/process","q":{"i":"EMZBns'
                        b's7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN","role":"witness"}}')

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
    assert said == 'ELmXgZxjRRAPXy7_miHaNkMhz2G0yaTiy78H5zQQp_Dq'

    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAFR.",
        "t": "rpy",
        "d": "ELmXgZxjRRAPXy7_miHaNkMhz2G0yaTiy78H5zQQp_Dq",
        "i": "EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN",
        "dt": "2020-08-21T17:52:00.000000+00:00",
        "r": "/oobi/process",
        "a":
        {
            "i": "EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN",
            "url": "https://example.com/witness/BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B"
        }
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAFR.","t":"rpy","d":"ELmXgZxjRRAPXy7_miHaNkMhz2G0yaTiy7'
                        b'8H5zQQp_Dq","i":"EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN","dt":"2020-08'
                        b'-21T17:52:00.000000+00:00","r":"/oobi/process","a":{"i":"EMZBnss7FmDlFir3D6h'
                        b'pNyyNYyuDWYARuVSUslB-8uRN","url":"https://example.com/witness/BGKV6v93ue5L5w'
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
    assert said == 'ED13KketbicYgoAj44QWT-qHy-Giez3WtsDbl3us3NA-'

    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAEp.",
        "t": "pro",
        "d": "ED13KketbicYgoAj44QWT-qHy-Giez3WtsDbl3us3NA-",
        "i": "EJync0CSV0HLN4zdVgCyIUHIG_KiZTRFByXJcOclFbaC",
        "dt": "2025-08-21T17:50:00.000000+00:00",
        "r": "/confidential",
        "rr": "/confidential/process",
        "q":
        {
            "i": "EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN",
            "name": True
        }
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAEp.","t":"pro","d":"ED13KketbicYgoAj44QWT-qHy-Giez3Wts'
                        b'Dbl3us3NA-","i":"EJync0CSV0HLN4zdVgCyIUHIG_KiZTRFByXJcOclFbaC","dt":"2025-08'
                        b'-21T17:50:00.000000+00:00","r":"/confidential","rr":"/confidential/process",'
                        b'"q":{"i":"EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN","name":true}}')


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
    assert said == 'EFvOLw6kMz1F5YEiQkGAEJYW4d5cyRVS7UJWhKhkYpIl'

    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAEV.",
        "t": "bar",
        "d": "EFvOLw6kMz1F5YEiQkGAEJYW4d5cyRVS7UJWhKhkYpIl",
        "i": "EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN",
        "dt": "2020-08-22T17:52:00.000000+00:00",
        "r": "/confidential/process",
        "a":
        {
            "i": "EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN",
            "name": "Ean"
        }
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAEV.","t":"bar","d":"EFvOLw6kMz1F5YEiQkGAEJYW4d5cyRVS7U'
                        b'JWhKhkYpIl","i":"EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN","dt":"2020-08'
                        b'-22T17:52:00.000000+00:00","r":"/confidential/process","a":{"i":"EMZBnss7FmD'
                        b'lFir3D6hpNyyNYyuDWYARuVSUslB-8uRN","name":"Ean"}}')

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
    assert said == 'EP-HUOsmNTzFrzdeoGYSHMCWf3uDZRVyGET2IwRFkDA-'
    xid = said  # exchange ID
    prior = said

    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAFn.",
        "t": "xip",
        "d": "EP-HUOsmNTzFrzdeoGYSHMCWf3uDZRVyGET2IwRFkDA-",
        "u": "0ABrZXJpc3BlY3dvcmtyYXcw",
        "i": "EJync0CSV0HLN4zdVgCyIUHIG_KiZTRFByXJcOclFbaC",
        "ri": "EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN",
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

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAFn.","t":"xip","d":"EP-HUOsmNTzFrzdeoGYSHMCWf3uDZRVyGE'
                        b'T2IwRFkDA-","u":"0ABrZXJpc3BlY3dvcmtyYXcw","i":"EJync0CSV0HLN4zdVgCyIUHIG_Ki'
                        b'ZTRFByXJcOclFbaC","ri":"EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN","dt":"'
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
    assert said == 'ECroaY6bkgw0LijKoIcwrceXkTIqnfCRBnKyXIpBO-0G'

    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAGt.",
        "t": "exn",
        "d": "ECroaY6bkgw0LijKoIcwrceXkTIqnfCRBnKyXIpBO-0G",
        "i": "EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN",
        "ri": "EJync0CSV0HLN4zdVgCyIUHIG_KiZTRFByXJcOclFbaC",
        "x": "EP-HUOsmNTzFrzdeoGYSHMCWf3uDZRVyGET2IwRFkDA-",
        "p": "EP-HUOsmNTzFrzdeoGYSHMCWf3uDZRVyGET2IwRFkDA-",
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

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAGt.","t":"exn","d":"ECroaY6bkgw0LijKoIcwrceXkTIqnfCRBn'
                    b'KyXIpBO-0G","i":"EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN","ri":"EJync0C'
                    b'SV0HLN4zdVgCyIUHIG_KiZTRFByXJcOclFbaC","x":"EP-HUOsmNTzFrzdeoGYSHMCWf3uDZRVy'
                    b'GET2IwRFkDA-","p":"EP-HUOsmNTzFrzdeoGYSHMCWf3uDZRVyGET2IwRFkDA-","dt":"2020-'
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
    assert said == 'ECImC_XpiOBpRRFfPm8Zv4nrDyZEFnmypiM8OEyNMEyh'

    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAIA.",
        "t": "rpy",
        "d": "ECImC_XpiOBpRRFfPm8Zv4nrDyZEFnmypiM8OEyNMEyh",
        "i": "EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN",
        "dt": "2020-08-21T17:52:00.000000+00:00",
        "r": "/oobi/witness",
        "a":
        {
            "cid": "EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN",
            "urls":
            [
                "https://example.com/witness/wilma/BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B",
                "https://example.com/witness/watson/BAPv2MnoiCsgOnklmFyfU07QDK_93NeH9iKfOy8V22aH",
                "https://example.com/witness/winona/BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB"
            ]
        }
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAIA.","t":"rpy","d":"ECImC_XpiOBpRRFfPm8Zv4nrDyZEFnmypi'
                    b'M8OEyNMEyh","i":"EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN","dt":"2020-08'
                    b'-21T17:52:00.000000+00:00","r":"/oobi/witness","a":{"cid":"EMZBnss7FmDlFir3D'
                    b'6hpNyyNYyuDWYARuVSUslB-8uRN","urls":["https://example.com/witness/wilma/BGKV'
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
    assert said == 'EAPrRZ16UKbDo3s30wwDVF1tAFtrHvYlnUzlutxkib7Q'

    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAFq.",
        "t": "rpy",
        "d": "EAPrRZ16UKbDo3s30wwDVF1tAFtrHvYlnUzlutxkib7Q",
        "i": "EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN",
        "dt": "2020-08-21T17:52:00.000000+00:00",
        "r": "/oobi/EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN/witness",
        "a":
        {
            "eid": "BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B",
            "scheme": "https",
            "url": "https://example.com/witness/wilma"
        }
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAFq.","t":"rpy","d":"EAPrRZ16UKbDo3s30wwDVF1tAFtrHvYlnU'
                        b'zlutxkib7Q","i":"EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN","dt":"2020-08'
                        b'-21T17:52:00.000000+00:00","r":"/oobi/EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUsl'
                        b'B-8uRN/witness","a":{"eid":"BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B","s'
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
    assert said == 'EI55faTn-x2C2NnzYggXuVyNGZIt62MEtuBphwYReBBA'

    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAFI.",
        "t": "rpy",
        "d": "EI55faTn-x2C2NnzYggXuVyNGZIt62MEtuBphwYReBBA",
        "i": "EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN",
        "dt": "2020-08-21T17:52:00.000000+00:00",
        "r": "/end/role/add",
        "a":
        {
            "cid": "EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN",
            "role": "witness",
            "eid": "BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B"
        }
    }


    assert serder.raw == (b'{"v":"KERICAACAAJSONAAFI.","t":"rpy","d":"EI55faTn-x2C2NnzYggXuVyNGZIt62MEtu'
                    b'BphwYReBBA","i":"EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN","dt":"2020-08'
                    b'-21T17:52:00.000000+00:00","r":"/end/role/add","a":{"cid":"EMZBnss7FmDlFir3D'
                    b'6hpNyyNYyuDWYARuVSUslB-8uRN","role":"witness","eid":"BGKV6v93ue5L5wsgk75t6j8'
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
    assert said == 'EO2EhNQYVGblpuAn7WI0ExtCrwuNuAMf564ySizlrDnC'
    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAFI.",
        "t": "rpy",
        "d": "EO2EhNQYVGblpuAn7WI0ExtCrwuNuAMf564ySizlrDnC",
        "i": "EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN",
        "dt": "2020-08-21T17:52:10.000000+00:00",
        "r": "/end/role/cut",
        "a":
        {
            "cid": "EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN",
            "role": "witness",
            "eid": "BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B"
        }
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAFI.","t":"rpy","d":"EO2EhNQYVGblpuAn7WI0ExtCrwuNuAMf56'
                        b'4ySizlrDnC","i":"EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN","dt":"2020-08'
                        b'-21T17:52:10.000000+00:00","r":"/end/role/cut","a":{"cid":"EMZBnss7FmDlFir3D'
                        b'6hpNyyNYyuDWYARuVSUslB-8uRN","role":"witness","eid":"BGKV6v93ue5L5wsgk75t6j8'
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
    assert said == 'ECAIvQlLhF3ASGfwe3mkS8k2SYtwV-9gDje5xt2SSWqM'
    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAE6.",
        "t": "rpy",
        "d": "ECAIvQlLhF3ASGfwe3mkS8k2SYtwV-9gDje5xt2SSWqM",
        "i": "EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN",
        "dt": "2020-08-21T17:52:11.000000+00:00",
        "r": "/loc/scheme",
        "a":
        {
            "eid": "BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B",
            "scheme": "https",
            "url": "https//example.com/witness/wilma"
        }
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAE6.","t":"rpy","d":"ECAIvQlLhF3ASGfwe3mkS8k2SYtwV-9gDj'
                    b'e5xt2SSWqM","i":"EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN","dt":"2020-08'
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
    assert said == 'EBVw1fBeKaBKYUjLIqtBLrVOeot3aKLa5mAG641Vs2dM'
    assert serder.sad == \
    {
        "v": "KERICAACAAJSONAAEa.",
        "t": "rpy",
        "d": "EBVw1fBeKaBKYUjLIqtBLrVOeot3aKLa5mAG641Vs2dM",
        "i": "EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN",
        "dt": "2020-08-21T17:52:12.000000+00:00",
        "r": "/loc/scheme",
        "a":
        {
            "eid": "BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B",
            "scheme": "https",
            "url": ""
        }
    }

    assert serder.raw == (b'{"v":"KERICAACAAJSONAAEa.","t":"rpy","d":"EBVw1fBeKaBKYUjLIqtBLrVOeot3aKLa5m'
                        b'AG641Vs2dM","i":"EMZBnss7FmDlFir3D6hpNyyNYyuDWYARuVSUslB-8uRN","dt":"2020-08'
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
    bobacdc = 'EP-iKGmXD-iZu3RhVA2FTI-dOdX50bRBV3VDCy-peOtv'  # bob's project report ACDC
    bobbup = "EHdCoOs5P-xwHWjXuJOe8SWgTKVj_Vx_YbbDSYxJ6fK3" # issued blindable update said
    bobblid = "EItpXDP26bvHIRZ0GrJwhOIR5lLEaviFcIxFodP6IJ8N"  # issued blid said
    bobbupsn = '2' # sn of issuing bup

    debaid = "EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW"   # deb's AID
    debreg = "EJl5EUxL23p_pqgN3IyM-pzru89Nb7NzOM8ijH644xSU"  # deb's Registry
    debacdc = 'ELCZRc2VlaDv0mdooNQ_Y_MGiaBS0YQ2OaSpV97Y-wrt'  # deb's research report ACDC
    debupd = "EH_7mAMBpQ21f3nHSy8B6yCD_jdMYiZ__Je1Hac-c-Kc"  # deb's update said
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

    cnfg = []
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
    assert eanaid == 'EFGEi3daBWvNOZ3riL93RhKMd3qrAt2cPP4GYpdQKUPl'
    eanprior = serder.said
    eansn = serder.sn
    assert eansn == 0
    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAAJI.',
        't': 'icp',
        'd': 'EFGEi3daBWvNOZ3riL93RhKMd3qrAt2cPP4GYpdQKUPl',
        'i': 'EFGEi3daBWvNOZ3riL93RhKMd3qrAt2cPP4GYpdQKUPl',
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
        'c': [],
        'a': []
    }


    assert serder.raw == (b'-FCR0OKERICAACAAXicpEFGEi3daBWvNOZ3riL93RhKMd3qrAt2cPP4GYpdQKUPlEFGEi3daBWvN'
                        b'OZ3riL93RhKMd3qrAt2cPP4GYpdQKUPlMAAAMAAC-JAhDBFiIgoCOpJ_zW_OO0GdffhHfEvJWb1H'
                        b'xpDx95bFvufuDG-YwInLUxzVDD5z8SqZmS2FppXSB-ZX_f2bJC_ZnsM5DGIAk2jkC3xuLIe-DI9r'
                        b'cA0naevtZiKuU9wz91L_qBAVMAAC-JAhELeFYMmuJb0hevKjhv97joA5bTfuA8E697cMzi8eoaZB'
                        b'ENY9GYShOjeh7qZUpIipKRHgrWcoR2WkJ7Wgj4wZx1YTEGyJ7y3TlewCW97dgBN-4pckhCqsni-z'
                        b'HNZ_G8zVerPGMAAD-JAsBGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3BBJfueFAYc7N_'
                        b'V-zmDEn2SPCoVFx3H20alWsNZKgsS1vtBAPv2MnoiCsgOnklmFyfU07QDK_93NeH9iKfOy8V22aH'
                        b'BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB-JAA-JAA')


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
    assert fayaid == 'EPdjet_gItRBeXagqaAm3q9-yt5gZRc2vQKUW46Affqm'
    fayprior = serder.said
    faysn = serder.sn
    assert faysn == 0
    assert serder.delpre == eanaid
    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAAKM.',
        't': 'dip',
        'd': 'EPdjet_gItRBeXagqaAm3q9-yt5gZRc2vQKUW46Affqm',
        'i': 'EPdjet_gItRBeXagqaAm3q9-yt5gZRc2vQKUW46Affqm',
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
        'di': 'EFGEi3daBWvNOZ3riL93RhKMd3qrAt2cPP4GYpdQKUPl'
    }

    assert serder.raw == (b'-FCi0OKERICAACAAXdipEPdjet_gItRBeXagqaAm3q9-yt5gZRc2vQKUW46AffqmEPdjet_gItRB'
                        b'eXagqaAm3q9-yt5gZRc2vQKUW46AffqmMAAA4AADA1s2c1s2c1s2-JAhDEE-HCMSwqMDkEBzlmUN'
                        b'mVBAGIinGu7wZ5_hfY6bSMz3DHyJFyFzuD5vvUWv5jy6nwWI3wZmSnoePu29tBR-jXkvDN3JXVEv'
                        b'IjTbisPC4maYQWy6eQIRNdJsxqGFXYUm_ygr4AADA1s2c1s2c1s2-JAhEFzr1nnfHpT-nkSfd6vQ'
                        b'vbPC-Kq6zy8vbVvUmwxcM1e-EIXFsLk9kmESy0ZsoHMUaDyK_g3DVRiJQYiAlyeCeYJMEGVvq4Nj'
                        b'kki3EZv838rJrYShBtwXY9o8RUrG2w3nbujnMAAD-JAsBFATArhqG_ktVCRLWt2Knbc7JDpaPAFJ'
                        b'4npNEmIW_gPXBOtF-I9geAUjX9NW1kLIq5qDRNgEXCuwpE4mKHkYuWsFBEzZUvashpXh_nfPoR6a'
                        b'iqvag0a8E_tbhpeJIgHhOXzlBCE6biH4a-Zg8LI3cMSx7JRoOvb8rRD62xbyl9N4M2g6-JAA-JAA'
                        b'EFGEi3daBWvNOZ3riL93RhKMd3qrAt2cPP4GYpdQKUPl')

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
        'i': 'EPdjet_gItRBeXagqaAm3q9-yt5gZRc2vQKUW46Affqm',
        's': '0',
        'd': 'EPdjet_gItRBeXagqaAm3q9-yt5gZRc2vQKUW46Affqm'
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
    assert eanprior == 'EIGnvQZsQmEJFDzTvkpYVeWe5p4b7Li4Wenec-hrxSUu'
    eansn = serder.sn
    assert eansn == 1
    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAAEA.',
        't': 'ixn',
        'd': 'EIGnvQZsQmEJFDzTvkpYVeWe5p4b7Li4Wenec-hrxSUu',
        'i': 'EFGEi3daBWvNOZ3riL93RhKMd3qrAt2cPP4GYpdQKUPl',
        's': '1',
        'p': 'EFGEi3daBWvNOZ3riL93RhKMd3qrAt2cPP4GYpdQKUPl',
        'a':
        [
            {
                'i': 'EPdjet_gItRBeXagqaAm3q9-yt5gZRc2vQKUW46Affqm',
                's': '0',
                'd': 'EPdjet_gItRBeXagqaAm3q9-yt5gZRc2vQKUW46Affqm'
            }
        ]
    }

    assert serder.raw == (b'-FA_0OKERICAACAAXixnEIGnvQZsQmEJFDzTvkpYVeWe5p4b7Li4Wenec-hrxSUuEFGEi3daBWvN'
                        b'OZ3riL93RhKMd3qrAt2cPP4GYpdQKUPlMAABEFGEi3daBWvNOZ3riL93RhKMd3qrAt2cPP4GYpdQ'
                        b'KUPl-JAY-TAXEPdjet_gItRBeXagqaAm3q9-yt5gZRc2vQKUW46AffqmMAAAEPdjet_gItRBeXag'
                        b'qaAm3q9-yt5gZRc2vQKUW46Affqm')

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
    assert fayprior == 'ENJEBes6djQe9UyVwLD8ZnvxySkLe2bYvTdJuCHzeS4U'
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
        'd': 'ENJEBes6djQe9UyVwLD8ZnvxySkLe2bYvTdJuCHzeS4U',
        'i': 'EPdjet_gItRBeXagqaAm3q9-yt5gZRc2vQKUW46Affqm',
        's': '1',
        'p': 'EPdjet_gItRBeXagqaAm3q9-yt5gZRc2vQKUW46Affqm',
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

    assert serder.raw == (b'-FCN0OKERICAACAAXdrtENJEBes6djQe9UyVwLD8ZnvxySkLe2bYvTdJuCHzeS4UEPdjet_gItRB'
                        b'eXagqaAm3q9-yt5gZRc2vQKUW46AffqmMAABEPdjet_gItRBeXagqaAm3q9-yt5gZRc2vQKUW46A'
                        b'ffqm4AADA1s2c1s2c1s2-JAhDB1S8zOh4_qdFhxVHn7BDZb1ErWbBFvcVJX1suKSBctRDDCDFlbG'
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
        'i': 'EPdjet_gItRBeXagqaAm3q9-yt5gZRc2vQKUW46Affqm',
        's': '1',
        'd': 'ENJEBes6djQe9UyVwLD8ZnvxySkLe2bYvTdJuCHzeS4U'
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
    assert eanprior == 'EBxDwqO3n2CfSV2eU9uZGQdD2nZY0N4HongFEftt4kam'
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
        'd': 'EBxDwqO3n2CfSV2eU9uZGQdD2nZY0N4HongFEftt4kam',
        'i': 'EFGEi3daBWvNOZ3riL93RhKMd3qrAt2cPP4GYpdQKUPl',
        's': '2',
        'p': 'EIGnvQZsQmEJFDzTvkpYVeWe5p4b7Li4Wenec-hrxSUu',
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
                'i': 'EPdjet_gItRBeXagqaAm3q9-yt5gZRc2vQKUW46Affqm',
                's': '1',
                'd': 'ENJEBes6djQe9UyVwLD8ZnvxySkLe2bYvTdJuCHzeS4U'
            }
        ]
    }

    assert serder.raw == (b'-FCq0OKERICAACAAXrotEBxDwqO3n2CfSV2eU9uZGQdD2nZY0N4HongFEftt4kamEFGEi3daBWvN'
                        b'OZ3riL93RhKMd3qrAt2cPP4GYpdQKUPlMAACEIGnvQZsQmEJFDzTvkpYVeWe5p4b7Li4Wenec-hr'
                        b'xSUuMAAC-JAhDLv9BlDvjcZWkfPfWcYhNK-xQxz89h82_wA184Vxk8djDCx3WypeBym3fCkVizTg'
                        b'18qEThSrVnB63dFq2oX5c3mzDO0PG_ww4PbF2jUIxQnlb4DluJu5ndNehp0BTGWXErXfMAAC-JAh'
                        b'EA8_fj-Ezin_Us_gUcg5JQJkIIBnrcZt3HEIuH-E1lpeEERS8udHp2FW89nmaHweQWnZz7I8v9FT'
                        b'QdA-LZ_amqGhEAEzmrPusrj4CDKnSFQvhCEW6T95C7hBeFtZtRD7rOTgMAAE-JALBA4PSatfQMw1'
                        b'lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB-JAWBO3cCAfQiqndZBBxwNk6RGkyA-OA1XbZhBj3s4-V'
                        b'IsCoBPowpltoeF14nMbU1ng89JSoYf3AmWhZ50KaCaVO6SIW-JAA-JAY-TAXEPdjet_gItRBeXag'
                        b'qaAm3q9-yt5gZRc2vQKUW46AffqmMAABENJEBes6djQe9UyVwLD8ZnvxySkLe2bYvTdJuCHzeS4U')

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
        'd': 'EBxDwqO3n2CfSV2eU9uZGQdD2nZY0N4HongFEftt4kam',
        'i': 'EFGEi3daBWvNOZ3riL93RhKMd3qrAt2cPP4GYpdQKUPl',
        's': '2'
    }


    assert serder.raw == (b'-FAb0OKERICAACAAXrctEBxDwqO3n2CfSV2eU9uZGQdD2nZY0N4HongFEftt4kamEFGEi3daBWvN'
                          b'OZ3riL93RhKMd3qrAt2cPP4GYpdQKUPlMAAC')


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
    assert said == 'ELbgwacB_oOfKieZKbrCaGjFcAJfTEQtNpRWHRR6nTrd'

    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAAD0.',
        't': 'qry',
        'd': 'ELbgwacB_oOfKieZKbrCaGjFcAJfTEQtNpRWHRR6nTrd',
        'i': 'EPdjet_gItRBeXagqaAm3q9-yt5gZRc2vQKUW46Affqm',
        'dt': '2025-08-21T17:50:00.000000+00:00',
        'r': '/oobi',
        'rr': '/oobi/process',
        'q':
        {
            'i': 'EFGEi3daBWvNOZ3riL93RhKMd3qrAt2cPP4GYpdQKUPl',
            'role': 'witness'
        }
    }

    assert serder.raw == (b'-FA80OKERICAACAAXqryELbgwacB_oOfKieZKbrCaGjFcAJfTEQtNpRWHRR6nTrdEPdjet_gItRB'
                            b'eXagqaAm3q9-yt5gZRc2vQKUW46Affqm1AAG2025-08-21T17c50c00d000000p00c006AACAAA-'
                            b'oobi6AAEAAA-oobi-process-IAQ0J_iEFGEi3daBWvNOZ3riL93RhKMd3qrAt2cPP4GYpdQKUPl'
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
    assert said == 'EMbxfRKdIld1MMUSR-AMKNAfrYPqjfit3VLU0ePGb2Rd'

    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAAFA.',
        't': 'rpy',
        'd': 'EMbxfRKdIld1MMUSR-AMKNAfrYPqjfit3VLU0ePGb2Rd',
        'i': 'EFGEi3daBWvNOZ3riL93RhKMd3qrAt2cPP4GYpdQKUPl',
        'dt': '2020-08-21T17:52:00.000000+00:00',
        'r': '/oobi/process',
        'a':
        {
            'i': 'EFGEi3daBWvNOZ3riL93RhKMd3qrAt2cPP4GYpdQKUPl',
            'url': 'https://example.com/witness/BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B'
        }
    }

    assert serder.raw == (b'-FBP0OKERICAACAAXrpyEMbxfRKdIld1MMUSR-AMKNAfrYPqjfit3VLU0ePGb2RdEFGEi3daBWvN'
                        b'OZ3riL93RhKMd3qrAt2cPP4GYpdQKUPl1AAG2020-08-21T17c52c00d000000p00c006AAEAAA-'
                        b'oobi-process-IAm0J_iEFGEi3daBWvNOZ3riL93RhKMd3qrAt2cPP4GYpdQKUPlXurl4BAYaHR0'
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
    assert said == 'EDF6BrJYL9XLlDqVvhEQvflt0chv7wLZyhEGmAAtlTKN'

    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAAEA.',
        't': 'pro',
        'd': 'EDF6BrJYL9XLlDqVvhEQvflt0chv7wLZyhEGmAAtlTKN',
        'i': 'EPdjet_gItRBeXagqaAm3q9-yt5gZRc2vQKUW46Affqm',
        'dt': '2025-08-21T17:50:00.000000+00:00',
        'r': '/confidential',
        'rr': '/confidential/process',
        'q':
        {
            'i': 'EFGEi3daBWvNOZ3riL93RhKMd3qrAt2cPP4GYpdQKUPl',
            'name': True
        }
    }

    assert serder.raw == (b'-FA_0OKERICAACAAXproEDF6BrJYL9XLlDqVvhEQvflt0chv7wLZyhEGmAAtlTKNEPdjet_gItRB'
                        b'eXagqaAm3q9-yt5gZRc2vQKUW46Affqm1AAG2025-08-21T17c50c00d000000p00c006AAEAAA-'
                        b'confidential6AAGAAA-confidential-process-IAP0J_iEFGEi3daBWvNOZ3riL93RhKMd3qr'
                        b'At2cPP4GYpdQKUPl1AAFname1AAM')


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
    assert said == 'EPmHvAdXK7eGSL5iFC3MYrrXDfp8ZhW0i28PMvsjD_4Y'

    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAADs.',
        't': 'bar',
        'd': 'EPmHvAdXK7eGSL5iFC3MYrrXDfp8ZhW0i28PMvsjD_4Y',
        'i': 'EFGEi3daBWvNOZ3riL93RhKMd3qrAt2cPP4GYpdQKUPl',
        'dt': '2020-08-22T17:52:00.000000+00:00',
        'r': '/confidential/process',
        'a':
        {
            'i': 'EFGEi3daBWvNOZ3riL93RhKMd3qrAt2cPP4GYpdQKUPl',
            'name': 'Ean'
        }
    }

    assert serder.raw == (b'-FA60OKERICAACAAXbarEPmHvAdXK7eGSL5iFC3MYrrXDfp8ZhW0i28PMvsjD_4YEFGEi3daBWvN'
                        b'OZ3riL93RhKMd3qrAt2cPP4GYpdQKUPl1AAG2020-08-22T17c52c00d000000p00c006AAGAAA-'
                        b'confidential-process-IAP0J_iEFGEi3daBWvNOZ3riL93RhKMd3qrAt2cPP4GYpdQKUPl1AAF'
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
    assert said == 'EHlSjMkGvdcCdkbEHJTA_R3PsskZ9INsjgNrGncDV7LQ'
    xid = said  # exchange ID
    prior = said

    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAAE0.',
        't': 'xip',
        'd': 'EHlSjMkGvdcCdkbEHJTA_R3PsskZ9INsjgNrGncDV7LQ',
        'u': '0ABrZXJpc3BlY3dvcmtyYXcw',
        'i': 'EPdjet_gItRBeXagqaAm3q9-yt5gZRc2vQKUW46Affqm',
        'ri': 'EFGEi3daBWvNOZ3riL93RhKMd3qrAt2cPP4GYpdQKUPl',
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

    assert serder.raw == (b'-FBM0OKERICAACAAXxipEHlSjMkGvdcCdkbEHJTA_R3PsskZ9INsjgNrGncDV7LQ0ABrZXJpc3Bl'
                        b'Y3dvcmtyYXcwEPdjet_gItRBeXagqaAm3q9-yt5gZRc2vQKUW46AffqmEFGEi3daBWvNOZ3riL93'
                        b'RhKMd3qrAt2cPP4GYpdQKUPl1AAG2020-08-30T13c30c10d123456p00c005AACAA-offer-IAF'
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
    assert said == 'EF4AbFrsFVOoHzzMBfukwzsMg_8khKrRaxOMXb8cl6YI'

    assert serder.sad == \
    {
        'v': 'KERICAACAACESRAAFw.',
        't': 'exn',
        'd': 'EF4AbFrsFVOoHzzMBfukwzsMg_8khKrRaxOMXb8cl6YI',
        'i': 'EFGEi3daBWvNOZ3riL93RhKMd3qrAt2cPP4GYpdQKUPl',
        'ri': 'EPdjet_gItRBeXagqaAm3q9-yt5gZRc2vQKUW46Affqm',
        'x': 'EHlSjMkGvdcCdkbEHJTA_R3PsskZ9INsjgNrGncDV7LQ',
        'p': 'EHlSjMkGvdcCdkbEHJTA_R3PsskZ9INsjgNrGncDV7LQ',
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

    assert serder.raw == (b'-FBb0OKERICAACAAXexnEF4AbFrsFVOoHzzMBfukwzsMg_8khKrRaxOMXb8cl6YIEFGEi3daBWvN'
                    b'OZ3riL93RhKMd3qrAt2cPP4GYpdQKUPlEPdjet_gItRBeXagqaAm3q9-yt5gZRc2vQKUW46Affqm'
                    b'EHlSjMkGvdcCdkbEHJTA_R3PsskZ9INsjgNrGncDV7LQEHlSjMkGvdcCdkbEHJTA_R3PsskZ9INs'
                    b'jgNrGncDV7LQ1AAG2020-08-30T13c42c11d123456p00c005AACAA-agree-IAF0Mtiming0N_i'
                    b'mmediate-IAN0MactionXbuy1AAFitem1AANRembrant0L_price4HAC300000p0')



    """Done Test"""


if __name__ == "__main__":
    test_keri_examples_json()
    test_keri_examples_cesr()

