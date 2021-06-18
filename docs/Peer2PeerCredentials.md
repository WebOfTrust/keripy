# KERI Peer to Peer Communication / Credential Exchange Protocol

## Introduction

This document proposes additions to the KERI protocol to facilitate peer to peer secure communications. It also
introduces two enveloped protocols embedded in these new KERI messages for Credential Issuance and Presentation Exchange
leveraging the [https://identity.foundation/credential-manifest/](Credential Manifest)
and [https://identity. foundation/presentation-exchange/](Presentation Exchange) data formats.  Finally, CESR Proof 
Format for W3C Verifiable Credentials is defined for encoding and signing VCs.

## KERI Peer to Peer Communication
KERI Message: `exn` for peer to peer exchanges.

### JSON Schema for `exn` Messages
```
{
  "$id":"Ei98Pf-7LCJk8qaqSIyJMfXcZMIz0R7ZBVA411-Mb2wU",
  "$schema":"http://json-schema.org/draft-07/schema#",
  "type":"object",
  "properties":{
    "v":{
      "type":"string"
    },
    "t":{
      "type":"string"
    },
    "dt":{
      "type":"string",
      "format":"date-time"
    },
    "x":{
      "type":"string",
      "format":"uri"
    },
    "r":{
      "type":"string",
      "format":"uri"
    },
    "q":{
      "type":"object"
    }
  }
}
```


### Credential Offer `exn` Message
```
{
   "v": "KERI10JSON00011c_",                               // KERI Version String
   "t": "exn",                                             // peer to peer message ilk
   "dt": "2020-08-22T17:50:12.988921+00:00"
   "r": "/credential/offer"                                // resource with nested namespace
   "q": {
      "x": "EMbzB4tnrjBUdhcMadmXq2F2adYdW42iw2NPJz8kUo_c",
      "issuer": "did:keri:EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU"
      "output_descriptors: [
         "EckOnHB11J4H9q16I3tN8DdpNXnCiP5QJQ7yvkWqTDdA"
      ],
      "format": {
        "cesr": {
          "proof_type": ["Ed25519Signature2018"]
        }
      }
   } //embedded credential_manifest like structure, may contain presentation_definition of requirements for fullfilment 
}-AABAA1o61PgMhwhi89FES_vwYeSbbWnVuELV_jv7Yv6f5zNiOLnj1ZZa4MW2c6Z_vZDt55QUnLaiaikE-d_ApsFEgCA
// Count code for a couple: Senders FQ Identifier and signature or signatures
```

### JSON Schema for Offer Payload
```
{
  "$id":"EMbzB4tnrjBUdhcMadmXq2F2adYdW42iw2NPJz8kUo_c",
  "$schema":"http://json-schema.org/draft-07/schema#",
  "type":"object",
  "properties":{
    "x":{
      "type":"string",
      "format":"uri"
    },
    "issuer":{
      "type":"string",
      "format":"uri"
    },
    "output_descriptors":{
      "type":"array",
      "items":{
        "type":"string",
        "format":"uri"
      }
    },
    "format":{
      "type":"object",
      "properties":{
        "cesr":{
          "type":"object",
          "properties":{
            "proof_type":{
              "type":"array",
              "items":{
                "type":"string"
              }
            }
          }
        }
      }
    }
  }
}
```

### Credential Apply as `exn` Message
```
{
   "v": "KERI10JSON00011c_",                               // KERI Version String
   "t": "exn",                                             // peer to peer message ilk
   "dt": "2020-08-22T17:50:12.988921+00:00"
   "x": "Ei98Pf-7LCJk8qaqSIyJMfXcZMIz0R7ZBVA411-Mb2wU",    // SAI of exn meta-data schema
   "r": "/credential/apply"
   "q" {
      "x": "E7NDc95Rgl959Wh1r3dzCAGaQ6zGduFaJrD-ORbEXr_U",
      "issuer": "did:keri:EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU"
      "input_descriptors": [
         "EckOnHB11J4H9q16I3tN8DdpNXnCiP5QJQ7yvkWqTDdA"
      ],
      "format": {
         "cesr": {
           "proof_type": ["Ed25519Signature2018"]
         }
      }
   } //embedded credential_submission, may contain credential_fullfilment responding to presentation_def above
}-AABAA1o61PgMhwhi89FES_vwYeSbbWnVuELV_jv7Yv6f5zNiOLnj1ZZa4MW2c6Z_vZDt55QUnLaiaikE-d_ApsFEgCA
// Count code for a couple: Senders FQ Identifier and signature or signatures
```



### JSON Schema for Accept Payload
```
{
  "$id":"E7NDc95Rgl959Wh1r3dzCAGaQ6zGduFaJrD-ORbEXr_U",
  "$schema":"http://json-schema.org/draft-07/schema#",
  "type":"object",
  "properties":{
    "x":{
      "type":"string",
      "format":"uri"
    },
    "input_descriptors":{
      "type":"array",
      "items":{
        "type":"string",
        "format":"uri"
      }
    },
    "format":{
      "type":"object",
      "properties":{
        "cesr":{
          "type":"object",
          "properties":{
            "proof_type":{
              "type":"array",
              "items":{
                "type":"string"
              }
            }
          }
        }
      }
    }
  }
}
```


### Credential Issue as `exn` Message
```
{
   "v": "KERI10JSON00011c_",                               // KERI Version String
   "t": "exn",                                             // peer to peer message ilk
   "dt": "2020-08-22T17:50:12.988921+00:00"
   "x": "Ei98Pf-7LCJk8qaqSIyJMfXcZMIz0R7ZBVA411-Mb2wU",    // SAI of exn meta-data schema
   "r": "/credential/issue"
   "q" {
      "x": "",
      "vc" [
        {
           "v": "KERI10JSON00011c_", //KERI Version String
           "x": "",
           "i": "EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI", // Identifier prefix of the VC
           "ri":"Es34H0HfRYPXLyFASh0VxCem2cls0yrx8mwRBJLHtOKQ"  // Iss/Rev Registry identifier
           "t": "vc"
           "vc": {
                "type": [
                    "VerifiableCredential",
                    "vLEIGLEIFCredential"
                ],
                "id": "did:keri:EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI",
                "issuer": "did:keri:EchZLZUFqtBGRWMh3Ur_iKucjsrFcxU7AjfCPko9CkEA",  //Identifier prefix of the issuer
                "issuanceDate": "2021-06-09T17:35:54.169967+00:00",
                "credentialSubject": {
                    "id": "did:keri:did:keri:Efaavv0oadfghasdfn443fhbyyr4v",
                    "lei": "254900OPPU84GM83MG36"
                }
            } // embedded verifiable credential
        }-AABAA1o61PgMhwhi89FES_vwYeSbbWnVuELV_jv7Yv6f5zNiOLnj1ZZa4MW2c6Z_vZDt55QUnLaiaikE-d_ApsFEgCA-GAB0AAAAAAAAAAAAAAAAAAAAABQEchZLZUFqtBGRWMh3Ur_iKucjsrFcxU7AjfCPko9CkEA
      ]   //list of verifiable credentials
   } //embedded array of credentials
}-AABAA1o61PgMhwhi89FES_vwYeSbbWnVuELV_jv7Yv6f5zNiOLnj1ZZa4MW2c6Z_vZDt55QUnLaiaikE-d_ApsFEgCA
// Count code for a couple: Senders FQ Identifier and signature or signatures
```


### JSON Schema for vLEI
```
{
  "$id":"EckOnHB11J4H9q16I3tN8DdpNXnCiP5QJQ7yvkWqTDdA",
  "$schema":"http://json-schema.org/draft-07/schema#",
  "type":"object",
  "properties":{
    "id":{
      "type":"string"
    },
    "type":{
      "type":"array"
    },
    "issuer":{
      "type":"string"
    },
    "issuanceDate":{
      "type":"string",
      "format":"date-time"
    },
    "credentialSubject":{
      "type":"object",
      "properties":{
        "id":{
          "type":"string"
        },
        "lei":{
          "type":"string",
          "format":"lei"
        }
      }
    },
    "proof":{
      "type":"object",
      "properties":{
        "type":{
          "type":"array"
        },
        "created":{
          "type":"string",
          "format":"date-time"
        },
        "proofPurpose":{
          "type":"string"
        },
        "verificationMethod":{
          "type":"string"
        },
        "jws":{
          "type":"string"
        }
      }
    }
  }
}
```


## Presentation Exchange

### Presentation Request as `exn` Message
```
{
   "v": "KERI10JSON00011c_",                               // KERI Version String
   "t": "exn",                                             // peer to peer message ilk
   "dt": "2020-08-22T17:50:12.988921+00:00"
   "x": "Ei98Pf-7LCJk8qaqSIyJMfXcZMIz0R7ZBVA411-Mb2wU",    // SAI of exn meta-data schema
   "r": "/presentation/request"
   "q" {
      "x": "E7NDc95Rgl959Wh1r3dzCAGaQ6zGduFaJrD-ORbEXr_U",
      "submission_requirements": [{
         "name": "Proof of LEI",
         "rule": "pick",
         "count": 1,
         "from": "A"
       }]
      "input_descriptors": [
         {
            "x":"EckOnHB11J4H9q16I3tN8DdpNXnCiP5QJQ7yvkWqTDdA",
            "group": ["A"],
         }
      ],
      "format": {
         "cesr": {
           "proof_type": ["Ed25519Signature2018"]
         }
      }
   } //embedded credential_submission, may contain credential_fullfilment responding to presentation_def above
}-AABAA1o61PgMhwhi89FES_vwYeSbbWnVuELV_jv7Yv6f5zNiOLnj1ZZa4MW2c6Z_vZDt55QUnLaiaikE-d_ApsFEgCA
// Count code for a couple: Senders FQ Identifier and signature or signatures
```


### Presentation Proof as `exn` Message

```
{
   "v": "KERI10JSON00011c_",                               // KERI Version String
   "t": "exn",                                             // peer to peer message ilk
   "dt": "2020-08-22T17:50:12.988921+00:00"
   "x": "Ei98Pf-7LCJk8qaqSIyJMfXcZMIz0R7ZBVA411-Mb2wU",    // SAI of exn meta-data schema
   "r": "/presentation/proof"
   "q" {
      "x": "E7NDc95Rgl959Wh1r3dzCAGaQ6zGduFaJrD-ORbEXr_U",
      "presentation_submission": {
          "id": "a30e3b91-fb77-4d22-95fa-871689c322e2",
          "definition_id": "32f54163-7166-48f1-93d8-ff217bdb0653",
          "descriptor_map": [
               {
                 "id": "gleif_vlei",
                 "format": "cesr",
                 "path": "$.verifiableCredential[0]"
               }
          ]
      },
      "verifiableCredential": [
          {
             "v": "KERI10JSON00011c_", //KERI Version String
             "i": "EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI", // Identifier prefix of the VC
             "ri":"Es34H0HfRYPXLyFASh0VxCem2cls0yrx8mwRBJLHtOKQ"  // Iss/Rev Registry identifier
             "t": "vc"
             "vc": {
                  "type": [
                      "VerifiableCredential",
                      "vLEIGLEIFCredential"
                  ],
                  "id": "did:keri:EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI",
                  "issuer": "did:keri:EchZLZUFqtBGRWMh3Ur_iKucjsrFcxU7AjfCPko9CkEA",  //Identifier prefix of the issuer
                  "issuanceDate": "2021-06-09T17:35:54.169967+00:00",
                  "credentialSubject": {
                      "id": "did:keri:did:keri:Efaavv0oadfghasdfn443fhbyyr4v",
                      "lei": "254900OPPU84GM83MG36"
                  }
              } // embedded verifiable credential
          }-AABAA1o61PgMhwhi89FES_vwYeSbbWnVuELV_jv7Yv6f5zNiOLnj1ZZa4MW2c6Z_vZDt55QUnLaiaikE-d_ApsFEgCA
          -GAB0AAAAAAAAAAAAAAAAAAAAABQEchZLZUFqtBGRWMh3Ur_iKucjsrFcxU7AjfCPko9CkEA
        }
      ]
     }  //embedded verifiable_presentation - DOES HE NEED HIS OWN PROOF???
   } //embedded credential_submission, may contain credential_fullfilment responding to presentation_def above
}-AABAA1o61PgMhwhi89FES_vwYeSbbWnVuELV_jv7Yv6f5zNiOLnj1ZZa4MW2c6Z_vZDt55QUnLaiaikE-d_ApsFEgCA
// Count code for a couple: Senders FQ Identifier and signature or signatures
```


## CESR Proof Format for W3C Verifiable Credentials

Domain and Challege to avoid impersonation and replay attacks

### Verifiable Credential with CESR Proof Format

```
{
   "v": "KERI10JSON00011c_", //KERI Version String
   "i": "EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI", // Identifier prefix of the VC, SAI
   "ri":"Es34H0HfRYPXLyFASh0VxCem2cls0yrx8mwRBJLHtOKQ"  // Iss/Rev Registry identifier
   "t": "vc"
   "vc": {
        "x": "Ei98Pf-7LCJk8qaqSIyJMfXcZMIz0R7ZBVA411-Mb2wU",
        "type": [
            "VerifiableCredential",
            "vLEIGLEIFCredential"
        ],
        "id": "did:keri:EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI",
        "issuer": "did:keri:EchZLZUFqtBGRWMh3Ur_iKucjsrFcxU7AjfCPko9CkEA",  //Identifier prefix of the issuer
        "issuanceDate": "2021-06-09T17:35:54.169967+00:00",
        "credentialSubject": {
            "x": "E7NDc95Rgl959Wh1r3dzCAGaQ6zGduFaJrD-ORbEXr_U",
            "id": "did:keri:did:keri:Efaavv0oadfghasdfn443fhbyyr4v",
            "lei": "254900OPPU84GM83MG36"
        }
    } // embedded verifiable credential
}-AABAA1o61PgMhwhi89FES_vwYeSbbWnVuELV_jv7Yv6f5zNiOLnj1ZZa4MW2c6Z_vZDt55QUnLaiaikE-d_ApsFEgCA-GAB0AAAAAAAAAAAAAAAAAAAAABQEchZLZUFqtBGRWMh3Ur_iKucjsrFcxU7AjfCPko9CkEA
```

Questions:
1.  Where does the registry identifier belong...  It is part of the Verification method and thus part of the proof, 
    so likely as an attachment
2.  Where does the Source Seal pointing to the keys used?  It is part of Verification method and thus part of the 
    proof, so likely as an attachment
3.  Issuer is DID located inside the `issuer` field in the VC
4.  Do we need to replicate the VC ID in the `i` field of the outer envelope
5.  Should the VC have an `t` field?
   

### Verifiable Presentation with CESR Proof Format

```
{
   "v": "KERI10JSON00011c_", //KERI Version String
   "i": "EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI",  // Identifier prefix of the VC
   "ri":"Es34H0HfRYPXLyFASh0VxCem2cls0yrx8mwRBJLHtOKQ"
   "vp": {
       "id": "did:keri:EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI",
       "type": ["VerifiablePresentation", "vLEIGLEIFCredential"],
       "holder": "did:keri:did:keri:Efaavv0oadfghasdfn443fhbyyr4v"
       "vc": [
            {
               "v": "KERI10JSON00011c_", //KERI Version String
               "i": "EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI", // Identifier prefix of the VC
               "ri":"Es34H0HfRYPXLyFASh0VxCem2cls0yrx8mwRBJLHtOKQ"  // Iss/Rev Registry identifier
               "t": "vc"
               "vc": {
                    "type": [
                        "VerifiableCredential",
                        "vLEIGLEIFCredential"
                    ],
                    "id": "did:keri:EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI",
                    "issuer": "did:keri:EchZLZUFqtBGRWMh3Ur_iKucjsrFcxU7AjfCPko9CkEA",  //Identifier prefix of the issuer
                    "issuanceDate": "2021-06-09T17:35:54.169967+00:00",
                    "credentialSubject": {
                        "id": "did:keri:did:keri:Efaavv0oadfghasdfn443fhbyyr4v",
                        "lei": "254900OPPU84GM83MG36"
                    }
                } // embedded verifiable credential
            }-AABAA1o61PgMhwhi89FES_vwYeSbbWnVuELV_jv7Yv6f5zNiOLnj1ZZa4MW2c6Z_vZDt55QUnLaiaikE-d_ApsFEgCA-GAB0AAAAAAAAAAAAAAAAAAAAABQEchZLZUFqtBGRWMh3Ur_iKucjsrFcxU7AjfCPko9CkEA
    ]
   } // embedded verifiable presentation
}-AABAA1o61PgMhwhi89FES_vwYeSbbWnVuELV_jv7Yv6f5zNiOLnj1ZZa4MW2c6Z_vZDt55QUnLaiaikE-d_ApsFEgCA-GAB0AAAAAAAAAAAAAAAAAAAAABQEchZLZUFqtBGRWMh3Ur_iKucjsrFcxU7AjfCPko9CkEA
```
