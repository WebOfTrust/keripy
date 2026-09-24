# -*- encoding: utf-8 -*-
"""
KERI
keri.end package

ReST endpoints

"""

from .ending import (Signage, Inputage, signature,
                     designature, normalize, siginput,
                     desiginput, PointEnd, LocationEnd,
                     AdminEnd, OOBIEnd, loadEnds, setup,
                     OOBI_RE, DOOBI_RE, Mimes, KeriMimes,
                     WOOBI_RE, OOBI_AID_HEADER)
from .httpsigning import (HttpSigError, MissingSignature,
                          MissingSignatureInput, MalformedSignature,
                          MalformedSignatureInput, MalformedSignatureLabel,
                          MissingSignatureLabel, MalformedSignatureValue,
                          ModeMismatch, DuplicateComponent,
                          UnsupportedComponent, InsufficientCoverage,
                          MalformedKey, UnknownKey, UnsupportedSigner,
                          UnsupportedAlgorithm, MissingComponent,
                          SignatureMismatch, SignatureStale, SignatureExpired,
                          MalformedDigest, DigestMismatch, UncoveredBody,
                          Unauthenticated, errorForCode, Requestage,
                          contentDigest, verifyContentDigest, signatureParams,
                          signatureBase, normalizeAuthority, signRequest,
                          signResponse,
                          responseCovered, responseMinimum,
                          RequestMinimum, Verified, Deferred, Policy,
                          detectMode,
                          effectiveVerfer,
                          signatureKeyid, verifyRequest, checkBody,
                          verifyResponse, verifyLegacy, KeverResolver,
                          keverResolver)
from .priming import parseArgs
