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
from .httpsigning import (HttpSigError, HttpSigMissingSignatureError,
                          HttpSigMissingSignatureInputError,
                          HttpSigMalformedSignatureError,
                          HttpSigMalformedSignatureInputError,
                          HttpSigMalformedSignatureLabelError,
                          HttpSigMissingSignatureLabelError,
                          HttpSigMalformedSignatureValueError,
                          HttpSigModeMismatchError,
                          HttpSigDuplicateComponentError,
                          HttpSigUnsupportedComponentError,
                          HttpSigInsufficientCoverageError,
                          HttpSigMalformedKeyError, HttpSigUnknownKeyError,
                          HttpSigUnsupportedSignerError,
                          HttpSigUnsupportedAlgorithmError,
                          HttpSigMissingComponentError,
                          HttpSigSignatureMismatchError,
                          HttpSigSignatureStaleError,
                          HttpSigSignatureExpiredError,
                          HttpSigMalformedDigestError,
                          HttpSigDigestMismatchError,
                          HttpSigUncoveredBodyError,
                          HttpSigUnauthenticatedError, errorForCode,
                          Requestage, contentDigest, verifyContentDigest,
                          signatureParams, signatureBase, normalizeAuthority,
                          signRequest, signResponse, responseCovered,
                          responseMinimum, RequestMinimum, Verified, Deferred,
                          Policy, detectMode, peekMode, effectiveVerfer,
                          signatureKeyid, verifyRequest, checkBody,
                          verifyResponse, verifyLegacy, KeverResolver,
                          keverResolver)
from .priming import parseArgs
