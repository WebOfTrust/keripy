# -*- encoding: utf-8 -*-
"""
keri.end.httpsigning module

Canonical RFC 9421 HTTP Message Signatures under the KERI profile, with RFC
9530 Content-Digest, plus a verifier for the legacy KERI signed-header scheme
of keri.end.ending so a server can accept both while clients upgrade.

The profile itself (covered components, parameters, keyid resolution, mode
selection and the refusal codes) is specified in the "KERI profile of RFC 9421
HTTP Message Signatures", version 1.2, published at
https://github.com/bakobo/fiki/blob/keri-profile-v1.2/docs/keri-profile.md
Section numbers in comments below refer to it where they say "profile", and to
RFC 9421 otherwise.

Canonical mode verifies with a key state's single effective signer
(effectiveVerfer, profile R4). Legacy mode accepts a signature that verifies
under any current key that alone satisfies the signing threshold
(sufficientVerfers, profile section 8), and skips canonical mode's
derivation-code rules.

This module takes plain values (method, scheme, authority, path, query,
headers, body) rather than a framework request object, so any server or client
can adapt to it. It depends on nothing that is not also present on the keripy
1.2.x line.

The legacy functions in keri.end.ending are deliberately left untouched.
"""
import base64
import hashlib
import hmac
import math
import re
import secrets
from collections import namedtuple
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass

import http_sfv
import pysodium

from . import ending
from .. import kering
from ..kering import (HttpSigError, HttpSigMissingSignatureError,
                      HttpSigMissingSignatureInputError,
                      HttpSigMalformedSignatureError,
                      HttpSigMalformedSignatureInputError,
                      HttpSigMalformedSignatureLabelError,
                      HttpSigMissingSignatureLabelError,
                      HttpSigMalformedSignatureValueError,
                      HttpSigModeMismatchError, HttpSigDuplicateComponentError,
                      HttpSigUnsupportedComponentError,
                      HttpSigInsufficientCoverageError,
                      HttpSigMalformedKeyError, HttpSigUnknownKeyError,
                      HttpSigUnsupportedSignerError,
                      HttpSigUnsupportedAlgorithmError,
                      HttpSigMissingComponentError,
                      HttpSigSignatureMismatchError,
                      HttpSigSignatureStaleError, HttpSigSignatureExpiredError,
                      HttpSigMalformedDigestError, HttpSigDigestMismatchError,
                      HttpSigUncoveredBodyError, HttpSigUnauthenticatedError)
from ..core.coring import MtrDex, PreDex, NonTransDex, Prefixer, Verfer
from ..core import Cigar, Siger
from ..help import helping


def errorForCode(code):
    """
    Returns the HttpSigError subclass for refusal code, or None when unknown.

    Parameters:
        code (str): kebab-case refusal code
    """
    for klas in _errorClasses():
        if klas.code == code:
            return klas
    return None


def _errorClasses():
    stack = list(HttpSigError.__subclasses__())
    while stack:
        klas = stack.pop()
        stack.extend(klas.__subclasses__())
        yield klas


# Content-Digest, RFC 9530

DigestAlgs = {"sha-256": hashlib.sha256, "sha-512": hashlib.sha512}


def _bytify(body):
    if body is None:
        return b""
    if isinstance(body, str):
        return body.encode("utf-8")
    return bytes(body)


def contentDigest(body, alg="sha-256"):
    """
    Returns RFC 9530 Content-Digest field value for body, e.g.
    'sha-256=:<base64>:'.

    Parameters:
        body (bytes | str | None): message content as sent. str is UTF-8
            encoded; None is empty content.
        alg (str): 'sha-256' (default) or 'sha-512'
    """
    if alg not in DigestAlgs:
        raise ValueError(f"Unsupported Content-Digest algorithm {alg!r}.")
    digest = DigestAlgs[alg](_bytify(body)).digest()
    return f"{alg}=:{base64.b64encode(digest).decode('ascii')}:"


def verifyContentDigest(value, body):
    """
    Verify Content-Digest field value against the content actually received.

    Algorithms other than sha-256 and sha-512 are ignored (RFC 9530 section 2).
    Every recognized one must match. A value with no recognized member is an
    error, not a pass (profile section 5).

    Parameters:
        value (str | bytes): Content-Digest field value
        body (bytes | str | None): content as received

    Raises:
        HttpSigMalformedDigestError: value does not parse, a recognized
            member is not a Byte Sequence, or no member is recognized
        HttpSigDigestMismatchError: a recognized member does not match body
    """
    _compareDigest(_parseDigest(value), body)


def _parseDigest(value):
    """
    Returns list of (alg, digest bytes) for the recognized members of a
    Content-Digest value, so that every covered digest can be parsed before
    any is compared (malformed-digest precedes digest-mismatch).

    Raises HttpSigMalformedDigestError.
    """
    try:
        members = _parseDict(value)
    except ValueError as ex:
        raise HttpSigMalformedDigestError(
            f"Content-Digest does not parse: {ex}.") from ex

    recognized = []
    for alg, member in members.items():
        if alg not in DigestAlgs:
            continue
        if not isinstance(member, http_sfv.Item) or not isinstance(member.value, bytes):
            raise HttpSigMalformedDigestError(
                f"Content-Digest member {alg} is not a Byte Sequence.")
        recognized.append((alg, member.value))

    if not recognized:
        raise HttpSigMalformedDigestError(
            "Content-Digest has no sha-256 or sha-512 member.")
    return recognized


def _compareDigest(recognized, body):
    """Raises HttpSigDigestMismatchError unless every recognized digest
    matches body."""
    raw = _bytify(body)
    for alg, digest in recognized:
        if not hmac.compare_digest(DigestAlgs[alg](raw).digest(), digest):
            raise HttpSigDigestMismatchError(
                f"Content-Digest {alg} does not match the content.")


# Signature base, RFC 9421 section 2

# Derived components this profile supports (profile section 2). @status only
# in a response.
Derived = ("@method", "@authority", "@path", "@query", "@status")

# Order in which a signer emits signature parameters (profile section 4).
ParamOrder = ("created", "expires", "nonce", "alg", "keyid", "tag")

# Request a response answers, as the requester sent it or the server received
# it. headers as for signatureBase. body is the content, bytes. scheme is the
# scheme it was sent with, or None when unknown (profile section 2).
Requestage = namedtuple("Requestage",
                        "method authority path query headers body scheme",
                        defaults=(None,))

_ObsFold = re.compile(r"[ \t]*\r?\n[ \t]+")


def _fieldLines(headers):
    """
    Returns dict mapping lowercased field name to list of field line values in
    the order received.

    headers may be a mapping (including multidicts whose .items() yields
    repeated names) or an iterable of (name, value) pairs. A list or tuple
    value is several field lines. bytes names and values are decoded as
    latin-1. A value of None, as some header containers give for an absent
    field, is no field line, so a field with no other line is absent.
    """
    fields = {}
    if headers is None:
        return fields
    items = headers.items() if isinstance(headers, Mapping) else headers
    for name, value in items:
        if isinstance(value, (list, tuple)):
            values = [v for v in value if v is not None]
            if value and not values:
                continue
        elif value is None:
            continue
        else:
            values = [value]
        fields.setdefault(_latin1(name).lower(), []).extend(
            _latin1(v) for v in values)
    return fields


def _latin1(value):
    """Header names and values given as bytes are decoded as latin-1, as WSGI
    does, so every byte survives and a non-ASCII one refuses the base."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("latin-1")
    return str(value)


def _text(value):
    """A derived-component input (method, authority, path, query) given as
    bytes, as ASGI gives raw_path and query_string, is decoded as latin-1
    like a header value; None stays None."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("latin-1")
    return value


def _fieldValue(fields, name):
    """
    Returns RFC 9421 section 2.1 component value of field name, or None when
    absent: each line stripped, obsolete line folding replaced by a single
    space, lines joined by ', '.
    """
    lines = fields.get(name)
    if lines is None:
        return None
    # RFC 9421 section 2.1 strips SP and HTAB only; str.strip() would also
    # remove characters such as \x85 and \xa0 that an intermediary can add.
    return ", ".join(_ObsFold.sub(" ", line).strip(" \t") for line in lines)


def _component(component):
    """
    Returns component identifier as http_sfv.Item.

    component may be an http_sfv.Item (as parsed from Signature-Input), a
    serialized identifier such as '"@path";req' (wire form, must already be
    lowercase), or a plain name such as 'Content-Type' (local caller form,
    lowercased as a convenience).
    """
    if isinstance(component, http_sfv.Item):
        item = component
    elif isinstance(component, str) and component.startswith('"'):
        item = http_sfv.Item()
        try:
            item.parse(component.encode("utf-8"))
        except ValueError as ex:
            raise HttpSigMalformedSignatureInputError(
                f"Component identifier {component} does not parse.") from ex
    elif isinstance(component, str) and component:
        return http_sfv.Item(component.lower())
    else:
        raise HttpSigMalformedSignatureInputError(
            f"Invalid component identifier {component!r}.")

    if type(item.value) is not str or not item.value:  # String, not Token
        raise HttpSigMalformedSignatureInputError(
            f"Component identifier {item} is not a String.")
    if item.value != item.value.lower():
        raise HttpSigMalformedSignatureInputError(
            f"Component identifier {item} is not lowercase.")
    return item


def _componentKey(item):
    """Identity of a component for duplicate detection, ignoring parameter
    order."""
    return item.value, frozenset((k, repr(v)) for k, v in item.params.items())


def _serialize(item):
    """Serialized component identifier, e.g. '"@path";req'."""
    return str(item)


def _components(covered, *, response):
    """
    Returns list of http_sfv.Item for covered after the profile's duplicate and
    support checks, in that order (profile section 9).
    """
    items = [_component(c) for c in covered]

    seen = set()
    for item in items:
        key = _componentKey(item)
        if key in seen:
            raise HttpSigDuplicateComponentError(
                f"Component {_serialize(item)} is covered more than once.")
        seen.add(key)

    for item in items:
        name = item.value
        for param, value in item.params.items():
            if param != "req" or value is not True:
                raise HttpSigUnsupportedComponentError(
                    f"Component {_serialize(item)} has unsupported parameter "
                    f"{param}.")
            if not response:
                raise HttpSigUnsupportedComponentError(
                    f"Component {_serialize(item)}: req is only valid in a "
                    "response.")
        if name.startswith("@"):
            if name not in Derived:
                raise HttpSigUnsupportedComponentError(
                    f"Derived component {name} is not supported.")
            if name == "@status" and (not response or "req" in item.params):
                raise HttpSigUnsupportedComponentError(
                    f"Component {_serialize(item)} is only valid on a "
                    "response.")
            if name != "@status" and response and "req" not in item.params:
                raise HttpSigUnsupportedComponentError(
                    f"Component {_serialize(item)} targets a request; on a "
                    "response it needs req.")
    return items


_DefaultPorts = {"http": ":80", "https": ":443"}

# RFC 3986 section 3.2: host, an IP-literal in brackets or a reg-name (a list
# separator ',' and userinfo's '@' excluded), and an optional port of digits.
_Authority = re.compile(
    r"\A(?:\[[0-9a-z:.]+\]|[a-z0-9\-._~!$&'()*+;=%]*)(?::[0-9]*)?\Z")


def normalizeAuthority(authority, scheme=None):
    """
    Returns authority normalized for @authority (RFC 9421 section 2.2.3,
    profile section 2): lowercased, with the default port of scheme removed
    (':443' for https, ':80' for http).

    With scheme None, as for a verifier that has only the Host header and so
    does not know the scheme the request was sent with, no port is removed:
    the authority is used as received. A Host value has had SP and HTAB
    trimmed as a field value before it gets here, and nothing else.

    Parameters:
        authority (str | bytes): host[:port], bytes decoded as latin-1
        scheme (str | bytes | None): scheme the request was sent with
    """
    authority = _text(authority).lower()
    port = _DefaultPorts.get((_text(scheme) or "").lower())
    if port is not None and authority.endswith(port):
        return authority[:-len(port)]
    return authority


def _authorityValue(authority, fields, scheme):
    """
    Returns the @authority component value: authority, else the Host field,
    normalized for scheme, or None when neither is present.

    Raises HttpSigSignatureMismatchError when the value is not a valid
    authority, so the base cannot be built (profile sections 2 and 9).
    """
    if authority is None:
        authority = _fieldValue(fields, "host")
        if authority is None:
            return None
    authority = _text(authority)
    # checked before lowercasing, which reads U+212A KELVIN SIGN as 'k'
    value = normalizeAuthority(authority, scheme) if authority.isascii() else authority
    if not value.isascii() or not _Authority.match(value):
        raise HttpSigSignatureMismatchError(
            f"Signature base cannot be built: {value!r} is not a valid "
            "authority.")
    return value


_StatusLine = re.compile(r"\A([1-9][0-9]{2})(?: .*)?\Z", re.DOTALL)


def _statusCode(status):
    """
    Returns int status code from an int, or from a str whose first token is
    the three digit code, such as falcon's '200 OK'.

    Raises ValueError for anything else.
    """
    if type(status) is int:
        if 100 <= status <= 999:
            return status
    elif isinstance(status, str):
        match = _StatusLine.match(status)
        if match:
            return int(match.group(1))
    raise ValueError(f"Invalid response status {status!r}.")


def _componentValue(item, *, method, authority, path, query, fields, status,
                    scheme=None):
    method, authority, path, query = (_text(v) for v in
                                      (method, authority, path, query))
    name = item.value
    if name == "@method":
        value = method
    elif name == "@authority":
        value = _authorityValue(authority, fields, scheme)
    elif name == "@path":
        value = (path or "/") if path is not None else None
    elif name == "@query":
        value = f"?{query or ''}"
    elif name == "@status":
        if status is None:
            value = None
        else:
            try:
                value = f"{_statusCode(status):03d}"
            except ValueError as ex:
                raise HttpSigSignatureMismatchError(
                    f"Signature base cannot be built: {ex}") from ex
    else:
        value = _fieldValue(fields, name)

    if value is None:
        raise HttpSigMissingComponentError(
            f"Covered component {_serialize(item)} is absent from the "
            "message.")
    return value


def signatureParams(*, created, keyid, expires=None, nonce=None, alg=None,
                    tag=None):
    """
    Returns dict of signature parameters in the order a signer emits them:
    created, expires, nonce, alg, keyid, tag, omitting those that are None.
    """
    values = dict(created=created, expires=expires, nonce=nonce, alg=alg,
                  keyid=keyid, tag=tag)
    return {name: values[name] for name in ParamOrder if values[name] is not None}


def _innerList(items, params):
    """The @signature-params Inner List, which is also the Signature-Input
    member, so the two are serialized by one function."""
    inner = http_sfv.InnerList()
    for item in items:
        copy = http_sfv.Item(item.value)
        copy.params.update(item.params)
        inner.append(copy)
    inner.params.update(params)
    return inner


def _signatureParamsValue(items, params):
    return str(_innerList(items, params))


def signatureBase(covered, params, *, method=None, authority=None, path=None,
                  query=None, headers=None, status=None, request=None,
                  scheme=None):
    """
    Returns the RFC 9421 section 2.5 signature base as str.

    Parameters:
        covered (list): component identifiers in signature order. Each is an
            http_sfv.Item, a serialized identifier such as '"@path";req' (must
            be lowercase), or a plain name (lowercased).
        params (Mapping): signature parameters, serialized in their own order.
            A signer passes signatureParams(...); a verifier passes the
            parameters exactly as parsed, so wire order is kept.
        method (str): @method, exactly as sent
        authority (str): target authority, host[:port]; None means Host
        path (str): @path as sent, percent-encoding included
        query (str): query as sent without the leading '?'; None or '' is none
            method, authority, path and query may each be bytes, decoded as
            latin-1.
        headers: target message fields, mapping or iterable of pairs
        status (int | str): response status, an int or a status line such
            as '200 OK'. Set means the target is a response.
        request (Requestage): request answered, for components marked req
        scheme (str): scheme the request was sent with, 'http' or 'https',
            whose default port @authority drops; None, as for a verifier that
            has only Host, drops none (profile section 2). Ignored for a
            response, whose req components use request.scheme.

    Raises:
        HttpSigMalformedSignatureInputError, HttpSigDuplicateComponentError,
        HttpSigUnsupportedComponentError, HttpSigMissingComponentError, and
        HttpSigSignatureMismatchError when a component value has a newline or
        a non-ASCII character, or @authority is not a valid authority, so the
        base cannot be built
    """
    response = status is not None
    items = _components(covered, response=response)
    fields = _fieldLines(headers)
    reqFields = _fieldLines(request.headers) if request is not None else {}

    lines = []
    for item in items:
        if "req" in item.params:
            if request is None:
                raise HttpSigMissingComponentError(
                    f"Component {_serialize(item)} needs the request, which "
                    "was not supplied.")
            value = _componentValue(item, method=request.method,
                                    authority=request.authority,
                                    path=request.path, query=request.query,
                                    fields=reqFields, status=None,
                                    scheme=request.scheme)
        else:
            value = _componentValue(item, method=method, authority=authority,
                                    path=path, query=query, fields=fields,
                                    status=status, scheme=scheme)
        if "\n" in value or "\r" in value or not value.isascii():
            raise HttpSigSignatureMismatchError(
                "Signature base cannot be built: the value of "
                f"{_serialize(item)} has a newline or a non-ASCII character.")
        lines.append(f"{_serialize(item)}: {value}")

    lines.append(f'"@signature-params": {_signatureParamsValue(items, params)}')
    return "\n".join(lines)


# Sign

# Minimum covered components of a request (profile section 3), besides
# content-digest when there is a body. No policy may go below it.
RequestMinimum = ("@method", "@path", "@query")

# Default covered components of a signed request (profile section 3), plus
# content-digest when there is a body.
RequestCovered = ("@method", "@authority", "@path", "@query")

# Signature algorithm of this profile version, and the key codes it covers.
Alg = "ed25519"
_Ed25519Codes = (MtrDex.Ed25519N, MtrDex.Ed25519)

Canonical = "canonical"
Legacy = "legacy"


def _now():
    return int(helping.nowUTC().timestamp())


def _nonce():
    """128 random bits, unpadded base64url (profile section 4)."""
    return base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode()


def _plainNames(items):
    """Names of covered components that carry no parameters."""
    return {item.value for item in items if not item.params}


# Refusals a signer reports by their profile code (sections 3 and 9), shared
# with the vectors' signer cases. Any other failure while signing is the
# caller's own mistake, not a peer's message, so it is a ValueError rather
# than an AuthNError a server would turn into a 401.
_SignerRefusals = ("uncovered-body", "insufficient-coverage")


@contextmanager
def _signerErrors():
    try:
        yield
    except HttpSigError as ex:
        if ex.code in _SignerRefusals:
            raise
        raise ValueError(f"Cannot sign ({ex.code}): {ex}") from ex


def _sign(items, *, signer, hab, keyid, label, created, expires, nonce, tag,
          alg, baseKwa):
    """
    Returns dict with Signature-Input and Signature for covered items over the
    message described by baseKwa (keyword arguments of signatureBase).
    """
    if (signer is None) == (hab is None):
        raise ValueError("Exactly one of signer or hab is required.")
    if hab is not None:
        verfer = effectiveVerfer(hab.kever.verfers, hab.kever.tholder)
        keyid = keyid if keyid is not None else hab.pre
    else:
        verfer = signer.verfer
        if keyid is None:
            if verfer.transferable:
                raise ValueError("A transferable key is not its own keyid; "
                                 "supply keyid, the signer's AID.")
            keyid = verfer.qb64
    if alg is not None and alg != Alg:
        raise ValueError(f"Unsupported signature algorithm {alg!r}.")
    if verfer.code not in _Ed25519Codes:
        raise HttpSigUnsupportedAlgorithmError(
            f"Key code {verfer.code} is not Ed25519.")

    params = signatureParams(
        created=created if created is not None else _now(),
        expires=expires,
        nonce=_nonce() if nonce is None else (nonce or None),
        alg=alg, keyid=keyid, tag=tag)
    base = signatureBase(items, params, **baseKwa).encode("utf-8")

    if hab is not None:
        raw = hab.sign(ser=base, verfers=[verfer], indexed=False)[0].raw
    else:
        raw = signer.sign(base).raw

    inputs = http_sfv.Dictionary()
    inputs[label] = _innerList(items, params)
    signatures = http_sfv.Dictionary()
    signatures[label] = raw
    return {"Signature-Input": str(inputs), "Signature": str(signatures)}


def signRequest(*, method, path, query=None, authority=None, headers=None,
                body=None, signer=None, hab=None, keyid=None, label="signify",
                covered=None, created=None, expires=None, nonce=None, tag=None,
                alg=Alg, scheme=None):
    """
    Sign a request in canonical mode.

    Returns dict of header fields to add to the request: Content-Digest when
    content-digest is covered, then Signature-Input and Signature.

    Parameters:
        method (str): method exactly as it will be sent
        path (str): path as sent, percent-encoding included
        query (str): query as sent without the leading '?'; None if none
        authority (str): target authority, host[:port]; None uses Host
        headers: request header fields, mapping or iterable of pairs
        body (bytes | str | None): content as sent
        signer (Signer): signing key. Exactly one of signer or hab.
        hab (Hab): single key habitat to sign with
        keyid (str): signer's AID. Defaults to hab.pre, or to the verfer of a
            non-transferable signer.
        label (str): signature label
        covered (list): components to cover. Default @method @authority @path
            @query, plus content-digest when body is non-empty.
        created (int): seconds since the epoch; None is now
        expires (int): optional expiry, seconds since the epoch
        nonce (str): None generates 128 random bits; False omits it
        tag (str): optional application tag
        alg (str): 'ed25519', or None to omit the parameter
        scheme (str): scheme of the target URI, whose default port @authority
            drops (profile section 2); None drops none

    Raises:
        HttpSigInsufficientCoverageError: covered falls short of
            RequestMinimum
        HttpSigUncoveredBodyError: non-empty body without covered
            content-digest
        ValueError: anything else that stops signing, such as an unsupported
            or duplicate component, a covered field that is absent or not
            ASCII, a hab without a single effective signer (R4), a key that
            is not Ed25519, or bad arguments. The message names the profile
            code, and the HttpSigError is chained as its cause.
    """
    with _signerErrors():
        raw = _bytify(body)
        if covered is None:
            covered = RequestCovered + (("content-digest",) if raw else ())
        items = _components(covered, response=False)
        _checkCoverage(items, RequestMinimum)
        added, fields = _digestFields(items, headers, raw, "request")

        added.update(_sign(items, signer=signer, hab=hab, keyid=keyid,
                           label=label, created=created, expires=expires,
                           nonce=nonce, tag=tag, alg=alg,
                           baseKwa=dict(method=method, authority=authority,
                                        path=path, query=query,
                                        headers=fields, scheme=scheme)))
    return added


def _digestFields(items, headers, raw, kind):
    """
    Returns (added, fields): the Content-Digest header to add when items cover
    content-digest, and the header fields to build the base from, carrying
    that value. A non-empty body without covered content-digest is
    HttpSigUncoveredBodyError.
    """
    added = {}
    fields = list(_fieldLines(headers).items())
    if "content-digest" in _plainNames(items):
        added["Content-Digest"] = contentDigest(raw)
        fields = [(n, v) for n, v in fields if n != "content-digest"]
        fields.append(("content-digest", added["Content-Digest"]))
    elif raw:
        raise HttpSigUncoveredBodyError(
            f"A {kind} with a body must cover content-digest.")
    return added, fields


_RequestDigest = '"content-digest";req'


def responseMinimum(requestHadBody):
    """
    Returns the minimum covered components of a response (profile section 3),
    besides its own content-digest when it has a body: @status and the
    request's @method, @path, @query and, when it had a body,
    content-digest, each marked req.
    """
    minimum = ["@status", '"@method";req', '"@path";req', '"@query";req']
    if requestHadBody:
        minimum.append('"content-digest";req')
    return minimum


def responseCovered(request, body):
    """
    Returns default covered components of a response to request (profile
    section 3): @status, content-digest when body is non-empty, and the
    request's @method, @path, @query and, when it had a body, content-digest,
    each marked req.
    """
    minimum = responseMinimum(bool(_bytify(request.body)))
    if _bytify(body):
        minimum.insert(1, "content-digest")
    return minimum


def signResponse(*, status, request, headers=None, body=None, signer=None,
                 hab=None, keyid=None, label="signify", covered=None,
                 created=None, expires=None, nonce=None, tag=None, alg=Alg):
    """
    Sign a response to a canonical request. Never use it to answer a legacy
    request: that is answered in legacy mode with ending.siginput and
    ending.signature (profile section 8), and a canonical response to it is
    refused by the client as mode-mismatch.

    Returns dict of header fields to add to the response, as signRequest.

    Parameters:
        status (int | str): response status code, or a line such as '200 OK'
        request (Requestage): the request being answered, as received, with
            body the bytes received (b'' for none); None or Deferred is a
            ValueError
        headers, body, signer, hab, keyid, label, created, expires, nonce, tag,
        alg: as for signRequest
        covered (list): default responseCovered(request, body); must include
            responseMinimum(request had a body)

    Raises:
        as signRequest, with the response minimum set; a request that has no
        Content-Digest, or one that does not match request.body, when
        "content-digest";req is covered, is a ValueError
    """
    _statusCode(status)  # a caller's bad status is a ValueError, up front
    _checkRequestBody(request)
    with _signerErrors():
        raw = _bytify(body)
        if covered is None:
            covered = responseCovered(request, raw)
        items = _components(covered, response=True)
        _checkCoverage(items, responseMinimum(bool(_bytify(request.body))))
        if _RequestDigest in {_serialize(item) for item in items}:
            # never bind a request digest that the request body contradicts
            value = _fieldValue(_fieldLines(request.headers), "content-digest")
            if value is None:
                raise HttpSigMissingComponentError(
                    "The request has no Content-Digest.")
            verifyContentDigest(value, request.body)
        added, fields = _digestFields(items, headers, raw, "response")

        added.update(_sign(items, signer=signer, hab=hab, keyid=keyid,
                           label=label, created=created, expires=expires,
                           nonce=nonce, tag=tag, alg=alg,
                           baseKwa=dict(status=status, headers=fields,
                                        request=request)))
    return added


# Verify

# Result of a successful verification.
#   mode (str): 'canonical' or 'legacy'
#   keyid (str): the signer's AID; in legacy mode the Signify-Resource value
#   label (str): signature label
#   params (dict): signature parameters in wire order
#   covered (tuple): serialized covered component identifiers
#   verfer (Verfer): key that verified the signature
#   bodyOwed (bool): True when the body was Deferred and checkBody has not yet
#       run. A Verified with bodyOwed True is NOT a completed verification.
#   request (Requestage): the verified request, from verifyRequest; None from
#       verifyResponse and verifyLegacy. Only when mode is 'canonical' is it
#       ready to pass to signResponse. A legacy request is answered in legacy
#       mode (profile section 8): sign the response with ending.siginput and
#       ending.signature over the request's method and path, as KERIA's
#       SignedHeaderAuthenticator.outbound does. signResponse would produce a
#       canonical response, which the client refuses as mode-mismatch.
Verified = namedtuple("Verified",
                      "mode keyid label params covered verfer bodyOwed request")


class _DeferredType:
    """Type of Deferred, the body argument meaning "not read yet"."""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self):
        return "Deferred"

    def __reduce__(self):
        return (_DeferredType, ())


# Pass as body to verifyRequest or verifyResponse to verify the headers before
# the body is read. The result then has bodyOwed True, and the caller MUST
# call checkBody with the body before the message reaches application code.
Deferred = _DeferredType()


def _checkRequestBody(request):
    """The Requestage a response answers must carry the request as sent."""
    if request.body is None or request.body is Deferred:
        raise ValueError("request.body must be the request content as sent, "
                         "bytes (b'' for none), not None or Deferred.")


def _checkBodyArg(body):
    if body is None:
        raise ValueError("body is required: the content as bytes (b'' for "
                         "none), or Deferred when it has not been read yet.")


@dataclass(frozen=True)
class Policy:
    """
    Verifier policy (profile sections 3 and 6).

    Attributes:
        request (tuple): minimum covered components of a request, besides
            content-digest when there is a body. Must include RequestMinimum.
            @authority is not listed here: requireAuthority adds it, together
            with the comparison against authorities.
        requireAuthority (bool): also require @authority, compared with
            authorities
        authorities (frozenset): authorities this verifier serves, compared
            with the covered @authority as built (profile section 2): lowercase,
            without the default port of the request's scheme when the verifier
            passes one, and with whatever port Host carries when it does not.
            Lowercased here; required when requireAuthority. Applies to
            canonical requests only; a legacy request covers no authority.
        maxAge (int): seconds a signature stays fresh after created; positive
        skew (int): tolerated clock skew in seconds; positive

    Raises ValueError for a policy below the profile's floor.
    """
    request: tuple = RequestMinimum
    requireAuthority: bool = False
    authorities: frozenset = frozenset()
    maxAge: int = 300
    skew: int = 60

    def __post_init__(self):
        if isinstance(self.authorities, (str, bytes)):
            raise ValueError("authorities must be a collection of authorities, "
                             "not a single str.")
        object.__setattr__(self, "authorities",
                           frozenset(normalizeAuthority(a)
                                     for a in self.authorities))
        try:
            # a component no request can cover would refuse every request
            items = _components(self.request, response=False)
        except HttpSigError as ex:
            raise ValueError(f"Policy request set is invalid: {ex}") from ex
        given = {_componentKey(item) for item in items}
        for component in RequestMinimum:
            if _componentKey(_component(component)) not in given:
                raise ValueError(f"Policy request set must include "
                                 f"{component} (profile section 3).")
        if (_componentKey(_component("@authority")) in given
                and not self.requireAuthority):
            # covering @authority without comparing it with the authorities
            # served would let a request signed for one service replay to
            # another (profile section 3)
            raise ValueError("Require @authority with requireAuthority and "
                             "authorities, not in the request set.")
        for name in ("maxAge", "skew"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"Policy {name} must be a positive int.")
        if self.requireAuthority and not self.authorities:
            raise ValueError("requireAuthority needs the configured authorities "
                             "this verifier serves.")


DefaultPolicy = Policy()

# Signature parameters of the profile, and their types (section 4)
_ParamTypes = dict(created=int, expires=int, nonce=str, alg=str, keyid=str,
                   tag=str)


# What keripy's parsers raise for input that does not parse: the legacy
# header parsers of keri.end.ending raise ValueError (unpacking, a missing
# field, http_sfv) or TypeError (a Signature-Input member that is not an
# Inner List), and CESR primitives raise KeriError subclasses (and
# ValueError for bad base64). Anything else is a bug and propagates.
_ParseErrors = (kering.KeriError, ValueError, TypeError)


_BareItemStart = frozenset(b"=,( \t")


def _padByteSequences(value):
    """
    Returns value, bytes, with '=' padding added to every Byte Sequence that
    lacks it, so that one without padding parses (profile section 5, RFC 8941
    section 4.2.7). A Byte Sequence begins with ':' where a bare item begins,
    outside a String, and ends at the next ':', since base64 has none.
    Anything else is left for the parser to judge.
    """
    out = bytearray()
    i, n = 0, len(value)
    while i < n:
        c = value[i]
        if c == 0x22:  # a String, with its escapes
            j = i + 1
            while j < n and value[j] != 0x22:
                j += 2 if value[j] == 0x5C else 1
            out += value[i:j + 1]
            i = j + 1
        elif c == 0x3A and (i == 0 or value[i - 1] in _BareItemStart):
            j = value.find(b":", i + 1)
            if j < 0:
                out += value[i:]
                break
            content = value[i + 1:j]
            if b"=" not in content and len(content) % 4 in (2, 3):
                content += b"=" * (4 - len(content) % 4)
            out += b":" + content + b":"
            i = j + 1
        else:
            out.append(c)
            i += 1
    return bytes(out)


def _parseDict(value):
    """Returns http_sfv.Dictionary parsed from value, accepting a Byte
    Sequence without padding. Raises ValueError when it does not parse."""
    if isinstance(value, str):
        value = value.encode("utf-8")
    members = http_sfv.Dictionary()
    members.parse(_padByteSequences(value))
    return members


def detectMode(value):
    """
    Returns 'canonical' or 'legacy' for a Signature field value (profile
    section 8): canonical when it parses as an RFC 8941 Dictionary whose every
    member is a Byte Sequence, legacy when keri.end.ending.designature accepts
    it.

    Raises:
        HttpSigMalformedSignatureError: neither
    """
    try:
        members = _parseDict(value)
    except ValueError:
        members = None
    if members and all(isinstance(m, http_sfv.Item) and isinstance(m.value, bytes)
                       for m in members.values()):
        return Canonical

    try:
        if _designature(value):
            return Legacy
    except _ParseErrors:
        pass
    raise HttpSigMalformedSignatureError(
        "Signature is neither an RFC 9421 Byte Sequence nor the legacy KERI "
        "form.")


def _designature(value):
    """
    Returns the signages keri.end.ending.designature parses from a legacy
    Signature value, refusing one whose members are not CESR signatures. The
    legacy parser accepts any kind and leaves the members of a kind other than
    CESR as strings, which carry no signature to verify, so such a header is
    not the legacy form of profile section 8.

    Raises:
        ValueError: a member that is not a CESR signature
    """
    signages = ending.designature(value)
    for signage in signages:
        for name, marker in signage.markers.items():
            if not isinstance(marker, (Siger, Cigar)):
                raise ValueError(f"Signature member {name} is not a CESR "
                                 f"signature (kind {signage.kind}).")
    return signages


def peekMode(headers):
    """
    Returns the mode a message's Signature header selects, 'canonical' or
    'legacy', or None when there is no Signature or it is neither form. Never
    raises, and verifies nothing; the counterpart of signatureKeyid, so a
    server can route before verifying.
    """
    signature = _fieldValue(_fieldLines(headers), "signature")
    if signature is None:
        return None
    try:
        return detectMode(signature)
    except HttpSigMalformedSignatureError:
        return None


def signatureKeyid(headers):
    """
    Returns the keyid a request claims, without verifying anything: the keyid
    parameter in canonical mode, the Signify-Resource field in legacy mode, or
    None. The value is untrusted until verifyRequest returns; it exists so that
    a server can find the agent that holds the key state before verifying.
    """
    fields = _fieldLines(headers)
    signature = _fieldValue(fields, "signature")
    if signature is None:
        return None
    try:
        mode = detectMode(signature)
    except HttpSigMalformedSignatureError:
        return None
    if mode == Legacy:
        return _fieldValue(fields, "signify-resource")
    try:
        members = _parseDict(_fieldValue(fields, "signature-input") or "")
    except ValueError:
        return None
    if len(members) != 1:
        return None
    member = next(iter(members.values()))
    keyid = getattr(member, "params", {}).get("keyid")
    return keyid if type(keyid) is str else None


def _parseInput(value):
    """
    Returns (label, items, params) from Signature-Input field value.

    Raises HttpSigMalformedSignatureInputError, then
    HttpSigMalformedSignatureLabelError.
    """
    try:
        members = _parseDict(value)
    except ValueError as ex:
        raise HttpSigMalformedSignatureInputError(
            f"Signature-Input does not parse: {ex}.") from ex
    if not members:
        raise HttpSigMalformedSignatureInputError("Signature-Input is empty.")
    parsed = []
    for label, member in members.items():
        if not isinstance(member, http_sfv.InnerList):
            raise HttpSigMalformedSignatureInputError(
                f"Signature-Input member {label} is not an Inner List.")
        items = [_component(item) for item in member]
        for name, val in member.params.items():
            kind = _ParamTypes.get(name)
            if kind is None:
                raise HttpSigMalformedSignatureInputError(
                    f"Unknown signature parameter {name}.")
            if type(val) is not kind:  # excludes bool, Token, Decimal
                raise HttpSigMalformedSignatureInputError(
                    f"Signature parameter {name} has the wrong type.")
        for name in ("created", "keyid"):
            if name not in member.params:
                raise HttpSigMalformedSignatureInputError(
                    f"Signature parameter {name} is required.")
        parsed.append((label, items, dict(member.params)))
    if len(parsed) != 1:
        raise HttpSigMalformedSignatureLabelError(
            "Signature-Input must carry exactly one label.")
    return parsed[0]


def _parseSignature(value, label):
    """
    Returns raw signature bytes for label from canonical Signature value.

    Raises HttpSigMalformedSignatureLabelError,
    HttpSigMissingSignatureLabelError, HttpSigMalformedSignatureValueError.
    """
    members = _parseDict(value)  # detectMode has already parsed it
    if len(members) != 1:
        raise HttpSigMalformedSignatureLabelError(
            "Signature must carry exactly one label.")
    if label not in members:
        raise HttpSigMissingSignatureLabelError(
            f"Signature has no member for label {label}.")
    raw = members[label].value
    if len(raw) != 64:
        raise HttpSigMalformedSignatureValueError(
            f"Signature is {len(raw)} bytes, not 64.")
    return raw


_Decimal = re.compile(r"\A[0-9]+\Z")


def _hasBody(fields):
    """Header-time body test of a request (profile section 3): Content-Length
    greater than zero or not a plain decimal, or any Transfer-Encoding."""
    if fields.get("transfer-encoding"):
        return True
    length = _fieldValue(fields, "content-length")
    if length is None:
        return False
    if not _Decimal.match(length):
        return True  # not a plain decimal: fail closed, assume a body
    return length.strip("0") != ""  # never int(), which refuses 4301 digits


def _checkCoverage(items, required):
    covered = {_componentKey(item) for item in items}
    for component in required:
        item = _component(component)
        if _componentKey(item) not in covered:
            raise HttpSigInsufficientCoverageError(f"Policy requires covering "
                                                   f"{_serialize(item)}.")


def sufficientVerfers(verfers, tholder):
    """
    Returns list of the current signing keys of a key state that each satisfy
    the signing threshold alone, in key state order (profile section 8).

    Parameters:
        verfers (list): current signing keys, Verfer instances
        tholder (Tholder): current signing threshold
    """
    return [verfer for index, verfer in enumerate(verfers)
            if tholder.satisfy(indices=[index])]


def effectiveVerfer(verfers, tholder):
    """
    Returns the single effective signing key of a key state (profile section
    7, R4): the one current key that satisfies the signing threshold on its
    own. A canonical signature carries no key index, so exactly one key may
    qualify. A plain single key state qualifies, and so does a Signify
    controller after a passcode rotation (keys [new, prior-next], threshold
    ['1', '0']). R4 applies to canonical mode only; legacy mode takes any of
    sufficientVerfers.

    Parameters:
        verfers (list): current signing keys, Verfer instances
        tholder (Tholder): current signing threshold

    Raises:
        HttpSigUnsupportedSignerError: no key, or more than one key,
            satisfies the threshold alone, e.g. a 2-of-3 group or '1' over
            two keys
    """
    alone = sufficientVerfers(verfers, tholder)
    if len(alone) != 1:
        raise HttpSigUnsupportedSignerError(
            "Key state has no single key that satisfies its signing threshold "
            "alone.")
    return alone[0]


def _honestPoint(raw):
    """Returns True when raw is the canonical encoding of an Ed25519 point
    of the prime-order subgroup, as every key derived from a seed is (profile
    R1). libsodium's check refuses a point of small order, under which a
    signature verifies over any message, and one of mixed order, a subgroup
    point plus a torsion component."""
    return (len(raw) == 32
            and pysodium.sodium.crypto_core_ed25519_is_valid_point(raw) == 1)


def _resolve(resolver, prefixer, alg):
    """
    Returns the verfer for a well-formed keyid (profile R1), checking alg
    against the key (section 4), with section 9's steps 14 to 17 in order.

    A B keyid's key is its prefix, whose subgroup check _checkAid has made,
    and no resolver is consulted for it. Any other non-transferable code is
    unsupported-algorithm. Every transferable code resolves through resolver;
    resolver None means no key state for any keyid.
    """
    keyid = prefixer.qb64
    if prefixer.code == PreDex.Ed25519N:
        verfer = Verfer(raw=prefixer.raw, code=MtrDex.Ed25519N)
    elif prefixer.code in NonTransDex:
        raise HttpSigUnsupportedAlgorithmError(
            f"keyid {keyid} is a non-transferable key that is not Ed25519.")
    else:
        verfer = resolver(keyid) if resolver is not None else None
        if verfer is None:  # step 14; a resolver raises step 15 itself
            raise HttpSigUnknownKeyError(f"No key state for {keyid}.")
        if verfer.code in _Ed25519Codes and not _honestPoint(verfer.raw):
            raise HttpSigMalformedKeyError(  # step 16
                f"Key {keyid} is not an Ed25519 key an honest signer holds: a "
                "signature can be forged for any message under a point "
                "outside the prime-order subgroup, so none is checked against "
                "it.")
        if verfer.code not in _Ed25519Codes:  # step 17
            raise HttpSigUnsupportedAlgorithmError(
                f"Key {keyid} is not an Ed25519 key.")
    if alg is not None and alg != Alg:
        raise HttpSigUnsupportedAlgorithmError(
            f"Signature algorithm {alg} is not supported.")
    return verfer


def _checkNow(now):
    """
    Returns now as whole seconds, rounded down (profile section 6), or None.

    now is the caller's clock, not a peer's input, so a value that is not a
    finite number is the caller's mistake: a NaN would make every freshness
    comparison false and pass a stale message.

    Raises:
        TypeError: now is not an int or float, or is a bool
        ValueError: now is a NaN or an infinity
    """
    if now is None:
        return None
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        raise TypeError(f"now must be a number of seconds since the epoch, or "
                        f"None for the system clock, not {now!r}.")
    if isinstance(now, float) and not math.isfinite(now):
        raise ValueError(f"now must be finite, not {now!r}.")
    return math.floor(now)


def _checkFreshness(params, policy, now):
    now = _now() if now is None else now
    created = params["created"]
    if created < now - policy.maxAge - policy.skew or created > now + policy.skew:
        raise HttpSigSignatureStaleError(
            f"Signature created at {created} is outside the freshness window.")
    expires = params.get("expires")
    if expires is not None and expires < now - policy.skew:
        raise HttpSigSignatureExpiredError(f"Signature expired at {expires}.")


def _verifyCanonical(*, fields, required, resolver, policy, now, baseKwa,
                     response, expectKeyid=None, served=None):
    """Header, covered list, key, base, signature and freshness checks, in the
    order of profile section 9, steps 6 to 21. served, when not None, is the
    set of authorities a covered @authority must be in."""
    label, items, params = _parseInput(_fieldValue(fields, "signature-input"))
    raw = _parseSignature(_fieldValue(fields, "signature"), label)

    items = _components(items, response=response)
    _checkCoverage(items, required)

    keyid = params["keyid"]
    prefixer = _checkAid(keyid)  # step 13
    if expectKeyid is not None and keyid != expectKeyid:
        # step 14, before any key state is read
        raise HttpSigUnknownKeyError(
            f"Signed by {keyid}, not by {expectKeyid}.")
    verfer = _resolve(resolver, prefixer, params.get("alg"))

    base = signatureBase(items, params, **baseKwa)
    if served is not None and "@authority" in _plainNames(items):
        authority = _authorityValue(baseKwa.get("authority"), fields,
                                    baseKwa.get("scheme"))
        if authority not in served:
            raise HttpSigSignatureMismatchError(
                f"Signature is for authority {authority}, which this verifier "
                "does not serve.")
    if not verfer.verify(sig=raw, ser=base.encode("utf-8")):
        raise HttpSigSignatureMismatchError("Signature does not verify.")

    _checkFreshness(params, policy, now)
    return Verified(mode=Canonical, keyid=keyid, label=label, params=params,
                    bodyOwed=False, request=None,
                    covered=tuple(_serialize(item) for item in items),
                    verfer=verfer)


def verifyRequest(*, method, path, query=None, authority=None, headers,
                  body, resolver=None, policy=None, now=None,
                  acceptLegacy=True, scheme=None):
    """
    Verify a signed request in either mode (profile section 8).

    Returns Verified.

    The body check may be deferred, but never forgotten. Pass the body as
    bytes and the returned Verified is complete (bodyOwed False). Pass
    body=Deferred to verify on headers alone, before reading the body, which
    rejects forgeries cheaply; the returned Verified then has bodyOwed True
    and is NOT a completed verification: read the body, call
    checkBody(verified, headers, body), and use the Verified it returns. A
    request must not reach application code while bodyOwed is True
    (profile section 5). Either way the body stage, steps 22 to 24 of profile
    section 9, runs after the signature and freshness checks, so a verifier
    that holds the body and one that reads it later report the same code.

    Parameters:
        method (str): method as received
        path (str): path as received, percent-encoding included
        query (str): raw query without the leading '?'; None if none
        authority (str): authority of the target URI, host[:port]; None uses
            Host, from which only SP and HTAB are trimmed
        scheme (str): scheme the request was sent with, 'http' or 'https',
            when the verifier knows it; @authority then drops that scheme's
            default port. None, as for a verifier that has only Host, drops
            no port (profile section 2).
        headers: request header fields, mapping or iterable of pairs
        body (bytes | Deferred): content as received, b'' for none, or
            Deferred when not yet read. Required; None is a ValueError.
        resolver (callable | None): keyid -> Verfer for a transferable
            canonical keyid, with a .legacy(aid) lookup for legacy mode
            (without one, legacy mode calls the resolver itself); see
            KeverResolver. A canonical keyid that is not an AID is
            malformed-key before any resolver is called, and a B keyid's key
            is its prefix, so no resolver is consulted for it either. None
            means no key state is known: a transferable keyid is unknown-key.
            A custom resolver returns a Verfer, or None for unknown-key, or
            raises an HttpSigError subclass; any other exception it raises
            propagates unchanged. Its .legacy(aid) returns the keys that each
            satisfy the threshold alone, a list (a single Verfer is one key).
        policy (Policy): default Policy()
        now (int | float): seconds since the epoch, rounded down to whole
            seconds; None is now. Anything but a finite int or float (a bool
            included) is a TypeError or ValueError, since it is the caller's
            clock and not the peer's message.
        acceptLegacy (bool): False refuses legacy mode as malformed-signature

    Raises:
        HttpSigError subclass for the first check that fails (section 9)
    """
    _checkBodyArg(body)
    now = _checkNow(now)
    policy = policy if policy is not None else DefaultPolicy
    fields = _fieldLines(headers)
    signature = _fieldValue(fields, "signature")
    if signature is None:
        raise HttpSigMissingSignatureError("Request has no Signature.")
    if _fieldValue(fields, "signature-input") is None:
        raise HttpSigMissingSignatureInputError(
            "Request has no Signature-Input.")

    if authority is None:
        authority = _fieldValue(fields, "host")

    if detectMode(signature) == Legacy:
        if not acceptLegacy:
            raise HttpSigMalformedSignatureError(
                "Legacy signatures are not accepted.")
        verified = _verifyLegacyRequest(method=method, path=path,
                                        fields=fields, resolver=resolver)
        return verified._replace(request=Requestage(
            method=method, authority=authority, path=path, query=query,
            headers=fields, body=body, scheme=scheme))

    required = list(policy.request)
    if policy.requireAuthority:
        required.append("@authority")
    if _hasBody(fields):  # by the headers alone (profile section 3)
        required.append("content-digest")

    verified = _verifyCanonical(
        fields=fields, required=required, resolver=resolver, policy=policy,
        now=now, response=False,
        served=policy.authorities if policy.requireAuthority else None,
        baseKwa=dict(method=method, authority=authority, path=path,
                     query=query, headers=fields, scheme=scheme))
    verified = verified._replace(request=Requestage(
        method=method, authority=authority, path=path, query=query,
        headers=fields, body=body, scheme=scheme))
    return _bodyStage(verified, fields, body)


def _bodyStage(verified, fields, body):
    if body is Deferred:
        return verified._replace(bodyOwed=verified.mode == Canonical)
    return checkBody(verified, fields, body)


def checkBody(verified, headers, body):
    """
    Post-read body check of a verified message (profile sections 3 and 5): a
    non-empty body without covered content-digest is refused, and a covered
    Content-Digest is recomputed over the content received. Both must pass
    before the message reaches application code. Legacy mode covers no body,
    so there it checks nothing.

    Returns the Verified with bodyOwed False. Use the returned value; the
    one passed in still says the body check is owed.

    Parameters:
        verified (Verified): result of verifyRequest or verifyResponse
        headers: the message's header fields
        body (bytes): content as received, b'' for none

    Raises:
        HttpSigInsufficientCoverageError, HttpSigMalformedDigestError,
        HttpSigDigestMismatchError, and ValueError for a body that is None or
        Deferred
    """
    _checkBodyArg(body)
    if body is Deferred:
        raise ValueError("checkBody needs the body that was read.")
    if verified.request is not None:
        verified = verified._replace(
            request=verified.request._replace(body=body))
    if verified.mode != Canonical:
        return verified._replace(bodyOwed=False)
    raw = _bytify(body)
    if '"content-digest"' not in verified.covered:
        if raw:
            raise HttpSigInsufficientCoverageError(
                "Body is not covered by content-digest.")
        return verified._replace(bodyOwed=False)
    value = _fieldValue(_fieldLines(headers), "content-digest")
    if value is None:
        raise HttpSigMissingComponentError("Covered content-digest is absent.")
    verifyContentDigest(value, raw)
    return verified._replace(bodyOwed=False)


def verifyResponse(*, status, headers, body, request, keyid, resolver=None,
                   requestMode=Canonical, policy=None, now=None):
    """
    Verify the response to a request this client signed.

    Returns Verified.

    Parameters:
        status (int | str): response status code, or a line such as '200 OK'.
            A status without a three digit code is signature-mismatch.
        headers: response header fields
        body (bytes | Deferred): response content as received, b'' for none.
            A client holds a response's content before it verifies it, and
            profile section 9 judges it at the covered list (step 12), so
            pass it. Deferred checks the headers first; the result then has
            bodyOwed True and checkBody must follow, as for verifyRequest, and
            refuses uncovered content there with the same code,
            insufficient-coverage. Only a response with that defect and a
            later one too, such as an altered status, is reported differently
            when deferred, by the later defect's code.
        request (Requestage): the request as sent, with body the bytes sent
            (b'' for none); None or Deferred is a ValueError
        resolver (callable | None): keyid -> Verfer for a transferable
            canonical keyid, with a .legacy(aid) lookup for legacy mode
            (without one, legacy mode calls the resolver itself); see
            KeverResolver. A canonical keyid that is not an AID is
            malformed-key before any resolver is called, and a B keyid's key
            is its prefix, so no resolver is consulted for it either. None
            means no key state is known: a transferable keyid is unknown-key.
            A custom resolver returns a Verfer, or None for unknown-key, or
            raises an HttpSigError subclass; any other exception it raises
            propagates unchanged. Its .legacy(aid) returns the keys that each
            satisfy the threshold alone, a list (a single Verfer is one key).
        keyid (str): AID the client expects to be talking to. Required; one
            that is not a well-formed AID, or a B AID whose key is not a
            point of the prime-order subgroup, is a ValueError (profile R1).
            A response keyid that is well formed but different is
            unknown-key, checked after malformed-key and before any resolver
            or alg check.
        requestMode (str): mode the request was signed in, 'canonical' or
            'legacy'. A response in the other mode is mode-mismatch
            (section 8).
        policy (Policy): freshness settings; default Policy()
        now (int | float): seconds since the epoch, rounded down; None is
            now. As for verifyRequest, anything but a finite number is a
            TypeError or ValueError.

    When the response covers "content-digest";req, the request's
    Content-Digest is recomputed over request.body.

    Raises:
        HttpSigUnauthenticatedError: unsigned 401 to a canonical request
        HttpSigError subclass for the first check that fails (section 9)
    """
    _checkBodyArg(body)
    _checkRequestBody(request)
    if not isinstance(keyid, str) or not keyid:
        # without it the expected-AID check (profile R1) would be skipped
        raise ValueError("keyid, the AID the client expects to be talking "
                         "to, is required.")
    try:
        _checkAid(keyid)
    except HttpSigMalformedKeyError as ex:
        # the caller's expectation, not the peer's message
        raise ValueError(f"Expected keyid is not usable: {ex}") from ex
    now = _checkNow(now)
    if requestMode not in (Canonical, Legacy):
        raise ValueError(f"Unknown requestMode {requestMode!r}.")
    policy = policy if policy is not None else DefaultPolicy
    fields = _fieldLines(headers)
    signature = _fieldValue(fields, "signature")
    if not signature:
        # an empty Signature header is no signature (section 8)
        try:
            unauthorized = _statusCode(status) == 401
        except ValueError:
            unauthorized = False
        if requestMode == Canonical and unauthorized:
            raise HttpSigUnauthenticatedError("Server refused the request's "
                                              "authentication (unsigned 401).")
        raise HttpSigMissingSignatureError("Response has no Signature.")
    if _fieldValue(fields, "signature-input") is None:
        raise HttpSigMissingSignatureInputError(
            "Response has no Signature-Input.")

    mode = detectMode(signature)
    if mode != requestMode:
        raise HttpSigModeMismatchError(
            f"{mode.capitalize()} response to a {requestMode} request.")
    if mode == Legacy:
        resource = _fieldValue(fields, "signify-resource")
        if resource is None:
            raise HttpSigMissingComponentError(
                "Missing SIGNIFY-RESOURCE header")
        if resource != keyid:
            raise HttpSigUnknownKeyError(
                f"Response names {resource}, not {keyid}.")
        verfers = _legacyVerfers(resolver, keyid)
        return verifyLegacy(method=request.method, path=request.path,
                            headers=fields, verfers=verfers)

    # A response's body is its content; its Content-Length is not evidence,
    # since a HEAD or 304 response announces a length it does not send. A
    # deferred body is checked by checkBody.
    required = responseMinimum(bool(_bytify(request.body)))
    if body is not Deferred and _bytify(body):
        required.append("content-digest")

    verified = _verifyCanonical(
        fields=fields, required=required, resolver=resolver, policy=policy,
        now=now, response=True, expectKeyid=keyid,
        baseKwa=dict(status=status, headers=fields, request=request))

    # Body: parse every covered digest before comparing any, then recompute
    # the request's over the body the client kept; the response's own is
    # compared now, or by checkBody when the body is Deferred.
    reqDigest = _RequestDigest in verified.covered
    if '"content-digest"' in verified.covered:
        _parseDigest(_fieldValue(fields, "content-digest"))
    if reqDigest:
        reqFields = _fieldLines(request.headers)
        _compareDigest(_parseDigest(_fieldValue(reqFields, "content-digest")),
                       request.body)
    return _bodyStage(verified, fields, body)


# Legacy mode

def _legacyBase(inputage, *, method, path, fields):
    """
    Returns the legacy KERI signature base for inputage, bytes, exactly as
    KERIA's SignedHeaderAuthenticator.inbound builds it: derived components
    other than @method and @path are dropped, covered fields that are absent
    are skipped, and the final line keeps the legacy quote placement and
    unquoted parameter values.
    """
    method, path = _text(method), _text(path)
    items = []
    for field in inputage.fields:
        if field.startswith("@"):
            if field == "@method":
                items.append(f'"{field}": {method}')
            elif field == "@path":
                items.append(f'"{field}": {path}')
        else:
            field = field.lower()
            if field not in fields:
                continue
            value = ending.normalize(",".join(fields[field]))
            items.append(f'"{field}": {value}')

    values = [f"({' '.join(inputage.fields)})", f"created={inputage.created}"]
    if inputage.expires is not None:
        values.append(f"expires={inputage.expires}")
    if inputage.nonce is not None:
        values.append(f"nonce={inputage.nonce}")
    if inputage.keyid is not None:
        values.append(f"keyid={inputage.keyid}")
    if inputage.context is not None:
        values.append(f"context={inputage.context}")
    if inputage.alg is not None:
        values.append(f"alg={inputage.alg}")

    params = ";".join(values)
    items.append(f'"@signature-params: {params}"')
    return "\n".join(items).encode("utf-8")


def verifyLegacy(*, method, path, headers, verfer=None, verfers=None,
                 label="signify"):
    """
    Verify a message signed in legacy mode (keri.end.ending.siginput and
    signature), exactly as KERIA's SignedHeaderAuthenticator.inbound does, so
    that today's traffic keeps verifying byte for byte. No freshness check, and
    neither query nor body is covered (profile sections 6 and 8).

    Resolving the signer is the caller's business; KERIA looks the controller
    up by Signify-Resource. A legacy signature is not indexed, so nothing on
    the wire says which key made it: the caller passes every current key that
    alone satisfies the controller's signing threshold (sufficientVerfers,
    profile section 8), and the signature is accepted when it verifies under
    any of them. A response is verified with the method and path of the
    request it answers.

    Returns Verified with mode 'legacy'; keyid is the Signify-Resource value
    (the AID the message claims), or the keyid parameter when that field is
    absent; verfer is the key the signature verified under.

    Parameters:
        method (str): request method
        path (str): request path, as KERIA passes it
        headers: message header fields, mapping or iterable of pairs
        verfer (Verfer): the one key to verify with; or
        verfers (list): the keys to try, in order. Exactly one of verfer and
            verfers; an empty verfers is unsupported-signer.
        label (str): signature label; legacy Signify uses 'signify'

    Raises:
        HttpSigMissingSignatureError, HttpSigMissingSignatureInputError,
        HttpSigUnsupportedSignerError, HttpSigMalformedSignatureInputError
        (including a covered item that is not a String),
        HttpSigMalformedSignatureError, HttpSigMissingSignatureLabelError,
        HttpSigSignatureMismatchError (verifies under none of the keys)
    """
    if (verfer is None) == (verfers is None):
        raise ValueError("Exactly one of verfer or verfers is required.")
    verfers = [verfer] if verfer is not None else list(verfers)
    fields = _fieldLines(headers)
    signature = _fieldValue(fields, "signature")
    siginput = _fieldValue(fields, "signature-input")
    if siginput is None:
        raise HttpSigMissingSignatureInputError(
            "Missing SIGNATURE-INPUT header")
    if signature is None:
        raise HttpSigMissingSignatureError("Missing SIGNATURE header")
    if not verfers:
        raise HttpSigUnsupportedSignerError(
            "No current key satisfies the signing threshold alone.")

    try:
        inputs = ending.desiginput(siginput.encode("utf-8"))
    except _ParseErrors as ex:
        raise HttpSigMalformedSignatureInputError(
            f"Legacy Signature-Input does not parse: {ex}.") from ex
    for inputage in inputs:
        if not all(isinstance(field, str) for field in inputage.fields):
            raise HttpSigMalformedSignatureInputError(
                f"Legacy Signature-Input {inputage.name} covers an item that "
                "is not a String.")
    inputs = [i for i in inputs if i.name == label]
    if not inputs:
        raise HttpSigMissingSignatureLabelError(
            f"Missing {label} inputs in signature")

    try:
        signages = _designature(signature)
    except _ParseErrors as ex:
        raise HttpSigMalformedSignatureError(
            f"Legacy Signature does not parse: {ex}.") from ex

    signed = []
    for inputage in inputs:
        marker = signages[0].markers.get(inputage.name)
        if marker is None:
            raise HttpSigMissingSignatureLabelError(
                f"Signature has no member for label {inputage.name}.")
        signed.append((_legacyBase(inputage, method=method, path=path,
                                   fields=fields), marker.raw))

    for candidate in verfers:
        if candidate.code in _Ed25519Codes and not _honestPoint(candidate.raw):
            continue  # under such a key a signature verifies over anything
        if all(candidate.verify(sig=raw, ser=ser) for ser, raw in signed):
            break
    else:
        raise HttpSigSignatureMismatchError(
            f"Signature for {inputs[0]} invalid")

    inputage = inputs[0]
    params = {name: getattr(inputage, name)
              for name in ("created", "expires", "nonce", "keyid", "context",
                           "alg")
              if getattr(inputage, name) is not None}
    resource = _fieldValue(fields, "signify-resource")
    return Verified(mode=Legacy, bodyOwed=False, request=None,
                    keyid=resource if resource is not None else inputage.keyid,
                    label=inputage.name, params=params,
                    covered=tuple(inputage.fields), verfer=candidate)


def _legacyVerfers(resolver, aid):
    """
    Legacy key lookup (profile section 8): returns the list of keys to try,
    from resolver.legacy(aid) when the resolver has it, else from
    resolver(aid) itself. A lookup may return a Verfer, which is one key, or
    a list of them; None is unknown-key. Legacy mode never takes a key from a
    prefix: without key state even a B AID is unknown-key.
    """
    if resolver is None:
        raise HttpSigUnknownKeyError(
            "Unknown or invalid controller (controller KEL not resolved)")
    lookup = getattr(resolver, "legacy", resolver)
    found = lookup(aid)
    if found is None:
        raise HttpSigUnknownKeyError(
            "Unknown or invalid controller (controller KEL not resolved)")
    if isinstance(found, Verfer):
        return [found]
    found = list(found)
    if not found:
        raise HttpSigUnsupportedSignerError(
            "No current key satisfies the signing threshold alone.")
    return found


def _verifyLegacyRequest(*, method, path, fields, resolver):
    """Legacy request: the signer is the AID named by Signify-Resource, in
    the order of profile section 9's legacy list."""
    resource = _fieldValue(fields, "signify-resource")
    if resource is None:
        raise HttpSigMissingComponentError("Missing SIGNIFY-RESOURCE header")
    verfers = _legacyVerfers(resolver, resource)
    return verifyLegacy(method=method, path=path, headers=fields,
                        verfers=verfers)


# Resolvers

def _checkAid(keyid):
    """Returns Prefixer of keyid, or raises HttpSigMalformedKeyError when it
    is not the canonical qb64 spelling of an AID under one of keripy's PreDex
    codes, or is a B AID whose key is not a point of the prime-order subgroup
    (profile R1, section 9 step 13). That key is in the keyid itself, so it
    is refused before any resolver is consulted, as for a verifier with no
    key state for it at all."""
    if not isinstance(keyid, str):
        raise HttpSigMalformedKeyError(f"keyid {keyid!r} is not an AID.")
    try:
        prefixer = Prefixer(qb64=keyid)
    except _ParseErrors as ex:
        raise HttpSigMalformedKeyError(
            f"keyid {keyid!r} is not an AID.") from ex
    if prefixer.qb64 != keyid or prefixer.code not in PreDex:
        raise HttpSigMalformedKeyError(f"keyid {keyid!r} is not an AID.")
    if prefixer.code == PreDex.Ed25519N and not _honestPoint(prefixer.raw):
        raise HttpSigMalformedKeyError(
            f"keyid {keyid!r} is a key outside the prime-order subgroup, "
            "under which a signature can be forged.")
    return prefixer


class KeverResolver:
    """
    Resolves keyids against key state kevers, e.g. hab.kevers or a Baser's
    kevers.

    Calling it resolves a canonical keyid (profile section 7, R1 and R4): the
    keyid is an AID in qb64 resolved by its derivation code, never by its
    first character alone. Every transferable code, including the basic
    transferable Ed25519 prefix, must have key state in kevers, and the key
    returned is that state's single effective signer (effectiveVerfer). The
    verifiers of this module never call it for a B keyid, whose key is its
    prefix; called directly, it returns that key. Another non-transferable
    code is unsupported-algorithm.

    .legacy(aid) is the legacy lookup (profile section 8): every current key
    of kevers[aid] that alone satisfies its signing threshold
    (sufficientVerfers), without canonical mode's derivation-code rules. For
    a Signify controller with one key, or after a passcode rotation, that is
    its first current key alone; for '1' over two keys it is both. A key state
    in which no key alone suffices, such as a 2-of-3 group, is
    unsupported-signer.

    Both use in and [] on kevers, never get: Baser.kevers reads through to
    the database on in and [] only, so get would miss key state that is
    stored but not yet cached, as after a restart.

    Attributes:
        kevers (Mapping): prefix qb64 -> Kever
    """

    def __init__(self, kevers):
        self.kevers = kevers

    def __call__(self, keyid):
        prefixer = _checkAid(keyid)

        if prefixer.code == PreDex.Ed25519N:
            return Verfer(raw=prefixer.raw, code=MtrDex.Ed25519N)
        if prefixer.code in NonTransDex:
            raise HttpSigUnsupportedAlgorithmError(
                f"keyid {keyid} is a non-transferable key that is not "
                "Ed25519.")

        if keyid not in self.kevers:
            raise HttpSigUnknownKeyError(f"No key state for {keyid}.")
        kever = self.kevers[keyid]
        return effectiveVerfer(kever.verfers, kever.tholder)

    def legacy(self, aid):
        """Returns list of the current keys of aid's key state that each
        satisfy its signing threshold alone, in key state order.

        Raises:
            HttpSigUnknownKeyError: no key state for aid, with KERIA's legacy
                message
            HttpSigUnsupportedSignerError: no key satisfies the threshold
                alone
        """
        if aid not in self.kevers:
            raise HttpSigUnknownKeyError(
                "Unknown or invalid controller (controller KEL not resolved)")
        kever = self.kevers[aid]
        verfers = sufficientVerfers(kever.verfers, kever.tholder)
        if not verfers:
            raise HttpSigUnsupportedSignerError(
                "No current key satisfies the signing threshold alone.")
        return verfers


def keverResolver(kevers):
    """Returns KeverResolver(kevers)."""
    return KeverResolver(kevers)
