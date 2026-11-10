# -*- encoding: utf-8 -*-
"""
keri.end.httpsigning module

Canonical RFC 9421 HTTP Message Signatures under the KERI profile, with RFC
9530 Content-Digest, plus a verifier for the legacy KERI signed-header scheme
of keri.end.ending so a server can accept both while clients upgrade.

The profile itself (covered components, parameters, keyid resolution, mode
selection and the refusal codes) is specified in the "KERI profile of RFC 9421
HTTP Message Signatures", version 1, published at
https://github.com/bakobo/fiki/blob/main/docs/keri-profile.md
Section numbers in comments below refer to it where they say "profile", and to
RFC 9421 otherwise.

This module takes plain values (method, authority, path, query, headers, body)
rather than a framework request object, so any server or client can adapt to
it. It depends on nothing that is not also present on the keripy 1.2.x line.

The legacy functions in keri.end.ending are deliberately left untouched.
"""
import base64
import hashlib
import hmac
import re
import secrets
from collections import namedtuple
from collections.abc import Mapping
from dataclasses import dataclass

import http_sfv

from .. import kering
from ..core.coring import MtrDex, PreDex, NonTransDex, Prefixer, Verfer
from ..help import helping


# Errors. Each refusal carries the profile section 9 code as .code so that a
# caller, and the shared test vectors, can name refusals independently of this
# implementation's class names.

class HttpSigError(kering.AuthNError):
    """
    Base class for HTTP message signature refusals.

    Subclasses kering.AuthNError so that a server which already maps AuthNError
    to 401 refuses these without a new except clause.

    Attributes:
        code (str): kebab-case refusal code from profile section 9
    """
    code = "http-signature-error"


class MissingSignature(HttpSigError):
    """No Signature header, or an unsigned response."""
    code = "missing-signature"


class MissingSignatureInput(HttpSigError):
    """No Signature-Input header."""
    code = "missing-signature-input"


class MalformedSignature(HttpSigError):
    """Signature header is neither canonical nor legacy form, or legacy mode
    is refused by configuration."""
    code = "malformed-signature"


class MalformedSignatureInput(HttpSigError):
    """Signature-Input does not parse, names an uppercase field, or carries an
    unknown or ill-typed parameter."""
    code = "malformed-signature-input"


class MalformedSignatureLabel(HttpSigError):
    """Other than exactly one label."""
    code = "malformed-signature-label"


class MissingSignatureLabel(HttpSigError):
    """Signature and Signature-Input name different labels."""
    code = "missing-signature-label"


class MalformedSignatureValue(HttpSigError):
    """Signature member is not a 64 byte Byte Sequence."""
    code = "malformed-signature-value"


class ModeMismatch(HttpSigError):
    """A legacy response to a canonical request."""
    code = "mode-mismatch"


class DuplicateComponent(HttpSigError):
    """The same component appears twice in one covered list."""
    code = "duplicate-component"


class UnsupportedComponent(HttpSigError):
    """A component or component parameter this profile does not support."""
    code = "unsupported-component"


class InsufficientCoverage(HttpSigError):
    """The policy minimum set is not covered, including a body without a
    covered content-digest."""
    code = "insufficient-coverage"


class MalformedKey(HttpSigError):
    """The keyid is not a well formed AID."""
    code = "malformed-key"


class UnknownKey(HttpSigError):
    """No key state for a transferable keyid."""
    code = "unknown-key"


class UnsupportedSigner(HttpSigError):
    """Key state without a single effective signer (profile R4)."""
    code = "unsupported-signer"


class UnsupportedAlgorithm(HttpSigError):
    """An alg other than ed25519, or one that disagrees with the key."""
    code = "unsupported-algorithm"


class MissingComponent(HttpSigError):
    """A covered component is absent from the message."""
    code = "missing-component"


class SignatureMismatch(HttpSigError):
    """The signature does not verify over the signature base."""
    code = "signature-mismatch"


class SignatureStale(HttpSigError):
    """created is outside the freshness window."""
    code = "signature-stale"


class SignatureExpired(HttpSigError):
    """expires is in the past."""
    code = "signature-expired"


class MalformedDigest(HttpSigError):
    """Content-Digest does not parse or has no recognized algorithm."""
    code = "malformed-digest"


class DigestMismatch(HttpSigError):
    """Content-Digest does not match the content."""
    code = "digest-mismatch"


class UncoveredBody(HttpSigError):
    """Signer side only: a non-empty body without a covered content-digest."""
    code = "uncovered-body"


class Unauthenticated(HttpSigError):
    """
    An unsigned 401 answering a canonical request (profile sections 8 and 9).
    Response only, and checked before any other response check: the server
    refused the request's authentication, and the body of its response is not
    to be trusted.
    """
    code = "unauthenticated"


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
        MalformedDigest: value does not parse, a recognized member is not a
            Byte Sequence, or no member is recognized
        DigestMismatch: a recognized member does not match body
    """
    _compareDigest(_parseDigest(value), body)


def _parseDigest(value):
    """
    Returns list of (alg, digest bytes) for the recognized members of a
    Content-Digest value, so that every covered digest can be parsed before
    any is compared (malformed-digest precedes digest-mismatch).

    Raises MalformedDigest.
    """
    if isinstance(value, str):
        value = value.encode("utf-8")
    members = http_sfv.Dictionary()
    try:
        members.parse(value)
    except ValueError as ex:
        raise MalformedDigest(f"Content-Digest does not parse: {ex}.") from ex

    recognized = []
    for alg, member in members.items():
        if alg not in DigestAlgs:
            continue
        if not isinstance(member, http_sfv.Item) or not isinstance(member.value, bytes):
            raise MalformedDigest(f"Content-Digest member {alg} is not a Byte "
                                  f"Sequence.")
        recognized.append((alg, member.value))

    if not recognized:
        raise MalformedDigest("Content-Digest has no sha-256 or sha-512 member.")
    return recognized


def _compareDigest(recognized, body):
    """Raises DigestMismatch unless every recognized digest matches body."""
    raw = _bytify(body)
    for alg, digest in recognized:
        if not hmac.compare_digest(DigestAlgs[alg](raw).digest(), digest):
            raise DigestMismatch(f"Content-Digest {alg} does not match the "
                                 f"content.")


# Signature base, RFC 9421 section 2

# Derived components this profile supports (profile section 2). @status only
# in a response.
Derived = ("@method", "@authority", "@path", "@query", "@status")

# Order in which a signer emits signature parameters (profile section 4).
ParamOrder = ("created", "expires", "nonce", "alg", "keyid", "tag")

# Request a response answers, as the requester sent it or the server received
# it. headers as for signatureBase. body is the content, bytes.
Requestage = namedtuple("Requestage", "method authority path query headers body")

_OBSFOLD = re.compile(r"[ \t]*\r?\n[ \t]+")


def _fieldLines(headers):
    """
    Returns dict mapping lowercased field name to list of field line values in
    the order received.

    headers may be a mapping (including multidicts whose .items() yields
    repeated names) or an iterable of (name, value) pairs. A list or tuple
    value is several field lines. bytes names and values are decoded as
    latin-1.
    """
    fields = {}
    if headers is None:
        return fields
    items = headers.items() if isinstance(headers, Mapping) else headers
    for name, value in items:
        lines = fields.setdefault(_latin1(name).lower(), [])
        if isinstance(value, (list, tuple)):
            lines.extend(_latin1(v) for v in value)
        else:
            lines.append(_latin1(value))
    return fields


def _latin1(value):
    """Header names and values given as bytes are decoded as latin-1, as WSGI
    does, so every byte survives and a non-ASCII one refuses the base."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("latin-1")
    return str(value)


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
    return ", ".join(_OBSFOLD.sub(" ", line).strip(" \t") for line in lines)


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
            raise MalformedSignatureInput(f"Component identifier {component} "
                                          f"does not parse.") from ex
    elif isinstance(component, str) and component:
        return http_sfv.Item(component.lower())
    else:
        raise MalformedSignatureInput(f"Invalid component identifier "
                                      f"{component!r}.")

    if type(item.value) is not str or not item.value:  # String, not Token
        raise MalformedSignatureInput(f"Component identifier {item} is not a "
                                      f"String.")
    if item.value != item.value.lower():
        raise MalformedSignatureInput(f"Component identifier {item} is not "
                                      f"lowercase.")
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
            raise DuplicateComponent(f"Component {_serialize(item)} is covered "
                                     f"more than once.")
        seen.add(key)

    for item in items:
        name = item.value
        for param, value in item.params.items():
            if param != "req" or value is not True:
                raise UnsupportedComponent(f"Component {_serialize(item)} has "
                                           f"unsupported parameter {param}.")
            if not response:
                raise UnsupportedComponent(f"Component {_serialize(item)}: req "
                                           f"is only valid in a response.")
        if name.startswith("@"):
            if name not in Derived:
                raise UnsupportedComponent(f"Derived component {name} is not "
                                           f"supported.")
            if name == "@status" and (not response or "req" in item.params):
                raise UnsupportedComponent(f"Component {_serialize(item)} is "
                                           f"only valid on a response.")
            if name != "@status" and response and "req" not in item.params:
                raise UnsupportedComponent(f"Component {_serialize(item)} "
                                           f"targets a request; on a response "
                                           f"it needs req.")
    return items


_DefaultPorts = (":80", ":443")


def normalizeAuthority(authority):
    """
    Returns authority normalized for @authority (RFC 9421 section 2.2.3):
    lowercased, with port 80 or 443 removed.

    Both ports are removed whatever the scheme, because a verifier that has
    only the Host header behind a TLS-terminating proxy cannot know the scheme,
    which is the input the default-port rule needs. The only request this gets
    wrong is http on 443 or https on 80, and that fails closed as
    signature-mismatch.
    """
    authority = authority.lower()
    for port in _DefaultPorts:
        if authority.endswith(port):
            return authority[:-len(port)]
    return authority


_STATUS = re.compile(r"\A([1-9][0-9]{2})(?: .*)?\Z", re.DOTALL)


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
        match = _STATUS.match(status)
        if match:
            return int(match.group(1))
    raise ValueError(f"Invalid response status {status!r}.")


def _componentValue(item, *, method, authority, path, query, fields, status):
    name = item.value
    if name == "@method":
        value = method
    elif name == "@authority":
        value = authority if authority is not None else _fieldValue(fields, "host")
        value = normalizeAuthority(value) if value is not None else None
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
                raise SignatureMismatch(f"Signature base cannot be built: "
                                        f"{ex}") from ex
    else:
        value = _fieldValue(fields, name)

    if value is None:
        raise MissingComponent(f"Covered component {_serialize(item)} is absent "
                               f"from the message.")
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
                  query=None, headers=None, status=None, request=None):
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
        authority (str): @authority without default port; None means Host
        path (str): @path as sent, percent-encoding included
        query (str): query as sent without the leading '?'; None or '' is none
        headers: target message fields, mapping or iterable of pairs
        status (int | str): response status, an int or a status line such
            as '200 OK'. Set means the target is a response.
        request (Requestage): request answered, for components marked req

    Raises:
        MalformedSignatureInput, DuplicateComponent, UnsupportedComponent,
        MissingComponent, and SignatureMismatch when a component value has a
        newline or a non-ASCII character, so the base cannot be built
    """
    response = status is not None
    items = _components(covered, response=response)
    fields = _fieldLines(headers)
    reqFields = _fieldLines(request.headers) if request is not None else {}

    lines = []
    for item in items:
        if "req" in item.params:
            if request is None:
                raise MissingComponent(f"Component {_serialize(item)} needs "
                                       f"the request, which was not supplied.")
            value = _componentValue(item, method=request.method,
                                    authority=request.authority,
                                    path=request.path, query=request.query,
                                    fields=reqFields, status=None)
        else:
            value = _componentValue(item, method=method, authority=authority,
                                    path=path, query=query, fields=fields,
                                    status=status)
        if "\n" in value or "\r" in value or not value.isascii():
            raise SignatureMismatch(f"Signature base cannot be built: the "
                                    f"value of {_serialize(item)} has a "
                                    f"newline or a non-ASCII character.")
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
        raise UnsupportedAlgorithm(f"Key code {verfer.code} is not Ed25519.")

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
                alg=Alg):
    """
    Sign a request in canonical mode.

    Returns dict of header fields to add to the request: Content-Digest when
    content-digest is covered, then Signature-Input and Signature.

    Parameters:
        method (str): method exactly as it will be sent
        path (str): path as sent, percent-encoding included
        query (str): query as sent without the leading '?'; None if none
        authority (str): target authority without default port; None uses Host
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

    Raises:
        InsufficientCoverage: covered falls short of RequestMinimum
        UnsupportedComponent: a component or parameter the profile lacks
        UncoveredBody: non-empty body without covered content-digest
        UnsupportedSigner: hab without a single effective signer (R4)
        UnsupportedAlgorithm: key is not Ed25519
        ValueError: bad arguments
    """
    raw = _bytify(body)
    if covered is None:
        covered = RequestCovered + (("content-digest",) if raw else ())
    items = _components(covered, response=False)
    _checkCoverage(items, RequestMinimum)
    added, fields = _digestFields(items, headers, raw, "request")

    added.update(_sign(items, signer=signer, hab=hab, keyid=keyid, label=label,
                       created=created, expires=expires, nonce=nonce, tag=tag,
                       alg=alg,
                       baseKwa=dict(method=method, authority=authority,
                                    path=path, query=query, headers=fields)))
    return added


def _digestFields(items, headers, raw, kind):
    """
    Returns (added, fields): the Content-Digest header to add when items cover
    content-digest, and the header fields to build the base from, carrying
    that value. A non-empty body without covered content-digest is
    UncoveredBody.
    """
    added = {}
    fields = list(_fieldLines(headers).items())
    if "content-digest" in _plainNames(items):
        added["Content-Digest"] = contentDigest(raw)
        fields = [(n, v) for n, v in fields if n != "content-digest"]
        fields.append(("content-digest", added["Content-Digest"]))
    elif raw:
        raise UncoveredBody(f"A {kind} with a body must cover content-digest.")
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
        as signRequest, with the response minimum set; MalformedDigest or
        DigestMismatch when "content-digest";req is covered and the request's
        Content-Digest does not match request.body
    """
    _statusCode(status)  # a caller's bad status is a ValueError, up front
    _checkRequestBody(request)
    raw = _bytify(body)
    if covered is None:
        covered = responseCovered(request, raw)
    items = _components(covered, response=True)
    _checkCoverage(items, responseMinimum(bool(_bytify(request.body))))
    if _RequestDigest in {_serialize(item) for item in items}:
        # never bind a request digest that the request body contradicts
        value = _fieldValue(_fieldLines(request.headers), "content-digest")
        if value is None:
            raise MissingComponent("The request has no Content-Digest.")
        verifyContentDigest(value, request.body)
    added, fields = _digestFields(items, headers, raw, "response")

    added.update(_sign(items, signer=signer, hab=hab, keyid=keyid, label=label,
                       created=created, expires=expires, nonce=nonce, tag=tag,
                       alg=alg,
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
        authorities (frozenset): authorities this verifier serves, lowercase
            and without default port; required when requireAuthority
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


def _parseDict(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    members = http_sfv.Dictionary()
    members.parse(value)
    return members


def detectMode(value):
    """
    Returns 'canonical' or 'legacy' for a Signature field value (profile
    section 8): canonical when it parses as an RFC 8941 Dictionary whose every
    member is a Byte Sequence, legacy when keri.end.ending.designature accepts
    it.

    Raises:
        MalformedSignature: neither
    """
    try:
        members = _parseDict(value)
    except ValueError:
        members = None
    if members and all(isinstance(m, http_sfv.Item) and isinstance(m.value, bytes)
                       for m in members.values()):
        return Canonical

    from .ending import designature
    try:
        if designature(value):
            return Legacy
    except Exception:
        pass
    raise MalformedSignature("Signature is neither an RFC 9421 Byte Sequence "
                             "nor the legacy KERI form.")


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
    except MalformedSignature:
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
    except MalformedSignature:
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

    Raises MalformedSignatureInput, then MalformedSignatureLabel.
    """
    try:
        members = _parseDict(value)
    except ValueError as ex:
        raise MalformedSignatureInput(f"Signature-Input does not parse: "
                                      f"{ex}.") from ex
    if not members:
        raise MalformedSignatureInput("Signature-Input is empty.")
    parsed = []
    for label, member in members.items():
        if not isinstance(member, http_sfv.InnerList):
            raise MalformedSignatureInput(f"Signature-Input member {label} is "
                                          f"not an Inner List.")
        items = [_component(item) for item in member]
        for name, val in member.params.items():
            kind = _ParamTypes.get(name)
            if kind is None:
                raise MalformedSignatureInput(f"Unknown signature parameter "
                                              f"{name}.")
            if type(val) is not kind:  # excludes bool, Token, Decimal
                raise MalformedSignatureInput(f"Signature parameter {name} has "
                                              f"the wrong type.")
        for name in ("created", "keyid"):
            if name not in member.params:
                raise MalformedSignatureInput(f"Signature parameter {name} is "
                                              f"required.")
        parsed.append((label, items, dict(member.params)))
    if len(parsed) != 1:
        raise MalformedSignatureLabel("Signature-Input must carry exactly one "
                                      "label.")
    return parsed[0]


def _parseSignature(value, label):
    """
    Returns raw signature bytes for label from canonical Signature value.

    Raises MalformedSignatureLabel, MissingSignatureLabel,
    MalformedSignatureValue.
    """
    members = _parseDict(value)  # detectMode has already parsed it
    if len(members) != 1:
        raise MalformedSignatureLabel("Signature must carry exactly one label.")
    if label not in members:
        raise MissingSignatureLabel(f"Signature has no member for label "
                                    f"{label}.")
    raw = members[label].value
    if len(raw) != 64:
        raise MalformedSignatureValue(f"Signature is {len(raw)} bytes, not 64.")
    return raw


_DECIMAL = re.compile(r"\A[0-9]+\Z")


def _hasBody(fields):
    """Header-time body test of a request (profile section 3): Content-Length
    greater than zero or not a plain decimal, or any Transfer-Encoding."""
    if fields.get("transfer-encoding"):
        return True
    length = _fieldValue(fields, "content-length")
    if length is None:
        return False
    if not _DECIMAL.match(length):
        return True  # not a plain decimal: fail closed, assume a body
    return int(length) > 0


def _checkCoverage(items, required):
    covered = {_componentKey(item) for item in items}
    for component in required:
        item = _component(component)
        if _componentKey(item) not in covered:
            raise InsufficientCoverage(f"Policy requires covering "
                                       f"{_serialize(item)}.")


def effectiveVerfer(verfers, tholder):
    """
    Returns the single effective signing key of a key state (profile section
    7, R4): the one current key that satisfies the signing threshold on its
    own. A canonical signature carries no key index, so exactly one key may
    qualify. A plain single key state qualifies, and so does a Signify
    controller after a passcode rotation (keys [new, prior-next], threshold
    ['1', '0']).

    Parameters:
        verfers (list): current signing keys, Verfer instances
        tholder (Tholder): current signing threshold

    Raises:
        UnsupportedSigner: no key, or more than one key, satisfies the
            threshold alone, e.g. a 2-of-3 group or '1' over two keys
    """
    alone = [verfer for index, verfer in enumerate(verfers)
             if tholder.satisfy(indices=[index])]
    if len(alone) != 1:
        raise UnsupportedSigner("Key state has no single key that satisfies "
                                "its signing threshold alone.")
    return alone[0]


def _resolve(resolver, keyid, alg):
    """Returns verfer for keyid, checking alg against the key (section 4).
    resolver None means no key is known for any keyid. A keyid that is not a
    well formed AID is malformed-key before any resolver sees it, so every
    resolver is called only with an AID."""
    _checkAid(keyid)
    if resolver is None:
        raise UnknownKey(f"No key state for {keyid}.")
    verfer = resolver(keyid)
    if verfer is None:
        raise UnknownKey(f"No key state for {keyid}.")
    if verfer.code not in _Ed25519Codes:
        raise UnsupportedAlgorithm(f"Key {keyid} is not an Ed25519 key.")
    if alg is not None and alg != Alg:
        raise UnsupportedAlgorithm(f"Signature algorithm {alg} is not "
                                   f"supported.")
    return verfer


def _checkFreshness(params, policy, now):
    now = _now() if now is None else int(now)
    created = params["created"]
    if created < now - policy.maxAge - policy.skew or created > now + policy.skew:
        raise SignatureStale(f"Signature created at {created} is outside the "
                             f"freshness window.")
    expires = params.get("expires")
    if expires is not None and expires < now - policy.skew:
        raise SignatureExpired(f"Signature expired at {expires}.")


def _verifyCanonical(*, fields, required, resolver, policy, now, baseKwa,
                     response, expectKeyid=None, authority=None):
    """Header, covered list, key, base, signature and freshness checks, in the
    order of profile section 9."""
    label, items, params = _parseInput(_fieldValue(fields, "signature-input"))
    raw = _parseSignature(_fieldValue(fields, "signature"), label)

    items = _components(items, response=response)
    _checkCoverage(items, required)

    keyid = params["keyid"]
    if expectKeyid is not None:
        # signify-ts's order: well-formedness first (malformed-key), then a
        # keyid other than the expected AID is unknown-key, before any
        # resolver or alg check runs
        _checkAid(keyid)
        if keyid != expectKeyid:
            raise UnknownKey(f"Signed by {keyid}, not by {expectKeyid}.")
    verfer = _resolve(resolver, keyid, params.get("alg"))

    base = signatureBase(items, params, **baseKwa)
    if authority is not None and authority not in policy.authorities:
        raise SignatureMismatch(f"Signature is for authority {authority}, "
                                f"which this verifier does not serve.")
    if not verfer.verify(sig=raw, ser=base.encode("utf-8")):
        raise SignatureMismatch("Signature does not verify.")

    _checkFreshness(params, policy, now)
    return Verified(mode=Canonical, keyid=keyid, label=label, params=params,
                    bodyOwed=False, request=None,
                    covered=tuple(_serialize(item) for item in items),
                    verfer=verfer)


def verifyRequest(*, method, path, query=None, authority=None, headers,
                  body, resolver=None, policy=None, now=None,
                  acceptLegacy=True):
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
    (profile section 5).

    Parameters:
        method (str): method as received
        path (str): path as received, percent-encoding included
        query (str): raw query without the leading '?'; None if none
        authority (str): authority the request was sent to; None uses Host
        headers: request header fields, mapping or iterable of pairs
        body (bytes | Deferred): content as received, b'' for none, or
            Deferred when not yet read. Required; None is a ValueError.
        resolver (callable | None): keyid -> Verfer for canonical mode, with
            a .legacy(aid) lookup for legacy mode (without one, legacy mode
            calls the resolver itself); see KeverResolver. None
            means no key is known: malformed-key for a keyid that is not an
            AID, otherwise unknown-key. A canonical keyid that is not an AID
            is malformed-key before any resolver is called. A custom resolver
            returns a Verfer, or None for unknown-key, or raises an
            HttpSigError subclass; any other exception it raises propagates
            unchanged.
        policy (Policy): default Policy()
        now (int): seconds since the epoch; None is now
        acceptLegacy (bool): False refuses legacy mode as malformed-signature

    Raises:
        HttpSigError subclass for the first check that fails (section 9)
    """
    _checkBodyArg(body)
    policy = policy if policy is not None else DefaultPolicy
    fields = _fieldLines(headers)
    signature = _fieldValue(fields, "signature")
    if signature is None:
        raise MissingSignature("Request has no Signature.")
    if _fieldValue(fields, "signature-input") is None:
        raise MissingSignatureInput("Request has no Signature-Input.")

    if detectMode(signature) == Legacy:
        if not acceptLegacy:
            raise MalformedSignature("Legacy signatures are not accepted.")
        verified = _verifyLegacyRequest(method=method, path=path,
                                        fields=fields, resolver=resolver)
        return verified._replace(request=Requestage(
            method=method, authority=authority, path=path, query=query,
            headers=fields, body=body))

    required = list(policy.request)
    if policy.requireAuthority:
        required.append("@authority")
    if _hasBody(fields):
        required.append("content-digest")

    if authority is None:
        authority = _fieldValue(fields, "host")
    verified = _verifyCanonical(
        fields=fields, required=required, resolver=resolver, policy=policy,
        now=now, response=False,
        authority=normalizeAuthority(authority or "") if policy.requireAuthority else None,
        baseKwa=dict(method=method, authority=authority, path=path,
                     query=query, headers=fields))
    verified = verified._replace(request=Requestage(
        method=method, authority=authority, path=path, query=query,
        headers=fields, body=body))
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
        InsufficientCoverage, MalformedDigest, DigestMismatch, and ValueError
        for a body that is None or Deferred
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
            raise InsufficientCoverage("Body is not covered by content-digest.")
        return verified._replace(bodyOwed=False)
    value = _fieldValue(_fieldLines(headers), "content-digest")
    if value is None:
        raise MissingComponent("Covered content-digest is absent.")
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
        body (bytes | Deferred): response content as received, b'' for none,
            or Deferred to check the headers first; then the result has
            bodyOwed True and checkBody must follow, as for verifyRequest.
        request (Requestage): the request as sent, with body the bytes sent
            (b'' for none); None or Deferred is a ValueError
        resolver (callable | None): keyid -> Verfer for canonical mode, with
            a .legacy(aid) lookup for legacy mode (without one, legacy mode
            calls the resolver itself); see KeverResolver. None
            means no key is known: malformed-key for a keyid that is not an
            AID, otherwise unknown-key. A canonical keyid that is not an AID
            is malformed-key before any resolver is called. A custom resolver
            returns a Verfer, or None for unknown-key, or raises an
            HttpSigError subclass; any other exception it raises propagates
            unchanged.
        keyid (str): AID the client expects to be talking to. Required; None
            or '' is a ValueError. A response keyid that is well formed but
            different is unknown-key, checked after malformed-key and before
            any resolver or alg check.
        requestMode (str): mode the request was signed in, 'canonical' or
            'legacy'. A response in the other mode is mode-mismatch
            (section 8).
        policy (Policy): freshness settings; default Policy()
        now (int): seconds since the epoch; None is now

    When the response covers "content-digest";req, the request's
    Content-Digest is recomputed over request.body.

    Raises:
        Unauthenticated: unsigned 401 to a canonical request
        HttpSigError subclass for the first check that fails (section 9)
    """
    _checkBodyArg(body)
    _checkRequestBody(request)
    if not isinstance(keyid, str) or not keyid:
        # without it the expected-AID check (profile R1) would be skipped
        raise ValueError("keyid, the AID the client expects to be talking "
                         "to, is required.")
    if requestMode not in (Canonical, Legacy):
        raise ValueError(f"Unknown requestMode {requestMode!r}.")
    policy = policy if policy is not None else DefaultPolicy
    fields = _fieldLines(headers)
    signature = _fieldValue(fields, "signature")
    if signature is None:
        try:
            unauthorized = _statusCode(status) == 401
        except ValueError:
            unauthorized = False
        if requestMode == Canonical and unauthorized:
            raise Unauthenticated("Server refused the request's "
                                  "authentication (unsigned 401).")
        raise MissingSignature("Response has no Signature.")
    if _fieldValue(fields, "signature-input") is None:
        raise MissingSignatureInput("Response has no Signature-Input.")

    mode = detectMode(signature)
    if mode != requestMode:
        raise ModeMismatch(f"{mode.capitalize()} response to a {requestMode} "
                           f"request.")
    if mode == Legacy:
        resource = _fieldValue(fields, "signify-resource")
        if resource != keyid:
            raise UnknownKey(f"Response names {resource}, not {keyid}.")
        verfer = _legacyVerfer(resolver, keyid)
        return verifyLegacy(method=request.method, path=request.path,
                            headers=fields, verfer=verfer)

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
    from .ending import normalize

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
            value = normalize(",".join(fields[field]))
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


def verifyLegacy(*, method, path, headers, verfer, label="signify"):
    """
    Verify a message signed in legacy mode (keri.end.ending.siginput and
    signature), exactly as KERIA's SignedHeaderAuthenticator.inbound does, so
    that today's traffic keeps verifying byte for byte. No freshness check, and
    neither query nor body is covered (profile sections 6 and 8).

    Resolving the signer is the caller's business; KERIA looks the controller
    up by Signify-Resource. A response is verified with the method and path of
    the request it answers.

    Returns Verified with mode 'legacy'; keyid is the Signify-Resource value
    (the AID the message claims), or the keyid parameter when that field is
    absent.

    Parameters:
        method (str): request method
        path (str): request path, as KERIA passes it
        headers: message header fields, mapping or iterable of pairs
        verfer (Verfer): key to verify with
        label (str): signature label; legacy Signify uses 'signify'

    Raises:
        MissingSignature, MissingSignatureInput, MalformedSignatureInput,
        MalformedSignature, MissingSignatureLabel, SignatureMismatch
    """
    from .ending import desiginput, designature

    fields = _fieldLines(headers)
    signature = _fieldValue(fields, "signature")
    siginput = _fieldValue(fields, "signature-input")
    if siginput is None:
        raise MissingSignatureInput("Missing SIGNATURE-INPUT header")
    if signature is None:
        raise MissingSignature("Missing SIGNATURE header")

    try:
        inputs = desiginput(siginput.encode("utf-8"))
    except Exception as ex:
        raise MalformedSignatureInput(f"Legacy Signature-Input does not parse: "
                                      f"{ex}.") from ex
    inputs = [i for i in inputs if i.name == label]
    if not inputs:
        raise MissingSignatureLabel(f"Missing {label} inputs in signature")

    try:
        signages = designature(signature)
    except Exception as ex:
        raise MalformedSignature(f"Legacy Signature does not parse: {ex}.") from ex

    for inputage in inputs:
        ser = _legacyBase(inputage, method=method, path=path, fields=fields)
        marker = signages[0].markers.get(inputage.name)
        if marker is None:
            raise MissingSignatureLabel(f"Signature has no member for label "
                                        f"{inputage.name}.")
        if not verfer.verify(sig=marker.raw, ser=ser):
            raise SignatureMismatch(f"Signature for {inputage} invalid")

    inputage = inputs[0]
    params = {name: getattr(inputage, name)
              for name in ("created", "expires", "nonce", "keyid", "context",
                           "alg")
              if getattr(inputage, name) is not None}
    resource = _fieldValue(fields, "signify-resource")
    return Verified(mode=Legacy, bodyOwed=False, request=None,
                    keyid=resource if resource is not None else inputage.keyid,
                    label=inputage.name, params=params,
                    covered=tuple(inputage.fields), verfer=verfer)


def _legacyVerfer(resolver, aid):
    """Legacy key lookup (profile section 8): resolver.legacy(aid) when the
    resolver has it, else resolver(aid) itself; None is unknown-key."""
    if resolver is None:
        raise UnknownKey("Unknown or invalid controller (controller KEL not "
                         "resolved)")
    lookup = getattr(resolver, "legacy", resolver)
    verfer = lookup(aid)
    if verfer is None:
        raise UnknownKey("Unknown or invalid controller (controller KEL not "
                         "resolved)")
    return verfer


def _verifyLegacyRequest(*, method, path, fields, resolver):
    """Legacy request: the signer is the AID named by Signify-Resource."""
    resource = _fieldValue(fields, "signify-resource")
    if resource is None:
        raise MissingComponent("Missing SIGNIFY-RESOURCE header")
    verfer = _legacyVerfer(resolver, resource)
    return verifyLegacy(method=method, path=path, headers=fields,
                        verfer=verfer)


# Resolvers

def _checkAid(keyid):
    """Returns Prefixer of keyid, or raises MalformedKey when it is not a well
    formed AID in qb64."""
    try:
        prefixer = Prefixer(qb64=keyid)
    except Exception as ex:
        raise MalformedKey(f"keyid {keyid!r} is not an AID.") from ex
    if prefixer.qb64 != keyid or prefixer.code not in PreDex:
        raise MalformedKey(f"keyid {keyid!r} is not an AID.")
    return prefixer


class KeverResolver:
    """
    Resolves keyids against key state kevers, e.g. hab.kevers or a Baser's
    kevers.

    Calling it resolves a canonical keyid (profile section 7, R1 and R4): the
    keyid is an AID in qb64 resolved by its derivation code, never by its
    first character alone. A non-transferable code yields the key directly;
    every transferable code, including the basic transferable Ed25519 prefix,
    must have key state in kevers, and the key returned is that state's single
    effective signer (effectiveVerfer).

    .legacy(aid) is the legacy lookup (profile section 8), exactly as KERIA
    does it: kevers[aid].verfers[0], with none of those rules, so legacy
    traffic from multi-key controllers keeps verifying.

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

        if prefixer.code in NonTransDex:
            try:
                return Verfer(qb64=keyid)
            except Exception as ex:
                raise UnsupportedAlgorithm(f"Key {keyid} has an unsupported "
                                           f"algorithm.") from ex

        if keyid not in self.kevers:
            raise UnknownKey(f"No key state for {keyid}.")
        kever = self.kevers[keyid]
        return effectiveVerfer(kever.verfers, kever.tholder)

    def legacy(self, aid):
        """Returns the first current key of aid, as KERIA's legacy
        authenticator takes it."""
        if aid not in self.kevers:
            raise UnknownKey("Unknown or invalid controller (controller KEL "
                             "not resolved)")
        return self.kevers[aid].verfers[0]


def keverResolver(kevers):
    """Returns KeverResolver(kevers)."""
    return KeverResolver(kevers)
