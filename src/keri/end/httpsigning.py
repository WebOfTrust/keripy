# -*- encoding: utf-8 -*-
"""
keri.end.httpsigning module

Canonical RFC 9421 HTTP Message Signatures under the KERI profile, with RFC
9530 Content-Digest, plus a verifier for the legacy KERI signed-header scheme
of keri.end.ending so a server can accept both while clients upgrade.

The profile itself (covered components, parameters, keyid resolution, mode
selection and the refusal codes) is specified in the "KERI profile of RFC 9421
HTTP Message Signatures". Section numbers in comments below refer to it where
they say "profile", and to RFC 9421 otherwise.

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
    """Key state with other than one signing key and a threshold of one."""
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
    An unsigned 401 answering a canonical request (profile section 8). Not a
    verification refusal: the server refused the request's authentication, and
    the body of its response is not to be trusted.
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
    value is several field lines.
    """
    fields = {}
    if headers is None:
        return fields
    items = headers.items() if isinstance(headers, Mapping) else headers
    for name, value in items:
        lines = fields.setdefault(name.lower(), [])
        if isinstance(value, (list, tuple)):
            lines.extend(value)
        else:
            lines.append(value)
    return fields


def _fieldValue(fields, name):
    """
    Returns RFC 9421 section 2.1 component value of field name, or None when
    absent: each line stripped, obsolete line folding replaced by a single
    space, lines joined by ', '.
    """
    lines = fields.get(name)
    if lines is None:
        return None
    return ", ".join(_OBSFOLD.sub(" ", str(line)).strip() for line in lines)


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
        value = f"{int(status):03d}" if status is not None else None
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


def _signatureParamsValue(items, params):
    inner = http_sfv.InnerList()
    for item in items:
        copy = http_sfv.Item(item.value)
        copy.params.update(item.params)
        inner.append(copy)
    inner.params.update(params)
    return str(inner)


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
        status (int): response status. Set means the target is a response.
        request (Requestage): request answered, for components marked req

    Raises:
        MalformedSignatureInput, DuplicateComponent, UnsupportedComponent,
        MissingComponent
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
        verfers = hab.kever.verfers
        if len(verfers) != 1 or not _simpleThreshold(hab.kever.tholder):
            raise UnsupportedSigner(f"{hab.pre} is not a single key signer.")
        verfer = verfers[0]
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
    inner = http_sfv.InnerList()
    for item in items:
        inner.append(item)
    inner.params.update(params)
    inputs[label] = inner
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
        UncoveredBody: non-empty body without covered content-digest
        UnsupportedSigner: hab with other than one key and threshold one
        UnsupportedAlgorithm: key is not Ed25519
        ValueError: bad arguments
    """
    raw = _bytify(body)
    if covered is None:
        covered = RequestCovered + (("content-digest",) if raw else ())
    items = _components(covered, response=False)

    added = {}
    fields = [(n, v) for n, v in _fieldLines(headers).items()]
    if "content-digest" in _plainNames(items):
        added["Content-Digest"] = contentDigest(raw)
        fields = [(n, v) for n, v in fields if n != "content-digest"]
        fields.append(("content-digest", added["Content-Digest"]))
    elif raw:
        raise UncoveredBody("A request with a body must cover content-digest.")

    added.update(_sign(items, signer=signer, hab=hab, keyid=keyid, label=label,
                       created=created, expires=expires, nonce=nonce, tag=tag,
                       alg=alg,
                       baseKwa=dict(method=method, authority=authority,
                                    path=path, query=query, headers=fields)))
    return added


def responseCovered(request, body):
    """
    Returns default covered components of a response to request (profile
    section 3): @status, content-digest when body is non-empty, and the
    request's @method, @path, @query and, when it had a body, content-digest,
    each marked req.
    """
    covered = ["@status"]
    if _bytify(body):
        covered.append("content-digest")
    covered.extend(['"@method";req', '"@path";req', '"@query";req'])
    if _bytify(request.body):
        covered.append('"content-digest";req')
    return covered


def signResponse(*, status, request, headers=None, body=None, signer=None,
                 hab=None, keyid=None, label="signify", covered=None,
                 created=None, expires=None, nonce=None, tag=None, alg=Alg):
    """
    Sign a response to a canonical request.

    Returns dict of header fields to add to the response, as signRequest.

    Parameters:
        status (int): response status code
        request (Requestage): the request being answered, as received
        headers, body, signer, hab, keyid, label, created, expires, nonce, tag,
        alg: as for signRequest
        covered (list): default responseCovered(request, body)

    Raises:
        as signRequest
    """
    raw = _bytify(body)
    if covered is None:
        covered = responseCovered(request, raw)
    items = _components(covered, response=True)

    added = {}
    fields = [(n, v) for n, v in _fieldLines(headers).items()]
    if "content-digest" in _plainNames(items):
        added["Content-Digest"] = contentDigest(raw)
        fields = [(n, v) for n, v in fields if n != "content-digest"]
        fields.append(("content-digest", added["Content-Digest"]))
    elif raw:
        raise UncoveredBody("A response with a body must cover content-digest.")

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
Verified = namedtuple("Verified", "mode keyid label params covered verfer")


@dataclass(frozen=True)
class Policy:
    """
    Verifier policy (profile sections 3 and 6).

    Attributes:
        request (tuple): minimum covered components of a request, besides
            content-digest when there is a body. Must include RequestMinimum.
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
        given = {_componentKey(_component(c)) for c in self.request}
        for component in RequestMinimum:
            if _componentKey(_component(component)) not in given:
                raise ValueError(f"Policy request set must include "
                                 f"{component} (profile section 3).")
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


def _hasBody(fields):
    """Header-time body test (profile section 3): Content-Length greater than
    zero or any Transfer-Encoding."""
    if fields.get("transfer-encoding"):
        return True
    length = _fieldValue(fields, "content-length")
    if length is None:
        return False
    try:
        return int(length) > 0
    except ValueError:
        return True  # unparsable: assume a body rather than skip coverage


def _checkCoverage(items, required):
    covered = {_componentKey(item) for item in items}
    for component in required:
        item = _component(component)
        if _componentKey(item) not in covered:
            raise InsufficientCoverage(f"Policy requires covering "
                                       f"{_serialize(item)}.")


def _simpleThreshold(tholder):
    return not tholder.weighted and tholder.thold == 1


def _resolve(resolver, keyid, alg):
    """Returns verfer for keyid, checking alg against the key (section 4)."""
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
    if expectKeyid is not None and keyid != expectKeyid:
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
                    covered=tuple(_serialize(item) for item in items),
                    verfer=verfer)


def verifyRequest(*, method, path, query=None, authority=None, headers,
                  body=None, resolver, policy=None, now=None,
                  acceptLegacy=True):
    """
    Verify a signed request in either mode (profile section 8).

    Returns Verified.

    Parameters:
        method (str): method as received
        path (str): path as received, percent-encoding included
        query (str): raw query without the leading '?'; None if none
        authority (str): authority the request was sent to; None uses Host
        headers: request header fields, mapping or iterable of pairs
        body (bytes | None): content, or None when not yet read. With None
            only the header-time body test runs and the caller must call
            checkBody once the body is read.
        resolver (callable): keyid -> Verfer, see keverResolver
        policy (Policy): default Policy()
        now (int): seconds since the epoch; None is now
        acceptLegacy (bool): False refuses legacy mode as malformed-signature

    Raises:
        HttpSigError subclass for the first check that fails (section 9)
    """
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
        return _verifyLegacyRequest(method=method, path=path, fields=fields,
                                    resolver=resolver)

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
    if body is not None:
        checkBody(verified, fields, body)
    return verified


def checkBody(verified, headers, body):
    """
    Post-read body check of a verified message (profile sections 3 and 5): a
    non-empty body without covered content-digest is refused, and a covered
    Content-Digest is recomputed over the content received. Both must pass
    before the message reaches application code. A no-op in legacy mode,
    which covers no body.

    Raises:
        InsufficientCoverage, MalformedDigest, DigestMismatch
    """
    if verified.mode != Canonical:
        return
    raw = _bytify(body)
    if '"content-digest"' not in verified.covered:
        if raw:
            raise InsufficientCoverage("Body is not covered by content-digest.")
        return
    value = _fieldValue(_fieldLines(headers), "content-digest")
    if value is None:
        raise MissingComponent("Covered content-digest is absent.")
    verifyContentDigest(value, raw)


def verifyResponse(*, status, headers, body, request, resolver, keyid,
                   requestMode=Canonical, policy=None, now=None):
    """
    Verify the response to a request this client signed.

    Returns Verified.

    Parameters:
        status (int): response status code
        headers: response header fields
        body (bytes): response content as received
        request (Requestage): the request as sent
        resolver (callable): keyid -> Verfer
        keyid (str): AID the client expects to be talking to
        requestMode (str): mode the request was signed in. After a canonical
            request only a canonical response is accepted (section 8).
        policy (Policy): freshness settings; default Policy()
        now (int): seconds since the epoch; None is now

    Raises:
        Unauthenticated: unsigned 401 to a canonical request
        HttpSigError subclass for the first check that fails (section 9)
    """
    policy = policy if policy is not None else DefaultPolicy
    fields = _fieldLines(headers)
    signature = _fieldValue(fields, "signature")
    if signature is None:
        if requestMode == Canonical and int(status) == 401:
            raise Unauthenticated("Server refused the request's "
                                  "authentication (unsigned 401).")
        raise MissingSignature("Response has no Signature.")
    if _fieldValue(fields, "signature-input") is None:
        raise MissingSignatureInput("Response has no Signature-Input.")

    mode = detectMode(signature)
    if requestMode == Canonical and mode == Legacy:
        raise ModeMismatch("Legacy response to a canonical request.")
    if mode == Legacy:
        resource = _fieldValue(fields, "signify-resource")
        if resource != keyid:
            raise UnknownKey(f"Response names {resource}, not {keyid}.")
        verfer = resolver(keyid)
        if verfer is None:
            raise UnknownKey(f"No key state for {keyid}.")
        return verifyLegacy(method=request.method, path=request.path,
                            headers=fields, verfer=verfer)

    raw = _bytify(body)
    required = ["@status"]
    if raw or (body is None and _hasBody(fields)):
        required.append("content-digest")
    required.extend(['"@method";req', '"@path";req', '"@query";req'])
    if _bytify(request.body):
        required.append('"content-digest";req')

    verified = _verifyCanonical(
        fields=fields, required=required, resolver=resolver, policy=policy,
        now=now, response=True, expectKeyid=keyid,
        baseKwa=dict(status=status, headers=fields, request=request))
    if body is not None:
        checkBody(verified, fields, body)
    return verified


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
    return Verified(mode=Legacy,
                    keyid=resource if resource is not None else inputage.keyid,
                    label=inputage.name, params=params,
                    covered=tuple(inputage.fields), verfer=verfer)


def _verifyLegacyRequest(*, method, path, fields, resolver):
    """Legacy request: the signer is the AID named by Signify-Resource."""
    resource = _fieldValue(fields, "signify-resource")
    if resource is None:
        raise MissingComponent("Missing SIGNIFY-RESOURCE header")
    verfer = resolver(resource)
    if verfer is None:
        raise UnknownKey(f"No key state for {resource}.")
    return verifyLegacy(method=method, path=path, headers=fields,
                        verfer=verfer)


# Resolvers

def keverResolver(kevers):
    """
    Returns resolver callable(keyid) -> Verfer over key state kevers (profile
    section 7, R1 and R4).

    The keyid is an AID in qb64 and is resolved by its derivation code, never
    by its first character alone: a non-transferable code yields the key
    directly; every transferable code, including the basic transferable
    Ed25519 prefix, must have key state in kevers. That key state must have
    exactly one signing key and a threshold of one.

    Parameters:
        kevers (Mapping): prefix qb64 -> Kever, e.g. hab.kevers
    """
    def resolve(keyid):
        try:
            prefixer = Prefixer(qb64=keyid)
        except Exception as ex:
            raise MalformedKey(f"keyid {keyid!r} is not an AID.") from ex
        if prefixer.qb64 != keyid or prefixer.code not in PreDex:
            raise MalformedKey(f"keyid {keyid!r} is not an AID.")

        if prefixer.code in NonTransDex:
            try:
                return Verfer(qb64=keyid)
            except Exception as ex:
                raise UnsupportedAlgorithm(f"Key {keyid} has an unsupported "
                                           f"algorithm.") from ex

        # in and [], never get: Baser.kevers reads through to the database on
        # in and [] only, so get would miss key state not yet cached, as
        # after a restart.
        if keyid not in kevers:
            raise UnknownKey(f"No key state for {keyid}.")
        kever = kevers[keyid]
        if len(kever.verfers) != 1 or not _simpleThreshold(kever.tholder):
            raise UnsupportedSigner(f"{keyid} is not a single key signer.")
        return kever.verfers[0]

    return resolve
