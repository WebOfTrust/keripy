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
from collections import namedtuple
from collections.abc import Mapping

import http_sfv

from .. import kering


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

    if not isinstance(item.value, str) or not item.value:
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


def _componentValue(item, *, method, authority, path, query, fields, status):
    name = item.value
    if name == "@method":
        value = method
    elif name == "@authority":
        value = authority if authority is not None else _fieldValue(fields, "host")
        value = value.lower() if value is not None else None
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
