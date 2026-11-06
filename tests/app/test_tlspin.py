"""keripy pins a witness's self-signed TLS certificate to the fingerprint the witness declared.

A witness is known by its AID, not by a certificate authority. When it serves https with a
self-signed certificate, it states that certificate's SHA-256 as the ``tls-cert-sha256`` attrib of
a signed /decl/attribs reply, and keripy authenticates the connection by comparing the certificate
it is shown against the fingerprint from the reply BADA accepted. The pin replaces the CA and
hostname checks for that connection and nothing else: a peer that declares no fingerprint gets
the CA check it always got, so a self-signed peer with no declaration is still refused.

First contact is the one fetch made before any declaration is held. An OOBI fetch tries the CA
check first and, only when that fails, retries without verifying the certificate, because what an
OOBI returns is signed and is checked after it arrives. The pin then governs every later
connection.

These tests use a real TLS server on loopback with a freshly made self-signed certificate,
because the property under test is what a real handshake accepts and refuses.
"""

import datetime
import hashlib
import ipaddress
import socket
import ssl
import threading
import time
from urllib.parse import urlparse

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from hio.base import tyming
from hio.core import http, tcp

from keri.kering import Vrsn_1_0, Kinds, Schemes
from keri.core import Salter
from keri.app import openHby, agenting, httping, oobiing
from keri.recording import OobiRecord


# --- certificates -------------------------------------------------------------------------------

def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, key, issuer=None, issuerKey=None, ca=False):
    """A certificate for 127.0.0.1, self-signed unless an issuer is given."""
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(_name(subject))
               .issuer_name(_name(issuer or subject))
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=30))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if not ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False)
    return builder.sign(issuerKey or key, hashes.SHA256())


def _write(tmp_path, stem, cert, key):
    certpath = tmp_path / f"{stem}.crt"
    keypath = tmp_path / f"{stem}.key"
    certpath.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keypath.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    return str(certpath), str(keypath)


def _fingerprint(cert):
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


@pytest.fixture
def selfSigned(tmp_path):
    """Two unrelated self-signed certificates: (certpath, keypath, fingerprint) each."""
    made = []
    for stem in ("one", "two"):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = _cert(f"witness-{stem}", key)
        made.append((*_write(tmp_path, stem, cert, key), _fingerprint(cert)))
    return made


@pytest.fixture
def caSigned(tmp_path):
    """A server certificate chained to a test CA: (certpath, keypath, cafilepath)."""
    cakey = ec.generate_private_key(ec.SECP256R1())
    cacert = _cert("test-ca", cakey, ca=True)
    cafile, _ = _write(tmp_path, "ca", cacert, cakey)
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _cert("witness-ca", key, issuer="test-ca", issuerKey=cakey)
    certpath, keypath = _write(tmp_path, "leaf", cert, key)
    return certpath, keypath, cafile


# --- a real TLS server ----------------------------------------------------------------------------

class TlsServer:
    """A one-connection-at-a-time https server on loopback that answers every request with 200.

    It records the bytes each connection delivered, so a test can show that a refused connection
    carried no request at all -- the pin is checked before anything is sent."""

    def __init__(self, certpath, keypath):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile=certpath, keyfile=keypath)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.received = []
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"https://127.0.0.1:{self.port}/"

    def _serve(self):
        while self.running:
            try:
                raw, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            data = bytearray()
            try:
                raw.settimeout(2.0)
                conn = self.context.wrap_socket(raw, server_side=True)
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data.extend(chunk)
                if b"\r\n\r\n" in data:
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                                 b"Content-Type: text/plain\r\nConnection: close\r\n\r\nok")
                conn.close()
            except (ssl.SSLError, OSError):
                raw.close()
            self.received.append(bytes(data))

    def close(self):
        self.running = False
        self.thread.join(timeout=2.0)
        self.sock.close()


@pytest.fixture
def serve():
    servers = []

    def make(certpath, keypath):
        server = TlsServer(certpath, keypath)
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


def _get(url, connector=None, timeout=3.0):
    """Drive one hio GET to completion. Returns the response, or raises what the client raised."""
    tymist = tyming.Tymist(tock=0.01)
    up = urlparse(url)
    if connector is not None:
        connector.wind(tymist.tymen())
    client = http.clienting.Client(scheme=up.scheme, hostname=up.hostname, port=up.port,
                                   connector=connector, tymth=tymist.tymen())
    client.request(method="GET", path="/")
    deadline = time.monotonic() + timeout
    try:
        while not client.responses:
            if time.monotonic() > deadline:
                return None
            client.service()
            tymist.tick()
            time.sleep(0.01)
        return client.respond()
    finally:
        client.close()


# --- declarations ---------------------------------------------------------------------------------

def _witness_and_consumer(withby, conhby):
    withab = withby.makeHab(name="wit", isith="1", icount=1, transferable=False,
                            version=Vrsn_1_0, kind=Kinds.json)
    conhab = conhby.makeHab(name="con", isith="1", icount=1, transferable=True,
                            version=Vrsn_1_0, kind=Kinds.json)
    conhab.psr.parse(bytearray(withab.msgOwnInception(framed=True, gvrsn=Vrsn_1_0)))
    return withab, conhab


def _declare(withab, conhab, fingerprint, stamp=None):
    """The witness declares a fingerprint and the consumer accepts the reply under BADA."""
    msg = withab.makeDeclAttribs(attribs={"tls-cert-sha256": fingerprint}, stamp=stamp,
                                 version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
    conhab.psr.parse(bytearray(msg))


@pytest.fixture
def pair():
    salt = Salter(raw=b'abcdef0123456789').qb64
    with openHby(name="wit", base="test", salt=salt, version=Vrsn_1_0) as withby, \
            openHby(name="con", base="test", salt=salt, version=Vrsn_1_0) as conhby:
        yield _witness_and_consumer(withby, conhby)


# --- the four behaviours the change exists for ----------------------------------------------------

def test_a_pinned_connection_to_a_self_signed_witness_succeeds(pair, selfSigned, serve):
    withab, conhab = pair
    certpath, keypath, fingerprint = selfSigned[0]
    server = serve(certpath, keypath)
    _declare(withab, conhab, fingerprint)

    connector = httping.tlsConnector(conhab.db, withab.pre, server.url)
    assert isinstance(connector, httping.PinnedClientTls)

    rep = _get(server.url, connector=connector)
    assert rep is not None and rep.status == 200


def test_a_mismatched_fingerprint_is_refused_before_any_request_is_sent(pair, selfSigned, serve):
    withab, conhab = pair
    certpath, keypath, _ = selfSigned[0]
    _, _, otherFingerprint = selfSigned[1]
    server = serve(certpath, keypath)
    _declare(withab, conhab, otherFingerprint)

    connector = httping.tlsConnector(conhab.db, withab.pre, server.url)
    with pytest.raises(httping.TlsPinError):
        _get(server.url, connector=connector)

    time.sleep(0.3)
    assert all(b"GET" not in data for data in server.received)


def test_a_self_signed_witness_with_no_declaration_is_refused(pair, selfSigned, serve):
    """No declaration means the CA check keripy always made, which a self-signed certificate
    fails. The pin only ever loosens the check for a witness that signed for its certificate."""
    withab, conhab = pair
    certpath, keypath, _ = selfSigned[0]
    server = serve(certpath, keypath)

    assert httping.tlsConnector(conhab.db, withab.pre, server.url) is None
    with pytest.raises(ssl.SSLCertVerificationError):
        _get(server.url)


def test_a_newer_declaration_with_a_new_fingerprint_replaces_the_old_pin(pair, selfSigned, serve):
    withab, conhab = pair
    (oldCert, oldKey, oldFp), (newCert, newKey, newFp) = selfSigned
    _declare(withab, conhab, oldFp, stamp="2026-01-01T00:00:00.000000+00:00")
    _declare(withab, conhab, newFp, stamp="2026-02-01T00:00:00.000000+00:00")

    newServer = serve(newCert, newKey)
    rep = _get(newServer.url, connector=httping.tlsConnector(conhab.db, withab.pre, newServer.url))
    assert rep is not None and rep.status == 200

    oldServer = serve(oldCert, oldKey)
    with pytest.raises(httping.TlsPinError):
        _get(oldServer.url, connector=httping.tlsConnector(conhab.db, withab.pre, oldServer.url))


# --- what counts as a declared fingerprint --------------------------------------------------------

def test_a_fingerprint_is_read_in_upper_case_or_with_colons(pair, selfSigned):
    withab, conhab = pair
    _, _, fingerprint = selfSigned[0]
    colons = ":".join(fingerprint[i:i + 2] for i in range(0, 64, 2)).upper()
    _declare(withab, conhab, colons)
    assert httping.declaredCertPin(conhab.db, withab.pre) == bytes.fromhex(fingerprint)


@pytest.mark.parametrize("value", ["", "not-a-fingerprint", "ab" * 31, "ab" * 33, "zz" * 32])
def test_an_unrecognized_fingerprint_is_treated_as_absent(pair, value):
    """DeclRecord's rule: a value a consumer does not recognize is not acted on. Here that means
    the CA check, which still refuses a self-signed certificate."""
    withab, conhab = pair
    _declare(withab, conhab, value)
    assert httping.declaredCertPin(conhab.db, withab.pre) is None
    assert httping.tlsConnector(conhab.db, withab.pre, "https://127.0.0.1:1/") is None


def test_only_a_declaration_by_the_peer_itself_pins_it(pair, selfSigned):
    """The pin is looked up by the AID being connected to, so another AID's declaration -- the
    consumer's own, here -- never pins a connection to the witness."""
    withab, conhab = pair
    _, _, fingerprint = selfSigned[0]
    conhab.psr.parse(bytearray(conhab.makeDeclAttribs(
        attribs={"tls-cert-sha256": fingerprint}, version=Vrsn_1_0, kind=Kinds.json,
        gvrsn=Vrsn_1_0)))
    assert httping.declaredCertPin(conhab.db, conhab.pre) is not None
    assert httping.declaredCertPin(conhab.db, withab.pre) is None


def test_plain_http_is_never_pinned(pair, selfSigned):
    withab, conhab = pair
    _declare(withab, conhab, selfSigned[0][2])
    assert httping.tlsConnector(conhab.db, withab.pre, "http://127.0.0.1:5642/") is None


# --- first contact: the OOBI fetch ----------------------------------------------------------------

def test_an_oobi_fetch_reaches_a_self_signed_server_without_a_pin(selfSigned, serve):
    certpath, keypath, _ = selfSigned[0]
    server = serve(certpath, keypath)

    connector = httping.bootstrapConnector(server.url)
    rep = _get(server.url, connector=connector)
    assert rep is not None and rep.status == 200
    assert connector.verified is False


def test_an_oobi_fetch_tries_the_ca_check_first(caSigned, serve):
    """A CA-backed server is fetched with the certificate verified, exactly as before."""
    certpath, keypath, cafile = caSigned
    server = serve(certpath, keypath)

    connector = httping.bootstrapConnector(server.url, cafilepath=cafile)
    rep = _get(server.url, connector=connector)
    assert rep is not None and rep.status == 200
    assert connector.verified is True


def test_an_oobi_fetch_ignores_a_stale_pin(pair, selfSigned, serve):
    """Re-resolving the OOBI is how a consumer learns a rotated certificate, so the OOBI fetch
    must not be held to the pin it is fetching a replacement for."""
    withab, conhab = pair
    (_, _, oldFp), (newCert, newKey, _) = selfSigned
    _declare(withab, conhab, oldFp)
    server = serve(newCert, newKey)

    rep = _get(server.url, connector=httping.bootstrapConnector(server.url))
    assert rep is not None and rep.status == 200


def test_the_oobiery_fetches_https_oobis_with_the_bootstrap_connector():
    salt = Salter(raw=b'abcdef0123456789').qb64
    with openHby(name="oobi", base="test", salt=salt, version=Vrsn_1_0) as hby:
        oobiery = oobiing.Oobiery(hby=hby)
        oobiery.clienter.wind(tyming.Tymist().tymen())  # a Doist does this when it runs
        url = "https://127.0.0.1:5643/oobi/BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE/controller"
        oobiery.request(url, OobiRecord(date="2026-01-01T00:00:00.000000+00:00"))
        assert isinstance(oobiery.clients[url].connector, httping.BootstrapClientTls)

        hurl = "http://127.0.0.1:5642/oobi/BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE/controller"
        oobiery.request(hurl, OobiRecord(date="2026-01-01T00:00:00.000000+00:00"))
        assert not isinstance(oobiery.clients[hurl].connector, tcp.ClientTls)


# --- every place keripy connects to a witness over https ------------------------------------------

@pytest.fixture
def witnessed():
    """A consumer whose AID uses the witness, and which holds the witness's https location."""
    salt = Salter(raw=b'abcdef0123456789').qb64
    with openHby(name="wit", base="test", salt=salt, version=Vrsn_1_0) as withby, \
            openHby(name="con", base="test", salt=salt, version=Vrsn_1_0) as conhby:
        withab = withby.makeHab(name="wit", isith="1", icount=1, transferable=False,
                                version=Vrsn_1_0, kind=Kinds.json)
        conhab = conhby.makeHab(name="con", isith="1", icount=1, transferable=True,
                                wits=[withab.pre], toad=1, version=Vrsn_1_0, kind=Kinds.json)
        conhab.psr.parse(bytearray(withab.msgOwnInception(framed=True, gvrsn=Vrsn_1_0)))
        conhab.psr.parse(bytearray(withab.makeLocScheme(
            url="https://127.0.0.1:5643/", scheme=Schemes.https, version=Vrsn_1_0,
            kind=Kinds.json, gvrsn=Vrsn_1_0)))
        assert conhab.fetchUrls(eid=withab.pre, scheme=Schemes.https)
        yield withab, conhab, conhby


def _sites(withab, conhab, conhby):
    """The https client each witness call site builds, by name."""
    urls = conhab.fetchUrls(eid=withab.pre)
    url = urls[Schemes.https]
    yield "HTTPMessenger", agenting.HTTPMessenger(hab=conhab, wit=withab.pre, url=url).client
    yield "HTTPStreamMessenger", agenting.HTTPStreamMessenger(
        hab=conhab, wit=withab.pre, url=url, msg=b"x").client
    yield "messengerFrom", agenting.messengerFrom(conhab, withab.pre, urls).client
    yield "streamMessengerFrom", agenting.streamMessengerFrom(conhab, withab.pre, urls,
                                                             msg=b"x").client
    yield "httpClient", agenting.httpClient(conhab, withab.pre)[0]

    receiptor = agenting.Receiptor(hby=conhby)
    receiptor.clienter.wind(tyming.Tymist().tymen())  # a Doist does this when it runs
    receiptor.tock = 0.0
    next(receiptor.get(conhab.pre))
    yield "Receiptor.get", receiptor.clienter.clients[-1][0]


def test_every_witness_https_site_pins_a_declared_fingerprint(witnessed, selfSigned):
    withab, conhab, conhby = witnessed
    _declare(withab, conhab, selfSigned[0][2])
    for name, client in _sites(withab, conhab, conhby):
        assert isinstance(client.connector, httping.PinnedClientTls), name
        assert client.connector.pin == bytes.fromhex(selfSigned[0][2]), name
        # hio follows a redirect to another host with a fresh connector that would keep the
        # pin's unverified context and drop the pin, so a pinned client does not redirect.
        assert client.respondent.redirectable is False, name


def test_every_witness_https_site_is_unchanged_without_a_declaration(witnessed):
    withab, conhab, conhby = witnessed
    for name, client in _sites(withab, conhab, conhby):
        assert isinstance(client.connector, tcp.ClientTls), name
        assert not isinstance(client.connector, httping.PinnedClientTls), name
        assert not isinstance(client.connector, httping.BootstrapClientTls), name
        assert client.respondent.redirectable is True, name
