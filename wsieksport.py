#!/usr/bin/env python3
"""
SOAP-klient til Brugerdatabasen wsiEKSPORT v7.

WS-Security: RSA-SHA256 med eksklusiv C14N.
Signerede elementer: Body, Timestamp, MessageID, UdbydersystemId.
"""

import base64
import contextlib
import hashlib
import io
import logging
import os
import ssl
import tempfile
import time
import uuid
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from dotenv import load_dotenv
from lxml import etree
import requests

# ---------------------------------------------------------------------------
# Konfiguration start - environmentvariabler
# ---------------------------------------------------------------------------

load_dotenv()

BASE_DIR = Path(__file__).parent

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

_log_level = os.getenv("LOG_LEVEL", "INFO").upper()
_log_file  = os.getenv("LOG_FILE")

_handlers: list[logging.Handler] = [logging.StreamHandler()]
if _log_file:
    _handlers.append(logging.FileHandler(_log_file, encoding="utf-8"))

logging.basicConfig(
    level=getattr(logging, _log_level, logging.INFO),
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=_handlers,
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Konfiguration fortsat — certifikatfiler, udbydersystem-id og endpoint
# ---------------------------------------------------------------------------
_cert_env = os.getenv("CERT_FILE")
_key_env  = os.getenv("KEY_FILE")
if not _cert_env or not _key_env:
    raise EnvironmentError(
        "CERT_FILE og KEY_FILE skal være defineret i .env eller som miljøvariabler."
    )

CERT_FILE  = Path(_cert_env)
KEY_FILE   = Path(_key_env)
CA_ROOT    = BASE_DIR / "ca" / "oces-root-ca.pem"
CA_INTER   = BASE_DIR / "ca" / "oces-intermediate-ca.pem"

UDBYDER_SYSTEM_ID = os.getenv("UDBYDER_SYSTEM_ID")
if not UDBYDER_SYSTEM_ID:
    raise EnvironmentError(
        "UDBYDER_SYSTEM_ID skal være defineret i .env eller som miljøvariabel."
    )

ENDPOINT = "https://brugerdatabasen.stil.dk/bpi/wsieksport/7"

# ---------------------------------------------------------------------------
# Namespace- og algoritmekonstanter
# ---------------------------------------------------------------------------

_NS = {
    "soap": "http://www.w3.org/2003/05/soap-envelope",
    "wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
    "wsu":  "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
    "wsa":  "http://www.w3.org/2005/08/addressing",
    "ds":   "http://www.w3.org/2000/09/xmldsig#",
    "bpi":  "https://brugerdatabasen.stil.dk/bpi/common/3",
    "eks":  "https://brugerdatabasen.stil.dk/bpi/wsieksport/7",
}

_C14N_EXC   = "http://www.w3.org/2001/10/xml-exc-c14n#"
_DIGEST_256 = "http://www.w3.org/2001/04/xmlenc#sha256"
_SIG_RSA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
_X509V3     = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
_BASE64BIN  = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"


def _q(prefix: str, local: str) -> str:
    """Returnerer det fuldt kvalificerede XML-elementnavn: {namespace-uri}lokalnavn."""
    return f"{{{_NS[prefix]}}}{local}"


# ---------------------------------------------------------------------------
# Hjælpefunktioner — XML og kryptografi
# ---------------------------------------------------------------------------

def _new_id(prefix: str) -> str:
    """Genererer et unikt wsu:Id på formen 'Præfiks-<uuid4>'."""
    return f"{prefix}-{uuid.uuid4()}"


def _exc_c14n(element: etree._Element) -> bytes:
    """Eksklusiv C14N til signering af udgående elementer (bevarer arvede namespaces via deepcopy)."""
    buf = io.BytesIO()
    etree.ElementTree(deepcopy(element)).write_c14n(
        buf, exclusive=True, with_comments=False
    )
    return buf.getvalue()


def _exc_c14n_in_context(element: etree._Element, inclusive_prefixes: list[str] | None = None) -> bytes:
    """Eksklusiv C14N til verifikation af indgående elementer.
    inclusive_prefixes: navnerum-præfikser der altid inkluderes (ec:InclusiveNamespaces PrefixList)."""
    return etree.tostring(element, method="c14n", exclusive=True,
                          inclusive_ns_prefixes=inclusive_prefixes or [])


def _sha256_b64(data: bytes) -> str:
    """Beregner SHA256-digest af data og returnerer resultatet base64-kodet."""
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


def _cert_b64(der: bytes) -> str:
    """Base64-koder et DER-certifikat til brug i BinarySecurityToken."""
    return base64.b64encode(der).decode()


@contextlib.contextmanager
def _tls_cert(cert_der: bytes, key_pem: bytes):
    """Opretter midlertidige PEM-filer til TLS-klientcertifikat og frigiver dem bagefter."""
    cert_pem = ssl.DER_cert_to_PEM_cert(cert_der).encode()
    cf = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    kf = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    try:
        cf.write(cert_pem); cf.close()
        kf.write(key_pem);  kf.close()
        yield cf.name, kf.name
    finally:
        os.unlink(cf.name)
        os.unlink(kf.name)


def _find_id(root: etree._Element, wsu_id: str) -> etree._Element:
    """Finder et element i udgående envelope ud fra dets wsu:Id-attribut."""
    hits = root.xpath(
        f"//*[@wsu:Id='{wsu_id}']", namespaces={"wsu": _NS["wsu"]}
    )
    if not hits:
        raise ValueError(f"Intet element med wsu:Id='{wsu_id}'")
    return hits[0]


# ---------------------------------------------------------------------------
# Bygning af SOAP-envelope
# ---------------------------------------------------------------------------

def _build_envelope(
    cert_der: bytes, action: str, body_element: etree._Element
) -> tuple[etree._Element, dict[str, str]]:
    """Bygger en SOAP 1.2-envelope med WS-Addressing og WS-Security headers.
    Returnerer envelope-elementet og en dict med wsu:Id-værdier for de elementer der skal signeres."""
    now        = datetime.now(timezone.utc).replace(microsecond=0)
    ts_created = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    ts_expires = (now + timedelta(seconds=300)).strftime("%Y-%m-%dT%H:%M:%SZ")

    ids = {k: _new_id(k)
           for k in ("Body", "Timestamp", "MessageID", "UdbydersystemId", "BST")}

    env = etree.Element(_q("soap", "Envelope"), nsmap=_NS)

    # Header
    hdr = etree.SubElement(env, _q("soap", "Header"))

    etree.SubElement(hdr, _q("wsa", "Action")).text = action
    etree.SubElement(hdr, _q("wsa", "To")).text = ENDPOINT
    etree.SubElement(
        etree.SubElement(hdr, _q("wsa", "ReplyTo")),
        _q("wsa", "Address"),
    ).text = "http://www.w3.org/2005/08/addressing/anonymous"

    msgid = etree.SubElement(hdr, _q("wsa", "MessageID"))
    msgid.set(_q("wsu", "Id"), ids["MessageID"])
    msgid.text = f"urn:uuid:{uuid.uuid4()}"

    udb = etree.SubElement(hdr, _q("bpi", "UdbydersystemId"))
    udb.set(_q("wsu", "Id"), ids["UdbydersystemId"])
    udb.text = UDBYDER_SYSTEM_ID

    # wsse:Security
    sec = etree.SubElement(hdr, _q("wsse", "Security"))
    sec.set(_q("soap", "mustUnderstand"), "1")

    ts = etree.SubElement(sec, _q("wsu", "Timestamp"))
    ts.set(_q("wsu", "Id"), ids["Timestamp"])
    etree.SubElement(ts, _q("wsu", "Created")).text = ts_created
    etree.SubElement(ts, _q("wsu", "Expires")).text = ts_expires

    bst = etree.SubElement(sec, _q("wsse", "BinarySecurityToken"))
    bst.set(_q("wsu", "Id"), ids["BST"])
    bst.set("ValueType", _X509V3)
    bst.set("EncodingType", _BASE64BIN)
    bst.text = _cert_b64(cert_der)

    # Body
    body = etree.SubElement(env, _q("soap", "Body"))
    body.set(_q("wsu", "Id"), ids["Body"])
    body.append(body_element)

    return env, ids


# ---------------------------------------------------------------------------
# XML-digital signatur (WS-Security)
# ---------------------------------------------------------------------------

def _ds_ref(uri: str, digest: str) -> etree._Element:
    """Opretter et ds:Reference-element med eksklusiv C14N-transform og SHA256-digest."""
    ref = etree.Element(_q("ds", "Reference"))
    ref.set("URI", uri)
    t = etree.SubElement(
        etree.SubElement(ref, _q("ds", "Transforms")),
        _q("ds", "Transform"),
    )
    t.set("Algorithm", _C14N_EXC)
    etree.SubElement(ref, _q("ds", "DigestMethod")).set("Algorithm", _DIGEST_256)
    etree.SubElement(ref, _q("ds", "DigestValue")).text = digest
    return ref


def _apply_signature(
    env: etree._Element, ids: dict[str, str], private_key
) -> None:
    """Beregner digests, signerer SignedInfo med RSA-SHA256 og indsætter ds:Signature i wsse:Security."""
    sign_keys = ["Body", "Timestamp", "MessageID", "UdbydersystemId"]
    refs = [
        _ds_ref(
            f"#{ids[k]}",
            _sha256_b64(_exc_c14n(_find_id(env, ids[k]))),
        )
        for k in sign_keys
    ]

    si = etree.Element(_q("ds", "SignedInfo"), nsmap={"ds": _NS["ds"]})
    etree.SubElement(si, _q("ds", "CanonicalizationMethod")).set("Algorithm", _C14N_EXC)
    etree.SubElement(si, _q("ds", "SignatureMethod")).set("Algorithm", _SIG_RSA256)
    for ref in refs:
        si.append(ref)

    raw_sig = private_key.sign(_exc_c14n(si), padding.PKCS1v15(), hashes.SHA256())

    sig = etree.Element(_q("ds", "Signature"), nsmap={"ds": _NS["ds"]})
    sig.append(si)
    etree.SubElement(sig, _q("ds", "SignatureValue")).text = (
        base64.b64encode(raw_sig).decode()
    )

    ki   = etree.SubElement(sig, _q("ds", "KeyInfo"))
    str_ = etree.SubElement(ki, _q("wsse", "SecurityTokenReference"))
    r    = etree.SubElement(str_, _q("wsse", "Reference"))
    r.set("URI", f"#{ids['BST']}")
    r.set("ValueType", _X509V3)

    env.xpath("//wsse:Security", namespaces={"wsse": _NS["wsse"]})[0].append(sig)


# ---------------------------------------------------------------------------
# Verifikation af SOAP-svarets WS-Security signatur
# ---------------------------------------------------------------------------

def _load_ca_cert(path: Path) -> x509.Certificate:
    """Indlæser et PEM-kodet CA-certifikat fra disk."""
    return x509.load_pem_x509_certificate(path.read_bytes())


def _verify_cert_chain(server_cert: x509.Certificate) -> None:
    """Verificer at serverens certifikat er udstedt af Den Danske Stats OCES CA."""
    inter = _load_ca_cert(CA_INTER)
    root  = _load_ca_cert(CA_ROOT)
    now   = datetime.now(timezone.utc)

    for cert, label in [
        (server_cert, "Serverens certifikat"),
        (inter,       "Mellemliggende CA"),
    ]:
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            raise ValueError(f"{label}: certifikatet er udløbet eller endnu ikke gyldigt.")

    cn = server_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    log.debug("Certifikat-CN: %s — udløber %s",
              cn, server_cert.not_valid_after_utc.strftime("%Y-%m-%d"))

    # verify_directly_issued_by håndterer automatisk RSA-PSS, RSA-PKCS1v15 og ECDSA
    try:
        server_cert.verify_directly_issued_by(inter)
    except Exception:
        raise ValueError("Serverens certifikat er ikke udstedt af den forventede OCES udstedende CA.")
    try:
        inter.verify_directly_issued_by(root)
    except Exception:
        raise ValueError("Den mellemliggende CA er ikke udstedt af OCES rod-CA.")

    log.debug("Certifikatkæde OK: %s → OCES udstedende CA → OCES rod-CA", cn)


def _find_by_any_id(root: etree._Element, id_value: str) -> etree._Element:
    """Find element med wsu:Id eller standard Id-attribut (uanset namespace)."""
    hits = root.xpath(f"//*[@*[local-name()='Id']='{id_value}']")
    if not hits:
        raise ValueError(f"Intet element med Id='{id_value}' i svaret.")
    return hits[0]


def verify_response_signature(xml_text: str) -> None:
    """
    Verificerer WS-Security signaturen på SOAP-svaret fra STIL.
    Kontrollerer: certifikatkæde → OCES CA, digest-værdier og RSA-SHA256 signatur.
    Kaster ValueError hvis noget ikke stemmer.
    """
    root = etree.fromstring(xml_text.encode())

    # 1. Hent serverens certifikat fra BinarySecurityToken
    bst_els = root.xpath("//wsse:BinarySecurityToken", namespaces={"wsse": _NS["wsse"]})
    if not bst_els:
        raise ValueError("Intet BinarySecurityToken i svaret — kan ikke verificere signatur.")
    server_cert_der = base64.b64decode(bst_els[0].text.strip())
    server_cert = x509.load_der_x509_certificate(server_cert_der)

    # 2. Verificer certifikatkæden mod OCES CA
    _verify_cert_chain(server_cert)

    # 3. Find ds:Signature og ds:SignedInfo
    sig_els = root.xpath("//ds:Signature", namespaces={"ds": _NS["ds"]})
    if not sig_els:
        raise ValueError("Ingen ds:Signature i svaret.")
    sig = sig_els[0]
    si  = sig.find(f"{{{_NS['ds']}}}SignedInfo")

    # 4. Verificer digest for hvert signeret element
    _EC14N_NS = "http://www.w3.org/2001/10/xml-exc-c14n#"

    # Læs PrefixList fra CanonicalizationMethod (bruges til C14N af SignedInfo)
    c14n_method = si.find(f"{{{_NS['ds']}}}CanonicalizationMethod")
    c14n_inc    = c14n_method.find(f"{{{_EC14N_NS}}}InclusiveNamespaces")
    si_prefixes = c14n_inc.get("PrefixList", "").split() if c14n_inc is not None else []
    for ref in si.findall(f"{{{_NS['ds']}}}Reference"):
        uri      = ref.get("URI", "")
        elem_id  = uri.lstrip("#")
        elem     = _find_by_any_id(root, elem_id)

        # Læs InclusiveNamespaces PrefixList fra Transform-elementet
        inc_ns_el = ref.find(
            f"{{{_NS['ds']}}}Transforms"
            f"/{{{_NS['ds']}}}Transform"
            f"/{{{_EC14N_NS}}}InclusiveNamespaces"
        )
        prefixes = inc_ns_el.get("PrefixList", "").split() if inc_ns_el is not None else []

        beregnet  = _sha256_b64(_exc_c14n_in_context(elem, prefixes))
        forventet = ref.findtext(f"{{{_NS['ds']}}}DigestValue", "").strip()
        if beregnet != forventet:
            raise ValueError(f"Digest-mismatch for element '{uri}': svaret er blevet ændret.")

    # 5. Verificer signaturen på SignedInfo med serverens offentlige nøgle
    sig_value = base64.b64decode(
        sig.findtext(f"{{{_NS['ds']}}}SignatureValue", "").strip()
    )
    try:
        server_cert.public_key().verify(
            sig_value, _exc_c14n_in_context(si, si_prefixes), padding.PKCS1v15(), hashes.SHA256()
        )
    except InvalidSignature:
        raise ValueError("SignatureValue er ugyldig — svaret er ikke fra STIL.")

    log.debug("WS-Security signatur OK — alle digests og SignatureValue verificeret")


# ---------------------------------------------------------------------------
# HTTP-transport
# ---------------------------------------------------------------------------

def _post(envelope: etree._Element, action: str, cert_der: bytes, key_pem: bytes) -> str:
    """Serialiserer og sender SOAP-envelope via HTTPS med TLS-klientcertifikat.
    Verificerer WS-Security-signaturen på svaret. Returnerer svarets XML som streng."""
    xml_bytes = etree.tostring(envelope, xml_declaration=True, encoding="UTF-8")
    operation = action.rsplit("/", 1)[-1]
    log.debug("Sender %s (%d bytes) → %s", operation, len(xml_bytes), ENDPOINT)

    t0 = time.monotonic()
    with _tls_cert(cert_der, key_pem) as (cert_path, key_path):
        resp = requests.post(
            ENDPOINT,
            data=xml_bytes,
            headers={
                "Content-Type": f'application/soap+xml; charset=UTF-8; action="{action}"'
            },
            cert=(cert_path, key_path),
            verify=True,
        )
    elapsed = time.monotonic() - t0

    log.debug("Svar modtaget: HTTP %d, %d bytes, %.2fs",
              resp.status_code, len(resp.content), elapsed)

    if not resp.ok:
        log.error("HTTP %d fra %s: %s", resp.status_code, operation, resp.text[:500])
        raise RuntimeError(f"HTTP {resp.status_code}:\n{resp.text}")

    verify_response_signature(resp.text)
    log.info("%-30s HTTP %d  %6.2fs  %s KB",
             operation, resp.status_code, elapsed, len(resp.content) // 1024)
    return resp.text


# ---------------------------------------------------------------------------
# Interne hjælpere til offentlige operationer
# ---------------------------------------------------------------------------

def _call(action: str, body_element: etree._Element) -> str:
    """Signerer og sender en SOAP-forespørgsel; returnerer det rå XML-svar."""
    cert_der    = CERT_FILE.read_bytes()
    key_pem     = KEY_FILE.read_bytes()
    private_key = serialization.load_pem_private_key(key_pem, password=None)

    env, ids = _build_envelope(cert_der, action, body_element)
    _apply_signature(env, ids, private_key)

    return _post(env, action, cert_der, key_pem)


# ---------------------------------------------------------------------------
# Offentlige operationer — testforbindelse
# ---------------------------------------------------------------------------

def hello_world_with_certificate() -> str:
    """Tester forbindelsen og certifikatautentificering."""
    body = etree.Element(_q("eks", "helloWorldWithCertificate"))
    return _call(f"{_NS['eks']}/helloWorldWithCertificate", body)


# ---------------------------------------------------------------------------
# Offentlige operationer — eksporterXml* (kræver institutionsnummer)
# ---------------------------------------------------------------------------

def eksporter_xml_lille(instnr: str) -> str:
    """Lille eksport: grupper, medlemmer og kontaktpersoner for én institution."""
    body = etree.Element(_q("eks", "eksporterXmlLille"))
    etree.SubElement(body, _q("eks", "instnr")).text = instnr
    return _call(f"{_NS['eks']}/eksporterXmlLille", body)


def eksporter_xml_mellem(instnr: str) -> str:
    """Mellemstor eksport: som lille, men inkluderer CPR-numre."""
    body = etree.Element(_q("eks", "eksporterXmlMellem"))
    etree.SubElement(body, _q("eks", "instnr")).text = instnr
    return _call(f"{_NS['eks']}/eksporterXmlMellem", body)


def eksporter_xml_fuld(instnr: str) -> str:
    """Fuld eksport for én institution."""
    body = etree.Element(_q("eks", "eksporterXmlFuld"))
    etree.SubElement(body, _q("eks", "instnr")).text = instnr
    return _call(f"{_NS['eks']}/eksporterXmlFuld", body)


def eksporter_xml_fuld_myndighed(instnr: str) -> str:
    """Fuld eksport på myndighedsniveau for én institution."""
    body = etree.Element(_q("eks", "eksporterXmlFuldMyndighed"))
    etree.SubElement(body, _q("eks", "instnr")).text = instnr
    return _call(f"{_NS['eks']}/eksporterXmlFuldMyndighed", body)


# ---------------------------------------------------------------------------
# Offentlige operationer — hentDataAftaler* (ingen argumenter)
# ---------------------------------------------------------------------------

def hent_data_aftaler_lille() -> str:
    """Returnerer liste over dataaftaler for lille eksport."""
    body = etree.Element(_q("eks", "hentDataAftalerLille"))
    return _call(f"{_NS['eks']}/hentDataAftalerLille", body)


def hent_data_aftaler_mellem() -> str:
    """Returnerer liste over dataaftaler for mellemstor eksport."""
    body = etree.Element(_q("eks", "hentDataAftalerMellem"))
    return _call(f"{_NS['eks']}/hentDataAftalerMellem", body)


def hent_data_aftaler_fuld() -> str:
    """Returnerer liste over dataaftaler for fuld eksport."""
    body = etree.Element(_q("eks", "hentDataAftalerFuld"))
    return _call(f"{_NS['eks']}/hentDataAftalerFuld", body)


def hent_data_aftaler_fuld_myndighed() -> str:
    """Returnerer liste over dataaftaler for fuld eksport på myndighedsniveau."""
    body = etree.Element(_q("eks", "hentDataAftalerFuldMyndighed"))
    return _call(f"{_NS['eks']}/hentDataAftalerFuldMyndighed", body)


# ---------------------------------------------------------------------------
# Kommandolinjegrænseflade
# ---------------------------------------------------------------------------

# Oversigt over alle tilgængelige funktioner:
#   navn -> (funktion, kræver_instnr)
_FUNKTIONER: dict[str, tuple] = {
    "hello":                  (hello_world_with_certificate,  False),
    "lille":                  (eksporter_xml_lille,            True),
    "mellem":                 (eksporter_xml_mellem,           True),
    "fuld":                   (eksporter_xml_fuld,             True),
    "fuld-myndighed":         (eksporter_xml_fuld_myndighed,   True),
    "aftaler-lille":          (hent_data_aftaler_lille,        False),
    "aftaler-mellem":         (hent_data_aftaler_mellem,       False),
    "aftaler-fuld":           (hent_data_aftaler_fuld,         False),
    "aftaler-fuld-myndighed": (hent_data_aftaler_fuld_myndighed, False),
}

# OK, lets'ago!
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        prog="main.py",
        description="STIL wsiEKSPORT v7 — kommandolinjeklient",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Tilgængelige funktioner:
  hello                      Test certifikatforbindelsen
  lille          [instnr…]   Lille eksport
  mellem         [instnr…]   Mellemstor eksport (inkl. CPR)
  fuld           [instnr…]   Fuld eksport
  fuld-myndighed [instnr…]   Fuld eksport på myndighedsniveau
  aftaler-lille              Dataaftaler for lille eksport
  aftaler-mellem             Dataaftaler for mellemstor eksport
  aftaler-fuld               Dataaftaler for fuld eksport
  aftaler-fuld-myndighed     Dataaftaler for fuld myndighed

En eller flere institutionsnumre kan angives på kommandolinjen eller som standard
i .env via: INSTITUTIONS=101155,101126,101088

Eksempler:
  python main.py fuld-myndighed 101155 101126
  python main.py fuld-myndighed          # bruger INSTITUTIONS fra .env
  python main.py aftaler-fuld
  python main.py hello
""",
    )
    parser.add_argument(
        "funktion",
        choices=_FUNKTIONER.keys(),
        metavar="funktion",
        help="Funktion der skal kaldes (se liste nedenfor)",
    )
    parser.add_argument(
        "institutioner",
        nargs="*",
        metavar="instnr",
        help="Institutionsnumre (tilsidesætter INSTITUTIONS i .env)",
    )
    parser.add_argument(
        "--output", "-o",
        default=str(BASE_DIR),
        metavar="MAPPE",
        help="Mappe til outputfiler (standard: projektmappen)",
    )

    args = parser.parse_args()
    fn, kræver_instnr = _FUNKTIONER[args.funktion]
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    def gem(filnavn: str, raw: str) -> None:
        """Parser XML-svaret, pretty-printer det og gemmer det som UTF-8-fil i output_dir."""
        tree   = etree.fromstring(raw.encode())
        pretty = etree.tostring(tree, pretty_print=True, encoding="unicode")
        sti    = output_dir / filnavn
        sti.write_text(pretty, encoding="utf-8")
        log.info("Gemt: %s (%d KB)", sti, len(pretty) // 1024)

    def kald(label: str, kald_fn, *kald_args) -> bool:
        """Udfør ét servicekald og håndtér fejl. Returnerer True ved succes."""
        try:
            gem(label, kald_fn(*kald_args))
            return True
        except RuntimeError as e:
            tekst = str(e)
            try:
                rod = etree.fromstring(tekst.split("\n", 1)[1].encode())
                fejl = rod.findtext(".//{http://www.w3.org/2003/05/soap-envelope}Text") or tekst
            except Exception:
                fejl = tekst
            log.error("Servicekald fejlede: %s", fejl)
            return False
        except ValueError as e:
            log.error("Signaturverifikation fejlede: %s", e)
            return False
        except Exception as e:
            log.error("Uventet fejl: %s: %s", type(e).__name__, e)
            return False

    fejl_antal = 0

    if kræver_instnr:
        institutioner = args.institutioner
        if not institutioner:
            env_liste = os.getenv("INSTITUTIONS", "")
            institutioner = [i.strip() for i in env_liste.split(",") if i.strip()]
        if not institutioner:
            parser.error(
                "Angiv mindst ét institutionsnummer, eller sæt INSTITUTIONS i .env"
            )
        for instnr in institutioner:
            log.info("Henter '%s' for institution %s", args.funktion, instnr)
            if not kald(f"eksport_{args.funktion}_{instnr}.xml", fn, instnr):
                fejl_antal += 1
    else:
        log.info("Kalder '%s'", args.funktion)
        if not kald(f"eksport_{args.funktion}.xml", fn):
            fejl_antal += 1

    if fejl_antal:
        raise SystemExit(1)
