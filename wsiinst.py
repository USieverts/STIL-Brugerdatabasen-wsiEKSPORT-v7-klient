#!/usr/bin/env python3
"""
SOAP-klient til Brugerdatabasen wsiINST v6.

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
# Konfiguration — environmentvariabler
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

ENDPOINT = "https://brugerdatabasen.stil.dk/bpi/wsiinst/6"

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
    "inst": "https://brugerdatabasen.stil.dk/bpi/wsiinst/6",
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

    try:
        server_cert.verify_directly_issued_by(inter)
    except Exception:
        raise ValueError("Serverens certifikat er ikke udstedt af den forventede OCES udstedende CA.")
    try:
        inter.verify_directly_issued_by(root)
    except Exception:
        raise ValueError("Den mellemliggende CA er ikke udstedt af OCES rod-CA.")

    log.debug("Certifikatkæde OK: %s -> OCES udstedende CA -> OCES rod-CA", cn)


def _find_by_any_id(root: etree._Element, id_value: str) -> etree._Element:
    """Find element med wsu:Id eller standard Id-attribut (uanset namespace)."""
    hits = root.xpath(f"//*[@*[local-name()='Id']='{id_value}']")
    if not hits:
        raise ValueError(f"Intet element med Id='{id_value}' i svaret.")
    return hits[0]


def verify_response_signature(xml_text: str) -> None:
    """
    Verificerer WS-Security signaturen på SOAP-svaret fra STIL.
    Kontrollerer: certifikatkæde -> OCES CA, digest-værdier og RSA-SHA256 signatur.
    Kaster ValueError hvis noget ikke stemmer.
    """
    root = etree.fromstring(xml_text.encode())

    bst_els = root.xpath("//wsse:BinarySecurityToken", namespaces={"wsse": _NS["wsse"]})
    if not bst_els:
        raise ValueError("Intet BinarySecurityToken i svaret — kan ikke verificere signatur.")
    server_cert = x509.load_der_x509_certificate(
        base64.b64decode(bst_els[0].text.strip())
    )
    _verify_cert_chain(server_cert)

    sig_els = root.xpath("//ds:Signature", namespaces={"ds": _NS["ds"]})
    if not sig_els:
        raise ValueError("Ingen ds:Signature i svaret.")
    sig = sig_els[0]
    si  = sig.find(f"{{{_NS['ds']}}}SignedInfo")

    _EC14N_NS = "http://www.w3.org/2001/10/xml-exc-c14n#"
    c14n_method = si.find(f"{{{_NS['ds']}}}CanonicalizationMethod")
    c14n_inc    = c14n_method.find(f"{{{_EC14N_NS}}}InclusiveNamespaces")
    si_prefixes = c14n_inc.get("PrefixList", "").split() if c14n_inc is not None else []

    for ref in si.findall(f"{{{_NS['ds']}}}Reference"):
        uri     = ref.get("URI", "")
        elem    = _find_by_any_id(root, uri.lstrip("#"))
        inc_el  = ref.find(
            f"{{{_NS['ds']}}}Transforms"
            f"/{{{_NS['ds']}}}Transform"
            f"/{{{_EC14N_NS}}}InclusiveNamespaces"
        )
        prefixes = inc_el.get("PrefixList", "").split() if inc_el is not None else []
        beregnet = _sha256_b64(_exc_c14n_in_context(elem, prefixes))
        forventet = ref.findtext(f"{{{_NS['ds']}}}DigestValue", "").strip()
        if beregnet != forventet:
            raise ValueError(f"Digest-mismatch for element '{uri}': svaret er blevet ændret.")

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
    log.debug("Sender %s (%d bytes) -> %s", operation, len(xml_bytes), ENDPOINT)

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
# Internt hjælper
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
# Offentlige operationer
# ---------------------------------------------------------------------------

def hello_world_with_certificate() -> str:
    """Tester forbindelsen og certifikatautentificering."""
    body = etree.Element(_q("inst", "helloWorldWithCertificate"))
    return _call(f"{_NS['inst']}/helloWorldWithCertificate", body)


def hent_grupper(instnr: str) -> str:
    """Henter alle grupper (inkl. basisklasser) for en institution. Kræver ikke dataaftale."""
    body = etree.Element(_q("inst", "hentGrupper"))
    etree.SubElement(body, _q("inst", "instnr")).text = instnr
    return _call(f"{_NS['inst']}/hentGrupper", body)


def hent_brugere_i_gruppe(instnr: str, gruppeid: str) -> str:
    """Henter alle brugertilknytninger i en specifik gruppe på en institution."""
    body = etree.Element(_q("inst", "hentBrugereIGruppe"))
    etree.SubElement(body, _q("inst", "instnr")).text = instnr
    etree.SubElement(body, _q("inst", "gruppeid")).text = gruppeid
    return _call(f"{_NS['inst']}/hentBrugereIGruppe", body)


def hent_institution(instnr: str) -> str:
    """Henter oplysninger om én institution. Kræver ikke dataaftale."""
    body = etree.Element(_q("inst", "hentInstitution"))
    etree.SubElement(body, _q("inst", "instnr")).text = instnr
    return _call(f"{_NS['inst']}/hentInstitution", body)


def hent_institutioner(instnr_liste: list[str]) -> str:
    """Henter oplysninger om en eller flere institutioner i ét kald. Kræver ikke dataaftale."""
    body = etree.Element(_q("inst", "hentInstitutioner"))
    for instnr in instnr_liste:
        etree.SubElement(body, _q("inst", "instnr")).text = instnr
    return _call(f"{_NS['inst']}/hentInstitutioner", body)


def hent_inst_bruger(brugerid: str, instnr: str | None = None) -> str:
    """Henter en brugers institutionstilknytning inkl. grupper, klassetrin og stilling."""
    body = etree.Element(_q("inst", "hentInstBruger"))
    if instnr:
        etree.SubElement(body, _q("inst", "instnr")).text = instnr
    etree.SubElement(body, _q("inst", "brugerid")).text = brugerid
    return _call(f"{_NS['inst']}/hentInstBruger", body)


def hent_institutionshierarki(instnr: str) -> str:
    """Henter institutionshierarkiet (hovedinstitution og afdelinger). Kræver ikke dataaftale."""
    body = etree.Element(_q("inst", "hentInstitutionshierarki"))
    etree.SubElement(body, _q("inst", "instnr")).text = instnr
    return _call(f"{_NS['inst']}/hentInstitutionshierarki", body)


def hent_data_aftaler() -> str:
    """Henter liste over dataaftaler for udbyderssystemet."""
    body = etree.Element(_q("inst", "hentDataAftaler"))
    return _call(f"{_NS['inst']}/hentDataAftaler", body)


# ---------------------------------------------------------------------------
# Kommandolinjegrænseflade
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        prog="wsiinst.py",
        description="STIL wsiINST v6 — kommandolinjeklient",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Tilgængelige funktioner:
  hello                     Test certifikatforbindelsen
  grupper       instnr      Institutionens grupper
  brugere-i-gruppe instnr --gruppe ID
                            Medlemmer af en gruppe
  institution   instnr      Oplysninger om én institution
  institutioner instnr …   Oplysninger om flere institutioner
  inst-bruger  --bruger ID [instnr]
                            En brugers institutionstilknytning
  hierarki      instnr      Institutionshierarki
  aftaler                   Dataaftaler for udbyderssystemet

Eksempler:
  python wsiinst.py grupper 101088
  python wsiinst.py brugere-i-gruppe 101088 --gruppe dk:stil:bs:gruppe:12345
  python wsiinst.py institutioner 101088 101155 101126
  python wsiinst.py inst-bruger --bruger jens1234 --institution 101088
  python wsiinst.py hierarki 101088
  python wsiinst.py aftaler
""",
    )
    parser.add_argument(
        "funktion",
        choices=["hello", "grupper", "brugere-i-gruppe", "institution",
                 "institutioner", "inst-bruger", "hierarki", "aftaler"],
        metavar="funktion",
        help="Funktion der skal kaldes (se liste nedenfor)",
    )
    parser.add_argument(
        "institutioner",
        nargs="*",
        metavar="instnr",
        help="Institutionsnummer(e)",
    )
    parser.add_argument("--gruppe",      metavar="ID",  help="Gruppe-ID (til brugere-i-gruppe)")
    parser.add_argument("--bruger",      metavar="ID",  help="Bruger-ID (til inst-bruger)")
    parser.add_argument("--institution", metavar="NR",  help="Institutionsnummer (valgfrit til inst-bruger)")
    parser.add_argument(
        "--output", "-o",
        default=str(BASE_DIR),
        metavar="MAPPE",
        help="Mappe til outputfiler (standard: projektmappen)",
    )

    args = parser.parse_args()
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    def gem(filnavn: str, raw: str) -> None:
        """Parser XML-svaret, pretty-printer det og gemmer det som UTF-8-fil i output_dir."""
        tree   = etree.fromstring(raw.encode())
        pretty = etree.tostring(tree, pretty_print=True, encoding="unicode")
        sti    = output_dir / filnavn
        sti.write_text(pretty, encoding="utf-8")
        log.info("Gemt: %s (%d KB)", sti, len(pretty) // 1024)

    def kald(filnavn: str, fn, *fn_args) -> bool:
        """Udfør ét servicekald og håndtér fejl. Returnerer True ved succes."""
        try:
            gem(filnavn, fn(*fn_args))
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

    ok = True
    fn = args.funktion
    insts = args.institutioner

    if fn == "hello":
        log.info("Kalder 'hello'")
        ok = kald("inst_hello.xml", hello_world_with_certificate)

    elif fn == "grupper":
        for nr in insts:
            log.info("Henter grupper for institution %s", nr)
            ok = kald(f"inst_grupper_{nr}.xml", hent_grupper, nr) and ok

    elif fn == "brugere-i-gruppe":
        if not insts or not args.gruppe:
            parser.error("brugere-i-gruppe kræver instnr og --gruppe ID")
        log.info("Henter brugere i gruppe %s for institution %s", args.gruppe, insts[0])
        ok = kald(f"inst_brugere_{insts[0]}_{args.gruppe}.xml",
                  hent_brugere_i_gruppe, insts[0], args.gruppe)

    elif fn == "institution":
        for nr in insts:
            log.info("Henter institution %s", nr)
            ok = kald(f"inst_institution_{nr}.xml", hent_institution, nr) and ok

    elif fn == "institutioner":
        if not insts:
            parser.error("institutioner kræver mindst ét instnr")
        log.info("Henter institutioner: %s", ", ".join(insts))
        ok = kald(f"inst_institutioner_{'_'.join(insts)}.xml", hent_institutioner, insts)

    elif fn == "inst-bruger":
        if not args.bruger:
            parser.error("inst-bruger kræver --bruger ID")
        log.info("Henter bruger %s", args.bruger)
        ok = kald(f"inst_bruger_{args.bruger}.xml",
                  hent_inst_bruger, args.bruger, args.institution)

    elif fn == "hierarki":
        for nr in insts:
            log.info("Henter hierarki for institution %s", nr)
            ok = kald(f"inst_hierarki_{nr}.xml", hent_institutionshierarki, nr) and ok

    elif fn == "aftaler":
        log.info("Henter dataaftaler")
        ok = kald("inst_aftaler.xml", hent_data_aftaler)

    if not ok:
        raise SystemExit(1)
