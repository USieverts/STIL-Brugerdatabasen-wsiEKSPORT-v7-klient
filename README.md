# STIL wsiEKSPORT v7 — Python SOAP-klient

Python-klient til STILs [Brugerdatabasen BPI-webservice wsiEKSPORT v7](https://viden.stil.dk/spaces/INFRA2/pages/2360658/Unilogin+SkoleGrunddata+BPI-webservices).

Klienten håndterer WS-Security-autentificering med OCES3-certifikat (RSA-SHA256, eksklusiv C14N) og understøtter alle ni operationer i webservicen. Hvert svar verificeres automatisk mod STILs OCES3-certifikatkæde.

---

## Forudsætninger

- Python 3.12+
- Et **udbydersystem-ID** hos STIL
  - [Bliv oprettet som udbyder](https://viden.stil.dk/spaces/OFFTILSLU/pages/299139435/Bliv+oprettet+som+udbyder)
- Et gyldigt **OCES3-organisationscertifikat** tilknyttet udbydersystemet
  - [Administrér organisations- og systemcertifikater](https://www.mitid-erhverv.dk/sadan-bruger-du-mitid-erhverv/administrer-certifikater/administrer-organisations-og-systemcertifikater/)
  - [Tilføj certifikat til udbydersystem](https://viden.stil.dk/spaces/OFFTILSLU/pages/343441603/Tilf%C3%B8j+certifikat)
- Godkendte **dataaftaler** for udbydersystemet i STILs selvbetjeningsportal til de institutioner og eksporttyper der ønskes adgang til
  - [Anmod om dataadgang](https://viden.stil.dk/spaces/OFFTILSLU/pages/299139418/Anmodning+om+data+fra+eller+p%C3%A5+vegne+af+institutioner+Dataadgange)

---

## Installation

```bash
# Opret virtuelt miljø
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS

# Installér afhængigheder
pip install -r requirements.txt
```

---

## Konfiguration

Kopiér `.env.example` til `.env` og udfyld dine egne værdier:

```bash
cp .env.example .env
```

```ini
# Sti til OCES3-certifikat (.cer, DER-format)
CERT_FILE=C:\Users\dig\.credentials\dit-certifikat.cer

# Sti til tilhørende privat nøgle (.key, ukrypteret PKCS8)
KEY_FILE=C:\Users\dig\.credentials\din-private.key

# Udbydersystem-ID registreret hos STIL
UDBYDER_SYSTEM_ID=ABxxxxxx

# Standard-institutionsliste (bruges når ingen instnr angives på kommandolinjen)
INSTITUTIONS=101088,101155

# Logniveau: DEBUG, INFO, WARNING eller ERROR (standard: INFO)
LOG_LEVEL=INFO

# Valgfri logfil — udelad for kun at logge til konsollen
# LOG_FILE=wsieksport.log
```

> **Vigtigt:** Certifikatet og den private nøgle bør ligge offline og uden for projektmappen.

---

## Brug

```
python main.py <funktion> [instnr …] [--output MAPPE]
```

### Tilgængelige funktioner

| Funktion | Beskrivelse | Kræver instnr |
|---|---|---|
| `hello` | Test certifikatforbindelsen | Nej |
| `lille` | Lille eksport (grupper, medlemmer, kontaktpersoner) | Ja |
| `mellem` | Mellemstor eksport (som lille + CPR-numre) | Ja |
| `fuld` | Fuld eksport for én institution | Ja |
| `fuld-myndighed` | Fuld eksport på myndighedsniveau | Ja |
| `aftaler-lille` | Liste over dataaftaler for lille eksport | Nej |
| `aftaler-mellem` | Liste over dataaftaler for mellemstor eksport | Nej |
| `aftaler-fuld` | Liste over dataaftaler for fuld eksport | Nej |
| `aftaler-fuld-myndighed` | Liste over dataaftaler for fuld myndighed | Nej |

### Eksempler

```bash
# Test forbindelsen
python main.py hello 
#OBS! STIL's server returnerer konsekvent HTTP 500 på den operation. Brug i stedet eksv. aftaler-lille til at teste at forbindelsen virker.

# Hent fuld-myndighed for specifikke institutioner
python main.py fuld-myndighed 101088 101155

# Brug standardlisten fra .env (INSTITUTIONS=...)
python main.py fuld-myndighed

# Gem filer i en bestemt mappe
python main.py fuld-myndighed 101088 --output C:\eksporter\

# Se alle dataaftaler for fuld eksport
python main.py aftaler-fuld
```

Output gemmes som pretty-printed XML med filnavnet `eksport_<funktion>_<instnr>.xml` (eller `eksport_<funktion>.xml` for funktioner uden instnr).

---

## Logging

Klienten logger til konsollen via Pythons standard `logging`-modul. Adfærden styres med to valgfrie `.env`-variabler:

```ini
# Logniveau: DEBUG, INFO, WARNING eller ERROR (standard: INFO)
LOG_LEVEL=INFO

# Valgfri logfil — udelad for kun at logge til konsollen
LOG_FILE=wsieksport.log
```

| Niveau | Hvad logges |
|---|---|
| `INFO` | Operationsnavn, HTTP-statuskode, svartid, filsti og størrelse |
| `DEBUG` | Requeststørrelse, certifikat-CN og udløbsdato, certifikatkæde, digest- og signaturverifikation |
| `ERROR` | HTTP-fejl, signaturverifikations fejl, netværksfejl |

Eksempel på INFO-output:
```
2026-06-01 11:35:20 INFO     Henter 'fuld-myndighed' for institution 101088
2026-06-01 11:35:21 INFO     eksporterXmlFuldMyndighed      HTTP 200    1.23s  245 KB
2026-06-01 11:35:21 INFO     Gemt: eksport_fuld-myndighed_101088.xml (312 KB)
```

---

## Certifikat og nøgle

OCES3-certifikater til webserviceadgang udstedes af **Den Danske Stat** via [Nets/MitID Erhverv](https://erhverv.mitid.dk). 

Se STILs vejledning: [Certifikatsikkerhed](https://viden.stil.dk/spaces/INFRA2/pages/314540219/Certifikatsikkerhed)

Den private nøgle genereres ved certifikatansøgningen og leveres typisk i en PKCS12-fil (`.pfx`/`.p12`). Nøglen kan udpakkes til ukrypteret PEM-format med OpenSSL:

```bash
openssl pkcs12 -in certifikat.pfx -nocerts -nodes -out private.key
openssl pkcs12 -in certifikat.pfx -clcerts -nokeys -out certifikat.cer
```

---

## Svarverifikation

Hvert SOAP-svar fra STIL verificeres automatisk, inden det behandles. Verifikationen består af tre trin:

1. **Certifikatkæde** — serverens OCES3-certifikat kontrolleres mod `Den Danske Stat OCES udstedende-CA 1` og `Den Danske Stat OCES rod-CA`, som er inkluderet i mappen `ca/`. Certifikatets gyldighed (udløbsdato) tjekkes ligeledes.
2. **Digest-værdier** — SHA256-digest for hvert signeret element (Body, Timestamp, MessageID m.fl.) beregnes og sammenlignes med de værdier serveren har angivet i signaturen.
3. **RSA-SHA256 signatur** — `SignatureValue` verificeres med serverens offentlige nøgle mod det kanoniserede `SignedInfo`-element.

Hvis et af trinene fejler, afbrydes kaldet med en fejlmeddelelse og exit-kode 1. 

CA-certifikaterne hentes fra [ca1.gov.dk](https://www.ca1.gov.dk/certifikater/) og kan fornyes ved at erstatte filerne i `ca/`.

---

## Projektstruktur

```
.
├── main.py              # SOAP-klient og kommandolinjegrænseflade
├── ca/
│   ├── oces-root-ca.pem         # Den Danske Stat OCES rod-CA
│   └── oces-intermediate-ca.pem # Den Danske Stat OCES udstedende-CA 1
├── .env                 # Lokale indstillinger — gitignored
├── .env.example         # Skabelon til .env
├── .gitignore
├── LICENSE
├── README.md
└── requirements.txt
```

Certifikat og privat nøgle opbevares **uden for** projektmappen (se [Konfiguration](#konfiguration)).
