# STIL BPI-webservices — Python SOAP-klienter

Python-klienter til STILs [Brugerdatabasen BPI-webservices](https://viden.stil.dk/spaces/INFRA2/pages/2360658/Unilogin+SkoleGrunddata+BPI-webservices).

Klienterne håndterer WS-Security-autentificering med OCES3-certifikat (RSA-SHA256, eksklusiv C14N) og understøtter alle operationer i den pågældende webservice. Svar verificeres automatisk mod STILs OCES3-certifikatkæde.

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

Projektet indeholder fem separate klienter, én pr. STIL-webservice:

| Script | Service | Formål |
|---|---|---|
| `wsieksport.py` | wsiEKSPORT v7 | Masseeksport af grupper, medlemmer og kontaktpersoner |
| `wsiinst.py` | wsiINST v6 | Opslag på institutioner, grupper og brugertilknytninger |
| `wsibruger.py` | wsiBRUGER v7 | Opslag på bruger–kontaktperson-relationer |
| `wsiidentifikation.py` | wsiIDENTIFIKATION v6 | Mapping mellem UniID og CPR-nummer |
| `wsaimport.py` | wsaIMPORT v8 | Import af brugere og grupper til SkoleGrunddata |

Alle scripts gemmer svar som pretty-printed XML og understøtter `--output MAPPE`. Kald `python <script>.py --help` for fuld hjælp.

---

### wsieksport.py — wsiEKSPORT v7

```
python wsieksport.py <funktion> [instnr …] [--output MAPPE]
```

| Funktion | Beskrivelse | Parametre |
|---|---|---|
| `hello` | Test certifikatforbindelsen | — |
| `lille` | Lille eksport (grupper, medlemmer, kontaktpersoner) | instnr … |
| `mellem` | Mellemstor eksport (som lille + CPR-numre) | instnr … |
| `fuld` | Fuld eksport for én institution | instnr … |
| `fuld-myndighed` | Fuld eksport på myndighedsniveau | instnr … |
| `aftaler-lille` | Dataaftaler for lille eksport | — |
| `aftaler-mellem` | Dataaftaler for mellemstor eksport | — |
| `aftaler-fuld` | Dataaftaler for fuld eksport | — |
| `aftaler-fuld-myndighed` | Dataaftaler for fuld myndighed | — |

```bash
python wsieksport.py fuld-myndighed 101088 101155
python wsieksport.py fuld-myndighed          # bruger INSTITUTIONS fra .env
python wsieksport.py fuld-myndighed 101088 --output C:\eksporter\
python wsieksport.py aftaler-fuld
```

> `hello` returnerer konsekvent HTTP 500 fra STILs server. Brug `aftaler-fuld` til forbindelsestest.

---

### wsiinst.py — wsiINST v6

```
python wsiinst.py <funktion> [instnr …] [--gruppe ID] [--bruger ID] [--output MAPPE]
```

| Funktion | Beskrivelse | Parametre |
|---|---|---|
| `hello` | Test certifikatforbindelsen | — |
| `grupper` | Institutionens grupper | instnr |
| `brugere-i-gruppe` | Medlemmer af en gruppe | instnr `--gruppe ID` |
| `institution` | Oplysninger om én institution | instnr |
| `institutioner` | Oplysninger om flere institutioner | instnr … |
| `inst-bruger` | En brugers institutionstilknytning | `--bruger ID` [instnr] |
| `hierarki` | Institutionshierarki | instnr |
| `aftaler` | Dataaftaler | — |

```bash
python wsiinst.py grupper 101088
python wsiinst.py brugere-i-gruppe 101088 --gruppe dk:stil:bs:gruppe:12345
python wsiinst.py institutioner 101088 101155 101126
python wsiinst.py inst-bruger --bruger jens1234 --institution 101088
python wsiinst.py hierarki 101088
python wsiinst.py aftaler
```

---

### wsibruger.py — wsiBRUGER v7

```
python wsibruger.py <funktion> [instnr] [--bruger ID] [--institution NR] [--output MAPPE]
```

| Funktion | Beskrivelse | Parametre |
|---|---|---|
| `hello` | Test certifikatforbindelsen | — |
| `kontakter` | Kontaktpersoner tilknyttet en elev | instnr `--bruger ID` |
| `elever` | Elever tilknyttet en kontaktperson | `--bruger ID` [`--institution NR`] |
| `tilknytninger` | Alle institutioner og roller for en bruger | `--bruger ID` |
| `aftaler` | Dataaftaler | — |

```bash
python wsibruger.py kontakter 101088 --bruger jens1234
python wsibruger.py elever --bruger kontakt5678 --institution 101088
python wsibruger.py tilknytninger --bruger jens1234
python wsibruger.py aftaler
```

---

### wsiidentifikation.py — wsiIDENTIFIKATION v6

```
python wsiidentifikation.py <funktion> [--cpr XXXXXXXXXX] [--bruger ID] [--output MAPPE]
```

| Funktion | Beskrivelse | Parametre |
|---|---|---|
| `hello` | Test certifikatforbindelsen | — |
| `brugerid` | UniLogin-brugerid (UniID) for et CPR-nummer | `--cpr XXXXXXXXXX` |
| `cpr` | CPR-nummer for et UniLogin-brugerid | `--bruger ID` |

```bash
python wsiidentifikation.py brugerid --cpr 1234567890
python wsiidentifikation.py cpr --bruger jens1234
```

> **OBS:** Svarfiler indeholder CPR-numre og er gitignored som `idi_*.xml`. Håndtér dem i overensstemmelse med persondatalovgivningen.

> `hello` returnerer konsekvent HTTP 500 fra STILs server.

---

### wsaimport.py — wsaIMPORT v8

```
python wsaimport.py <funktion> [--xml FIL] [--output MAPPE]
```

| Funktion | Beskrivelse | Parametre |
|---|---|---|
| `hello` | Test certifikatforbindelsen | — |
| `fuld` | Fuld import — erstatter alle eksisterende data for institutionen | `--xml FIL` |
| `delta` | Delta-import af ændrede brugere (primær importmetode) | `--xml FIL` |
| `slet` | Slet-import — fjerner angivne brugere fra SkoleGrunddata | `--xml FIL` |
| `aftaler` | Dataaftaler for udbyderssystemet | — |

```bash
python wsaimport.py fuld --xml skoledata.xml
python wsaimport.py delta --xml aendringer.xml
python wsaimport.py slet --xml slettes.xml
python wsaimport.py aftaler
```

> **OBS:** Import-operationerne skriver direkte til STILs Brugerdatabase. Kontrollér altid input-XML grundigt, inden du kører. Se STILs [SkoleGrunddata-dokumentation](https://viden.stil.dk/spaces/INFRA2/pages/2360666) for det forventede XML-format.

> `hello` returnerer konsekvent HTTP 500 fra STILs server. Brug `aftaler` til forbindelsestest.

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

OCES3-certifikater til webserviceadgang udstedes af Den Danske Stat via [Nets/MitID Erhverv](https://erhverv.mitid.dk). 

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
├── wsieksport.py        # SOAP-klient til wsiEKSPORT v7 (masseeksport)
├── wsiinst.py           # SOAP-klient til wsiINST v6 (institutionsopslag)
├── wsibruger.py         # SOAP-klient til wsiBRUGER v7 (bruger–kontakt-relationer)
├── wsiidentifikation.py # SOAP-klient til wsiIDENTIFIKATION v6 (UniID ↔ CPR)
├── wsaimport.py         # SOAP-klient til wsaIMPORT v8 (import til SkoleGrunddata)
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
