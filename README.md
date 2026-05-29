# STIL wsiEKSPORT v7 — Python SOAP-klient

Python-klient til STILs [Brugerdatabasen BPI-webservice wsiEKSPORT v7](https://viden.stil.dk/spaces/INFRA2/pages/2360658/Unilogin+SkoleGrunddata+BPI-webservices).

Klienten håndterer WS-Security-autentificering med OCES3-certifikat (RSA-SHA256, eksklusiv C14N) og understøtter alle ni operationer i webservicen.

---

## Forudsætninger

- Python 3.12+
- Et **udbydersystem-ID** hos STIL 
- Et gyldigt **OCES3-organisationscertifikat** tilknyttet udbydersystemet 
- Godkendte **dataaftaler** for udbydersystemet i STILs selvbetjeningsportal til de institutioner og eksporttyper der ønskes adgang til

Opret udbydersystem:    [Styrelsen for IT og Lærings vidensbase: Bliv oprettet som udbyder](https://viden.stil.dk/spaces/OFFTILSLU/pages/299139435/Bliv+oprettet+som+udbyder)
Opret organisationscertifikat:  [MitID erhverv: Administrér organisations- og systemcertifikater](https://www.mitid-erhverv.dk/sadan-bruger-du-mitid-erhverv/administrer-certifikater/administrer-organisations-og-systemcertifikater/)
Tilknyt certifikat:     [Styrelsen for IT og Lærings vidensbase: Tilføj certifikat](https://viden.stil.dk/spaces/OFFTILSLU/pages/343441603/Tilf%C3%B8j+certifikat)
Anmod om dataadgang:    [Styrelsen for IT og Lærings vidensbase: Anmod om data fra eller på vegne af institutioner](https://viden.stil.dk/spaces/OFFTILSLU/pages/299139418/Anmodning+om+data+fra+eller+p%C3%A5+vegne+af+institutioner+Dataadgange)

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
```

> **Vigtigt:** Certifikatet og den private nøgle bør ligge **offline** og **uden for projektmappen**.

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
python main.py hello #OBS! STIL's server returnerer konsekvent HTTP 500 på den operation. Brug i stedet aftaler-fuld eller aftaler-lille til at teste at forbindelsen virker.

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

## Certifikat og nøgle

OCES3-certifikater til webserviceadgang udstedes af **Den Danske Stat** via [Nets/MitID Erhverv](https://erhverv.mitid.dk). Certifikatet skal registreres hos STIL før brug.

Se STILs vejledning: [Certifikatsikkerhed](https://viden.stil.dk/spaces/INFRA2/pages/314540219/Certifikatsikkerhed)

Den private nøgle genereres lokalt ved certifikatansøgningen og leveres typisk i en PKCS12-fil (`.pfx`/`.p12`). Nøglen kan udpakkes til ukrypteret PEM-format med OpenSSL:

```bash
openssl pkcs12 -in certifikat.pfx -nocerts -nodes -out private.key
openssl pkcs12 -in certifikat.pfx -clcerts -nokeys -out certifikat.cer
```

---

## Projektstruktur

```
.
├── main.py            # SOAP-klient og kommandolinjegrænseflade
├── .env               # Lokale indstillinger (gitignored)
├── .env.example       # Skabelon til .env
├── .gitignore
└── requirements.txt
```
