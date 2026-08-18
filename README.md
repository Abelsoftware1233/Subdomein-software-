# Subdomain Scanner (NEXUS)

Recon-tool om subdomeinen van je **eigen** domeinen in kaart te brengen —
inclusief wildcard-detectie en subdomain-takeover-detectie.

## Wat hij doet

1. **Certificate Transparency (crt.sh)** — doorzoekt publieke SSL-certificaatlogs.
2. **Wildcard DNS-detectie** — probeert eerst een gegarandeerd niet-bestaand
   subdomein te resolven. Resolvt dat toch (catch-all DNS), dan worden
   brute-force resultaten met hetzelfde IP gemarkeerd als mogelijke ruis
   in plaats van als losse valse positieven getoond te worden.
3. **DNS brute-force** — ingebouwde wordlist (~150 namen: www, api, dev,
   staging, vpn, ...). Eigen woorden via de UI worden **toegevoegd** aan
   deze lijst, niet vervangen. Input wordt gesaneerd tot geldige
   hostname-tekens (a-z, 0-9, -) voordat het in een lookup terechtkomt.
4. **DNS-resolutie check** — alleen subdomeinen die echt naar een IP
   resolven komen door.
5. **HTTP check** — status code, title-tag, Server-header per host.
6. **Subdomain takeover-detectie** — vergelijkt de HTTP-response-body en
   CNAME-target tegen bekende fingerprints van diensten (GitHub Pages,
   S3, Heroku, Shopify, Azure, ...) die "dit is niet geclaimd"-pagina's
   tonen. Een match betekent: er wijst een CNAME naar een dienst die
   niemand meer claimt — een aanvaller kan die dan zelf claimen en zo
   jouw subdomein overnemen. Dit is puur passieve detectie (HTTP GET +
   DNS lookup), geen exploitatie.
7. **Optionele TCP poortcheck** — 80, 443, 8080, 8443, 3000, 8000.
   Simpele connect-check, geen exploitatie.

Resultaten stromen live binnen via Server-Sent Events. Export naar CSV
met één klik. Een ingebouwde limiet (5000 kandidaten) voorkomt dat de
scan onbeheersbaar groot wordt bij een zeer lange eigen wordlist.

## Snel starten (development)

```bash
cd subscanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Draait op **poort 5065**: `http://localhost:5065`.

## Productie-deploy (systemd)

`deploy.sh` installeert de tool als systemd-service, draaiend onder een
eigen unprivileged systeemgebruiker (niet als root), met een hardened
unit-bestand (`ProtectSystem=strict`, `NoNewPrivileges`, etc.).

```bash
sudo ./deploy.sh install     # kopieert bestanden naar /opt/subscanner, zet venv + service op
sudo ./deploy.sh start
sudo ./deploy.sh status      # laat systemd-status + health-check zien
sudo ./deploy.sh logs        # journalctl -f
```

Andere commando's: `stop`, `restart`, `uninstall`.

Instelbaar via omgevingsvariabelen:
```bash
sudo INSTALL_DIR=/srv/subscanner SERVICE_USER=scanner ./deploy.sh install
```

Na `install` + `start` draait de service automatisch bij een reboot
(via `systemctl enable`), luistert op poort 5065, en herstart zichzelf
bij een crash (`Restart=on-failure`).

## Gebruik

1. Open `http://localhost:5065` (of je server-IP:5065 via VNC/browser).
2. Vul je eigen domein in (bv. `voorbeeld.nl`).
3. Zet brute-force / poortcheck / takeover-detectie aan of uit.
4. Klik "Start scan".
5. Rijen met een takeover-risico worden rood gemarkeerd; wildcard-matches
   grijzig gedimd zodat je ruis snel kunt onderscheiden van echte hits.
6. Exporteer naar CSV.

## Structuur

```
subscanner/
├── app.py              # Flask backend
├── deploy.sh           # systemd install/start/stop/status/logs/uninstall
├── requirements.txt
├── .gitignore
└── static/
    ├── index.html
    ├── style.css        # "nexus" donker thema + globe-animatie
    └── script.js         # canvas-achtergrond, globe, scan + rendering logica
```

## Getest

- Unit tests op `is_valid_domain`, `sanitize_word`, `resolve_host`,
  `check_takeover`, `scan_port` — inclusief edge cases (te lang domein,
  ongeldige tekens, injectie-poging in wordlist-veld, niet-bestaand host).
- Volledige SSE-scanflow end-to-end getest tegen een lokaal testdomein
  (DNS brute-force → resolutie → progress-events → result-events → done-event).
- Gracieuze afhandeling geverifieerd wanneer crt.sh onbereikbaar is (de
  scan gaat door met alleen brute-force resultaten in plaats van te crashen).
- `deploy.sh` gecontroleerd op bash-syntax en dependency-checks.

## Verder uit te breiden

- **Screenshot per host** (Playwright) voor snel visueel overzicht.
- **Geschiedenis/diff** — scans opslaan en nieuwe/verdwenen subdomeinen
  tussen runs signaleren (handig tegen shadow IT).
- **Grotere wordlists** — plak zelf een uitgebreidere lijst (bv. SecLists)
  in het wordlist-veld voor grondiger werk.
- **Rate limiting instelbaar** — voor scans op grote domeinen waar je
  DNS-infrastructuur niet wilt overbelasten.

## Let op

Gebruik dit alleen op domeinen die je zelf beheert of waarvoor je
expliciete toestemming hebt. crt.sh-queries en DNS-lookups zijn
passief; poortscans en herhaalde HTTP-requests kunnen door sommige
netwerken/monitoring als verdacht verkeer worden gezien.
