# Subdomain Scanner

Recon-tool om subdomeinen van je **eigen** domeinen in kaart te brengen.

## Wat hij doet

1. **Certificate Transparency (crt.sh)** — zoekt publieke SSL-certificaatlogs voor bekende subdomeinen. Snel en verrassend compleet.
2. **DNS brute-force** — probeert een ingebouwde wordlist (~150 veelvoorkomende namen: www, api, dev, staging, vpn, mail, ...) tegen het domein. Je kunt zelf een extra lijst opgeven (komma-gescheiden) in de UI.
3. **DNS-resolutie check** — filtert alleen de subdomeinen die daadwerkelijk naar een IP resolven.
4. **HTTP check** — haalt per actief subdomein op: status code (80/443), title-tag, Server-header.
5. **Optionele poortcheck** — checkt of 80, 443, 8080, 8443, 3000, 8000 open staan (TCP connect, geen exploitatie).

Resultaten stromen live binnen via Server-Sent Events, dus je ziet ze verschijnen terwijl de scan loopt. Export naar CSV kan met één klik.

## Installatie

```bash
cd subscanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Starten

```bash
python3 app.py
```

De server draait dan op **poort 5065**, bereikbaar op `http://localhost:5065` (of `http://<jouw-ip>:5065` als je 'm via VNC/remote desktop opent in de browser op die machine).

## Gebruik

1. Open `http://localhost:5065` in de browser.
2. Vul je eigen domein in (bv. `voorbeeld.nl`).
3. Zet DNS brute-force aan/uit, eventueel poortcheck aan.
4. Klik "Start scan" en kijk de resultaten binnenkomen.
5. Exporteer naar CSV indien gewenst.

## Structuur

```
subscanner/
├── app.py              # Flask backend: crt.sh, DNS, HTTP, poortcheck, SSE-stream
├── requirements.txt
└── static/
    ├── index.html
    ├── style.css
    └── script.js
```

## Uitbreidingsideeën

- **Wildcard DNS detectie** — sommige domeinen resolven *elk* subdomein (wildcard record), wat valse positieven geeft. Een check die eerst een random niet-bestaand subdomein probeert zou dat kunnen filteren.
- **Subdomain takeover check** — kijk of een CNAME wijst naar een dienst (bv. een oude S3 bucket of Herokuapp) die niet meer bestaat — een bekend, veelvoorkomend beveiligingslek bij eigen infrastructuur.
- **Screenshot per host** — met bv. Playwright/Selenium een thumbnail maken van elke live site voor snel visueel overzicht.
- **Grotere wordlists** — de ingebouwde lijst is bewust compact; voor grondiger werk kun je zelf een grotere lijst plakken in het wordlist-veld (bv. SecLists' subdomains-top1million).
- **Rate limiting / delay instelbaar** — als je respectvoller wilt scannen richting je eigen DNS-infrastructuur.
- **Geschiedenis/diff** — resultaten opslaan en latere scans vergelijken om nieuwe/verdwenen subdomeinen te zien (handig voor continue monitoring van shadow IT).

## Let op

Gebruik dit alleen op domeinen die je zelf beheert of waarvoor je expliciete toestemming hebt. crt.sh-queries en DNS-lookups zijn passief/legaal, maar poortscans kunnen door sommige netwerken als verdacht verkeer worden gezien.
