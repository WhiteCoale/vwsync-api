# Setup

Diese Anleitung führt von einem Linux-Server ohne Vorbereitung bis zum laufenden Dienst hinter nginx. Der Dienst läuft auf einem eigenen Server und erreicht Vaultwarden über HTTPS auf einem anderen. Sie dauert etwa 30 Minuten. Eine Einführung in den Dienst steht in der [README](README.md), die Endpunkte beschreibt die [API-Referenz](docs/API.md).

## Kurzfassung

Für alle, die den Ablauf kennen. Jeder Befehl ist in den Schritten darunter erklärt.

```bash
# Auf dem Rechner mit Go, im Projektverzeichnis
make linux
scp dist/vwsync-api deploy/vwsync-api.service deploy/vwsync-api.logrotate deploy/nginx.conf admin@vwsync-server:

# Auf dem vwsync-Server, im Home-Verzeichnis
sudo useradd --system --no-create-home --shell /usr/sbin/nologin vwsync
sudo install -d /opt/vwsync-api /etc/vwsync-api
sudo install -m 0755 vwsync-api /opt/vwsync-api/vwsync-api
/opt/vwsync-api/vwsync-api generate-key       # Schlüssel an den Aufrufer, Hash-Zeile in die env-Datei
sudoedit /etc/vwsync-api/env                   # Inhalt nach Schritt 5
sudo chown root:vwsync /etc/vwsync-api/env && sudo chmod 0640 /etc/vwsync-api/env
sudo install -m 0644 vwsync-api.service /etc/systemd/system/
sudo install -m 0644 vwsync-api.logrotate /etc/logrotate.d/vwsync-api
sudo systemctl daemon-reload && sudo systemctl enable --now vwsync-api
curl -s http://127.0.0.1:8080/readyz           # {"status":"ready"}
# Danach nginx und TLS einrichten (Schritt 7)
```

```mermaid
flowchart LR
    A["1 Vaultwarden<br/>vorbereiten"] --> B["2 Binary<br/>bauen"]
    B --> C["3 Server<br/>vorbereiten"]
    C --> D["4 Zugangsschlüssel<br/>erzeugen"]
    D --> E["5 Konfiguration<br/>schreiben"]
    E --> F["6 systemd"]
    F --> G["7 nginx + TLS"]
    G --> H["8 Testen"]
```

## Topologie

```mermaid
flowchart LR
    caller["Server des Aufrufers"] -- "HTTPS 443" --> nginx
    subgraph vwsync["vwsync-Server"]
        nginx["nginx"] -- "127.0.0.1:8080" --> svc["vwsync-api"]
    end
    svc -- "HTTPS 443" --> vwproxy
    subgraph vaultwarden["Vaultwarden-Server"]
        vwproxy["Reverse-Proxy"] --> vwd["Vaultwarden (systemd)"]
    end
```

Zwei Verbindungen müssen offen sein. Der Aufrufer muss den vwsync-Server auf Port 443 erreichen. Der vwsync-Server muss den Vaultwarden-Server auf dessen HTTPS-Port erreichen, mehr ausgehenden Verkehr braucht der Dienst nicht. Der Dienst selbst lauscht auf dem vwsync-Server nur lokal.

## Voraussetzungen

| Voraussetzung | Zweck |
|---|---|
| Eigener Linux-Server mit systemd ab Version 239 und nginx, etwa Rocky Linux 8 oder 9, RHEL oder Debian 12 | Hier läuft der Dienst. Er lauscht nur auf `127.0.0.1`, nginx ist der einzige Zugang. Für Rocky Linux und RHEL gelten zusätzlich die [Hinweise unten](#rocky-linux-und-rhel) |
| Domain mit DNS-Eintrag und TLS-Zertifikat | nginx terminiert HTTPS. Ohne TLS gehen Zugangsdaten im Klartext über die Leitung |
| Vaultwarden auf einem anderen Server, per HTTPS erreichbar | Der Dienst nutzt dessen Benutzer-API über das Netz. Die Pfade `/identity` und `/api` müssen vom vwsync-Server aus erreichbar sein |
| Go ab Version 1.26 | Nur zum Bauen, auf einem beliebigen Rechner. Der Server braucht kein Go |
| Ein eigenes Vaultwarden-Konto für den Dienst | Siehe Schritt 1 |

### Rocky Linux und RHEL

Auf Rocky Linux und RHEL 8 und 9 laufen Dienst, Unit und logrotate-Vorlage unverändert. Fünf Dinge sind dort anders als auf Debian, sie gehören zu den Schritten unten.

**SELinux und nginx (Schritt 7).** Rocky läuft mit SELinux im Modus enforcing. nginx darf dann nicht zu einem lokalen Port wie 8080 verbinden und antwortet mit `502`, im Audit-Log steht ein `denied` für `name_connect`. Diese Freigabe gilt dauerhaft:

```bash
sudo setsebool -P httpd_can_network_connect 1
```

**SELinux und das Binary (Schritt 3).** Kopiere das Binary mit `install` nach `/opt/vwsync-api`, nicht mit `mv` aus dem Home-Verzeichnis. Sonst behält es den SELinux-Kontext des Home-Verzeichnisses, und systemd startet es nicht (`status=203/EXEC`). Damit systemd es sicher ausführen darf, bekommt das Verzeichnis den Kontext für Programme:

```bash
sudo dnf install -y policycoreutils-python-utils
sudo semanage fcontext -a -t bin_t '/opt/vwsync-api(/.*)?'
sudo restorecon -Rv /opt/vwsync-api
```

**Firewall (Schritt 7).** firewalld lässt HTTP und HTTPS erst nach einer Freigabe durch. HTTP braucht certbot und die Umleitung auf HTTPS.

```bash
sudo firewall-cmd --permanent --add-service=http --add-service=https
sudo firewall-cmd --reload
```

**nginx und certbot (Schritt 7).** nginx kommt aus den Standardquellen, certbot aus EPEL. Die Konfiguration gehört nach `/etc/nginx/conf.d/vwsync.conf`, ein `sites-available` gibt es nicht.

```bash
sudo dnf install -y nginx epel-release
sudo dnf install -y certbot python3-certbot-nginx
sudo systemctl enable --now nginx
```

**logrotate und Rocky 8.** logrotate ist vorinstalliert und läuft täglich, auf Rocky 9 über einen systemd-Timer, auf Rocky 8 über cron. Rocky 8 bringt systemd 239 mit. Vier Härtungs-Einträge der Unit kennt es noch nicht (`ProtectClock`, `ProtectHostname`, `ProtectKernelLogs`, `RestrictSUIDSGID`). Es meldet dazu beim `daemon-reload` eine Warnung `Unknown lvalue` im Journal und ignoriert sie. Der Dienst läuft trotzdem, die übrige Härtung bleibt aktiv.

## 1. Vaultwarden vorbereiten

**Dienstkonto anlegen.** Der Dienst darf alles, was sein Konto in den Organisationen darf. Ein eigenes Konto, etwa `vwsync@example.com`, lässt sich getrennt prüfen und bei Bedarf sperren. Ein persönliches Konto eignet sich nicht.

**Rechte vergeben.** Das Konto muss in jeder Organisation, die der Dienst verwaltet, Owner sein. Admin genügt zum Einladen, Entfernen und Bestätigen normaler Mitglieder. Die Rollen `owner`, `admin`, `manager` und `custom` darf in Vaultwarden jedoch nur ein Owner vergeben. Organisationen, die der Dienst selbst anlegt, gehören dem Konto automatisch.

**API-Key abrufen.** Im Web-Vault als Dienstkonto anmelden und unter *Kontoeinstellungen, Sicherheit, Schlüssel* den API-Schlüssel anzeigen. Notiere `client_id` (Format `user.<uuid>`) und `client_secret`.

**Registrierung statt Einladung.** Der Dienst ist für Vaultwarden ohne Mailversand ausgelegt, und niemand muss eine Einladung annehmen. Eine Person muss sich nur in Vaultwarden registrieren und legt dabei ihr Master-Passwort fest. Das kann vor oder nach der Einladung geschehen.

- Hat sich die Person schon registriert, setzt die Einladung sie sofort auf `accepted`, und sie lässt sich bestätigen.
- Hat sie sich noch nicht registriert, bleibt sie `invited`. Mit ihrer Registrierung wird sie von selbst `accepted`, und der nächste `confirm`-Aufruf bestätigt sie. Vorher lässt sie sich nicht bestätigen, weil es noch keinen öffentlichen Schlüssel für sie gibt.

Damit das funktioniert, muss `INVITATIONS_ALLOWED` in Vaultwarden aktiv sein (der Standard). Eine eingeladene Person darf sich auch dann registrieren, wenn die allgemeine Registrierung (`SIGNUPS_ALLOWED`) abgeschaltet ist. Ist `SIGNUPS_DOMAINS_WHITELIST` gesetzt, müssen die Adressen der Eingeladenen zu einer der Domains passen. Der Dienst benachrichtigt niemanden, die Personen müssen Adresse und Server kennen.

**Master-Passwort bereithalten.** Der Dienst braucht es nur für `POST /v1/confirm` und `POST /v1/orgs`. Ohne Master-Passwort laufen alle anderen Endpunkte, diese beiden antworten mit `503`. PBKDF2-SHA256 und Argon2id werden als Schlüsselableitung unterstützt. Eine Zwei-Faktor-Anmeldung des Kontos stört nicht, denn der Login mit API-Key umgeht sie.

**Servereinstellungen prüfen.** Setzt die Vaultwarden-Instanz `ORG_CREATION_USERS`, muss das Dienstkonto dort stehen, sonst scheitert `POST /v1/orgs` mit `502`. Dasselbe gilt, wenn das Konto Mitglied einer Organisation mit der Richtlinie "Single organization" ist. Läuft Vaultwarden als systemd-Dienst, stehen die Einstellungen als Umgebungsvariablen in der `EnvironmentFile` der Unit, deren Pfad von der Installation abhängt. Nach einer Änderung braucht Vaultwarden einen Neustart, etwa mit `systemctl restart vaultwarden`.

**Zugriff für den Dienst freigeben.** Steht vor Vaultwarden ein Reverse-Proxy oder eine Firewall mit Adresslisten, muss die Adresse des vwsync-Servers die Pfade `/identity/connect/token` und `/api/` erreichen dürfen. Die Adresse taucht dort als Quelle auf, und Vaultwarden begrenzt Logins je Adresse. Der Dienst meldet sich nur etwa alle zwei Stunden neu an.

## 2. Binary bauen

Auf einem Rechner mit Go, im Projektverzeichnis:

```bash
make linux          # erzeugt dist/vwsync-api, statisch gelinkt und ohne Abhängigkeiten
```

Ohne `make`, etwa in PowerShell:

```powershell
$env:CGO_ENABLED = "0"; $env:GOOS = "linux"; $env:GOARCH = "amd64"
go build -trimpath -ldflags="-s -w" -o dist/vwsync-api ./cmd/vwsync-api
```

Für einen ARM-Server gilt `GOARCH=arm64`.

Kopiere das Binary und die drei Vorlagen aus `deploy/` auf den vwsync-Server, zum Beispiel ins Home-Verzeichnis. Die folgenden Schritte laufen dort.

```bash
scp dist/vwsync-api deploy/vwsync-api.service deploy/vwsync-api.logrotate deploy/nginx.conf admin@vwsync-server:
```

## 3. Server vorbereiten

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin vwsync
sudo install -d /opt/vwsync-api /etc/vwsync-api
sudo install -m 0755 vwsync-api /opt/vwsync-api/vwsync-api
```

## 4. Zugangsschlüssel erzeugen

Aufrufer weisen sich mit einem festen Zugangsschlüssel aus und senden ihn mit jedem Request im Header `Authorization: Bearer <Schlüssel>`. Es gibt keinen Login und kein Ablaufdatum. Der Schlüssel besteht aus 256 Bit Zufall. Der Server speichert nur seinen SHA-256-Hash.

```bash
/opt/vwsync-api/vwsync-api generate-key
```

Der Befehl gibt zwei Dinge aus. Das erste ist der Schlüssel, er beginnt mit `vwsk_`. Das zweite ist die Zeile `VWSYNC_API_KEY_HASH=...` mit 64 Hex-Zeichen für die Konfiguration in Schritt 5.

Sichere den Schlüssel sofort im Secret-Store des Aufrufers. Der Dienst speichert ihn nicht und kann ihn nicht erneut anzeigen. Geht er verloren, erzeugst du mit `generate-key` einen neuen und tauschst den Hash aus.

Der Zugangsschlüssel ist nicht der API-Key des Vaultwarden-Dienstkontos aus Schritt 1. Er gehört dem Aufrufer und öffnet diesen Dienst. Der Vaultwarden-API-Key gehört dem Dienst und öffnet Vaultwarden.

## 5. Konfiguration schreiben

Lege `/etc/vwsync-api/env` an. Eine Vorlage liegt in [.env.example](.env.example).

```bash
VWSYNC_LISTEN=127.0.0.1:8080
VWSYNC_API_KEY_HASH=...
VWSYNC_TRUST_PROXY=true
VWSYNC_LOG_FILE=/var/log/vwsync-api/vwsync-api.log

VW_URL=https://vault.example.com
VW_CLIENT_ID=user.00000000-0000-0000-0000-000000000000
VW_CLIENT_SECRET=...
VW_MASTER_PASSWORD=...
#VW_CA_FILE=/etc/vwsync-api/vaultwarden-ca.pem
```

| Variable | Pflicht | Beschreibung |
|---|---|---|
| `VWSYNC_LISTEN` | nein | Adresse und Port. Standard ist `127.0.0.1:8080`. Nicht auf `0.0.0.0` setzen |
| `VWSYNC_API_KEY_HASH` | ja | SHA-256-Hash des Zugangsschlüssels aus Schritt 4, 64 Hex-Zeichen. Mehrere Hashes durch Kommas getrennt gelten gleichzeitig, das erleichtert den Austausch eines Schlüssels |
| `VWSYNC_TRUST_PROXY` | nein | `true`, wenn nginx den Header `X-Real-IP` setzt. Der Dienst glaubt den Header nur bei Anfragen von `127.0.0.1` oder `::1`, nginx muss also auf demselben Server laufen. Ohne diese Einstellung steht bei abgewiesenen Aufrufen die Adresse von nginx im Log statt die des Aufrufers |
| `VWSYNC_LOG_FILE` | nein | Logdatei, unter systemd `/var/log/vwsync-api/vwsync-api.log`. Die Unit legt das Verzeichnis `/var/log/vwsync-api` an, nur dort darf der Dienst schreiben, weil der Rest des Dateisystems schreibgeschützt ist. Ohne die Variable geht das Log ins Journal von systemd |
| `VWSYNC_LOG_LEVEL` | nein | `debug`, `info` (Standard), `warn` oder `error`. Mit `debug` protokolliert der Dienst jeden Aufruf an Vaultwarden mit Methode, Pfad, Status und Dauer, nie mit Bodies oder Schlüsseln |
| `VWSYNC_LOG_FORMAT` | nein | `text` (Standard) oder `json`, etwa für Loki oder ELK |
| `VW_URL` | ja | Adresse von Vaultwarden ohne abschließenden Schrägstrich. Sie muss mit `https://` beginnen. Unverschlüsseltes `http://` akzeptiert der Dienst nur für `localhost`, weil API-Key und Schlüsselmaterial über diese Verbindung gehen |
| `VW_CA_FILE` | nein | PEM-Datei mit zusätzlichen Zertifizierungsstellen, wenn das Zertifikat von Vaultwarden von einer internen CA stammt. Die Prüfung des Zertifikats bleibt aktiv, die Datei erweitert nur die vertrauenswürdigen Aussteller |
| `VW_CLIENT_ID`, `VW_CLIENT_SECRET` | ja | API-Key aus Schritt 1 |
| `VW_MASTER_PASSWORD` | nein | Nur für `confirm` und das Anlegen von Organisationen. Enthält es Sonderzeichen, gehört es in einfache Anführungszeichen |

Stammt das Zertifikat von Vaultwarden von einer internen CA, lege deren Zertifikat auf dem vwsync-Server ab, etwa als `/etc/vwsync-api/vaultwarden-ca.pem`, und setze `VW_CA_FILE`. Die Datei muss für den Benutzer `vwsync` lesbar sein.

Die `env`-Datei enthält API-Key und Master-Passwort und braucht strenge Rechte:

```bash
sudo chown root:vwsync /etc/vwsync-api/env
sudo chmod 0640 /etc/vwsync-api/env
```

## 6. Dienst starten

```bash
sudo install -m 0644 vwsync-api.service /etc/systemd/system/
sudo install -m 0644 vwsync-api.logrotate /etc/logrotate.d/vwsync-api
sudo systemctl daemon-reload
sudo systemctl enable --now vwsync-api
sudo systemctl status vwsync-api
curl -s http://127.0.0.1:8080/readyz
# {"status":"ready"}
```

`systemctl start` kehrt erst zurück, wenn der Dienst bereit ist. Er hat dann seinen Port belegt, sich bei Vaultwarden angemeldet und das an systemd gemeldet (`Type=notify`). `systemctl status` zeigt danach `active (running)` und eine Statuszeile wie `Status: "ready"`. Die erste Zeile im Log lautet etwa `msg=listening addr=127.0.0.1:8080 version=v1.0.0 confirm_enabled=true log_file=/var/log/vwsync-api/vwsync-api.log`.

### Verhalten unter systemd

| Befehl oder Ereignis | Was der Dienst tut |
|---|---|
| `systemctl start` | Prüft die Konfiguration, öffnet die Logdatei, belegt den Port, meldet sich bei Vaultwarden an und meldet sich bereit |
| `systemctl stop` | Meldet `deactivating`, nimmt keine neuen Verbindungen mehr an und lässt laufende Requests zu Ende laufen, bis zu 14 Minuten. Ein Sync wird also nicht mittendrin abgebrochen. Danach endet der Prozess mit Code 0 |
| `systemctl restart` | Wie `stop`, danach `start` |
| `systemctl reload` | Öffnet die Logdatei neu, etwa nach logrotate. Laufende Requests merken davon nichts |
| `systemctl kill vwsync-api` während des Wartens | Sendet ein zweites SIGTERM. Der Dienst bricht laufende Requests sofort ab und endet mit Code 0. Ein zweites `systemctl stop` reicht dafür nicht, es wartet nur weiter |
| Absturz oder unerwarteter Fehler | systemd startet den Dienst nach 5 Sekunden neu, höchstens 10 Mal in 5 Minuten |
| Dienst hängt | Der Dienst meldet systemd regelmäßig, dass er auf `/healthz` antwortet. Bleibt das 60 Sekunden aus, beendet systemd ihn und startet ihn neu (`WatchdogSec`). Im Journal steht dann `Failed with result 'watchdog'` und ein Stacktrace, der zeigt, wo der Prozess hing |
| Fehler in der Konfiguration | Der Prozess endet mit Code 78. `systemctl status` zeigt `failed` mit `status=78`, und systemd startet ihn nicht neu, denn ein Neustart änderte nichts. Dazu gehören fehlende Variablen, eine nicht beschreibbare Logdatei und ein von Vaultwarden abgelehnter API-Key |
| Vaultwarden beim Start nicht erreichbar | Der Dienst startet trotzdem und meldet sich beim ersten Request an. `/readyz` antwortet bis dahin mit `503`, im Log steht `vaultwarden is not reachable`. Startet etwa der Vaultwarden-Server gleichzeitig neu, muss niemand eingreifen |
| Token von Vaultwarden läuft ab | Der Dienst erneuert es von selbst kurz vor Ablauf. Erklärt Vaultwarden es vorher für ungültig, meldet sich der Dienst einmal neu an und wiederholt den Request |

`/healthz` meldet nur, dass der Prozess antwortet. `/readyz` meldet, ob der Dienst gerade arbeiten kann, also ob Vaultwarden antwortet und der Dienst nicht herunterfährt. Für Überwachung und Load-Balancer ist `/readyz` die richtige Wahl.

Die Unit startet den Dienst als eigenen Benutzer ohne Schreibrechte im Dateisystem, mit Ausnahme von `/var/log/vwsync-api`, ohne zusätzliche Capabilities und mit eingeschränkten Systemaufrufen.

## 7. nginx und TLS

Zertifikat besorgen, zum Beispiel mit certbot:

```bash
sudo certbot certonly --nginx -d vwsync.example.com
```

Installiere die übertragene Vorlage [nginx.conf](deploy/nginx.conf) und passe darin `server_name` sowie die Zertifikatspfade an. Sie bindet eine Proxy-Datei ein, die du einmal anlegst. Ihr Inhalt steht auch als Kommentar am Ende der Vorlage.

```bash
sudo install -m 0644 nginx.conf /etc/nginx/sites-available/vwsync
sudoedit /etc/nginx/sites-available/vwsync      # server_name und Zertifikatspfade anpassen
sudo tee /etc/nginx/vwsync-proxy.inc >/dev/null <<'EOF'
proxy_pass         http://127.0.0.1:8080;
proxy_set_header   Host $host;
proxy_set_header   X-Real-IP $remote_addr;
proxy_read_timeout 600s;
proxy_send_timeout 600s;
EOF
sudo ln -s /etc/nginx/sites-available/vwsync /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Die langen Timeouts brauchen große Abgleiche und Bestätigungen. Die Konfiguration begrenzt außerdem die Anfragen je Adresse auf 60 pro Minute mit kurzen Spitzen von bis zu 30 weiteren. Der Dienst selbst begrenzt nicht, bei 256 Bit Zufall im Schlüssel lässt sich ein Schlüssel nicht erraten.

Kennt die Distribution kein `sites-available`, etwa RHEL, gehört die Datei nach `/etc/nginx/conf.d/vwsync.conf`, und der Link entfällt.

Ist der Dienst nur über ein internes Netz oder per VPN erreichbar, darf `server_name` ein interner Name sein. TLS bleibt in jedem Fall erforderlich.

## 8. Testen

```bash
BASE=https://vwsync.example.com
KEY=vwsk_...    # Schlüssel aus Schritt 4

curl $BASE/healthz
# {"status":"ok"}

curl -H "Authorization: Bearer $KEY" $BASE/v1/orgs
# {"orgs":[...]}
```

Als Nächstes lohnt sich ein Lauf ohne Wirkung. `GET /v1/export` liefert im Feld `desired` den aktuellen Zustand im Format des Abgleichs. Schickt man ihn mit `dry_run=true` an `POST /v1/sync`, ergibt das einen Plan ohne Änderungen und zeigt, dass Lesen, Planen und Zugriffsrechte funktionieren. Ohne `dry_run=true` würde der Dienst den Plan ausführen, hier wäre er leer:

```bash
curl -s -H "Authorization: Bearer $KEY" $BASE/v1/export | jq .desired > ist.json
curl -s -X POST "$BASE/v1/sync?dry_run=true" -H "Authorization: Bearer $KEY" -d @ist.json | jq .
```

Weil schreibende Aufrufe sofort ausgeführt werden, sollte jede neue Soll-Datei zuerst mit `dry_run=true` laufen. Beim ersten echten Lauf empfiehlt sich eine Testorganisation. Lege sie mit `POST /v1/orgs` an und lade einen Testnutzer ein. So zeigt sich früh, ob Richtlinien oder Servereinstellungen etwas ablehnen, bevor echte Organisationen betroffen sind.

## Betrieb

### Logs

Mit `VWSYNC_LOG_FILE=/var/log/vwsync-api/vwsync-api.log` schreibt der Dienst sein Log in diese Datei.

```bash
sudo tail -f /var/log/vwsync-api/vwsync-api.log
```

Ohne die Variable geht das Log ins Journal (`journalctl -u vwsync-api`). Fehler, die auftreten, bevor die Logdatei offen ist, etwa eine falsche Konfiguration, stehen immer im Journal. Bei einem Startproblem lohnt deshalb zuerst `journalctl -u vwsync-api -n 50`.

**Rotation.** Sie läuft automatisch, sobald die Vorlage `/etc/logrotate.d/vwsync-api` installiert ist. logrotate wird vom System täglich aufgerufen, rotiert die Datei, komprimiert ältere Dateien und hebt 30 Tage auf. Danach ruft es `systemctl reload vwsync-api` auf, und der Dienst öffnet sofort die neue Datei. Kommt dieser Aufruf nicht an, etwa wegen einer SELinux-Regel, bemerkt der Dienst die Rotation spätestens zehn Sekunden später selbst und öffnet die neue Datei. Es gehen in keinem Fall Zeilen verloren, und laufende Requests merken davon nichts. `systemctl list-timers logrotate.timer` zeigt den nächsten Lauf, `sudo logrotate -d /etc/logrotate.d/vwsync-api` macht einen Probelauf ohne Änderung. Aufbewahrung und Intervall lassen sich in der Vorlage ändern. Die Logs enthalten E-Mail-Adressen, die Aufbewahrungsdauer sollte deshalb zu den Datenschutzvorgaben passen.

**Inhalt.** Der Dienst schreibt je Anfrage Methode, Pfad, Query, Status und Dauer. Die Query verrät, ob `dry_run=true` gesetzt war und der Aufruf nur eine Vorschau lieferte. Dazu kommen abgewiesene Aufrufe mit der Adresse des Aufrufers (`request rejected`) und für jede ausgeführte Änderung eine Zeile `audit`.

```
level=INFO msg=audit org="Team Alpha" type=invite email=carol@example.com ok=true role=user
level=INFO msg=audit org="Team Alpha" type=remove email=dave@example.com ok=true
level=INFO msg=audit org="Team Alpha" type=confirm email=alice@example.com ok=true
```

`grep msg=audit /var/log/vwsync-api/vwsync-api.log` listet alle Änderungen, `zgrep` auch in rotierten Dateien. Header, Bodies, Schlüssel und Passwörter stehen nie im Log. Bei einem Absturz steht der Stacktrace im Log, der Aufrufer erhält nur eine Referenz wie `internal error (ref 1a2b3c4d)`.

### Version

`/opt/vwsync-api/vwsync-api version` nennt den laufenden Stand. Er steht auch beim Start im Log (`version=...`). Beim Bauen legt `make linux VERSION=v1.2.0` die Version fest. Ohne Angabe kommt sie aus `git describe`.

### Aktualisieren

```bash
# Neues Binary bauen und übertragen (Schritt 2), dann auf dem Server:
sudo install -m 0755 vwsync-api /opt/vwsync-api/vwsync-api
sudo systemctl restart vwsync-api
```

Der Dienst hält keinen Zustand auf der Platte. Zu sichern ist nur `/etc/vwsync-api/env`.

### Zugangsdaten wechseln

| Was | Vorgehen |
|---|---|
| Zugangsschlüssel ohne Unterbrechung austauschen | Mit `generate-key` einen neuen Schlüssel erzeugen und seinen Hash zusätzlich in `VWSYNC_API_KEY_HASH` eintragen, kommagetrennt. Dienst neu starten, den Aufrufer auf den neuen Schlüssel umstellen, danach den alten Hash entfernen und neu starten |
| Zugangsschlüssel sofort sperren | Seinen Hash aus `VWSYNC_API_KEY_HASH` entfernen und den Dienst neu starten. Ein Schlüssel hat kein Ablaufdatum und gilt bis dahin |
| API-Key von Vaultwarden | Schlüssel im Web-Vault rotieren, `VW_CLIENT_SECRET` ersetzen, Dienst neu starten |
| Master-Passwort geändert | `VW_MASTER_PASSWORD` ersetzen, Dienst neu starten |

### Checkliste

- [ ] Der Dienst lauscht nur auf `127.0.0.1`. nginx läuft auf demselben Server und ist der einzige Zugang.
- [ ] HTTPS mit gültigem Zertifikat.
- [ ] `/etc/vwsync-api/env` gehört `root:vwsync` und hat die Rechte `0640`.
- [ ] Das Log geht nach `/var/log/vwsync-api/`, und `/etc/logrotate.d/vwsync-api` ist installiert.
- [ ] Die Überwachung fragt `/readyz` ab.
- [ ] Der Dienst nutzt ein eigenes Vaultwarden-Konto.
- [ ] Der Zugangsschlüssel liegt nur beim Aufrufer, in einer Datei mit Rechten `0600` oder einem Secret-Store, nicht in Crontab, Repository oder Log.
- [ ] Der Zugangsschlüssel wird nie in einer URL übergeben, nur im Header `Authorization`.
- [ ] Der Aufrufer wertet bei `207` das Feld `failures` aus.

## Fehlersuche

| Symptom | Ursache | Abhilfe |
|---|---|---|
| Start bricht ab mit `invalid configuration: ... is missing` | Eine Variable fehlt oder ist leer | Die Meldung nennt alle fehlenden Variablen. `env`-Datei prüfen |
| Start bricht ab mit `VWSYNC_API_KEY_HASH is missing` | Die Variable fehlt oder ist leer | Mit `vwsync-api generate-key` Schlüssel und Hash erzeugen und die Zeile `VWSYNC_API_KEY_HASH=...` eintragen |
| Start bricht ab mit `VWSYNC_API_KEY_HASH: ... is not a SHA-256 hash` | Der Hash ist abgeschnitten, oder statt des Hashes steht der Schlüssel selbst | Die Hash-Zeile aus `generate-key` verwenden, sie hat 64 Hex-Zeichen. Der Schlüssel beginnt mit `vwsk_` und gehört nur zum Aufrufer |
| `systemctl status` zeigt `failed` und `status=78` | Fehler in der Konfiguration. Die genaue Meldung steht im Journal | `journalctl -u vwsync-api -n 50` lesen, die Ursache beheben, `systemctl restart vwsync-api` |
| Start bricht ab mit `vaultwarden rejected the API key` | `VW_CLIENT_ID` oder `VW_CLIENT_SECRET` ist falsch | API-Key im Web-Vault erneut ansehen. Die `client_id` beginnt mit `user.` |
| Start bricht ab mit `VWSYNC_LOG_FILE: opening log file` | Das Verzeichnis fehlt oder liegt außerhalb von `/var/log/vwsync-api` | Den Pfad unter `/var/log/vwsync-api/` legen. Nur dort darf der Dienst schreiben |
| Log zeigt `vaultwarden is not reachable`, `/readyz` meldet `503` | `VW_URL` ist falsch, oder der Vaultwarden-Server ist vom vwsync-Server aus nicht erreichbar | Vom vwsync-Server aus `curl $VW_URL/alive` prüfen. Firewall und Reverse-Proxy von Vaultwarden kontrollieren. Der Dienst erholt sich von selbst, sobald Vaultwarden erreichbar ist |
| Log zeigt `certificate signed by unknown authority` | Das Zertifikat von Vaultwarden stammt von einer CA, die der vwsync-Server nicht kennt | Das CA-Zertifikat als PEM ablegen und `VW_CA_FILE` setzen |
| Start bricht ab mit `VW_URL must use https` | `VW_URL` beginnt mit `http://` und zeigt nicht auf `localhost` | HTTPS am Vaultwarden-Reverse-Proxy einrichten und die URL anpassen |
| `401` bei jedem Aufruf | Der Schlüssel fehlt oder ist falsch, oder der Header hat nicht die Form `Authorization: Bearer <Schlüssel>` | Im Log steht `request rejected` mit der Adresse des Aufrufers. Ob der Schlüssel zur Konfiguration passt, zeigt `printf %s "$KEY" \| sha256sum`. Das Ergebnis muss einem Eintrag in `VWSYNC_API_KEY_HASH` entsprechen |
| `404` bei `/v1/sync` | Der Organisationsname stimmt nicht, oder das Konto ist dort weder Owner noch Admin | `GET /v1/orgs` zeigt, welche Organisationen der Dienst sieht. Die Groß- und Kleinschreibung spielt keine Rolle |
| `422` mit `matches several organizations` | Zwei Organisationen unterscheiden sich nur in der Schreibweise ihres Namens | Statt des Namens die ID verwenden, sie steht in der Meldung |
| `409` bei einem schreibenden Aufruf | Ein anderer Schreiblauf läuft | Kurz warten und erneut senden |
| `400` mit `the apply parameter does not exist` | Ein Aufrufer sendet `apply=true` oder `apply=false` | Den Parameter entfernen. Schreibende Aufrufe laufen direkt, `dry_run=true` zeigt nur eine Vorschau |
| Ein Mitglied erscheint in `confirm` unter `waiting` und wird nicht bestätigt | Die Person hat sich noch nicht registriert | Sie muss sich in Vaultwarden mit genau dieser Adresse registrieren. Danach bestätigt der nächste Aufruf sie |
| `502` mit `User does not exist` beim Einladen | Vaultwarden erlaubt keine Einladungen für unregistrierte Personen | `INVITATIONS_ALLOWED` in Vaultwarden aktivieren, oder die Person zuerst registrieren lassen |
| `502` mit `Email domain not eligible for invitations` | Die Domain steht nicht in `SIGNUPS_DOMAINS_WHITELIST` | Die Domain in Vaultwarden aufnehmen |
| `422` mit Hinweis auf `max_removals` | Der Lauf plant mehr Entfernungen als erlaubt | Soll-Zustand prüfen. Ist er richtig, `max_removals` erhöhen |
| `500` mit `MAC mismatch (wrong master password?)` | `VW_MASTER_PASSWORD` ist falsch | Passwort korrigieren und den Dienst neu starten |
| `503` bei `confirm` oder `POST /v1/orgs` | `VW_MASTER_PASSWORD` ist nicht gesetzt | Variable in der `env`-Datei ergänzen und den Dienst neu starten |
| `502` mit einer Meldung von Vaultwarden | Vaultwarden lehnt den Aufruf ab | Meldung lesen. Häufige Gründe sind fehlende Owner-Rechte für `admin` oder `custom`, `ORG_CREATION_USERS` und die Richtlinie "Single organization" |
| nginx meldet `504` bei großen Läufen | Das Timeout ist zu kurz | `proxy_read_timeout` in der Proxy-Datei erhöhen |
| nginx meldet `413` | Der Body ist größer als 1 MB | `client_max_body_size` in der Konfiguration erhöhen |
| `systemctl stop` dauert lange | Ein Sync oder Confirm läuft noch, der Dienst wartet bis zu 14 Minuten darauf | Abwarten. `systemctl kill vwsync-api` bricht sofort ab, laufende Requests enden dann mit einem Fehler |
| Die Logdatei wird nie rotiert | Die logrotate-Vorlage fehlt | `/etc/logrotate.d/vwsync-api` installieren. Nach einer Rotation folgt der Dienst der neuen Datei spätestens nach zehn Sekunden, auch ohne `reload` |
| nginx meldet `502`, das Log des Dienstes zeigt keinen Request | SELinux verbietet nginx die Verbindung zum Dienst (Rocky, RHEL) | `sudo setsebool -P httpd_can_network_connect 1` |
| `systemctl status` zeigt `status=203/EXEC` | SELinux verbietet systemd das Ausführen des Binarys (Rocky, RHEL) | Kontext setzen wie unter [Rocky Linux und RHEL](#rocky-linux-und-rhel) beschrieben |
