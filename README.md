# tinder-detector

To repozytorium zawiera prosty skrypt do monitorowania instancji Pi-hole w poszukiwaniu zapytań DNS do wybranych serwisów randkowych (`tinder.com`, `badoo.com`, `sympatia.pl`).

Skrypt `pihole_monitor.py` odczytuje jedynie nowe linie z `/var/log/pihole/pihole.log` od poprzedniego uruchomienia i wysyła powiadomienia przez Mailgun, gdy wykryje nowe IP klienta pytające o jedną z tych domen. Stan jest zapisywany w `/var/tmp/pihole_monitor_state.json`.
Temat oraz treść wysyłanych e‑maili zawierają wykrytą domenę, adres IP klienta oraz czas ostatniego zapytania.
Powiadomienia wysyłane są nie częściej niż raz na 30 minut dla danej kombinacji adresu IP i domeny. Każdy e‑mail zawiera listę wszystkich odwołań z tego okresu.

## Użycie

```bash
pip install --user requests  # tylko przy pierwszym użyciu
python3 pihole_monitor.py [-d]
```

Tryb debugowania (`-d` lub `--debug`) wyświetla jedynie istotne zdarzenia
(np. wykryte zapytania i odpowiedzi Mailguna), pomijając pełne linie z
`pihole.log`.

Dane logowania do Mailguna można podać w pliku `tinder-detector.conf` lub w
następujących zmiennych środowiskowych:

- `MAILGUN_API_KEY`
- `MAILGUN_DOMAIN`
- `MAILGUN_API_URL` (domyślnie `https://api.mailgun.net`)
- `MAILGUN_FROM`
- `MAILGUN_TO`

Mailgun udostępnia dwa regiony API: US (domyślny) i EU.
Odpowiednie adresy to `https://api.mailgun.net` oraz
`https://api.eu.mailgun.net`. W pliku konfiguracyjnym (`api_url`) lub w
zmiennej `MAILGUN_API_URL` możesz wybrać region EU.

Przykładowy plik konfiguracyjny znajduje się w `tinder-detector.conf.sample`.
Po instalacji skopiuj go do `tinder-detector.conf` i uzupełnij wartości.

Skrypt jest lekki i może być uruchamiany okresowo z crona. Przy starcie
zmienia katalog roboczy na ten, w którym się znajduje, dzięki czemu plik
`tinder-detector.conf` jest poprawnie znajdowany nawet w zadaniach cron.

## Automatyczne uruchamianie (cron)

Aby skrypt uruchamiał się co 5 minut na instalacji Pi-hole, dodaj go do crontaba użytkownika `root` (lub innego, który ma dostęp do `pihole.log`).

Edytuj crontab poleceniem:

```bash
sudo crontab -e
```

Na końcu pliku dopisz linię (aktualizując ścieżkę do skryptu):

```cron
*/5 * * * * /usr/bin/python3 /sciezka/do/tinder-detector/pihole_monitor.py
```

Po zapisaniu pliku cron będzie uruchamiał skrypt automatycznie co 5 minut. Upewnij się, że konfiguracja Mailguna w `tinder-detector.conf` lub zmiennych środowiskowych jest prawidłowa.
