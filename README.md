# tinder-detector

To repozytorium zawiera prosty skrypt do monitorowania instancji Pi-hole w poszukiwaniu zapytań DNS do wybranych serwisów randkowych (`tinder.com`, `badoo.com`, `sympatia.pl`).

Skrypt `pihole_monitor.py` odczytuje jedynie nowe linie z `/var/log/pihole/pihole.log` od poprzedniego uruchomienia i wysyła powiadomienia przez Mailgun, gdy wykryje nowe IP klienta pytające o jedną z tych domen. Stan jest zapisywany w `/var/tmp/pihole_monitor_state.json`.

## Użycie

```bash
pip install --user requests  # tylko przy pierwszym użyciu
python3 pihole_monitor.py [-d]
```

Przełącznik `-d` lub `--debug` wyświetla dodatkowe informacje diagnostyczne.

Dane logowania do Mailguna można podać w pliku `tinder-detector.conf` lub w
następujących zmiennych środowiskowych:

- `MAILGUN_API_KEY`
- `MAILGUN_DOMAIN`
- `MAILGUN_FROM`
- `MAILGUN_TO`

Przykładowy plik konfiguracyjny znajduje się w `tinder-detector.conf.sample`.
Po instalacji skopiuj go do `tinder-detector.conf` i uzupełnij wartości.

Skrypt jest lekki i może być uruchamiany okresowo z crona.
