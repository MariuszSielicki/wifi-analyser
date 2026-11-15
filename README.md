# Analizator Wi-Fi

Windows i Linux (Debian/Ubuntu), Python 3.8+, bez zależności.

```
python wifi_analyzer.py                 # skan + analiza
python wifi_analyzer.py --ssid MojaSiec # porady dla Twojej sieci (domyślnie: połączona)
python wifi_analyzer.py --watch 5       # odświeżanie co 5 s
python wifi_analyzer.py --band 5 --json # tylko 5 GHz, wynik JSON
python wifi_analyzer.py --demo          # dane przykładowe
python -m unittest                      # testy parserów
```

- **Windows:** `netsh wlan` (PL/EN). Windows 11 24H2+ wymaga włączonych usług lokalizacji.
- **Linux:** `nmcli` (`sudo apt install network-manager`); awaryjnie `iw` (wymaga `sudo`, daje realne dBm i szerokość kanału).
- Szerokość kanału: tylko Linux. Sygnał z netsh/nmcli to % przeliczony na dBm (przybliżenie).
