#!/usr/bin/env python3
"""Analizator Wi-Fi: lista sieci, obłożenie kanałów, parametry i rekomendacje.

Windows: netsh wlan (+ WlanScan przez ctypes)
Linux (Debian/Ubuntu/...): nmcli (NetworkManager), awaryjnie `iw dev <if> scan`
Tylko biblioteka standardowa Pythona (3.8+).
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

IS_WINDOWS = sys.platform.startswith("win")

# --------------------------------------------------------------------------
# Model danych
# --------------------------------------------------------------------------


@dataclass
class Network:
    ssid: str
    bssid: str
    channel: int
    freq: int                      # MHz
    band: str                      # "2.4" | "5" | "6"
    signal: float                  # dBm (dla nmcli/netsh – przybliżone z %)
    security: str = "?"
    width: Optional[int] = None    # MHz, jeśli znane
    phy: str = ""                  # 802.11n/ac/ax
    rate: str = ""
    in_use: bool = False

    @property
    def hidden(self) -> bool:
        return not self.ssid


def pct_to_dbm(pct: float) -> float:
    return pct / 2.0 - 100.0


def freq_to_channel(freq: int) -> Tuple[int, str]:
    if freq == 2484:
        return 14, "2.4"
    if 2400 <= freq < 2500:
        return (freq - 2407) // 5, "2.4"
    if 5000 <= freq < 5925:
        return (freq - 5000) // 5, "5"
    if 5925 <= freq <= 7125:
        return (freq - 5950) // 5, "6"
    return 0, "?"


def channel_to_freq(ch: int, band: str) -> int:
    if band == "2.4":
        return 2484 if ch == 14 else 2407 + 5 * ch
    if band == "6":
        return 5950 + 5 * ch
    return 5000 + 5 * ch


def band_of_freq(freq: int) -> str:
    return freq_to_channel(freq)[1]


# --------------------------------------------------------------------------
# Skanowanie: Windows
# --------------------------------------------------------------------------


def _run(cmd: List[str], timeout: int = 30) -> str:
    p = subprocess.run(cmd, capture_output=True, timeout=timeout)
    raw = p.stdout
    encs = ["utf-8"]
    if IS_WINDOWS:
        try:
            import ctypes
            encs = ["cp%d" % ctypes.windll.kernel32.GetOEMCP(), "utf-8"]
        except Exception:
            encs = ["cp852", "utf-8"]
    for enc in encs:
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


def _win_trigger_scan() -> None:
    """Prosi sterownik o świeży skan (WlanScan). Błędy są ignorowane."""
    import ctypes
    from ctypes import wintypes

    wlan = ctypes.windll.wlanapi
    h = wintypes.HANDLE()
    ver = wintypes.DWORD()
    if wlan.WlanOpenHandle(2, None, ctypes.byref(ver), ctypes.byref(h)):
        return
    try:
        lst = ctypes.c_void_p()
        if wlan.WlanEnumInterfaces(h, None, ctypes.byref(lst)):
            return
        try:
            n = ctypes.c_uint32.from_address(lst.value).value
            for i in range(n):  # nagłówek 8 B, element 532 B (GUID + WCHAR[256] + stan)
                wlan.WlanScan(h, ctypes.c_void_p(lst.value + 8 + 532 * i), None, None, None)
        finally:
            wlan.WlanFreeMemory(lst)
    finally:
        wlan.WlanCloseHandle(h, None)


_K_SIGNAL = ("signal", "sygnał", "sygna")
_K_CHANNEL = ("channel", "kanał")
_K_AUTH = ("authentication", "uwierzytelnianie")
_K_ENC = ("encryption", "szyfrowanie")
_K_RADIO = ("radio type", "typ radia")
_K_BAND = ("band", "pasmo")
_MAC = r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"


def _norm_win_security(auth: str, enc: str) -> str:
    a = auth.lower()
    if "open" in a or "otwar" in a:
        base = "Open"
    elif "wpa3" in a:
        base = "WPA3"
    elif "wpa2" in a:
        base = "WPA2"
    elif "wpa" in a:
        base = "WPA"
    elif "wep" in a or "shared" in a or "udost" in a:
        base = "WEP"
    else:
        base = auth or "?"
    if "enterprise" in a or "przedsi" in a:
        base += "-Ent"
    if base == "Open" and enc.lower().startswith("wep"):
        base = "WEP"
    return base


def parse_netsh(text: str, connected_bssid: str = "") -> List[Network]:
    nets: List[Network] = []
    ssid = auth = enc = ""
    cur: Optional[dict] = None

    def flush():
        nonlocal cur
        if cur and cur.get("channel"):
            band = cur.get("band") or ("2.4" if cur["channel"] <= 14 else "5")
            ch = cur["channel"]
            freq = channel_to_freq(ch, band)
            nets.append(Network(
                ssid=ssid, bssid=cur["bssid"].lower(), channel=ch, freq=freq, band=band,
                signal=pct_to_dbm(cur.get("signal", 0)),
                security=_norm_win_security(auth, enc), phy=cur.get("phy", ""),
                in_use=cur["bssid"].lower() == connected_bssid))
        cur = None

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line, re.I)
        if m:
            flush()
            ssid, auth, enc = m.group(1).strip(), "", ""
            continue
        m = re.match(r"^BSSID\s+\d+\s*:\s*" + _MAC, line, re.I)
        if m:
            flush()
            cur = {"bssid": m.group(1)}
            continue
        key, sep, val = line.partition(":")
        if not sep:
            continue
        key, val = key.strip().lower(), val.strip()
        if cur is None:
            if key in _K_AUTH:
                auth = val
            elif key in _K_ENC:
                enc = val
            continue
        if key in _K_SIGNAL or key.startswith("sygna"):
            cur["signal"] = int(re.sub(r"\D", "", val) or 0)
        elif key in _K_CHANNEL or (key.startswith("kana") and len(key) <= 6):
            if val.isdigit():
                cur["channel"] = int(val)
        elif key in _K_RADIO:
            cur["phy"] = val
        elif key in _K_BAND:
            cur["band"] = "2.4" if val.startswith("2") else "6" if val.startswith("6") else "5"
    flush()
    return nets


def scan_windows(rescan: bool = True) -> List[Network]:
    if rescan:
        try:
            _win_trigger_scan()
            time.sleep(3)
        except Exception:
            pass
    text = _run(["netsh", "wlan", "show", "networks", "mode=bssid"])
    connected = ""
    try:
        m = re.search(r"^\s*BSSID\s*:\s*" + _MAC, _run(["netsh", "wlan", "show", "interfaces"]),
                      re.I | re.M)
        connected = m.group(1).lower() if m else ""
    except Exception:
        pass
    nets = parse_netsh(text, connected)
    if not nets:
        raise RuntimeError(
            "Brak wyników z netsh. Sprawdź czy Wi-Fi jest włączone, a w Windows 11 24H2+ "
            "włącz: Ustawienia → Prywatność i zabezpieczenia → Lokalizacja "
            "(usługi lokalizacji + dostęp aplikacji klasycznych).")
    return nets


# --------------------------------------------------------------------------
# Skanowanie: Linux
# --------------------------------------------------------------------------


def _split_terse(line: str) -> List[str]:
    return [p.replace("\\:", ":").replace("\\\\", "\\") for p in re.split(r"(?<!\\):", line)]


def _norm_nm_security(sec: str) -> str:
    sec = sec.strip()
    if sec in ("", "--"):
        return "Open"
    parts = sec.split()
    out = " ".join(p for p in parts if p != "802.1X")
    if "802.1X" in parts:
        out = (out + " Ent").strip()
    return out


def parse_nmcli(text: str, with_bw: bool) -> List[Network]:
    nets = []
    for line in text.splitlines():
        f = _split_terse(line)
        need = 9 if with_bw else 8
        if len(f) < need:
            continue
        inuse, ssid, bssid, chan, freq, signal, sec, rate = f[:8]
        bw = f[8] if with_bw else ""
        try:
            freq_mhz = int(re.sub(r"\D", "", freq))
            ch = int(chan)
            sig = int(signal)
        except ValueError:
            continue
        m = re.match(r"(\d+)", bw)
        nets.append(Network(
            ssid=ssid, bssid=bssid.lower(), channel=ch, freq=freq_mhz, band=band_of_freq(freq_mhz),
            signal=pct_to_dbm(sig), security=_norm_nm_security(sec),
            width=int(m.group(1)) if m else None, rate=rate, in_use=inuse.strip() == "*"))
    return nets


def _scan_nmcli(rescan: bool) -> List[Network]:
    base = ["nmcli", "-t", "-e", "yes", "-f"]
    rs = ["dev", "wifi", "list", "--rescan", "yes" if rescan else "no"]
    try:
        return parse_nmcli(_run(base + ["IN-USE,SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY,RATE,BANDWIDTH"] + rs), True)
    except subprocess.SubprocessError:
        return parse_nmcli(_run(base + ["IN-USE,SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY,RATE"] + rs), False)


def parse_iw(text: str) -> List[Network]:
    nets: List[Network] = []
    cur: Optional[dict] = None

    def flush():
        if cur and cur.get("freq"):
            ch, band = freq_to_channel(cur["freq"])
            sec = "WPA3" if cur.get("sae") else "WPA2" if cur.get("rsn") else \
                "WPA" if cur.get("wpa") else "WEP" if cur.get("priv") else "Open"
            nets.append(Network(ssid=cur.get("ssid", ""), bssid=cur["bssid"], channel=ch,
                                freq=cur["freq"], band=band, signal=cur.get("signal", -100.0),
                                security=sec, width=cur.get("width"), phy=cur.get("phy", ""),
                                in_use=cur.get("assoc", False)))

    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"^BSS\s+" + _MAC + r"(.*)$", line)
        if m:
            flush()
            cur = {"bssid": m.group(1).lower(), "assoc": "associated" in m.group(2)}
            continue
        if cur is None:
            continue
        if line.startswith("freq:"):
            cur["freq"] = int(float(line.split(":", 1)[1]))
        elif line.startswith("signal:"):
            cur["signal"] = float(line.split(":", 1)[1].split()[0])
        elif line.startswith("SSID:"):
            cur["ssid"] = line.split(":", 1)[1].strip()
        elif line.startswith("RSN:"):
            cur["rsn"] = True
        elif line.startswith("WPA:"):
            cur["wpa"] = True
        elif "Authentication suites" in line and "SAE" in line:
            cur["sae"] = True
        elif line.startswith("capability:") and "Privacy" in line:
            cur["priv"] = True
        elif line.startswith("* channel width:"):
            m2 = re.search(r"\((\d+) MHz\)", line)
            cur["width"] = int(m2.group(1)) if m2 else (40 if "1" in line.split(":")[1][:3] else 20)
        elif line.startswith("VHT capabilities"):
            cur["phy"] = "802.11ac"
        elif line.startswith("HE capabilities"):
            cur["phy"] = "802.11ax"
        elif line.startswith("HT capabilities") and not cur.get("phy"):
            cur["phy"] = "802.11n"
    flush()
    return nets


def _scan_iw(rescan: bool) -> List[Network]:
    out = _run(["iw", "dev"])
    ifaces = re.findall(r"Interface\s+(\S+)", out)
    if not ifaces:
        raise RuntimeError("Nie znaleziono interfejsu Wi-Fi (iw dev).")
    cmd = ["iw", "dev", ifaces[0], "scan"] if rescan else ["iw", "dev", ifaces[0], "scan", "dump"]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if p.returncode != 0:
        raise RuntimeError("iw scan nie powiódł się (uruchom przez sudo?): " + p.stderr.strip())
    return parse_iw(p.stdout)


def scan_linux(rescan: bool = True) -> List[Network]:
    errors = []
    if shutil.which("nmcli"):
        try:
            nets = _scan_nmcli(rescan)
            if nets:
                return nets
        except Exception as e:  # noqa: BLE001
            errors.append("nmcli: %s" % e)
    if shutil.which("iw"):
        try:
            nets = _scan_iw(rescan)
            if nets:
                return nets
        except Exception as e:  # noqa: BLE001
            errors.append("iw: %s" % e)
    raise RuntimeError("Nie udało się przeskanować sieci. Zainstaluj network-manager lub iw "
                       "(sudo apt install network-manager iw). " + "; ".join(errors))


def scan(rescan: bool = True) -> List[Network]:
    return scan_windows(rescan) if IS_WINDOWS else scan_linux(rescan)


# --------------------------------------------------------------------------
# Dane demonstracyjne
# --------------------------------------------------------------------------


def demo_networks() -> List[Network]:
    def n(ssid, ch, band, dbm, sec, width=None, phy="802.11n", use=False):
        b = "%02x" % (abs(hash((ssid, ch))) % 256)
        return Network(ssid, "aa:bb:cc:00:%s:%02x" % (b, ch), ch, channel_to_freq(ch, band), band,
                       dbm, sec, width, phy, in_use=use)
    return [
        n("Dom_5G", 36, "5", -48, "WPA2 WPA3", 80, "802.11ac", True),
        n("Dom", 6, "2.4", -45, "WPA2", 20, "802.11n"),
        n("Sasiad_1", 6, "2.4", -58, "WPA2", 20),
        n("Sasiad_2", 6, "2.4", -66, "WPA2", 40),
        n("UPC1234567", 11, "2.4", -62, "WPA2", 20),
        n("TP-Link_A1B2", 9, "2.4", -71, "WPA2", 20),
        n("FreeWifi", 1, "2.4", -80, "Open", 20),
        n("Kamera", 4, "2.4", -74, "WEP", 20),
        n("Stary_router", 11, "2.4", -77, "WPA", 20),
        n("", 8, "2.4", -83, "WPA2", 20),
        n("Orange_Swiatlowod", 3, "2.4", -68, "WPA2", 20),
        n("Orange_5G", 44, "5", -69, "WPA2", 80, "802.11ac"),
        n("Sasiad_1_5G", 36, "5", -75, "WPA2 WPA3", 80, "802.11ax"),
        n("Biuro", 100, "5", -72, "WPA2-Ent", 40, "802.11ac"),
    ]


# --------------------------------------------------------------------------
# Analiza
# --------------------------------------------------------------------------

CHANNELS_24 = list(range(1, 14))
CHANNELS_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
              132, 136, 140, 149, 153, 157, 161, 165]
CHANNELS_6 = list(range(1, 234, 4))


def is_dfs(ch: int) -> bool:
    return 52 <= ch <= 144


def weight(dbm: float) -> float:
    """Siła sieci jako wkład w zakłócenia (0.05 … 1.0)."""
    return min(1.0, max(0.05, (dbm + 95.0) / 60.0))


def occupied_5_6(ch: int, width: int, band: str) -> List[int]:
    n = max(1, width // 20)
    if band == "6":
        base = 1
    else:
        base = 36 if ch < 100 else 100 if ch < 149 else 149
    idx = (ch - base) // 4
    g = idx // n
    return [base + 4 * (g * n + k) for k in range(n)]


def overlap(net: Network, ch: int) -> float:
    """Jaką część widma kanału `ch` zajmuje sieć (0…1)."""
    w = net.width or 20
    if net.band == "2.4":
        d = abs(net.channel - ch)
        d = max(0, d - (2 if w >= 40 else 0))
        return max(0.0, 1.0 - d / 4.0)
    return 1.0 if ch in occupied_5_6(net.channel, w, net.band) else 0.0


def channel_load(nets: List[Network], ch: int, exclude: Optional[set] = None) -> float:
    return sum(weight(n.signal) * overlap(n, ch) for n in nets
               if not (exclude and n.bssid in exclude))


def load_label(score: float) -> str:
    return "wolny" if score < 0.6 else "umiarkowany" if score < 2.0 else "zatłoczony"


def candidates(band: str) -> List[int]:
    return {"2.4": CHANNELS_24, "5": CHANNELS_5, "6": CHANNELS_6}[band]


def best_channels(nets: List[Network], band: str, exclude: Optional[set] = None,
                  only: Optional[List[int]] = None) -> List[Tuple[int, float]]:
    pool = only or candidates(band)
    bn = [n for n in nets if n.band == band]
    return sorted(((c, channel_load(bn, c, exclude)) for c in pool), key=lambda x: (x[1], x[0]))


def sec_level(sec: str) -> str:
    s = sec.upper()
    if s.startswith("OPEN"):
        return "open"
    if "WPA3" in s or "WPA2" in s:
        return "ok"
    return "weak"  # WEP / sam WPA1


def recommendations(nets: List[Network], own_ssid: Optional[str]) -> List[Tuple[str, str]]:
    """Zwraca listę (poziom, tekst); poziom: good | info | warn | bad."""
    rec: List[Tuple[str, str]] = []
    by_band = {b: [n for n in nets if n.band == b] for b in ("2.4", "5", "6")}

    # --- własna sieć ---
    if own_ssid:
        mine = [n for n in nets if n.ssid == own_ssid]
        if not mine:
            rec.append(("warn", "Nie widzę sieci „%s” – sprawdź nazwę (--ssid)." % own_ssid))
        for band in ("2.4", "5", "6"):
            m = [n for n in mine if n.band == band]
            if not m:
                continue
            excl = {n.bssid for n in mine}
            ranking = best_channels(nets, band, excl)
            scores = dict(ranking)
            for ch in sorted({n.channel for n in m}):
                cur = channel_load([x for x in nets if x.band == band], ch, excl)
                best_ch, best = ranking[0]
                if band == "2.4":
                    best_ch, best = min(((c, scores[c]) for c in (1, 6, 11)), key=lambda x: x[1])
                if ch != best_ch and cur >= 1.0 and best < cur * 0.6:
                    rec.append(("warn", "Twoja sieć „%s” (%s GHz) na kanale %d: obciążenie %.1f (%s). "
                                "Zmień na kanał %d (obciążenie %.1f)." %
                                (own_ssid, band, ch, cur, load_label(cur), best_ch, best)))
                else:
                    rec.append(("good", "Twoja sieć „%s” (%s GHz) na kanale %d jest w dobrym miejscu "
                                "(obciążenie %.1f – %s)." % (own_ssid, band, ch, cur, load_label(cur))))
            if band == "2.4" and any((n.width or 20) >= 40 for n in m) and len(by_band["2.4"]) > 6:
                rec.append(("warn", "„%s” używa 40 MHz w zatłoczonym paśmie 2.4 GHz – ustaw 20 MHz." % own_ssid))
            if any(sec_level(n.security) != "ok" for n in m):
                rec.append(("bad", "„%s”: słabe/brak zabezpieczeń – włącz WPA2/WPA3 (AES)." % own_ssid))

    # --- najlepsze kanały ---
    excl = {n.bssid for n in nets if own_ssid and n.ssid == own_ssid}
    if by_band["2.4"]:
        r = best_channels(nets, "2.4", excl)
        top3 = best_channels(nets, "2.4", excl, [1, 6, 11])
        c, s = top3[0]
        rec.append(("info", "2.4 GHz – najlepszy kanał nienakładający się: %d (obciążenie %.1f, %s). "
                            "Najmniej zajęty w ogóle: %d (%.1f). Zalecane tylko 1/6/11, o ile "
                            "to możliwe." % (c, s, load_label(s), r[0][0], r[0][1])))
    if by_band["5"] or by_band["2.4"]:
        r = best_channels(nets, "5", excl)
        safe = [x for x in r if not is_dfs(x[0])]
        if safe:
            rec.append(("info", "5 GHz – najlepszy kanał bez DFS: %d (obciążenie %.1f, %s)." %
                        (safe[0][0], safe[0][1], load_label(safe[0][1]))))
        dfs = [x for x in r if is_dfs(x[0])]
        if dfs and dfs[0][1] + 0.3 < (safe[0][1] if safe else 99):
            rec.append(("info", "5 GHz – kanał DFS %d jest jeszcze luźniejszy (%.1f), ale router może go "
                                "opuścić po wykryciu radaru." % dfs[0]))
        if not by_band["5"]:
            rec.append(("info", "Nie wykryto sieci 5 GHz – Twoja karta może nie obsługiwać tego pasma."))
    if by_band["6"]:
        r = best_channels(nets, "6", excl, [c for c in CHANNELS_6 if c <= 93])
        rec.append(("info", "6 GHz – najlepszy kanał: %d (obciążenie %.1f)." % r[0]))

    # --- pasma ---
    if len(by_band["2.4"]) >= 8:
        rec.append(("warn", "Pasmo 2.4 GHz jest zatłoczone (%d sieci). Przenieś urządzenia na 5 GHz "
                            "wszędzie, gdzie zasięg na to pozwala." % len(by_band["2.4"])))
    if by_band["2.4"] and by_band["5"]:
        ch_count = {c: sum(1 for n in by_band["2.4"] if n.channel == c) for c in range(1, 14)}
        odd = sorted(c for c, k in ch_count.items() if k and c not in (1, 6, 11))
        if odd:
            rec.append(("warn", "Sieci na kanałach nakładających się (%s) zakłócają dwa sąsiednie kanały "
                                "– standardem są 1, 6, 11." % ", ".join(map(str, odd))))

    # --- bezpieczeństwo sąsiedztwa / pozostałe ---
    opens = sorted({n.ssid or "<ukryta>" for n in nets if sec_level(n.security) == "open"})
    weak = sorted({n.ssid or "<ukryta>" for n in nets if sec_level(n.security) == "weak"})
    if opens:
        rec.append(("warn", "Sieci otwarte (bez hasła): %s – nie łącz się bez VPN." % ", ".join(opens)))
    if weak:
        rec.append(("warn", "Przestarzałe zabezpieczenia (WEP/WPA1): %s." % ", ".join(weak)))
    hidden = sum(1 for n in nets if n.hidden)
    if hidden:
        rec.append(("info", "Ukryte sieci: %d (zajmują kanał tak samo jak widoczne)." % hidden))
    weaksig = sorted({n.ssid for n in nets if n.ssid and n.in_use and n.signal < -70})
    if weaksig:
        rec.append(("warn", "Sygnał połączonej sieci %s jest słaby (<-70 dBm) – zbliż się do routera "
                            "lub dodaj punkt dostępowy." % ", ".join(weaksig)))
    return rec


def analyse(nets: List[Network]) -> dict:
    out = {}
    for band in ("2.4", "5", "6"):
        bn = [n for n in nets if n.band == band]
        if not bn:
            continue
        chans = sorted({n.channel for n in bn} | (set(CHANNELS_24) if band == "2.4" else set()))
        out[band] = [{
            "channel": c,
            "networks": sum(1 for n in bn if n.channel == c),
            "load": round(channel_load(bn, c), 2),
            "ssids": sorted({n.ssid or "<ukryta>" for n in bn if n.channel == c}),
        } for c in chans]
    return out


# --------------------------------------------------------------------------
# Wyświetlanie
# --------------------------------------------------------------------------

USE_COLOR = False
COLORS = {"red": "31", "green": "32", "yellow": "33", "blue": "34", "cyan": "36",
          "grey": "90", "bold": "1"}


def c(text: str, color: str) -> str:
    return "\033[%sm%s\033[0m" % (COLORS[color], text) if USE_COLOR else text


def bar(frac: float, width: int = 10) -> str:
    n = int(round(max(0.0, min(1.0, frac)) * width))
    return "█" * n + "░" * (width - n)


def signal_color(dbm: float) -> str:
    return "green" if dbm >= -60 else "yellow" if dbm >= -75 else "red"


def trunc(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n - 1] + "…"


def render(nets: List[Network], own_ssid: Optional[str], band_filter: str) -> str:
    if band_filter != "all":
        nets = [n for n in nets if n.band == band_filter]
    L: List[str] = []
    nets_sorted = sorted(nets, key=lambda n: -n.signal)

    L.append(c("═══ DOSTĘPNE SIECI (%d) ═══" % len(nets), "bold"))
    hdr = "  %-24s %-17s %-5s %4s %5s  %-17s %-12s %s" % (
        "SSID", "BSSID", "Pasmo", "Kan.", "Szer.", "Sygnał", "Zabezp.", "Standard")
    L.append(c(hdr, "grey"))
    for n in nets_sorted:
        frac = (n.signal + 95) / 65
        sig = "%4.0f dBm %s" % (n.signal, bar(frac, 6))
        sec = n.security
        col = {"open": "red", "weak": "yellow", "ok": "green"}[sec_level(sec)]
        L.append("%s %-24s %-17s %-5s %4d %5s  %s %s %s" % (
            c("*", "cyan") if n.in_use else " ",
            trunc(n.ssid or "<ukryta>", 24), n.bssid, n.band, n.channel,
            ("%d" % n.width) if n.width else "-",
            c(sig, signal_color(n.signal)), c("%-12s" % trunc(sec, 12), col), n.phy))
    L.append(c("  * = aktualnie połączona; sygnał: -30 dBm (świetny) … -90 dBm (bardzo słaby)", "grey"))

    an = analyse(nets)
    for band, rows in an.items():
        L.append("")
        L.append(c("═══ OBŁOŻENIE KANAŁÓW – %s GHz ═══" % band, "bold"))
        mx = max([r["load"] for r in rows] + [2.0])
        for r in rows:
            if band != "2.4" and not r["networks"]:
                continue
            col = "green" if r["load"] < 0.6 else "yellow" if r["load"] < 2.0 else "red"
            tag = " DFS" if band == "5" and is_dfs(r["channel"]) else ""
            names = trunc(", ".join(r["ssids"]), 38)
            L.append("  Kanał %3d%-4s %s %2d sieci  obciążenie %4.1f  %s" % (
                r["channel"], tag, c(bar(r["load"] / mx, 20), col), r["networks"], r["load"],
                c(names, "grey")))
        L.append(c("  obciążenie = suma siły sieci × nakładanie widma (<0.6 wolny, >2 zatłoczony)", "grey"))

    L.append("")
    L.append(c("═══ PROPOZYCJE ═══", "bold"))
    icons = {"good": ("✔", "green"), "info": ("➜", "cyan"), "warn": ("!", "yellow"), "bad": ("✖", "red")}
    for lvl, txt in recommendations(nets, own_ssid):
        ic, col = icons[lvl]
        L.append("  %s %s" % (c(ic, col), txt))
    return "\n".join(L)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    global USE_COLOR
    ap = argparse.ArgumentParser(description="Analizator Wi-Fi (Windows / Linux)")
    ap.add_argument("--ssid", help="Twoja sieć – dla niej zostaną wygenerowane szczegółowe porady "
                                   "(domyślnie: aktualnie połączona)")
    ap.add_argument("--band", choices=["all", "2.4", "5", "6"], default="all")
    ap.add_argument("--min-signal", type=float, default=-100, help="ukryj sieci słabsze niż X dBm")
    ap.add_argument("--watch", type=int, nargs="?", const=10, metavar="SEK",
                    help="odświeżaj co SEK sekund (domyślnie 10)")
    ap.add_argument("--json", action="store_true", help="wynik w JSON")
    ap.add_argument("--no-rescan", action="store_true", help="użyj danych z cache systemu")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--demo", action="store_true", help="dane przykładowe (bez karty Wi-Fi)")
    a = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass
    USE_COLOR = sys.stdout.isatty() and not a.no_color and "NO_COLOR" not in os.environ
    if USE_COLOR and IS_WINDOWS:
        os.system("")  # włącza ANSI w konsoli Windows

    while True:
        try:
            nets = demo_networks() if a.demo else scan(not a.no_rescan)
        except Exception as e:  # noqa: BLE001
            print("Błąd: %s" % e, file=sys.stderr)
            return 1
        nets = [n for n in nets if n.signal >= a.min_signal]
        own = a.ssid or next((n.ssid for n in nets if n.in_use and n.ssid), None)

        if a.json:
            sel = [n for n in nets if a.band in ("all", n.band)]
            print(json.dumps({"networks": [asdict(n) for n in sel], "channels": analyse(sel),
                              "recommendations": [{"level": l, "text": t}
                                                  for l, t in recommendations(nets, own)]},
                             ensure_ascii=False, indent=2))
        else:
            if a.watch:
                print("\033[2J\033[H" if USE_COLOR else "", end="")
            print(render(nets, own, a.band))
            if a.watch:
                print(c("\n  odświeżanie co %d s – Ctrl+C aby wyjść  (%s)" %
                        (a.watch, time.strftime("%H:%M:%S")), "grey"))
        if not a.watch:
            return 0
        try:
            time.sleep(a.watch)
        except KeyboardInterrupt:
            return 0


if __name__ == "__main__":
    sys.exit(main())
