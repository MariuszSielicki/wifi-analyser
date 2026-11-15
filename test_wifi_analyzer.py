import unittest

import wifi_analyzer as w

NETSH_EN = """
Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : Dom
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:01
         Signal             : 80%
         Radio type         : 802.11n
         Band               : 2.4 GHz
         Channel            : 6
    BSSID 2                 : aa:bb:cc:dd:ee:02
         Signal             : 60%
         Radio type         : 802.11ac
         Band               : 5 GHz
         Channel            : 44

SSID 2 :
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : aa:bb:cc:dd:ee:03
         Signal             : 30%
         Radio type         : 802.11g
         Channel            : 1
"""

NETSH_PL = """
SSID 1 : Siec
    Typ sieci               : Infrastruktura
    Uwierzytelnianie        : WPA2-Osobiste
    Szyfrowanie             : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:09
         Sygnał             : 90%
         Typ radia          : 802.11ax
         Pasmo              : 5 GHz
         Kanał             : 100
"""

NMCLI = (" :Dom:AA\\:BB\\:CC\\:DD\\:EE\\:01:6:2437 MHz:75:WPA2:130 Mbit/s:20 MHz\n"
         "*:Moja\\:Siec:AA\\:BB\\:CC\\:DD\\:EE\\:02:36:5180 MHz:80:WPA2 WPA3:866 Mbit/s:80 MHz\n"
         " :Otwarta:AA\\:BB\\:CC\\:DD\\:EE\\:03:1:2412 MHz:40:--:54 Mbit/s:20 MHz\n")

IW = """BSS aa:bb:cc:dd:ee:01(on wlan0) -- associated
\tfreq: 2437
\tsignal: -52.00 dBm
\tSSID: Dom
\tRSN:\t * Version: 1
\t\t * Authentication suites: PSK
BSS aa:bb:cc:dd:ee:02(on wlan0)
\tfreq: 5180
\tsignal: -70.00 dBm
\tSSID: Open5
\tcapability: ESS (0x0401)
"""


class Parsers(unittest.TestCase):
    def test_netsh_en(self):
        n = w.parse_netsh(NETSH_EN, "aa:bb:cc:dd:ee:02")
        self.assertEqual(len(n), 3)
        self.assertEqual((n[0].ssid, n[0].channel, n[0].band, n[0].signal), ("Dom", 6, "2.4", -60))
        self.assertEqual(n[1].band, "5")
        self.assertTrue(n[1].in_use)
        self.assertEqual(n[2].security, "Open")
        self.assertEqual(n[2].ssid, "")

    def test_netsh_pl(self):
        n = w.parse_netsh(NETSH_PL)
        self.assertEqual((n[0].channel, n[0].band, n[0].security), (100, "5", "WPA2"))

    def test_nmcli(self):
        n = w.parse_nmcli(NMCLI, True)
        self.assertEqual(len(n), 3)
        self.assertEqual(n[1].ssid, "Moja:Siec")
        self.assertEqual(n[1].bssid, "aa:bb:cc:dd:ee:02")
        self.assertTrue(n[1].in_use)
        self.assertEqual((n[1].width, n[1].band), (80, "5"))
        self.assertEqual(n[2].security, "Open")

    def test_iw(self):
        n = w.parse_iw(IW)
        self.assertEqual(len(n), 2)
        self.assertEqual((n[0].channel, n[0].security, n[0].in_use), (6, "WPA2", True))
        self.assertEqual(n[1].security, "Open")


class Analysis(unittest.TestCase):
    def test_freq(self):
        self.assertEqual(w.freq_to_channel(2412), (1, "2.4"))
        self.assertEqual(w.freq_to_channel(5180), (36, "5"))
        self.assertEqual(w.freq_to_channel(2484), (14, "2.4"))

    def test_overlap_24(self):
        n = w.Network("x", "a", 6, 2437, "2.4", -50)
        self.assertEqual(w.overlap(n, 6), 1.0)
        self.assertEqual(w.overlap(n, 10), 0.0)
        self.assertGreater(w.overlap(n, 8), 0)

    def test_width_5ghz(self):
        self.assertEqual(w.occupied_5_6(36, 80, "5"), [36, 40, 44, 48])
        self.assertEqual(w.occupied_5_6(52, 40, "5"), [52, 56])

    def test_demo_runs(self):
        nets = w.demo_networks()
        text = w.render(nets, "Dom", "all")
        self.assertIn("PROPOZYCJE", text)
        self.assertTrue(w.recommendations(nets, "Dom"))


if __name__ == "__main__":
    unittest.main()
