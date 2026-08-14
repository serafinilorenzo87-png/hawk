"""memcached fingerprint must not false-positive on UnrealIRCd.

DB Fingerprint sends `version\\r\\n` to each port.  memcached answers
`VERSION 1.x\\r\\n` or, for an unknown verb, exactly `ERROR\\r\\n`.  An IRC
server (UnrealIRCd on Metasploitable2's 6667/6697) answers our junk line
with `ERROR :Closing Link: ... (Throttled: ...)` — which ALSO starts with
"ERROR".  The old `startswith(b"ERROR")` check mis-identified those IRC
ports as memcached and overwrote nmap's correct 'irc' classification.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class MemcachedClassifyTests(unittest.TestCase):
    def _classify(self, data):
        from utils.db_fingerprint import _classify_memcached
        return _classify_memcached(data)

    def test_version_reply_is_memcached_high(self):
        self.assertEqual(
            self._classify(b"VERSION 1.6.21\r\n"),
            ("memcached", "1.6.21", "high"))

    def test_bare_error_reply_is_memcached_medium(self):
        self.assertEqual(
            self._classify(b"ERROR\r\n"), ("memcached", "", "medium"))

    def test_unrealircd_throttle_error_is_not_memcached(self):
        # The exact line UnrealIRCd sends on Metasploitable2.
        irc = (b"ERROR :Closing Link: [192.168.177.132] "
               b"(Throttled: Reconnecting too fast) "
               b"-Email admin@Metasploitable.LAN for more information.\r\n")
        self.assertIsNone(self._classify(irc))

    def test_generic_irc_error_with_message_is_not_memcached(self):
        self.assertIsNone(self._classify(b"ERROR :Bad input\r\n"))

    def test_empty_is_none(self):
        self.assertIsNone(self._classify(b""))


if __name__ == "__main__":
    unittest.main()
