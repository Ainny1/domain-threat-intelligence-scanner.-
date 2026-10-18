import unittest
from unittest.mock import patch
from domain_intel.core import normalize_domain, findings, scan

class DomainTests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize_domain(' EXAMPLE.COM. '), 'example.com')
    def test_idna(self):
        self.assertTrue(normalize_domain('bücher.example').startswith('xn--'))
    def test_reject_url(self):
        for item in ['https://example.com', 'example.com/path', 'example.com:443', 'a', '127.0.0.1', '-bad.com', 'example..com']:
            with self.subTest(item=item), self.assertRaises(ValueError):
                normalize_domain(item)
    def test_findings(self):
        got = findings({'addresses': []}, {'error': 'SSLError', 'days_remaining': None}, {'error': 'HTTPError'})
        self.assertEqual(len(got), 3)
    @patch('domain_intel.core.rdap_metadata', return_value={'events': {}, 'status': [], 'error': None})
    @patch('domain_intel.core.tls_metadata', return_value={'error': None, 'days_remaining': 100})
    @patch('domain_intel.core.dns_addresses', return_value={'addresses': ['93.184.215.14'], 'error': None})
    def test_scanner(self, *_):
        self.assertEqual(scan('EXAMPLE.COM')['domain'], 'example.com')
        self.assertEqual(scan('example.com')['findings'], [])

if __name__ == '__main__':
    unittest.main()
