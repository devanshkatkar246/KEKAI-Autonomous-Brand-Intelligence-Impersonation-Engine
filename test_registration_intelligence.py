import unittest
from unittest.mock import patch
from services.registration_intelligence_service import clear_registration_cache, get_registration_intelligence, parse_rdap_registration, registrable_domain

RAW = {"entities": [{"roles": ["registrar"], "handle": "123", "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}, {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@example.test"], ["tel", {}, "text", "+1.555"]]]}], "events": [{"eventAction": "registration", "eventDate": "2026-01-01T00:00:00Z"}, {"eventAction": "last changed", "eventDate": "2026-02-01T00:00:00Z"}, {"eventAction": "expiration", "eventDate": "2027-01-01T00:00:00Z"}], "status": ["clientTransferProhibited"], "nameservers": [{"ldhName": "NS1.EXAMPLE.TEST."}, {"ldhName": "ns1.example.test"}]}
class TestRegistration(unittest.TestCase):
 def setUp(self): clear_registration_cache()
 def test_parse(self):
  r=parse_rdap_registration('example.test', RAW); self.assertEqual(r['registrar']['name'],'Example Registrar'); self.assertEqual(r['registrar']['iana_id'],'123'); self.assertEqual(r['abuse_contact']['state'],'VERIFIED'); self.assertEqual(r['nameservers'],['ns1.example.test']); self.assertEqual(r['registration']['updated_at'],'2026-02-01T00:00:00Z')
 def test_normalization(self): self.assertEqual(registrable_domain('https://login.example.co.uk/a')['registrable_domain'],'example.co.uk')
 @patch('services.registration_intelligence_service.fetch_rdap_data')
 def test_rdap_and_cache(self, mock):
  mock.return_value={'status':'RDAP_SUCCESS','raw_rdap':RAW}; self.assertEqual(get_registration_intelligence('login.example.test')['source'],'RDAP'); get_registration_intelligence('example.test'); self.assertEqual(mock.call_count,1)
 @patch('services.registration_intelligence_service._whois_lookup', return_value='Registrar: Fallback Registrar\nRegistrar Abuse Contact Email: abuse@fallback.test\nName Server: NS1.FALLBACK.TEST')
 @patch('services.registration_intelligence_service.fetch_rdap_data', return_value={'status':'RDAP_NOT_FOUND'})
 def test_whois_fallback(self, *_): self.assertEqual(get_registration_intelligence('fallback.test')['source'],'WHOIS')
 def test_invalid(self): self.assertEqual(get_registration_intelligence('bad')['source_status'],'INVALID_DOMAIN')
if __name__=='__main__': unittest.main()
