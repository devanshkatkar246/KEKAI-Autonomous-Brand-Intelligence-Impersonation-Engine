import unittest
from unittest.mock import patch
from services.provider_intelligence_service import get_provider_intelligence
DNS={'dns_status':'DNS_SUCCESS','resolved_ips':[{'ip':'104.16.1.1'}],'dns_intelligence':{'ns_records':[{'value':'ada.ns.cloudflare.com'}],'cname_records':[]}}
REG={'source':'RDAP','registrar':{'name':'Namecheap','abuse_email':'abuse@namecheap.test'},'abuse_contact':{'state':'VERIFIED'}}
class TestProvider(unittest.TestCase):
 @patch('services.provider_intelligence_service.lookup_ip_asn',return_value={'asn':'AS13335','asn_organization':'Cloudflare, Inc.','network_organization':'Cloudflare','provider_evidence_level':'VERIFIED'})
 def test_cloudflare_roles_and_targets(self,_):
  r=get_provider_intelligence('x.test',dns_data=DNS,registration=REG); self.assertEqual(r['provider_intelligence']['cloudflare']['confidence'],'HIGH'); self.assertTrue(r['provider_intelligence']['cloudflare']['origin_warning']); self.assertEqual(len(r['potential_targets']),2)
 @patch('services.provider_intelligence_service.lookup_ip_asn',return_value={'asn':'AS1','asn_organization':'Else','network_organization':'Else','provider_evidence_level':'INFERRED'})
 def test_not_cloudflare(self,_): self.assertFalse(get_provider_intelligence('x.test',dns_data={**DNS,'dns_intelligence':{'ns_records':[],'cname_records':[]}},registration=REG)['provider_intelligence']['cloudflare']['detected'])
if __name__=='__main__': unittest.main()
