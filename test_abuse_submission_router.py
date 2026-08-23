import unittest
from services.abuse_submission_router import AbuseSubmissionRouter
def evidence(screenshot='SUCCESS'): return {'sources':['dnstwist','openphish'],'domain_permutation':True,'strong_visual_match':True,'credential_indicators':True,'screenshot':{'status':screenshot}}
PROVIDERS={'potential_targets':[{'type':'REGISTRAR','provider':'Namecheap','source':'RDAP','verification':'VERIFIED'},{'type':'NETWORK/CDN','provider':'Cloudflare','source':'DNS+ASN','verification':'HIGH'}]}
class TestRouter(unittest.TestCase):
 def test_official_no_routes(self): self.assertEqual(AbuseSubmissionRouter().preview({'candidate_domain':'amazon.com','official_domain':'amazon.com','evidence':evidence()},PROVIDERS)['recommended_routes'],[])
 def test_dry_run_routes(self):
  r=AbuseSubmissionRouter().preview({'candidate_domain':'amaz0n.test','official_domain':'amazon.com','evidence':evidence()},PROVIDERS); self.assertEqual(r['mode'],'DRY_RUN'); self.assertTrue(r['recommended_routes']); self.assertTrue(all(p['status']=='DRY_RUN' for p in r['submission_previews']))
 def test_missing_screenshot(self):
  r=AbuseSubmissionRouter().preview({'candidate_domain':'amaz0n.test','official_domain':'amazon.com','evidence':evidence('FAILED')},PROVIDERS); self.assertIn('INSUFFICIENT_EVIDENCE',[x['status'] for x in r['recommended_routes']])
if __name__=='__main__': unittest.main()
