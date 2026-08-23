import os, unittest
from services.cloudflare_abuse_client import create_phishing_report
class TestCloudflareClient(unittest.TestCase):
 def test_dry_run_never_contacts_provider(self):
  old=os.environ.get('ABUSE_SUBMISSION_MODE'); os.environ['ABUSE_SUBMISSION_MODE']='DRY_RUN'
  try: self.assertEqual(create_phishing_report({})['state'],'DRY_RUN')
  finally:
   if old is None: os.environ.pop('ABUSE_SUBMISSION_MODE',None)
   else: os.environ['ABUSE_SUBMISSION_MODE']=old
if __name__=='__main__': unittest.main()
