"""Trusted Cloudflare Abuse Reports client. Calls are disabled unless LIVE is explicit."""
import json, os, urllib.request, urllib.error
API_BASE='https://api.cloudflare.com/client/v4'
def configured(): return bool(os.getenv('CLOUDFLARE_API_TOKEN') and os.getenv('CLOUDFLARE_ACCOUNT_ID'))
def create_phishing_report(payload):
    if os.getenv('ABUSE_SUBMISSION_MODE','DRY_RUN').upper()!='LIVE': return {'state':'DRY_RUN','response':None}
    if not configured(): return {'state':'CLOUDFLARE_NOT_CONFIGURED'}
    account=os.environ['CLOUDFLARE_ACCOUNT_ID']; token=os.environ['CLOUDFLARE_API_TOKEN']
    req=urllib.request.Request(f'{API_BASE}/accounts/{account}/abuse-reports/abuse_phishing',data=json.dumps(payload).encode(),method='POST',headers={'Authorization':f'Bearer {token}','Content-Type':'application/json','Accept':'application/json'})
    try:
        with urllib.request.urlopen(req,timeout=10) as response:
            body=json.loads(response.read().decode()); return {'state':'SUBMITTED','report_id':body.get('abuse_rand'),'response':{'result':body.get('result')}}
    except urllib.error.HTTPError as error:
        return {'state':{401:'CLOUDFLARE_AUTH_FAILED',403:'CLOUDFLARE_PERMISSION_DENIED',429:'CLOUDFLARE_RATE_LIMITED'}.get(error.code,'CLOUDFLARE_INVALID_REQUEST' if error.code<500 else 'CLOUDFLARE_SERVER_ERROR')}
    except TimeoutError: return {'state':'UNKNOWN_SUBMISSION_STATE'}
    except urllib.error.URLError: return {'state':'CLOUDFLARE_NETWORK_ERROR'}
