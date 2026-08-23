"""Dry-run provider routing only. No adapter performs network submission."""
from typing import Any, Dict, List
from services.abuse_response_service import evaluate_abuse_response

class AbuseProviderAdapter:
    provider = 'Generic'; method = 'MANUAL'; roles: List[str] = []
    def capabilities(self): return {'provider':self.provider,'method':self.method,'supported_roles':self.roles,'dry_run_only':True,'status_tracking':False,'screenshot_required':False}
    def can_handle(self,target): return target.get('provider','').lower()==self.provider.lower() and target.get('verification') in {'VERIFIED','HIGH','STRONG_INDICATOR'}
    def prepare(self,domain,evidence,target): return {'provider':self.provider,'method':self.method,'abuse_type':'PHISHING','target':{'domain':domain},'evidence':evidence.get('artifacts',[]),'status':'DRY_RUN','reason':target.get('reason','Provider intelligence route')}
    def submit(self,*_): return {'status':'ADAPTER_NOT_IMPLEMENTED','mode':'DRY_RUN'}
class CloudflareAdapter(AbuseProviderAdapter):
    provider='Cloudflare'; method='API'; roles=['CDN_PROXY','DNS']
    def capabilities(self): return {**super().capabilities(),'screenshot_required':True,'api_submission':'ADAPTER_NOT_IMPLEMENTED','supported_abuse_types':['PHISHING']}
class NamecheapAdapter(AbuseProviderAdapter):
    provider='Namecheap'; method='API'; roles=['REGISTRAR']
    def capabilities(self): return {**super().capabilities(),'api_submission':'API_NOT_CONFIGURED','supported_abuse_types':['PHISHING']}
class RegistrarEmailAdapter(AbuseProviderAdapter):
    provider='Registrar Email'; method='ABUSE_EMAIL'; roles=['REGISTRAR']
    def can_handle(self,target): return target.get('type')=='REGISTRAR' and target.get('verification') in {'VERIFIED','PARTIAL'}
class BrowserFormAdapter(AbuseProviderAdapter):
    provider='Official Provider Web Form'; method='OFFICIAL_WEB_FORM'; roles=['REGISTRAR','CDN_PROXY','NETWORK']
    def can_handle(self,target): return target.get('verification') in {'VERIFIED','HIGH','STRONG_INDICATOR'}
    def prepare(self,*args): return {**super().prepare(*args),'status':'MANUAL_FORM_REQUIRED'}
class ProviderRegistry:
    def __init__(self): self.adapters=[]
    def register(self,adapter): self.adapters.append(adapter)
    def find(self,target): return [adapter for adapter in self.adapters if adapter.can_handle(target)]
DEFAULT_REGISTRY=ProviderRegistry()
for adapter in (CloudflareAdapter(),NamecheapAdapter(),RegistrarEmailAdapter(),BrowserFormAdapter()): DEFAULT_REGISTRY.register(adapter)
class AbuseSubmissionRouter:
    def preview(self,payload:Dict[str,Any],provider_intelligence:Dict[str,Any]):
        assessment=evaluate_abuse_response(payload); eligibility=assessment['reporting_eligibility']['decision']
        if eligibility!='READY_FOR_HUMAN_REVIEW': return {'mode':'DRY_RUN','recommended_routes':[],'submission_previews':[],'decision':eligibility,'reasons':assessment['reporting_eligibility']['reasons']}
        routes=[]; previews=[]
        for target in provider_intelligence.get('potential_targets',[]):
            target={**target,'role':'CDN_PROXY' if target['type']=='NETWORK/CDN' else 'REGISTRAR'}
            for adapter in DEFAULT_REGISTRY.find(target):
                cap=adapter.capabilities(); missing=[]
                if cap.get('screenshot_required') and assessment['evidence'].get('screenshot_status')!='SUCCESS': missing.append('SCREENSHOT')
                status='INSUFFICIENT_EVIDENCE' if missing else 'READY_FOR_REVIEW'
                route={'provider':adapter.provider,'method':adapter.method,'role':target['role'],'priority':len(routes)+1,'status':status,'verification':target['verification'],'reason':f"{target['provider']} identified by {target['source']}",'missing_evidence':missing,'capabilities':cap}
                routes.append(route); previews.append({**adapter.prepare(payload['candidate_domain'],assessment['evidence'],route),'status':'DRY_RUN' if not missing else 'INSUFFICIENT_EVIDENCE'})
        return {'mode':'DRY_RUN','decision':eligibility,'recommended_routes':routes,'submission_previews':previews,'assessment':assessment}
