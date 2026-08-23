"""Passive provider attribution over existing DNS, ASN, and registration outputs."""
from typing import Any, Dict, List, Optional
from services.dns_intelligence_service import resolve_dns_records
from services.asn_intelligence_service import lookup_ip_asn
from services.registration_intelligence_service import get_registration_intelligence

def _cloudflare(dns: Dict[str, Any], ips: List[Dict[str, Any]]) -> Dict[str, Any]:
    signals=[]; roles=[]
    ns_values=[r.get('value','').lower() for r in dns.get('dns_intelligence',{}).get('ns_records',[])]
    cname_values=[r.get('value','').lower() for r in dns.get('dns_intelligence',{}).get('cname_records',[])]
    if any('.cloudflare.com' in value for value in ns_values): signals.append({'type':'NAMESERVER','confidence':'STRONG_INDICATOR'}); roles.append('DNS')
    if any('cloudflare' in value for value in cname_values): signals.append({'type':'CNAME','confidence':'POSSIBLE'}); roles.append('CDN_PROXY')
    if any('cloudflare' in str(item.get('asn_organization','')).lower() or item.get('asn') == 'AS13335' for item in ips): signals.append({'type':'IP_ASN','confidence':'HIGH'}); roles.append('CDN_PROXY')
    detected=bool(signals); confidence='HIGH' if any(s['type']=='IP_ASN' for s in signals) and len(signals)>1 else 'STRONG_INDICATOR' if any(s['type']=='IP_ASN' for s in signals) else 'POSSIBLE' if detected else 'NOT_DETECTED'
    return {'provider':'Cloudflare','detected':detected,'roles':sorted(set(roles)) or ['UNKNOWN'],'confidence':confidence,'signals':signals,'origin_warning': detected and ('CDN_PROXY' in roles)}

def get_provider_intelligence(domain: str, use_cache: bool=True, dns_data: Optional[Dict[str,Any]]=None, registration: Optional[Dict[str,Any]]=None) -> Dict[str,Any]:
    dns=dns_data or resolve_dns_records(domain,use_cache=use_cache); ips=[]
    for item in dns.get('resolved_ips',[]):
        info=lookup_ip_asn(item.get('ip'),use_cache=use_cache); ips.append({**item,**info})
    registration=registration or get_registration_intelligence(domain,use_cache=use_cache)
    cloudflare=_cloudflare(dns,ips); providers=[]
    registrar=registration.get('registrar') or {}
    if registrar.get('name'): providers.append({'name':registrar['name'],'role':'REGISTRAR','source':registration.get('source'),'confidence':'VERIFIED' if registrar.get('abuse_email') else 'PARTIAL'})
    for ip in ips:
        if ip.get('network_organization'): providers.append({'name':ip['network_organization'],'role':'NETWORK','source':'IP_RDAP','confidence':ip.get('provider_evidence_level','UNAVAILABLE')})
    if cloudflare['detected']:
        providers.extend({'name':'Cloudflare','role':role,'source':'DNS+ASN','confidence':cloudflare['confidence']} for role in cloudflare['roles'] if role!='UNKNOWN')
    targets=[]
    if registrar.get('name'): targets.append({'type':'REGISTRAR','provider':registrar['name'],'source':registration.get('source'),'verification':registration.get('abuse_contact',{}).get('state','UNAVAILABLE')})
    if cloudflare['detected']: targets.append({'type':'NETWORK/CDN','provider':'Cloudflare','source':'DNS+ASN','verification':cloudflare['confidence']})
    return {'domain':domain,'dns':dns,'network':{'ips':ips,'asns':[i.get('asn') for i in ips]},'registration_intelligence':registration,'provider_intelligence':{'providers':providers,'cloudflare':cloudflare},'potential_targets':targets}
