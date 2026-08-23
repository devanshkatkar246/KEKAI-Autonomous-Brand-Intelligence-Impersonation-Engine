import React, { useState, useEffect } from 'react';
import {
  Globe, Server, ShieldAlert, Activity, FileText, CheckCircle2,
  AlertTriangle, RefreshCw, Loader2, Eye, X, Copy, Check, Info, Mail, Calendar, HelpCircle, Building, FileCheck
} from 'lucide-react';

const NetworkIntelligenceSection = ({ apiBaseUrl, initialDomain = '', addToast = () => {} }) => {
  const [domainInput, setDomainInput] = useState(initialDomain);
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [activeModalTab, setActiveModalTab] = useState('readiness');

  useEffect(() => {
    if (initialDomain && initialDomain !== domainInput) {
      setDomainInput(initialDomain);
      fetchDomainIntelligence(initialDomain);
    }
  }, [initialDomain]);

  const fetchDomainIntelligence = async (targetDom) => {
    const queryDom = (targetDom || domainInput || '').trim();
    if (!queryDom) return;

    setLoading(true);
    try {
      const cleanDom = queryDom.replace(/^https?:\/\//, '').split('/')[0];
      const res = await fetch(`${apiBaseUrl}/api/domain-intelligence`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: cleanDom, use_cache: true })
      });
      const resData = await res.json();
      if (!res.ok || resData.status === 'error') {
        throw new Error(resData.error || 'Failed to resolve network infrastructure');
      }
      setData(resData.data);
    } catch (err) {
      addToast('Network Intelligence Error', err.message || 'Lookup failed', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchDomainIntelligence(domainInput);
  };

  const dnsIntel = data?.dns_intelligence || {};
  const rdapData = data?.rdap || {};
  const primaryAsn = data?.primary_asn || {};
  const reportingTargets = data?.reporting_targets || {};
  const abuseTargets = data?.abuse_targets || {};
  const legitimacyGate = data?.legitimacy_gate || {};
  const reportingReadiness = data?.reporting_readiness || {};

  const aRecords = dnsIntel.a || [];
  const aaaaRecords = dnsIntel.aaaa || [];
  const cnameRecords = dnsIntel.cname || [];
  const mxRecords = dnsIntel.mx || [];
  const nsRecords = dnsIntel.ns || [];
  const resolvedIps = data?.resolved_ips || [];
  const reverseDns = data?.reverse_dns || [];

  return (
    <div className="bg-surface-container-lowest p-6 rounded-xl border border-outline-variant space-y-6">
      {/* HEADER & SEARCH BAR */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-outline-variant pb-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="material-symbols-outlined text-primary text-[22px]">dns</span>
            <span className="font-label-caps text-xs text-primary font-bold">UNIFIED ABUSE TARGET RESOLUTION & INFRASTRUCTURE · V3D</span>
          </div>
          <h3 className="font-headline-md text-lg font-bold text-on-background">Abuse Target Resolution & Network Infrastructure</h3>
          <p className="font-body-md text-xs text-on-surface-variant">
            Resolves primary registrar & secondary network abuse targets, evaluates Legitimacy Gate protection, and calculates readiness for human review.
          </p>
        </div>

        {/* INPUT SEARCH */}
        <form onSubmit={handleSearchSubmit} className="flex items-center gap-2">
          <input
            type="text"
            placeholder="Enter domain for target resolution..."
            value={domainInput}
            onChange={(e) => setDomainInput(e.target.value)}
            className="px-3 py-1.5 text-xs bg-surface-container-low border border-outline-variant rounded-lg text-on-background focus:outline-none focus:border-primary font-technical-data w-56"
          />
          <button
            type="submit"
            disabled={loading || !domainInput.trim()}
            className="px-3 py-1.5 bg-primary text-on-primary font-bold text-xs rounded-lg hover:bg-primary-hover transition-colors flex items-center gap-1 disabled:opacity-50"
          >
            {loading ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
            <span>Resolve</span>
          </button>
        </form>
      </div>

      {/* RESULTS DISPLAY */}
      {data && (
        <div className="space-y-6 text-xs">
          {/* DNS & READINESS STATUS TOP BAR */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-surface-container-low p-4 rounded-lg border border-outline-variant">
            <div className="flex items-center gap-3 flex-wrap">
              <DnsStatusBadge status={data.dns_status} />
              <span className="font-technical-data font-bold text-sm text-on-background">{data.domain}</span>
              <ReadinessBadge readiness={reportingReadiness} />
            </div>

            <button
              onClick={() => setShowModal(true)}
              className="px-3 py-1.5 bg-primary text-on-primary font-bold text-xs rounded-lg hover:bg-primary-hover transition-colors flex items-center gap-1.5 self-start sm:self-auto"
            >
              <Eye size={14} /> View Evidence
            </button>
          </div>

          {/* TASK 3D: # ABUSE RESPONSE READINESS CARD */}
          <div className="bg-surface-container-low p-5 rounded-xl border border-outline-variant space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-outline-variant pb-3">
              <h4 className="font-headline-md font-bold text-sm text-on-background flex items-center gap-2">
                <FileCheck size={16} className="text-primary" /> # ABUSE RESPONSE READINESS & TARGET SELECTION
              </h4>
              <button
                type="button"
                onClick={() => addToast('Report Preparation', `Prepared abuse report package for ${data.domain}. Ready for analyst dispatch review.`, 'success')}
                className="px-4 py-2 bg-primary text-on-primary font-headline-md font-bold text-xs rounded-lg hover:bg-primary-hover transition-colors flex items-center gap-1.5 shadow-sm"
              >
                <FileText size={14} /> [ PREPARE ABUSE REPORT ]
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
              {/* PRIMARY TARGET */}
              <div className="bg-surface-container-lowest p-3.5 rounded-lg border border-outline-variant space-y-1">
                <span className="font-label-caps text-[9px] text-on-surface-variant block font-bold">PRIMARY TARGET (REGISTRAR)</span>
                <strong className="font-body-md text-xs text-on-background block">{abuseTargets.primary?.name || 'Unknown Registrar'}</strong>
                <div className="font-technical-data text-[10px] text-primary font-bold">
                  {abuseTargets.primary?.email || 'No email available'}
                </div>
                <span className="inline-block px-1.5 py-0.5 bg-primary/10 text-primary border border-primary/20 rounded text-[9px] font-bold">
                  Target Source: {abuseTargets.primary?.source || 'RDAP'} ✓
                </span>
              </div>

              {/* SECONDARY TARGET */}
              <div className="bg-surface-container-lowest p-3.5 rounded-lg border border-outline-variant space-y-1">
                <span className="font-label-caps text-[9px] text-on-surface-variant block font-bold">SECONDARY TARGET (NETWORK)</span>
                <strong className="font-body-md text-xs text-on-background block">{abuseTargets.secondary?.name || 'Unknown Network'}</strong>
                <div className="font-technical-data text-[10px] text-on-surface-variant">
                  ASN: {abuseTargets.secondary?.asn || 'AS-UNKNOWN'}
                </div>
                <div className="font-technical-data text-[10px] text-primary">
                  {abuseTargets.secondary?.email || 'No email available'}
                </div>
              </div>

              {/* LEGITIMACY GATE */}
              <div className="bg-surface-container-lowest p-3.5 rounded-lg border border-outline-variant space-y-1">
                <span className="font-label-caps text-[9px] text-on-surface-variant block font-bold">LEGITIMACY CHECK</span>
                <strong className={`font-technical-data text-xs block font-bold ${
                  legitimacyGate.reporting_eligibility === 'ELIGIBLE' ? 'text-primary' : 'text-[#e7000b]'
                }`}>
                  {legitimacyGate.reporting_eligibility === 'ELIGIBLE' ? 'PASSED ✓' : 'BLOCKED 🛑'}
                </strong>
                <div className="font-body-md text-[10px] text-on-surface-variant line-clamp-2">
                  {legitimacyGate.status?.replace(/_/g, ' ')}
                </div>
              </div>

              {/* READINESS STATUS */}
              <div className="bg-surface-container-lowest p-3.5 rounded-lg border border-outline-variant space-y-1">
                <span className="font-label-caps text-[9px] text-on-surface-variant block font-bold">REPORTING STATUS</span>
                <strong className={`font-technical-data text-xs block font-bold ${
                  reportingReadiness.status === 'READY_FOR_HUMAN_REVIEW' ? 'text-primary' : 'text-[#b45309]'
                }`}>
                  {reportingReadiness.status?.replace(/_/g, ' ')}
                </strong>
                <div className="font-body-md text-[10px] text-on-surface-variant line-clamp-2">
                  Evidence Score: <strong>{reportingReadiness.evidence_score || 85}%</strong>
                </div>
              </div>
            </div>

            {/* EXPLAINABLE TARGET SELECTION REASON */}
            <div className="bg-surface-container-lowest p-3 rounded-lg border border-outline-variant text-xs space-y-1">
              <span className="font-label-caps text-[9px] text-on-surface-variant font-bold block">TARGET SELECTION REASONING:</span>
              <p className="font-body-md text-on-background text-[11px] leading-relaxed">
                {abuseTargets.primary?.target_reason}
              </p>
            </div>
          </div>

          {/* TASK 3C: # INFRASTRUCTURE PROVIDER CARD */}
          <div className="bg-surface-container-low p-4 rounded-xl border border-outline-variant space-y-3">
            <div className="flex items-center justify-between border-b border-outline-variant pb-2">
              <h4 className="font-headline-md font-bold text-xs text-on-background flex items-center gap-1.5">
                <Building size={14} className="text-primary" /> # INFRASTRUCTURE & ASN PROVIDER CORRELATION
              </h4>
              <span className="font-technical-data text-[10px] text-on-surface-variant">
                Resolved IP Count: <strong className="text-on-background">{resolvedIps.length}</strong>
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              <div className="bg-surface-container-lowest p-3 rounded-lg border border-outline-variant">
                <span className="font-label-caps text-[9px] text-on-surface-variant block mb-1">PRIMARY HOSTING IP</span>
                <strong className="font-technical-data text-xs text-primary">{resolvedIps[0]?.ip || 'None'}</strong>
                <div className="font-technical-data text-[10px] text-on-surface-variant truncate mt-0.5">
                  Family: {resolvedIps[0]?.address_family || 'IPv4'}
                </div>
              </div>

              <div className="bg-surface-container-lowest p-3 rounded-lg border border-outline-variant">
                <span className="font-label-caps text-[9px] text-on-surface-variant block mb-1">ASN & OWNER</span>
                <strong className="font-technical-data text-xs text-on-background">{resolvedIps[0]?.asn || 'AS-UNKNOWN'}</strong>
                <div className="font-body-md text-[10px] text-on-surface-variant truncate mt-0.5">
                  {resolvedIps[0]?.asn_organization || 'Unknown Org'}
                </div>
              </div>

              <div className="bg-surface-container-lowest p-3 rounded-lg border border-outline-variant">
                <span className="font-label-caps text-[9px] text-on-surface-variant block mb-1">NETWORK ORGANIZATION</span>
                <strong className="font-body-md text-xs text-on-background">{resolvedIps[0]?.network_organization || 'Unknown Network'}</strong>
                <div className="font-technical-data text-[10px] text-on-surface-variant truncate mt-0.5">
                  Route: {resolvedIps[0]?.network_route || 'BGP Prefix'}
                </div>
              </div>

              <div className="bg-surface-container-lowest p-3 rounded-lg border border-outline-variant space-y-1">
                <span className="font-label-caps text-[9px] text-on-surface-variant block">PROVIDER EVIDENCE LEVEL</span>
                <EvidenceLevelBadge level={resolvedIps[0]?.provider_evidence_level || 'UNAVAILABLE'} />
                <div className="font-technical-data text-[10px] text-on-surface-variant truncate">
                  Country: {resolvedIps[0]?.country || 'US'}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TECHNICAL EVIDENCE MODAL */}
      {showModal && data && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
          <div className="bg-surface-container-lowest w-full max-w-3xl rounded-xl border border-outline-variant p-6 space-y-4 max-h-[90vh] overflow-y-auto shadow-2xl">
            <div className="flex items-center justify-between border-b border-outline-variant pb-3">
              <h3 className="font-headline-md font-bold text-base text-on-background flex items-center gap-2">
                <Globe size={18} className="text-primary" />
                Network Infrastructure & Target Evidence &mdash; {data.domain}
              </h3>
              <button onClick={() => setShowModal(false)} className="text-on-surface-variant hover:text-on-background">
                <X size={20} />
              </button>
            </div>

            {/* MODAL TABS */}
            <div className="flex items-center gap-2 border-b border-outline-variant pb-2 text-xs overflow-x-auto">
              {[
                { id: 'readiness', label: 'Reporting Target Analysis' },
                { id: 'asn', label: `ASN & Network IPs (${resolvedIps.length})` },
                { id: 'dns', label: `DNS Records (${aRecords.length + aaaaRecords.length + cnameRecords.length + mxRecords.length + nsRecords.length})` },
                { id: 'rdap', label: 'RDAP Registration' },
                { id: 'raw', label: 'Raw Payload' }
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveModalTab(tab.id)}
                  className={`px-3 py-1.5 rounded-lg font-bold transition-colors shrink-0 ${
                    activeModalTab === tab.id
                      ? 'bg-primary text-on-primary'
                      : 'bg-surface-container-low text-on-surface-variant hover:bg-surface-container-high'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* TAB CONTENT */}
            <div className="space-y-3 text-xs">
              {/* TAB 1: REPORTING TARGET ANALYSIS */}
              {activeModalTab === 'readiness' && (
                <div className="space-y-3">
                  <div className="bg-surface-container-low p-4 rounded-lg border border-outline-variant space-y-2">
                    <h5 className="font-headline-md font-bold text-xs text-on-background">Primary Target (Registrar)</h5>
                    <div className="grid grid-cols-2 gap-2 font-technical-data">
                      <div>Name: {abuseTargets.primary?.name}</div>
                      <div>Abuse Email: {abuseTargets.primary?.email || 'None'}</div>
                      <div>Source: {abuseTargets.primary?.source}</div>
                      <div>Confidence: {abuseTargets.primary?.confidence}</div>
                    </div>
                    <p className="font-body-md text-[11px] text-on-surface-variant pt-1 border-t border-outline-variant">
                      <strong>Why Selected:</strong> {abuseTargets.primary?.target_reason}
                    </p>
                  </div>

                  <div className="bg-surface-container-low p-4 rounded-lg border border-outline-variant space-y-2">
                    <h5 className="font-headline-md font-bold text-xs text-on-background">Secondary Target (Network Operator)</h5>
                    <div className="grid grid-cols-2 gap-2 font-technical-data">
                      <div>Name: {abuseTargets.secondary?.name}</div>
                      <div>ASN: {abuseTargets.secondary?.asn}</div>
                      <div>Abuse Email: {abuseTargets.secondary?.email || 'None'}</div>
                      <div>Confidence: {abuseTargets.secondary?.confidence}</div>
                    </div>
                    <p className="font-body-md text-[11px] text-on-surface-variant pt-1 border-t border-outline-variant">
                      <strong>Why Selected:</strong> {abuseTargets.secondary?.target_reason}
                    </p>
                  </div>

                  <div className="bg-surface-container-low p-4 rounded-lg border border-outline-variant space-y-1">
                    <h5 className="font-headline-md font-bold text-xs text-on-background">Legitimacy Gate & Readiness Results</h5>
                    <div>Legitimacy State: <strong>{legitimacyGate.status}</strong></div>
                    <div>Reporting Eligibility: <strong>{legitimacyGate.reporting_eligibility}</strong></div>
                    <div>Reporting Readiness: <strong>{reportingReadiness.status}</strong></div>
                    <div className="text-on-surface-variant">{reportingReadiness.message}</div>
                  </div>
                </div>
              )}

              {/* TAB 2: ASN & NETWORK IPS */}
              {activeModalTab === 'asn' && (
                <div className="space-y-3">
                  <div className="overflow-x-auto border border-outline-variant rounded-lg">
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="bg-surface-container-low border-b border-outline-variant font-label-caps text-[10px] text-on-surface-variant">
                          <th className="p-2.5">IP Address</th>
                          <th className="p-2.5">ASN</th>
                          <th className="p-2.5">Network Organization</th>
                          <th className="p-2.5">PTR Reverse DNS</th>
                          <th className="p-2.5">Evidence Level</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-outline-variant font-technical-data text-[11px]">
                        {resolvedIps.map((ipObj, ipIdx) => (
                          <tr key={ipIdx} className="hover:bg-surface-container-low">
                            <td className="p-2.5 font-bold text-primary">{ipObj.ip}</td>
                            <td className="p-2.5 text-on-background">{ipObj.asn || 'AS-UNKNOWN'}</td>
                            <td className="p-2.5 text-on-background">{ipObj.asn_organization || 'Unknown Org'}</td>
                            <td className="p-2.5 text-on-surface-variant">{ipObj.reverse_dns || 'No PTR'}</td>
                            <td className="p-2.5"><EvidenceLevelBadge level={ipObj.provider_evidence_level} /></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* TAB 3: DNS RECORDS */}
              {activeModalTab === 'dns' && (
                <div className="space-y-3">
                  <div className="overflow-x-auto border border-outline-variant rounded-lg">
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="bg-surface-container-low border-b border-outline-variant font-label-caps text-[10px] text-on-surface-variant">
                          <th className="p-2.5">Type</th>
                          <th className="p-2.5">Resolved Value</th>
                          <th className="p-2.5">TTL</th>
                          <th className="p-2.5">Lookup Timestamp</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-outline-variant font-technical-data text-[11px]">
                        {[...aRecords, ...aaaaRecords, ...cnameRecords, ...mxRecords, ...nsRecords].map((r, rIdx) => (
                          <tr key={rIdx} className="hover:bg-surface-container-low">
                            <td className="p-2.5 font-bold text-primary">{r.record_type}</td>
                            <td className="p-2.5 text-on-background">{r.value}</td>
                            <td className="p-2.5 text-on-surface-variant">{r.ttl ?? '—'}</td>
                            <td className="p-2.5 text-on-surface-variant">{r.lookup_timestamp?.split('T')[1]?.split('.')[0] || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* TAB 4: RDAP REGISTRATION */}
              {activeModalTab === 'rdap' && (
                <div className="bg-surface-container-low p-4 rounded-lg border border-outline-variant space-y-2">
                  <div className="grid grid-cols-2 gap-3">
                    <div><strong>Registrar:</strong> {rdapData.registrar}</div>
                    <div><strong>Abuse Email:</strong> <span className="text-primary font-technical-data">{rdapData.abuse_email}</span></div>
                    <div><strong>Creation Date:</strong> {rdapData.creation_date}</div>
                    <div><strong>Expiration Date:</strong> {rdapData.expiration_date}</div>
                  </div>
                </div>
              )}

              {/* TAB 5: RAW PAYLOAD */}
              {activeModalTab === 'raw' && (
                <pre className="bg-black/90 text-green-400 p-4 rounded-lg font-technical-data text-[11px] overflow-x-auto max-h-80">
                  {JSON.stringify(data, null, 2)}
                </pre>
              )}
            </div>

            <div className="flex justify-end pt-2 border-t border-outline-variant">
              <button
                onClick={() => setShowModal(false)}
                className="px-4 py-2 bg-primary text-on-primary font-bold text-xs rounded-lg hover:bg-primary-hover"
              >
                Close Evidence Modal
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const DnsStatusBadge = ({ status }) => {
  const config = {
    DNS_SUCCESS: { color: 'bg-primary/20 text-primary border-primary/30', label: 'DNS RESOLVED ✓' },
    DNS_NXDOMAIN: { color: 'bg-[#fffbe6] text-[#b45309] border-[#fef3c7]', label: 'DNS NXDOMAIN (No Host)' },
    DNS_TIMEOUT: { color: 'bg-[#fffbe6] text-[#b45309] border-[#fef3c7]', label: 'DNS TIMEOUT' },
    DNS_SERVFAIL: { color: 'bg-[#fff1f2] text-[#e7000b] border-[#ffe4e6]', label: 'DNS SERVFAIL' },
    DNS_NO_RECORD: { color: 'bg-surface-container-high text-on-surface-variant border-outline-variant', label: 'DNS NO RECORD' },
    DNS_ERROR: { color: 'bg-[#fff1f2] text-[#e7000b] border-[#ffe4e6]', label: 'DNS ERROR' }
  };
  const c = config[status] || config.DNS_ERROR;
  return (
    <span className={`px-2.5 py-1 rounded text-[10px] font-bold border font-technical-data ${c.color}`}>
      {c.label}
    </span>
  );
};

const EvidenceLevelBadge = ({ level }) => {
  const config = {
    VERIFIED: { color: 'bg-primary/20 text-primary border-primary/30', label: 'VERIFIED ✓' },
    INFERRED: { color: 'bg-[#fffbe6] text-[#b45309] border-[#fef3c7]', label: 'INFERRED' },
    UNAVAILABLE: { color: 'bg-surface-container-high text-on-surface-variant border-outline-variant', label: 'UNAVAILABLE' }
  };
  const c = config[level] || config.UNAVAILABLE;
  return (
    <span className={`px-2 py-0.5 rounded text-[9px] font-bold border font-technical-data inline-block ${c.color}`}>
      {c.label}
    </span>
  );
};

const ReadinessBadge = ({ readiness }) => {
  const isReady = readiness?.status === 'READY_FOR_HUMAN_REVIEW';
  return (
    <span className={`px-2.5 py-1 rounded text-[10px] font-bold border font-technical-data ${
      isReady ? 'bg-primary/20 text-primary border-primary/30' : 'bg-[#fffbe6] text-[#b45309] border-[#fef3c7]'
    }`}>
      {isReady ? 'READY FOR HUMAN REVIEW ✓' : 'NOT READY FOR REVIEW'}
    </span>
  );
};

export default NetworkIntelligenceSection;
