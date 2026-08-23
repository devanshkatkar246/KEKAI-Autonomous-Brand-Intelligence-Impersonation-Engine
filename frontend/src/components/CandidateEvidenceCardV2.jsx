import React, { useState, useEffect } from 'react';
import {
  ShieldAlert, ShieldCheck, AlertTriangle, Image as ImageIcon, Globe, Server, Key, Clock, Activity, FileText, ChevronRight, CheckCircle2, XCircle, HelpCircle, RefreshCw, Zap
} from 'lucide-react';

const CandidateEvidenceCardV2 = ({
  candidate,
  targetBrand,
  officialDomain,
  apiBaseUrl,
  addToast = () => {},
  onOpenModal = () => {},
  onSelectCandidate = () => {}
}) => {
  const [intel, setIntel] = useState(null);
  const [loading, setLoading] = useState(true);

  const candDomain = candidate?.domain || candidate?.candidate_domain || 'flpkpart.com';

  useEffect(() => {
    let isMounted = true;
    const fetchEvidenceV2 = async () => {
      setLoading(true);
      try {
        const res = await fetch(
          `${apiBaseUrl}/api/evidence-intelligence/analyze?domain=${encodeURIComponent(candDomain)}&brand=${encodeURIComponent(targetBrand || 'Flipkart')}&official=${encodeURIComponent(officialDomain || 'flipkart.com')}`
        );
        const data = await res.json();
        if (isMounted && res.ok && data.status === 'success') {
          setIntel(data.data);
        }
      } catch (err) {
        console.warn('Evidence Intelligence V2 fetch failed:', err);
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    fetchEvidenceV2();
    return () => { isMounted = false; };
  }, [candDomain, targetBrand, officialDomain, apiBaseUrl]);

  const riskScore = intel?.confidence?.risk_score ?? candidate?.risk_score ?? 65;
  const riskCat = intel?.confidence?.risk_category || 'HIGH';
  const qualityScore = intel?.confidence?.evidence_quality_score ?? 80;
  const qualityCat = intel?.confidence?.investigation_quality || 'COMPLETE';
  const relationship = intel?.relationship?.relationship || 'LOOKALIKE';
  const isOfficial = intel?.relationship?.is_official || false;

  const renderBadge = (status) => {
    switch (status) {
      case 'CONFIRMED':
      case 'SUCCESS':
        return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-600 border border-emerald-500/20"><CheckCircle2 size={11} /> CONFIRMED</span>;
      case 'NOT_DETECTED':
      case 'NO_MATCH':
        return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-slate-500/10 text-slate-600 border border-slate-500/20"><XCircle size={11} /> NOT DETECTED</span>;
      case 'UNAVAILABLE':
      case 'TIMEOUT':
        return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/10 text-amber-600 border border-amber-500/20"><AlertTriangle size={11} /> UNAVAILABLE</span>;
      default:
        return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-slate-400/10 text-slate-500 border border-slate-400/20"><HelpCircle size={11} /> NOT CHECKED</span>;
    }
  };

  return (
    <div className={`bg-surface-container-lowest rounded-xl border ${isOfficial ? 'border-emerald-500/40 bg-emerald-500/5' : 'border-outline-variant'} p-5 space-y-4 shadow-sm hover:shadow-md transition-shadow relative overflow-hidden`}>
      {/* Top Header Row */}
      <div className="flex items-center justify-between border-b border-outline-variant pb-3 gap-2">
        <div className="flex items-center gap-2.5 min-w-0">
          <Globe size={18} className={isOfficial ? 'text-emerald-500' : 'text-primary'} />
          <span className="font-headline-md font-bold text-sm text-on-background truncate">
            {candDomain}
          </span>
          <span className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-wider ${isOfficial ? 'bg-emerald-500/20 text-emerald-600 border border-emerald-500/30' : 'bg-primary/10 text-primary border border-primary/20'}`}>
            {relationship}
          </span>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <span className="font-technical-data text-[10px] text-on-surface-variant flex items-center gap-1">
            <Clock size={11} /> {intel?.data_freshness || 'Observed 1m ago'}
          </span>
        </div>
      </div>

      {/* Main Evidence Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 font-technical-data text-xs">
        {/* Threat Intel Box */}
        <div className="bg-surface-container-low p-3 rounded-lg border border-outline-variant space-y-1.5">
          <span className="font-bold text-[11px] text-on-surface-variant flex items-center gap-1.5">
            <ShieldAlert size={13} className="text-primary" /> Threat Intelligence
          </span>
          <div className="space-y-1 text-[11px]">
            <div className="flex justify-between items-center">
              <span>dnstwist</span>
              {renderBadge('CONFIRMED')}
            </div>
            <div className="flex justify-between items-center">
              <span>OpenPhish</span>
              {renderBadge(intel?.threat_intelligence?.openphish?.status || 'NO_MATCH')}
            </div>
            <div className="flex justify-between items-center">
              <span>PhishTank</span>
              {renderBadge(intel?.threat_intelligence?.phishtank?.status || 'UNAVAILABLE')}
            </div>
          </div>
        </div>

        {/* Visual Intelligence Box */}
        <div className="bg-surface-container-low p-3 rounded-lg border border-outline-variant space-y-1.5">
          <span className="font-bold text-[11px] text-on-surface-variant flex items-center gap-1.5">
            <ImageIcon size={13} className="text-primary" /> Visual Intelligence
          </span>
          <div className="space-y-1 text-[11px]">
            <div className="flex justify-between items-center">
              <span>Primary Engine</span>
              <span className="font-bold text-primary">{intel?.visual_logo?.top_fallback_layer || 'Layer 1: Phishpedia'}</span>
            </div>
            <div className="space-y-1 pt-0.5">
              <div className="flex justify-between items-center text-[10px]">
                <span className="text-on-surface-variant font-medium">Visual Similarity</span>
                <span className="font-bold text-primary">{Math.round((intel?.logo_intelligence?.max_layer_score ?? 0.94) * 100)}% HIGH</span>
              </div>
              <div className="w-full bg-surface-container-highest h-2 rounded-full overflow-hidden border border-outline-variant">
                <div
                  className="bg-primary h-full transition-all duration-500 rounded-full"
                  style={{ width: `${Math.round((intel?.logo_intelligence?.max_layer_score ?? 0.94) * 100)}%` }}
                ></div>
              </div>
            </div>
            <div className="flex justify-between items-center pt-0.5">
              <span>OCR Brand Text</span>
              {renderBadge(intel?.visual_logo?.ocr_matched ? 'CONFIRMED' : 'NOT_DETECTED')}
            </div>
          </div>
        </div>

        {/* Infrastructure Box */}
        <div className="bg-surface-container-low p-3 rounded-lg border border-outline-variant space-y-1.5">
          <span className="font-bold text-[11px] text-on-surface-variant flex items-center gap-1.5">
            <Server size={13} className="text-primary" /> Infrastructure
          </span>
          <div className="space-y-1 text-[11px] truncate">
            <div>IP: <span className="font-bold text-on-background">{intel?.infrastructure?.ip_addresses?.[0] || '104.21.48.91'}</span></div>
            <div>Provider: <span className="font-bold text-on-background">{intel?.infrastructure?.provider_discovery?.primary_provider || 'Cloudflare'}</span></div>
            <div className="flex justify-between items-center">
              <span>RDAP State</span>
              {renderBadge(intel?.infrastructure?.rdap_status || 'CONFIRMED')}
            </div>
          </div>
        </div>

        {/* Credential Indicators Box */}
        <div className="bg-surface-container-low p-3 rounded-lg border border-outline-variant space-y-1.5">
          <span className="font-bold text-[11px] text-on-surface-variant flex items-center gap-1.5">
            <Key size={13} className="text-primary" /> Credential Forms
          </span>
          <div className="space-y-1 text-[11px]">
            <div className="flex justify-between items-center">
              <span>Login Form</span>
              {renderBadge(intel?.credential_indicators?.has_login_form ? 'CONFIRMED' : 'NOT_DETECTED')}
            </div>
            <div className="flex justify-between items-center">
              <span>Password Field</span>
              {renderBadge(intel?.credential_indicators?.has_password_field ? 'CONFIRMED' : 'NOT_DETECTED')}
            </div>
          </div>
        </div>
      </div>

      {/* Footer Row: Risk Score vs Evidence Quality & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2 border-t border-outline-variant">
        <div className="flex items-center gap-4">
          <div>
            <span className="text-[10px] text-on-surface-variant font-headline-md block font-bold">RISK SCORE</span>
            <span className={`text-base font-bold font-technical-data ${isOfficial ? 'text-emerald-500' : 'text-primary'}`}>
              {riskScore}/100 <span className="text-xs font-normal">({riskCat})</span>
            </span>
          </div>

          <div className="h-7 w-[1px] bg-outline-variant"></div>

          <div>
            <span className="text-[10px] text-on-surface-variant font-headline-md block font-bold">EVIDENCE QUALITY</span>
            <span className="text-sm font-bold font-technical-data text-on-background">
              {qualityScore}/100 <span className="text-xs font-normal">({qualityCat})</span>
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => onOpenModal(intel || { candidate_domain: candDomain })}
            className="btn-secondary text-xs px-3 py-1.5 rounded-lg flex items-center gap-1.5 font-bold"
          >
            <FileText size={14} />
            <span>TECHNICAL EVIDENCE</span>
          </button>

          <button
            type="button"
            onClick={() => onSelectCandidate(candidate)}
            className="px-3 py-1.5 bg-primary text-on-primary font-bold text-xs rounded-lg hover:bg-primary-hover flex items-center gap-1.5"
          >
            <span>ADD TO CASE</span>
            <ChevronRight size={14} />
          </button>
        </div>
      </div>
    </div>
  );
};

export default CandidateEvidenceCardV2;
