import React, { useState, useEffect, useRef } from 'react';
import {
  Image as ImageIcon, Upload, Loader2, Sliders, X, Trash2,
  AlertCircle, ShieldAlert, CheckCircle2, Eye, Plus, ChevronRight,
  Filter, Search, FileText, ArrowRight, Activity, ExternalLink,
  Fingerprint, Camera, Zap, Hash, ScanLine, Globe, Server, Code, Layers, Send,
  Compass, Cpu, Check, HelpCircle
} from 'lucide-react';

const LogoMatchTab = ({
  apiBaseUrl,
  addToast,
  selectedLogos,
  toggleSelectLogo,
  logoMatchState,
  setLogoMatchState,
  investigationState,
  setInvestigationState,
  onInvestigateCandidate
}) => {
  const {
    logoFile = null,
    targetBrand = '',
    officialDomain = '',
    results = null
  } = logoMatchState || {};

  const [logoPreviewUrl, setLogoPreviewUrl] = useState(null);
  const [loading, setLoading] = useState(false);
  const [progressStage, setProgressStage] = useState('');
  const [progressStep, setProgressStep] = useState(0);
  const [selectedFilter, setSelectedFilter] = useState('all');
  const [modalCandidate, setModalCandidate] = useState(null);
  const [activeModalTab, setActiveModalTab] = useState('provenance');
  const fileInputRef = useRef(null);

  const updateState = (updates) => {
    if (setLogoMatchState) {
      setLogoMatchState((prev) => ({ ...prev, ...updates }));
    }
  };

  useEffect(() => {
    if (logoFile) {
      const url = URL.createObjectURL(logoFile);
      setLogoPreviewUrl(url);
      return () => URL.revokeObjectURL(url);
    } else {
      setLogoPreviewUrl(null);
    }
  }, [logoFile]);

  const handleLogoUpload = (file) => {
    if (!file) return;
    if (!file.type.startsWith('image/')) {
      addToast('File Error', `File '${file.name}' is not a valid image. Please select PNG, JPG, or WEBP.`, 'error');
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      addToast('File Error', `File '${file.name}' exceeds the 5 MB maximum size limit.`, 'error');
      return;
    }
    updateState({ logoFile: file });
    addToast('Logo Ingested', `Uploaded ${file.name} — reverse visual discovery ready.`, 'success');
  };

  const handleDrop = (e) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleLogoUpload(e.dataTransfer.files[0]);
    }
  };

  const handleStartInvestigation = async (e) => {
    e?.preventDefault();
    if (!logoFile && !targetBrand) {
      addToast('Input Required', 'Please upload a brand logo or enter the target brand name to begin investigation.', 'error');
      return;
    }

    setLoading(true);
    setProgressStep(1);
    setProgressStage('Ingesting Logo & Computing Visual Fingerprints (pHash / dHash / OCR)...');

    try {
      const formData = new FormData();
      if (logoFile) formData.append('logo', logoFile);
      if (targetBrand) formData.append('target_brand', targetBrand);
      if (officialDomain) formData.append('official_domain', officialDomain);
      formData.append('max_candidates', '25');

      setTimeout(() => { setProgressStep(2); setProgressStage('Auto-Identifying Brand & Searching Visual Intelligence Corpus...'); }, 800);
      setTimeout(() => { setProgressStep(3); setProgressStage('Correlating Multi-Source Threat Intelligence (dnstwist, OpenPhish, PhishTank)...'); }, 2200);
      setTimeout(() => { setProgressStep(4); setProgressStage('Fusing Candidates & Recovering Candidate Domains...'); }, 4000);
      setTimeout(() => { setProgressStep(5); setProgressStage('Executing Stage 2 Live Webpage Verification & Phishpedia Analysis...'); }, 6000);
      setTimeout(() => { setProgressStep(6); setProgressStage('Correlating Multi-Signal Evidence & Generating viaSocket Schema...'); }, 8000);

      const response = await fetch(`${apiBaseUrl}/api/logo-investigation`, {
        method: 'POST',
        body: formData
      });

      const resData = await response.json();

      if (!response.ok || resData.status === 'error') {
        throw new Error(resData.error || resData.detail || 'Logo investigation failed');
      }

      if (resData.status === 'requires_brand_input') {
        addToast('Brand Name Required', resData.data.message, 'warning');
        setLoading(false);
        return;
      }

      updateState({ results: resData.data });

      if (setInvestigationState) {
        setInvestigationState((prev) => ({
          ...prev,
          isInitialized: true,
          brandName: resData.data.target_brand,
          officialDomain: resData.data.official_domain,
          source: 'logo_investigation'
        }));
      }

      const verified = resData.data.live_verified_count || 0;
      const totalAnalyzed = resData.data.total_candidates_analyzed || 0;
      addToast(
        'V4 Logo-First Discovery Complete',
        `Discovered ${totalAnalyzed} candidates — ${verified} live verified matches for ${resData.data.target_brand || 'Target Brand'}.`,
        'success'
      );
    } catch (err) {
      addToast('Discovery Error', err.message || 'Failed to complete logo discovery', 'error');
    } finally {
      setLoading(false);
      setProgressStage('');
      setProgressStep(0);
    }
  };

  const resultsList = results?.results || [];

  const filteredResults = resultsList.filter((item) => {
    if (selectedFilter === 'all') return true;
    if (selectedFilter === 'strong') return item.classification === 'STRONG_IMPERSONATION_EVIDENCE';
    if (selectedFilter === 'likely') return item.classification === 'LIKELY_IMPERSONATION';
    if (selectedFilter === 'visual_verified') return item.two_stage_verification_status === 'VISUAL_MATCH_VERIFIED';
    if (selectedFilter === 'corpus_only') return item.two_stage_verification_status === 'VISUAL_MATCH_UNVERIFIED';
    if (selectedFilter === 'official_related') return ['TARGET_BRAND_ON_OFFICIAL_DOMAIN', 'RELATED_DOMAIN_REVIEW'].includes(item.classification);
    return true;
  });

  const brandId = results?.brand_identification;

  return (
    <div className="space-y-6">
      {/* PAGE HEADER */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-surface-container-low p-6 rounded-xl border border-outline-variant/60">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="material-symbols-outlined text-primary text-[24px]">center_focus_strong</span>
            <span className="font-label-caps text-xs text-primary font-bold">TRUE LOGO-FIRST REVERSE VISUAL DISCOVERY · V4</span>
          </div>
          <h2 className="font-headline-lg text-2xl font-bold text-on-background">Find Websites Impersonating a Brand Logo</h2>
          <p className="font-body-md text-sm text-on-surface-variant max-w-3xl mt-1">
            Upload a brand logo. KEIKAI auto-identifies the brand, searches the Visual Intelligence Corpus, recovers candidate domains, fuses multi-source threat intelligence, and verifies visual evidence via live webpage capture.
          </p>
        </div>

        {results && (
          <button
            onClick={() => updateState({ results: null })}
            className="px-4 py-2 text-xs font-bold font-label-caps text-primary border border-primary/30 rounded-lg hover:bg-primary/5 transition-colors self-start md:self-auto"
          >
            + New Logo Discovery
          </button>
        )}
      </div>

      {/* SEARCH / INPUT CARD */}
      {!results && (
        <div className="bg-surface-container-lowest p-6 rounded-xl border border-outline-variant shadow-sm max-w-4xl mx-auto space-y-6">
          <div className="border-b border-outline-variant pb-4">
            <h3 className="font-headline-md text-base font-bold text-on-background flex items-center gap-2">
              <Compass size={18} className="text-primary" /> Start Logo-First Discovery
            </h3>
            <p className="font-body-md text-xs text-on-surface-variant mt-1">
              Provide a brand logo image. Brand name and domain are optional — KEIKAI will attempt logo-based brand identification automatically.
            </p>
          </div>

          <form onSubmit={handleStartInvestigation} className="space-y-6">
            {/* DROPZONE */}
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleDrop}
              onClick={() => !logoPreviewUrl && fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-xl p-6 text-center cursor-pointer transition-all ${
                logoPreviewUrl
                  ? 'border-primary/40 bg-primary/5'
                  : 'border-outline-variant hover:border-primary/50 hover:bg-surface-container-low'
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept="image/png,image/jpeg,image/webp"
                className="hidden"
                onChange={(e) => e.target.files?.[0] && handleLogoUpload(e.target.files[0])}
              />

              {logoPreviewUrl ? (
                <div className="flex flex-col items-center gap-3">
                  <div className="w-32 h-32 bg-white p-2 rounded-lg border border-outline-variant shadow-sm flex items-center justify-center">
                    <img src={logoPreviewUrl} alt="Logo preview" className="max-w-full max-h-full object-contain" />
                  </div>
                  <div className="flex items-center gap-2 px-3 py-1.5 bg-primary/10 border border-primary/20 rounded-full">
                    <Fingerprint size={13} className="text-primary" />
                    <span className="font-technical-data text-[11px] font-bold text-primary">
                      VISUAL DISCOVERY READY — pHash/dHash/OCR + Corpus Domain Recovery
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={(e) => { e.stopPropagation(); fileInputRef.current?.click(); }}
                      className="px-3 py-1.5 text-xs font-bold text-primary bg-surface-container-low border border-primary/30 rounded-md hover:bg-primary/10"
                    >
                      Replace Logo
                    </button>
                    <button
                      type="button"
                      onClick={(e) => { e.stopPropagation(); updateState({ logoFile: null }); }}
                      className="px-3 py-1.5 text-xs font-bold text-[#e7000b] bg-surface-container-low border border-[#ffe4e6] rounded-md hover:bg-[#fff1f2]"
                    >
                      Remove Logo
                    </button>
                  </div>
                  <span className="text-xs text-primary font-bold flex items-center gap-1">
                    <CheckCircle2 size={14} /> Logo Uploaded ({logoFile?.name})
                  </span>
                </div>
              ) : (
                <div className="py-6 flex flex-col items-center gap-2">
                  <div className="w-12 h-12 rounded-full bg-primary/10 text-primary flex items-center justify-center mb-1">
                    <Upload size={24} />
                  </div>
                  <h4 className="font-headline-md font-bold text-sm text-on-background">Upload Target Brand Logo</h4>
                  <p className="font-body-md text-xs text-on-surface-variant">Drag & drop or browse image file to start reverse visual discovery</p>
                  <span className="font-technical-data text-[11px] text-on-surface-variant/70 mt-1">PNG • JPG • WEBP • max 5MB</span>
                </div>
              )}
            </div>

            {/* FORM INPUTS */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div>
                <label className="font-label-caps text-xs text-on-surface-variant font-bold block mb-1">
                  Target Brand (Optional Analyst Override)
                </label>
                <input
                  type="text"
                  placeholder="Leave blank for auto-identification"
                  value={targetBrand}
                  onChange={(e) => updateState({ targetBrand: e.target.value })}
                  className="w-full px-3 py-2 bg-surface-container-low border border-outline-variant rounded-lg text-on-background focus:outline-none focus:border-primary"
                />
                <span className="text-[10px] text-on-surface-variant mt-1 block">If left blank, KEIKAI will identify brand via OCR + reference database.</span>
              </div>

              <div>
                <label className="font-label-caps text-xs text-on-surface-variant font-bold block mb-1">
                  Official Domain (Optional Analyst Override)
                </label>
                <input
                  type="text"
                  placeholder="Leave blank for auto-inference"
                  value={officialDomain}
                  onChange={(e) => updateState({ officialDomain: e.target.value })}
                  className="w-full px-3 py-2 bg-surface-container-low border border-outline-variant rounded-lg text-on-background focus:outline-none focus:border-primary"
                />
                <span className="text-[10px] text-on-surface-variant mt-1 block">If left blank, KEIKAI will infer domain from identified brand.</span>
              </div>
            </div>

            {/* DISCOVERY METHODS LIST */}
            <div className="bg-surface-container-low p-3.5 rounded-lg border border-outline-variant space-y-2 text-xs">
              <span className="font-label-caps text-[10px] text-on-surface-variant font-bold block">ACTIVE DISCOVERY METHODOLOGY:</span>
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 font-headline-md text-[11px]">
                <div className="flex items-center gap-1.5 text-primary font-bold"><Check size={14} /> Visual Corpus</div>
                <div className="flex items-center gap-1.5 text-primary font-bold"><Check size={14} /> Brand Intelligence</div>
                <div className="flex items-center gap-1.5 text-primary font-bold"><Check size={14} /> dnstwist</div>
                <div className="flex items-center gap-1.5 text-primary font-bold"><Check size={14} /> OpenPhish</div>
                <div className="flex items-center gap-1.5 text-primary font-bold"><Check size={14} /> PhishTank</div>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 bg-primary text-on-primary font-headline-md font-bold text-sm rounded-lg hover:bg-primary-hover transition-colors flex items-center justify-center gap-2 shadow-sm disabled:opacity-50"
            >
              {loading ? (
                <>
                  <Loader2 size={18} className="animate-spin" />
                  <span>Executing Logo-First Discovery Pipeline...</span>
                </>
              ) : (
                <>
                  <Compass size={18} />
                  <span>Find Impersonating Websites</span>
                </>
              )}
            </button>
          </form>

          {/* LIVE PIPELINE VISUALIZER */}
          {loading && (
            <div className="p-4 bg-primary/5 border border-primary/20 rounded-lg space-y-3">
              <div className="flex items-center justify-between">
                <span className="font-technical-data text-xs font-bold text-primary flex items-center gap-2">
                  <Loader2 size={14} className="animate-spin" />
                  {progressStage}
                </span>
                <span className="font-technical-data text-xs text-primary font-bold">Step {progressStep} / 6</span>
              </div>
              <div className="w-full bg-surface-container-high h-2 rounded-full overflow-hidden">
                <div
                  className="bg-primary h-full transition-all duration-500"
                  style={{ width: `${(progressStep / 6) * 100}%` }}
                ></div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* RESULTS DISPLAY */}
      {results && (
        <div className="space-y-6">
          {/* BRAND IDENTIFICATION STATUS PANEL */}
          {brandId && (
            <div className={`p-4 rounded-xl border space-y-2 ${
              brandId.status === 'BRAND_IDENTIFIED'
                ? 'bg-primary/5 border-primary/30'
                : 'bg-[#fffbe6] border-[#fef3c7]'
            }`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  {brandId.status === 'BRAND_IDENTIFIED' ? (
                    <CheckCircle2 size={18} className="text-primary" />
                  ) : (
                    <HelpCircle size={18} className="text-[#b45309]" />
                  )}
                  <span className="font-label-caps text-xs font-bold text-on-background">
                    BRAND IDENTIFICATION: <strong className="text-primary">{brandId.identified_brand || 'UNCERTAIN'}</strong>
                  </span>
                </div>
                <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold ${
                  brandId.confidence === 'HIGH' ? 'bg-primary/20 text-primary' : 'bg-surface-container-high text-on-surface-variant'
                }`}>
                  Confidence: {brandId.confidence}
                </span>
              </div>
              <p className="font-body-md text-xs text-on-surface-variant">{brandId.message}</p>
            </div>
          )}

          {/* DISCOVERY COVERAGE */}
          {results.discovery && (
            <div className="bg-surface-container-lowest p-4 rounded-xl border border-outline-variant">
              <div className="flex items-center gap-2 mb-3">
                <Activity size={14} className="text-primary" />
                <span className="font-label-caps text-xs font-bold text-primary">MULTI-SOURCE DISCOVERY PROVENANCE</span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-6 gap-2 text-xs">
                {[
                  { label: 'VISUAL CORPUS', val: results.discovery.visual_corpus_matches, color: 'text-primary' },
                  { label: 'DNSTWIST', val: results.discovery.dnstwist, color: 'text-primary' },
                  { label: 'OPENPHISH', val: results.discovery.openphish, color: 'text-primary' },
                  { label: 'PHISHTANK', val: results.discovery.phishtank, color: 'text-primary' },
                  { label: 'UNIQUE TOTAL', val: results.discovery.unique_candidates, color: 'text-on-background' },
                  { label: 'ANALYZED', val: results.discovery.analyzed, color: 'text-on-background' }
                ].map(({ label, val, color }) => (
                  <div key={label} className="bg-surface-container-low p-2.5 rounded-lg border border-outline-variant text-center">
                    <span className="font-label-caps text-[9px] text-on-surface-variant block">{label}</span>
                    <strong className={`font-headline-md text-base ${color}`}>{val ?? 0}</strong>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* SUMMARY CARDS */}
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
            <div className="bg-surface-container-lowest p-4 rounded-xl border border-outline-variant">
              <span className="font-label-caps text-[10px] text-on-surface-variant block">TARGET BRAND</span>
              <strong className="font-headline-md text-base text-on-background">{results.target_brand || 'Auto-Detect'}</strong>
            </div>
            <div className="bg-surface-container-lowest p-4 rounded-xl border border-outline-variant">
              <span className="font-label-caps text-[10px] text-on-surface-variant block">OFFICIAL DOMAIN</span>
              <strong className="font-headline-md text-base text-primary">{results.official_domain || 'Auto-Infer'}</strong>
            </div>
            <div className="bg-surface-container-lowest p-4 rounded-xl border border-outline-variant">
              <span className="font-label-caps text-[10px] text-on-surface-variant block">ANALYZED</span>
              <strong className="font-headline-md text-base text-on-background">{results.total_candidates_analyzed}</strong>
            </div>
            <div className="bg-surface-container-lowest p-4 rounded-xl border border-outline-variant">
              <span className="font-label-caps text-[10px] text-on-surface-variant block">LIVE VERIFIED</span>
              <strong className="font-headline-md text-base text-primary">{results.live_verified_count ?? 0}</strong>
            </div>
            <div className="bg-surface-container-lowest p-4 rounded-xl border border-outline-variant">
              <span className="font-label-caps text-[10px] text-on-surface-variant block">STRONG EVIDENCE</span>
              <strong className="font-headline-md text-base text-[#e7000b]">{results.strong_impersonations}</strong>
            </div>
            <div className="bg-surface-container-lowest p-4 rounded-xl border border-outline-variant">
              <span className="font-label-caps text-[10px] text-on-surface-variant block">CORPUS MATCHES</span>
              <strong className="font-headline-md text-base text-primary">{results.corpus_info?.matches_found ?? 0}</strong>
            </div>
          </div>

          {/* FILTER BAR */}
          <div className="flex items-center gap-2 overflow-x-auto pb-2 border-b border-outline-variant text-xs">
            <span className="font-label-caps text-on-surface-variant font-bold mr-2 shrink-0">Filter:</span>
            {[
              { id: 'all', label: `All Candidates (${resultsList.length})` },
              { id: 'strong', label: 'Strong Evidence' },
              { id: 'likely', label: 'Likely Impersonation' },
              { id: 'visual_verified', label: 'Live Verified Matches' },
              { id: 'corpus_only', label: 'Corpus Match Only' },
              { id: 'official_related', label: 'Official / Related' }
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setSelectedFilter(tab.id)}
                className={`px-3 py-1.5 rounded-lg font-bold shrink-0 transition-colors ${
                  selectedFilter === tab.id
                    ? 'bg-primary text-on-primary'
                    : 'bg-surface-container-lowest text-on-surface-variant border border-outline-variant hover:bg-surface-container-low'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* CANDIDATES LIST */}
          <div className="space-y-4">
            {filteredResults.length === 0 ? (
              <div className="bg-surface-container-lowest p-8 rounded-xl border border-outline-variant text-center space-y-2">
                <AlertCircle size={32} className="mx-auto text-on-surface-variant/50" />
                <h4 className="font-headline-md font-bold text-sm text-on-background">No candidates match selected filter</h4>
                <p className="font-body-md text-xs text-on-surface-variant">Try selecting 'All Candidates' to view complete results.</p>
              </div>
            ) : (
              filteredResults.map((item, idx) => {
                const isStrong = item.classification === 'STRONG_IMPERSONATION_EVIDENCE';
                const isLikely = item.classification === 'LIKELY_IMPERSONATION';
                const isOfficial = item.official_domain_match;
                const sc = item.screenshot || {};
                const logoMatch = item.logo_match;
                const logoLevel = logoMatch?.level || 'UNAVAILABLE';
                const twoStageStatus = item.two_stage_verification_status || 'VISUAL_MATCH_UNAVAILABLE';
                const discoverySources = item.discovery_sources || item.signals?.threat_intelligence?.sources || ['dnstwist'];

                return (
                  <div
                    key={idx}
                    className={`bg-surface-container-lowest p-5 rounded-xl border transition-all space-y-4 ${
                      isStrong
                        ? 'border-[#e7000b]/40 bg-[#fff1f2]/20'
                        : isLikely
                        ? 'border-[#f59e0b]/40 bg-[#fffbe6]/20'
                        : twoStageStatus === 'VISUAL_MATCH_VERIFIED'
                        ? 'border-primary/40 bg-primary/5'
                        : 'border-outline-variant hover:border-primary/40'
                    }`}
                  >
                    {/* CARD HEADER */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-outline-variant/60 pb-3">
                      <div className="flex items-center gap-2 flex-wrap">
                        <ShieldAlert
                          size={20}
                          className={isStrong ? 'text-[#e7000b]' : isLikely ? 'text-[#f59e0b]' : isOfficial ? 'text-primary' : 'text-on-surface-variant'}
                        />
                        <h3 className="font-headline-md font-bold text-sm text-on-background font-technical-data">
                          {item.candidate_domain}
                        </h3>
                        {isOfficial && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-primary/10 text-primary border border-primary/20">
                            OFFICIAL ASSET
                          </span>
                        )}
                        <TwoStageBadge status={twoStageStatus} />
                      </div>

                      <span
                        className={`px-3 py-1 rounded-full text-xs font-bold font-technical-data self-start sm:self-auto ${
                          isStrong
                            ? 'bg-[#fff1f2] text-[#e7000b] border border-[#ffe4e6]'
                            : isLikely
                            ? 'bg-[#fffbe6] text-[#b45309] border border-[#fef3c7]'
                            : 'bg-surface-container-low text-on-surface-variant border border-outline-variant'
                        }`}
                      >
                        {item.classification?.replace(/_/g, ' ')}
                      </span>
                    </div>

                    {/* DISCOVERY PROVENANCE BADGES */}
                    <div className="flex items-center gap-2 text-xs">
                      <span className="font-label-caps text-[9px] text-on-surface-variant font-bold">DISCOVERY PROVENANCE:</span>
                      <div className="flex items-center gap-1 flex-wrap">
                        {discoverySources.map((s, sIdx) => (
                          <span
                            key={sIdx}
                            className={`px-2 py-0.5 rounded text-[9px] font-bold border ${
                              s === 'LOGO_VISUAL_MATCH'
                                ? 'bg-primary/20 text-primary border-primary/30'
                                : 'bg-surface-container-low text-on-surface-variant border-outline-variant'
                            }`}
                          >
                            ✓ {s.replace(/_/g, ' ')}
                          </span>
                        ))}
                      </div>
                    </div>

                    {/* METRICS GRID */}
                    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 text-xs">
                      <div className="bg-surface-container-low p-2.5 rounded-lg border border-outline-variant">
                        <span className="font-label-caps text-[9px] text-on-surface-variant block">PHISHPEDIA LOGO</span>
                        <strong className="font-headline-md text-xs text-primary">
                          {item.brand_match
                            ? `${item.detected_brand} (${Math.round(item.logo_confidence * 100)}%)`
                            : sc.status !== 'success' ? 'NOT RUN' : 'None'}
                        </strong>
                      </div>

                      <div className="bg-surface-container-low p-2.5 rounded-lg border border-outline-variant">
                        <span className="font-label-caps text-[9px] text-on-surface-variant block">LOGO MATCH LEVEL</span>
                        <strong className={`font-headline-md text-xs ${logoMatch?.matched ? 'text-primary' : 'text-on-surface-variant'}`}>
                          {logoLevel.replace(/_/g, ' ')}
                        </strong>
                      </div>

                      <div className="bg-surface-container-low p-2.5 rounded-lg border border-outline-variant">
                        <span className="font-label-caps text-[9px] text-on-surface-variant block">LIVE VERIFICATION</span>
                        <strong className={`font-headline-md text-xs ${
                          twoStageStatus === 'VISUAL_MATCH_VERIFIED' ? 'text-primary' : 'text-on-surface-variant'
                        }`}>
                          {twoStageStatus.replace('VISUAL_MATCH_', '')}
                        </strong>
                      </div>

                      <div className="bg-surface-container-low p-2.5 rounded-lg border border-outline-variant">
                        <span className="font-label-caps text-[9px] text-on-surface-variant block">DOMAIN ALIGNMENT</span>
                        <strong className={`font-headline-md text-xs ${item.official_domain_match ? 'text-primary' : 'text-[#e7000b]'}`}>
                          {item.official_domain_match ? 'Official Match' : 'Mismatch'}
                        </strong>
                      </div>

                      <div className="bg-surface-container-low p-2.5 rounded-lg border border-outline-variant">
                        <span className="font-label-caps text-[9px] text-on-surface-variant block">pHASH DISTANCE</span>
                        <strong className="font-headline-md text-xs text-on-background font-technical-data">
                          {logoMatch?.phash_distance ?? '—'}
                        </strong>
                      </div>

                      <div className="bg-surface-container-low p-2.5 rounded-lg border border-outline-variant">
                        <span className="font-label-caps text-[9px] text-on-surface-variant block">CREDENTIALS</span>
                        <strong className="font-headline-md text-xs text-on-background font-technical-data">
                          {item.signals?.credential_indicators?.assessment || 'NOT RUN'}
                        </strong>
                      </div>
                    </div>

                    {/* REASONS */}
                    <div className="bg-surface-container-low p-3 rounded-lg border border-outline-variant text-xs space-y-1">
                      <span className="font-label-caps text-[10px] text-on-surface-variant font-bold block">EXPLAINABLE EVIDENCE STATEMENTS:</span>
                      <ul className="space-y-1 font-body-md text-on-background">
                        {(item.reasons || []).slice(0, 3).map((r, rIdx) => (
                          <li key={rIdx} className="flex items-center gap-1.5">
                            <CheckCircle2 size={13} className="text-primary shrink-0" />
                            <span>{r}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    {/* ACTION BUTTONS */}
                    <div className="flex items-center justify-between pt-2 border-t border-outline-variant/60">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => onInvestigateCandidate && onInvestigateCandidate(item)}
                          className="px-3 py-1.5 bg-primary text-on-primary font-headline-md font-bold text-xs rounded-lg hover:bg-primary-hover transition-colors flex items-center gap-1.5"
                        >
                          <Eye size={14} /> Investigate
                        </button>
                        <button
                          onClick={() => { setModalCandidate(item); setActiveModalTab('provenance'); }}
                          className="px-3 py-1.5 bg-surface-container-low text-on-background font-headline-md font-bold text-xs rounded-lg border border-outline-variant hover:bg-surface-container-high transition-colors flex items-center gap-1.5"
                        >
                          <FileText size={14} /> Technical Evidence
                        </button>
                      </div>

                      <button
                        onClick={() => toggleSelectLogo && toggleSelectLogo(item)}
                        className={`px-3 py-1.5 font-headline-md font-bold text-xs rounded-lg transition-colors flex items-center gap-1.5 ${
                          selectedLogos?.some((l) => l.candidate_domain === item.candidate_domain)
                            ? 'bg-primary/20 text-primary border border-primary/40'
                            : 'bg-surface-container-low text-on-background border border-outline-variant hover:bg-surface-container-high'
                        }`}
                      >
                        <Plus size={14} />
                        {selectedLogos?.some((l) => l.candidate_domain === item.candidate_domain) ? 'Added to Case' : 'Add to Case'}
                      </button>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* ENHANCED V4 EVIDENCE MODAL */}
      {modalCandidate && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
          <div className="bg-surface-container-lowest w-full max-w-3xl rounded-xl border border-outline-variant p-6 space-y-4 max-h-[90vh] overflow-y-auto shadow-xl">
            <div className="flex items-center justify-between border-b border-outline-variant pb-3">
              <h3 className="font-headline-md font-bold text-base text-on-background flex items-center gap-2">
                <ShieldAlert size={20} className="text-primary" />
                V4 Logo-First Technical Evidence — {modalCandidate.candidate_domain}
              </h3>
              <button onClick={() => setModalCandidate(null)} className="text-on-surface-variant hover:text-on-background">
                <X size={20} />
              </button>
            </div>

            {/* MODAL TABS */}
            <div className="flex items-center gap-2 border-b border-outline-variant pb-2 text-xs overflow-x-auto">
              {[
                { id: 'provenance', label: 'Discovery Provenance' },
                { id: 'retrieval', label: 'Visual Retrieval' },
                { id: 'live', label: 'Live Verification' },
                { id: 'correlation', label: 'Correlation Evidence' },
                ...(modalCandidate.viasocket_event ? [{ id: 'viasocket', label: 'viaSocket Event' }] : [])
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

            <div className="space-y-4 text-xs">
              {/* TAB 1: DISCOVERY PROVENANCE */}
              {activeModalTab === 'provenance' && (
                <div className="space-y-3">
                  <div className="bg-surface-container-low p-3 rounded-lg border border-outline-variant space-y-2">
                    <strong className="font-label-caps text-xs text-on-surface-variant block">DISCOVERY SOURCES:</strong>
                    <div className="flex items-center gap-2 flex-wrap">
                      {(modalCandidate.discovery_sources || ['dnstwist']).map((s, idx) => (
                        <span key={idx} className="px-2.5 py-1 bg-primary/10 text-primary border border-primary/20 rounded font-bold text-[10px]">
                          ✓ {s.replace(/_/g, ' ')}
                        </span>
                      ))}
                    </div>
                  </div>
                  {modalCandidate.corpus_match_info && (
                    <div className="bg-surface-container-low p-3 rounded-lg border border-outline-variant space-y-1">
                      <strong className="font-label-caps text-xs text-on-surface-variant block">VISUAL CORPUS RECOVERY METADATA:</strong>
                      <div><strong>Source Domain:</strong> {modalCandidate.corpus_match_info.corpus_item?.source_domain || 'Unavailable'}</div>
                      <div><strong>Match Level:</strong> {modalCandidate.corpus_match_info.match_level}</div>
                      <div><strong>pHash Distance:</strong> {modalCandidate.corpus_match_info.phash_distance}</div>
                    </div>
                  )}
                </div>
              )}

              {/* TAB 2: VISUAL RETRIEVAL */}
              {activeModalTab === 'retrieval' && (
                <div className="space-y-3">
                  {modalCandidate.logo_match && (
                    <div className="bg-surface-container-low p-3 rounded-lg border border-outline-variant space-y-2">
                      <div className="flex items-center justify-between">
                        <strong>Target ↔ Candidate Logo Comparison:</strong>
                        <span className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-primary/10 text-primary">
                          {modalCandidate.logo_match.level}
                        </span>
                      </div>
                      <div className="grid grid-cols-2 gap-2 font-technical-data">
                        <div>pHash Distance: {modalCandidate.logo_match.phash_distance ?? '—'}</div>
                        <div>dHash Distance: {modalCandidate.logo_match.dhash_distance ?? '—'}</div>
                        <div>OCR Match Status: {modalCandidate.logo_match.signals?.ocr?.status || '—'}</div>
                        <div>Phishpedia Brand: {modalCandidate.logo_match.signals?.phishpedia_brand?.brand || 'None'}</div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* TAB 3: LIVE VERIFICATION */}
              {activeModalTab === 'live' && (
                <div className="space-y-3">
                  <div className="bg-surface-container-low p-3 rounded-lg border border-outline-variant grid grid-cols-2 gap-2">
                    <div><strong>Two-Stage Status:</strong> <span className="font-technical-data font-bold text-primary">{modalCandidate.two_stage_verification_status}</span></div>
                    <div><strong>Live Verified:</strong> {modalCandidate.live_verified ? 'YES ✓' : 'NO'}</div>
                    <div><strong>Screenshot Status:</strong> {modalCandidate.screenshot?.status?.toUpperCase()}</div>
                    <div><strong>Requested URL:</strong> {modalCandidate.screenshot?.requested_url}</div>
                  </div>
                </div>
              )}

              {/* TAB 4: CORRELATION */}
              {activeModalTab === 'correlation' && (
                <div className="space-y-3">
                  <div className="bg-surface-container-low p-3 rounded-lg border border-outline-variant space-y-1 font-body-md">
                    <strong className="font-label-caps text-xs text-on-surface-variant block mb-1">Correlated Evidence Statements:</strong>
                    <ul className="space-y-1 text-on-background">
                      {modalCandidate.reasons?.map((r, idx) => (
                        <li key={idx} className="flex items-center gap-2">
                          <CheckCircle2 size={14} className="text-primary shrink-0" />
                          <span>{r}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}

              {/* TAB 5: VIASOCKET EVENT */}
              {activeModalTab === 'viasocket' && modalCandidate.viasocket_event && (
                <div className="space-y-2">
                  <div className="flex items-center gap-2 text-primary font-bold">
                    <Send size={14} />
                    <span>HIGH_CONFIDENCE_IMPERSONATION_DETECTED Payload</span>
                  </div>
                  <pre className="bg-black/90 text-green-400 p-3 rounded-lg font-technical-data text-[11px] overflow-x-auto">
                    {JSON.stringify(modalCandidate.viasocket_event, null, 2)}
                  </pre>
                </div>
              )}
            </div>

            <div className="flex justify-end pt-2 border-t border-outline-variant">
              <button
                onClick={() => setModalCandidate(null)}
                className="px-4 py-2 bg-primary text-on-primary font-bold text-xs rounded-lg hover:bg-primary-hover"
              >
                Close Technical Evidence
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const TwoStageBadge = ({ status }) => {
  const config = {
    VISUAL_MATCH_VERIFIED: { color: 'bg-primary/20 text-primary border-primary/30', label: 'VISUAL MATCH VERIFIED ✓' },
    VISUAL_MATCH_UNVERIFIED: { color: 'bg-[#fffbe6] text-[#b45309] border-[#fef3c7]', label: 'CORPUS MATCH ONLY' },
    VISUAL_MATCH_DISPROVED: { color: 'bg-surface-container-low text-on-surface-variant border-outline-variant', label: 'VISUAL DISPROVED' },
    VISUAL_MATCH_UNAVAILABLE: { color: 'bg-surface-container-low text-on-surface-variant border-outline-variant', label: 'UNAVAILABLE' }
  };
  const c = config[status] || config.VISUAL_MATCH_UNAVAILABLE;
  return (
    <span className={`px-2 py-0.5 rounded text-[9px] font-bold border ${c.color}`}>
      {c.label}
    </span>
  );
};

export default LogoMatchTab;
