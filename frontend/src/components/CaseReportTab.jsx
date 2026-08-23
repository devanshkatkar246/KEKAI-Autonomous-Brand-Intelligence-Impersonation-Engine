import React, { useState, useEffect } from 'react';
import {
  FileCheck,
  Download,
  Trash2,
  BarChart3,
  Edit3,
  Loader2,
  Eye,
  ChevronDown,
  ChevronRight,
  Clock,
  Search,
  PlusCircle,
  Network,
  HelpCircle,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Activity
} from 'lucide-react';
import AbuseControlSection from './AbuseControlSection';

const CaseReportTab = ({
  apiBaseUrl,
  addToast,
  selectedDomains = [],
  setSelectedDomains = () => {},
  selectedLogos = [],
  setSelectedLogos = () => {},
  selectedVisualPhishing = [],
  setSelectedVisualPhishing = () => {},
  selectedListings = [],
  setSelectedListings = () => {},
  selectedSocialProfiles = [],
  setSelectedSocialProfiles = () => {},
  brandName = 'Acme Corporate Brand',
  setBrandName = () => {},
  notes = '',
  setNotes = () => {},
  handleClearCase = () => {}
}) => {
  const [generating, setGenerating] = useState(false);
  const [timelineEvents, setTimelineEvents] = useState([]);
  const [loadingTimeline, setLoadingTimeline] = useState(false);
  const [expandedRationale, setExpandedRationale] = useState({});

  const fetchTimeline = async () => {
    setLoadingTimeline(true);
    try {
      const res = await fetch(`${apiBaseUrl}/api/case/default/timeline`);
      const data = await res.json();
      if (res.ok && data.status === 'success') {
        setTimelineEvents(data.data.timeline || []);
      }
    } catch (err) {
      console.warn('Failed to fetch case timeline:', err);
    } finally {
      setLoadingTimeline(false);
    }
  };

  useEffect(() => {
    fetchTimeline();
  }, [apiBaseUrl, selectedDomains.length, selectedLogos.length, selectedVisualPhishing.length]);

  const toggleRationale = (id) => {
    setExpandedRationale((prev) => ({
      ...prev,
      [id]: !prev[id]
    }));
  };

  const calculateFactors = () => {
    const hasDomain = selectedDomains.length > 0;
    const hasLogo = selectedLogos.length > 0;
    const hasPhish = selectedVisualPhishing.length > 0;
    const hasListing = selectedListings.length > 0;
    const hasSocial = selectedSocialProfiles.length > 0;
    const hasNotes = notes.trim().length > 0;

    // Base relative weight allocation (Active Scope: Domain 45%, Logo 45%, Notes 10%)
    const baseWeights = {
      domain: hasDomain ? (hasPhish || hasListing || hasSocial ? 25.0 : 45.0) : 0,
      logo: hasLogo ? (hasPhish || hasListing || hasSocial ? 25.0 : 45.0) : 0,
      phish: hasPhish ? 20.0 : 0,
      listing: hasListing ? 15.0 : 0,
      social: hasSocial ? 15.0 : 0,
      notes: hasNotes ? 10.0 : 0
    };

    const sumActiveBase = Object.values(baseWeights).reduce((a, b) => a + b, 0);
    const normFactor = sumActiveBase > 0 ? (100.0 / sumActiveBase) : 1.0;

    const normWeights = {
      domain: Math.round(baseWeights.domain * normFactor * 10) / 10,
      logo: Math.round(baseWeights.logo * normFactor * 10) / 10,
      phish: Math.round(baseWeights.phish * normFactor * 10) / 10,
      listing: Math.round(baseWeights.listing * normFactor * 10) / 10,
      social: Math.round(baseWeights.social * normFactor * 10) / 10,
      notes: Math.round(baseWeights.notes * normFactor * 10) / 10
    };

    let domainScore = 0;
    if (hasDomain) {
      const avgDomainRisk = selectedDomains.reduce((acc, d) => acc + (d.riskScore || d.risk_score || 50), 0) / selectedDomains.length;
      domainScore = (avgDomainRisk / 100.0) * normWeights.domain;
    }

    let logoScore = 0;
    if (hasLogo) {
      const avgLogoSim = selectedLogos.reduce((acc, l) => acc + (l.combined_similarity_percentage || 50), 0) / selectedLogos.length;
      logoScore = (avgLogoSim / 100.0) * normWeights.logo;
    }

    let phishScore = 0;
    if (hasPhish) {
      const phishCount = selectedVisualPhishing.filter((vp) => vp.verdict === 'Phishing' || vp.verdict === 'Likely Phishing').length;
      phishScore = (phishCount / selectedVisualPhishing.length) * normWeights.phish;
    }

    let listingScore = 0;
    if (hasListing) {
      const avgListingRisk = selectedListings.reduce((acc, l) => acc + (l.risk_rating || 70), 0) / selectedListings.length;
      listingScore = (avgListingRisk / 100.0) * normWeights.listing;
    }

    let socialScore = 0;
    if (hasSocial) {
      const avgSocialRisk = selectedSocialProfiles.reduce((acc, s) => acc + (s.risk_rating || 70), 0) / selectedSocialProfiles.length;
      socialScore = (avgSocialRisk / 100.0) * normWeights.social;
    }

    let notesScore = 0;
    if (hasNotes) {
      notesScore = notes.trim().length > 20 ? normWeights.notes : (normWeights.notes * 0.5);
    }

    // Intent Legitimate Discount: Reduces risk when items are verified reseller/news/fan/parody
    const legitDomains = selectedDomains.filter((d) => d.isLegitimate || ["Authorized reseller/partner", "News/media coverage", "Fan page/community content", "Parody/commentary"].includes(d.intentLabel || d.intent_label)).length;
    let intentDiscount = 0;
    if (selectedDomains.length > 0 && legitDomains > 0) {
      intentDiscount = Math.round((legitDomains / selectedDomains.length) * 30.0 * 10) / 10;
    }

    const rawTotal = domainScore + logoScore + phishScore + listingScore + socialScore + notesScore - intentDiscount;
    const totalComposite = Math.max(0, Math.min(100, Math.round(rawTotal)));

    return {
      domainFactor: Math.round(domainScore * 10) / 10,
      logoFactor: Math.round(logoScore * 10) / 10,
      phishFactor: Math.round(phishScore * 10) / 10,
      listingFactor: Math.round(listingScore * 10) / 10,
      socialFactor: Math.round(socialScore * 10) / 10,
      notesFactor: Math.round(notesScore * 10) / 10,
      intentDiscount,
      totalComposite,
      weights: normWeights
    };
  };

  const factors = calculateFactors();

  const handleExportPDF = async () => {
    if (selectedDomains.length === 0 && selectedLogos.length === 0 && selectedVisualPhishing.length === 0 && selectedListings.length === 0 && selectedSocialProfiles.length === 0) {
      addToast('Validation Error', 'Please select at least one evidence item to include in the case report.', 'error');
      return;
    }

    setGenerating(true);
    try {
      const caseId = `CASE-${Date.now().toString(36).toUpperCase()}`;
      const payload = {
        case_id: caseId,
        timestamp: new Date().toISOString(),
        brand_name: brandName,
        composite_risk_score: factors.totalComposite,
        manual_notes: notes,
        score_breakdown: {
          domain_factor: factors.domainFactor,
          logo_factor: factors.logoFactor,
          phish_factor: factors.phishFactor,
          listing_factor: factors.listingFactor,
          social_factor: factors.socialFactor,
          notes_factor: factors.notesFactor,
          intent_discount: factors.intentDiscount,
          weights: factors.weights
        },
        flagged_domains: selectedDomains,
        flagged_logos: selectedLogos,
        visual_phishing: selectedVisualPhishing,
        flagged_listings: selectedListings,
        flagged_social_profiles: selectedSocialProfiles
      };

      const response = await fetch(`${apiBaseUrl}/api/generate-report`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        throw new Error('Failed to generate PDF report from server.');
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${caseId.toLowerCase()}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);

      addToast('Report Exported', `Downloaded PDF report ${caseId}.pdf`, 'success');
      fetchTimeline();
    } catch (err) {
      console.error('PDF export error:', err);
      addToast('Export Failed', err.message || 'An error occurred while generating PDF report.', 'error');
    } finally {
      setGenerating(false);
    }
  };

  const removeDomain = (domainName) => {
    setSelectedDomains(selectedDomains.filter((d) => d.domain !== domainName));
  };

  const removeLogo = (filename) => {
    setSelectedLogos(selectedLogos.filter((l) => l.candidate_filename !== filename));
  };

  const removeVisualPhishing = (key) => {
    setSelectedVisualPhishing(selectedVisualPhishing.filter((vp) => vp.key !== key && vp.id !== key && vp.url !== key));
  };

  const removeListing = (listingId) => {
    setSelectedListings(selectedListings.filter((l) => l.listing_id !== listingId));
  };

  const removeSocialProfile = (profileId) => {
    setSelectedSocialProfiles(selectedSocialProfiles.filter((s) => s.profile_id !== profileId && s.handle !== profileId));
  };

  const [rescanning, setRescanning] = useState(false);
  const [rescanResult, setRescanResult] = useState(null);
  const [lastCheckedTimestamp, setLastCheckedTimestamp] = useState(null);

  const handleRescanCase = async () => {
    setRescanning(true);
    try {
      const payload = {
        evidence_domains: selectedDomains,
        evidence_logos: selectedLogos,
        evidence_visual_phishing: selectedVisualPhishing
      };

      const res = await fetch(`${apiBaseUrl}/api/case/default/rescan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (res.ok && data.status === 'success') {
        setRescanResult(data.data);
        setLastCheckedTimestamp(data.data.last_checked);
        if (data.data.new_activity_detected) {
          addToast('New Activity Detected', `Found ${data.data.total_changes} infrastructure state change(s).`, 'error');
          if (data.data.updated_domains && data.data.updated_domains.length > 0) {
            setSelectedDomains(data.data.updated_domains);
          }
        } else {
          addToast('Re-scan Complete', 'No infrastructure changes detected across case evidence.', 'info');
        }
        fetchTimeline();
      }
    } catch (err) {
      console.error('Case re-scan error:', err);
      addToast('Re-scan Failed', 'Failed to execute case re-scan.', 'error');
    } finally {
      setRescanning(false);
    }
  };

  const handleExportJSON = () => {
    if (selectedDomains.length === 0 && selectedLogos.length === 0 && selectedVisualPhishing.length === 0 && selectedListings.length === 0 && selectedSocialProfiles.length === 0) {
      addToast('Validation Error', 'Please select at least one evidence item to export JSON payload.', 'error');
      return;
    }

    const caseId = `CASE-${Date.now().toString(36).toUpperCase()}`;
    const payload = {
      case_id: caseId,
      timestamp: new Date().toISOString(),
      brand_name: brandName,
      composite_risk_score: factors.totalComposite,
      manual_notes: notes,
      score_breakdown: factors,
      flagged_domains: selectedDomains,
      flagged_logos: selectedLogos,
      visual_phishing: selectedVisualPhishing,
      flagged_listings: selectedListings,
      flagged_social_profiles: selectedSocialProfiles
    };
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(payload, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `${caseId.toLowerCase()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    addToast('Report Exported', `Exported investigation JSON payload ${caseId}.json`, 'success');
  };

  return (
    <div className="space-y-6 font-body-md antialiased text-on-background">
      {/* Header Section */}
      <header className="flex flex-col gap-1">
        <h1 className="font-display text-display text-on-background">Case Report</h1>
        <p className="font-body-lg text-body-lg text-on-surface-variant max-w-3xl">
          Compile multi-surface threat evidence, generate legal takedown packages, and export formal PDF investigation reports.
        </p>
      </header>

      {/* Action Toolbar Card */}
      <section className="bg-surface-container-lowest rounded-lg border border-outline-variant p-6 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h2 className="font-headline-md font-semibold text-on-background text-lg flex items-center gap-2">
            <span className="material-symbols-outlined text-primary">assignment</span> Investigation Case Package
            {rescanResult?.new_activity_detected && (
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-error-container text-on-error-container border border-error/20 font-label-caps animate-pulse">
                New Activity Detected
              </span>
            )}
          </h2>
          <p className="font-body-md text-xs text-on-surface-variant">
            Compile flagged domain lookalikes, logo matches, and visual phishing findings into an executive audit report.
          </p>
          {lastCheckedTimestamp && (
            <span className="font-technical-data text-xs text-on-surface-variant mt-1 block">
              Last Checked: <strong className="text-on-background">{lastCheckedTimestamp}</strong>
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={handleRescanCase}
            disabled={rescanning || (selectedDomains.length === 0 && selectedLogos.length === 0 && selectedVisualPhishing.length === 0)}
            className="btn-secondary py-2 px-4 rounded text-xs font-medium inline-flex items-center gap-2 disabled:opacity-40"
          >
            <RefreshCw size={14} className={rescanning ? 'animate-spin' : ''} />
            <span>{rescanning ? 'Re-scanning...' : 'Re-verify Evidence'}</span>
          </button>

          <button
            type="button"
            onClick={handleExportJSON}
            disabled={selectedDomains.length === 0 && selectedLogos.length === 0 && selectedVisualPhishing.length === 0}
            className="btn-secondary py-2 px-4 rounded text-xs font-medium inline-flex items-center gap-2 disabled:opacity-40"
          >
            <Download size={14} />
            <span>Export JSON</span>
          </button>

          <button
            type="button"
            onClick={handleClearCase}
            className="btn-secondary py-2 px-4 rounded text-xs font-medium inline-flex items-center gap-2"
          >
            <Trash2 size={14} className="text-error" />
            <span>Clear Case</span>
          </button>

          <button
            onClick={handleExportPDF}
            disabled={generating || (selectedDomains.length === 0 && selectedLogos.length === 0 && selectedVisualPhishing.length === 0)}
            className="btn-primary py-2 px-6 rounded inline-flex items-center gap-2 disabled:opacity-40 whitespace-nowrap shadow-xs"
          >
            {generating ? (
              <>
                <Loader2 size={16} className="animate-spin" />
                <span>Generating PDF...</span>
              </>
            ) : (
              <>
                <span className="material-symbols-outlined text-[18px]">picture_as_pdf</span>
                <span>Generate PDF Report</span>
              </>
            )}
          </button>
        </div>
      </section>

      {/* TASK 5 — TAKEDOWN SUBMISSION CONTROL PLANE CARD */}
      <AbuseControlSection
        apiBaseUrl={apiBaseUrl}
        caseId="default"
        candidateDomain={selectedDomains[0]?.domain}
        targetBrand={brandName}
        addToast={addToast}
      />

      {/* STEP 8 — Report Compilation Loading Animation Checklist */}
      {generating && (
        <div className="bg-surface-container-lowest rounded-xl border border-primary/40 p-6 shadow-sm space-y-4 animate-fade-in">
          <div className="flex items-center justify-between border-b border-outline-variant pb-3">
            <h3 className="font-headline-md font-bold text-sm text-on-background flex items-center gap-2">
              <Loader2 size={16} className="animate-spin text-primary" /> GENERATING AUTOMATED CASE REPORT
            </h3>
            <span className="font-technical-data text-xs text-primary font-semibold">KEIKAI Intelligence Engine</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 text-xs">
            <div className="flex items-center gap-2 text-on-background"><CheckCircle2 size={14} className="text-primary shrink-0" /><span>Collecting investigation data</span></div>
            <div className="flex items-center gap-2 text-on-background"><CheckCircle2 size={14} className="text-primary shrink-0" /><span>Compiling evidence &amp; screenshots</span></div>
            <div className="flex items-center gap-2 text-on-background"><CheckCircle2 size={14} className="text-primary shrink-0" /><span>Building explainable risk weights</span></div>
            <div className="flex items-center gap-2 text-primary font-semibold"><Loader2 size={14} className="animate-spin shrink-0" /><span>Generating executive summary</span></div>
            <div className="flex items-center gap-2 text-on-surface-variant/50"><span className="w-3.5 h-3.5 rounded-full border border-outline-variant inline-block shrink-0" /><span>Preparing threat cluster findings</span></div>
            <div className="flex items-center gap-2 text-on-surface-variant/50"><span className="w-3.5 h-3.5 rounded-full border border-outline-variant inline-block shrink-0" /><span>Finalizing case PDF &amp; JSON</span></div>
          </div>
        </div>
      )}

      {/* Re-Scan Diff Results */}
      {rescanResult && (
        <div className="bg-surface-container-low p-5 rounded-lg border border-outline-variant space-y-3">
          <div className="flex items-center justify-between border-b border-outline-variant pb-2">
            <h3 className="font-headline-md font-semibold text-on-background text-xs flex items-center gap-2">
              <Activity size={14} className="text-primary" /> Re-scan Diff Results
            </h3>
            <span className="font-technical-data text-xs text-on-surface-variant">
              {rescanResult.total_changes} change(s) detected
            </span>
          </div>

          {rescanResult.diffs.length === 0 ? (
            <div className="text-xs text-on-surface-variant flex items-center gap-2">
              <CheckCircle2 size={14} className="text-primary" /> All case evidence domains remain unchanged.
            </div>
          ) : (
            <div className="space-y-2">
              {rescanResult.diffs.map((diff, dIdx) => (
                <div key={dIdx} className="bg-surface-container-lowest p-3 rounded border border-outline-variant flex items-center justify-between font-technical-data text-xs">
                  <div>
                    <span className="font-bold text-on-background">{diff.domain}</span>
                    <p className="text-[11px] text-error font-semibold">{diff.details}</p>
                  </div>
                  <div className="text-right text-[11px]">
                    <span className="text-on-surface-variant">{diff.old}</span>
                    <span className="text-on-background font-bold mx-1">&rarr;</span>
                    <span className="text-on-background font-bold">{diff.new}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Risk Score & Timeline Activity Feed */}
        <div className="space-y-6 lg:col-span-1">
          {/* Risk Score Card */}
          <div className="bg-surface-container-lowest rounded-lg border border-outline-variant p-6 space-y-5">
            <div className="flex items-center justify-between">
              <h3 className="font-headline-md font-semibold text-on-background text-sm">
                Composite Risk Score
              </h3>
              <span className="font-technical-data text-2xl font-bold text-on-background">{factors.totalComposite}%</span>
            </div>

            <div className="w-full bg-surface-container rounded-full h-3 overflow-hidden p-0.5 border border-outline-variant">
              <div
                className={`h-full rounded-full transition-all duration-500 ${
                  factors.totalComposite >= 70 ? 'bg-error' : 'bg-primary'
                }`}
                style={{ width: `${factors.totalComposite}%` }}
              ></div>
            </div>

            {/* Factor Breakdown */}
            <div className="space-y-4 pt-3 border-t border-outline-variant">
              <span className="font-label-caps text-label-caps text-on-surface-variant block">
                Risk Factor Breakdown
              </span>

              {factors.weights.domain > 0 && (
                <div className="space-y-1.5 text-xs">
                  <div className="flex justify-between">
                    <span className="text-on-background font-medium">Domain Typosquatting ({factors.weights.domain}%)</span>
                    <span className="font-technical-data font-semibold text-on-background">{factors.domainFactor} pts</span>
                  </div>
                  <div className="w-full bg-surface-container rounded-full h-2 overflow-hidden border border-outline-variant">
                    <div
                      className="bg-primary h-full rounded-full transition-all"
                      style={{ width: `${(factors.domainFactor / (factors.weights.domain || 1)) * 100}%` }}
                    ></div>
                  </div>
                </div>
              )}

              {factors.weights.logo > 0 && (
                <div className="space-y-1.5 text-xs">
                  <div className="flex justify-between">
                    <span className="text-on-background font-medium">Logo Match Risk ({factors.weights.logo}%)</span>
                    <span className="font-technical-data font-semibold text-on-background">{factors.logoFactor} pts</span>
                  </div>
                  <div className="w-full bg-surface-container rounded-full h-2 overflow-hidden border border-outline-variant">
                    <div
                      className="bg-primary h-full rounded-full transition-all"
                      style={{ width: `${(factors.logoFactor / (factors.weights.logo || 1)) * 100}%` }}
                    ></div>
                  </div>
                </div>
              )}

              <div className="space-y-1.5 text-xs">
                <div className="flex justify-between">
                  <span className="text-on-background font-medium">Investigator Rationale ({factors.weights.notes || 10}%)</span>
                  <span className="font-technical-data font-semibold text-on-background">{factors.notesFactor} pts</span>
                </div>
                <div className="w-full bg-surface-container rounded-full h-2 overflow-hidden border border-outline-variant">
                  <div
                    className="bg-primary h-full rounded-full transition-all"
                    style={{ width: `${(factors.notesFactor / (factors.weights.notes || 10)) * 100}%` }}
                  ></div>
                </div>
              </div>
            </div>
          </div>

          {/* Investigation Timeline Activity Log */}
          <div className="bg-surface-container-lowest rounded-lg border border-outline-variant p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="font-headline-md font-semibold text-on-background text-sm flex items-center gap-2">
                <Clock size={16} className="text-primary" /> Investigation Activity Log
              </h3>
              <button
                onClick={fetchTimeline}
                className="p-1 hover:bg-surface-container rounded text-on-surface-variant"
                title="Refresh Timeline"
              >
                <RefreshCw size={13} className={loadingTimeline ? 'animate-spin' : ''} />
              </button>
            </div>

            {timelineEvents.length === 0 ? (
              <div className="p-4 text-center text-xs text-on-surface-variant bg-surface-container rounded border border-outline-variant">
                No investigation actions logged yet.
              </div>
            ) : (
              <div className="relative border-l border-outline-variant ml-2 space-y-4 pl-4 max-h-[340px] overflow-y-auto">
                {timelineEvents.map((ev) => (
                  <div key={ev.id} className="relative group">
                    <span className="absolute -left-[21px] top-1 w-2.5 h-2.5 rounded-full bg-primary ring-4 ring-surface-container-lowest"></span>
                    <div className="text-xs space-y-0.5">
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="font-technical-data text-on-background font-semibold">{ev.event_type}</span>
                        <span className="font-technical-data text-on-surface-variant text-[10px]">{ev.created_at?.substring(11, 19) || 'Just now'}</span>
                      </div>
                      <p className="font-body-md text-on-surface-variant text-[11px] leading-relaxed">{ev.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Case Metadata & Investigator Notes Section */}
          <div className="bg-surface-container-lowest rounded-lg border border-outline-variant p-6 space-y-4">
            <h3 className="font-headline-md font-semibold text-on-background text-sm flex items-center gap-2">
              <Edit3 size={16} className="text-primary" /> Case Details &amp; Observations
            </h3>

            <div className="space-y-4">
              <div className="space-y-1">
                <label className="block font-label-caps text-label-caps text-on-surface-variant" htmlFor="brand-input">
                  Target Brand Name
                </label>
                <input
                  id="brand-input"
                  type="text"
                  value={brandName}
                  onChange={(e) => setBrandName(e.target.value)}
                  className="w-full px-3 py-2 bg-surface rounded border border-outline-variant font-body-md text-body-md text-on-background focus:ring-1 focus:ring-primary focus:border-primary outline-none"
                />
              </div>

              <div className="space-y-1">
                <label className="block font-label-caps text-label-caps text-on-surface-variant" htmlFor="notes-textarea">
                  Executive Summary Notes
                </label>
                <textarea
                  id="notes-textarea"
                  rows={4}
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="Enter manual observations, threat actor details, or escalation rationale..."
                  className="w-full px-3 py-2 bg-surface rounded border border-outline-variant font-body-md text-body-md text-on-background focus:ring-1 focus:ring-primary focus:border-primary outline-none"
                ></textarea>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Compiled Evidence Tables */}
        <div className="space-y-6 lg:col-span-2">
          {/* Flagged Domains Table */}
          <div className="bg-surface-container-lowest rounded-lg border border-outline-variant overflow-hidden">
            <div className="p-4 bg-surface-container-low border-b border-outline-variant flex items-center justify-between">
              <h3 className="font-headline-md font-semibold text-on-background text-sm">
                Selected Domain Evidence ({selectedDomains.length})
              </h3>
              {selectedDomains.length > 0 && (
                <button
                  onClick={() => setSelectedDomains([])}
                  className="font-label-caps text-label-caps text-error hover:underline"
                >
                  Clear All Domains
                </button>
              )}
            </div>

            {selectedDomains.length === 0 ? (
              <div className="p-8 text-center text-xs text-on-surface-variant">
                No domains selected. Go to the <strong className="text-on-background">Domain Watch</strong> tab to add evidence.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-outline-variant bg-surface-container-low font-label-caps text-label-caps text-on-surface-variant">
                      <th className="py-2.5 px-4 w-8"></th>
                      <th className="py-2.5 px-4">Domain</th>
                      <th className="py-2.5 px-4">Fuzzer</th>
                      <th className="py-2.5 px-4">Registered</th>
                      <th className="py-2.5 px-4">IP Address</th>
                      <th className="py-2.5 px-4 text-right">Remove</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-outline-variant">
                    {selectedDomains.map((dom) => {
                      const isExpanded = expandedRationale[`dom-${dom.domain}`];
                      return (
                        <React.Fragment key={dom.domain}>
                          <tr className="hover:bg-surface-bright transition-colors cursor-pointer" onClick={() => toggleRationale(`dom-${dom.domain}`)}>
                            <td className="py-3 px-4 text-on-surface-variant">
                              {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                            </td>
                            <td className="py-3 px-4 font-technical-data text-technical-data text-on-background">{dom.domain}</td>
                            <td className="py-3 px-4">
                              <span className="inline-flex px-2 py-0.5 bg-surface-container-highest rounded text-on-surface-variant font-body-md text-[12px] border border-outline-variant">
                                {dom.fuzzer || 'homoglyph'}
                              </span>
                            </td>
                            <td className="py-3 px-4 font-body-md text-on-background">
                              {dom.isRegistered ? 'Yes' : 'No'}
                            </td>
                            <td className="py-3 px-4 font-technical-data text-technical-data text-on-surface-variant">
                              {Array.isArray(dom.dns_a) ? dom.dns_a[0] : dom.dns_a || '-'}
                            </td>
                            <td className="py-3 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                              <button
                                onClick={() => removeDomain(dom.domain)}
                                className="text-error font-label-caps text-label-caps hover:underline"
                              >
                                REMOVE
                              </button>
                            </td>
                          </tr>

                          {isExpanded && (
                            <tr className="bg-surface-container-low border-b border-outline-variant">
                              <td colSpan={6} className="p-4 font-technical-data text-technical-data text-on-background">
                                <div className="space-y-2">
                                  <div className="font-headline-md font-semibold text-on-background text-xs flex items-center gap-2">
                                    <HelpCircle size={14} className="text-primary" /> Technical Rationale &amp; Evidence for {dom.domain}
                                  </div>
                                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 bg-surface-container-lowest p-3 rounded border border-outline-variant text-[11px]">
                                    <div>
                                      <span className="text-on-surface-variant block">Fuzzer Type:</span>
                                      <span className="text-on-background font-semibold">{dom.fuzzer || 'homoglyph'}</span>
                                    </div>
                                    <div>
                                      <span className="text-on-surface-variant block">Hosting IP:</span>
                                      <span className="text-on-background font-semibold">{Array.isArray(dom.dns_a) ? dom.dns_a[0] : dom.dns_a || 'Active'}</span>
                                    </div>
                                    <div>
                                      <span className="text-on-surface-variant block">Risk Score:</span>
                                      <span className="text-on-background font-semibold">{dom.riskScore || dom.risk_score || 85}%</span>
                                    </div>
                                    <div>
                                      <span className="text-on-surface-variant block">Registration:</span>
                                      <span className="text-on-background font-semibold">{dom.isRegistered ? 'Registered' : 'Unregistered'}</span>
                                    </div>
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Flagged Logos Table */}
          <div className="bg-surface-container-lowest rounded-lg border border-outline-variant overflow-hidden">
            <div className="p-4 bg-surface-container-low border-b border-outline-variant flex items-center justify-between">
              <h3 className="font-headline-md font-semibold text-on-background text-sm">
                Selected Logo Matches ({selectedLogos.length})
              </h3>
              {selectedLogos.length > 0 && (
                <button
                  onClick={() => setSelectedLogos([])}
                  className="font-label-caps text-label-caps text-error hover:underline"
                >
                  Clear All Logos
                </button>
              )}
            </div>

            {selectedLogos.length === 0 ? (
              <div className="p-8 text-center text-xs text-on-surface-variant">
                No logo matches selected. Go to the <strong className="text-on-background">Logo Match</strong> tab to add candidates.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-outline-variant bg-surface-container-low font-label-caps text-label-caps text-on-surface-variant">
                      <th className="py-2.5 px-4 w-8"></th>
                      <th className="py-2.5 px-4">Candidate Filename</th>
                      <th className="py-2.5 px-4">Similarity</th>
                      <th className="py-2.5 px-4">pHash Dist</th>
                      <th className="py-2.5 px-4">Status</th>
                      <th className="py-2.5 px-4 text-right">Remove</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-outline-variant">
                    {selectedLogos.map((logo) => {
                      const isExpanded = expandedRationale[`logo-${logo.candidate_filename}`];
                      return (
                        <React.Fragment key={logo.candidate_filename}>
                          <tr className="hover:bg-surface-bright transition-colors cursor-pointer" onClick={() => toggleRationale(`logo-${logo.candidate_filename}`)}>
                            <td className="py-3 px-4 text-on-surface-variant">
                              {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                            </td>
                            <td className="py-3 px-4 font-technical-data text-technical-data text-on-background">{logo.candidate_filename}</td>
                            <td className="py-3 px-4 font-technical-data font-bold text-on-background">
                              {logo.combined_similarity_percentage?.toFixed(1)}%
                            </td>
                            <td className="py-3 px-4 font-technical-data text-technical-data text-on-surface-variant">{logo.phash_distance}</td>
                            <td className="py-3 px-4">
                              {logo.likely_match ? (
                                <span className="inline-flex px-2 py-0.5 rounded-full bg-error-container text-on-error-container font-label-caps text-[10px]">MATCH</span>
                              ) : (
                                <span className="inline-flex px-2 py-0.5 rounded-full bg-surface-container text-on-surface-variant font-label-caps text-[10px]">LOW MATCH</span>
                              )}
                            </td>
                            <td className="py-3 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                              <button
                                onClick={() => removeLogo(logo.candidate_filename)}
                                className="text-error font-label-caps text-label-caps hover:underline"
                              >
                                REMOVE
                              </button>
                            </td>
                          </tr>

                          {isExpanded && (
                            <tr className="bg-surface-container-low border-b border-outline-variant">
                              <td colSpan={6} className="p-4 font-technical-data text-technical-data text-on-background">
                                <div className="space-y-2">
                                  <div className="font-headline-md font-semibold text-on-background text-xs flex items-center gap-2">
                                    <HelpCircle size={14} className="text-primary" /> Perceptual Hash Metrics for {logo.candidate_filename}
                                  </div>
                                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 bg-surface-container-lowest p-3 rounded border border-outline-variant text-[11px]">
                                    <div>
                                      <span className="text-on-surface-variant block">pHash Distance:</span>
                                      <span className="text-on-background font-semibold">{logo.phash_distance}</span>
                                    </div>
                                    <div>
                                      <span className="text-on-surface-variant block">dHash Distance:</span>
                                      <span className="text-on-background font-semibold">{logo.dhash_distance ?? 3}</span>
                                    </div>
                                    <div>
                                      <span className="text-on-surface-variant block">Combined Similarity:</span>
                                      <span className="text-on-background font-semibold">{logo.combined_similarity_percentage?.toFixed(1)}%</span>
                                    </div>
                                    <div>
                                      <span className="text-on-surface-variant block">Match Status:</span>
                                      <span className="text-on-background font-semibold">{logo.likely_match ? 'Match' : 'Low Match'}</span>
                                    </div>
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default CaseReportTab;

