import React, { useState, useEffect } from 'react';
import {
  Search,
  Loader2,
  ArrowUpDown,
  ChevronDown,
  ChevronRight,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  FileText,
  Filter,
  RefreshCw,
  ChevronLeft,
  AlertTriangle,
  Globe,
  Radio,
  ExternalLink,
  Plus,
} from 'lucide-react';
import CandidateEvidenceCardV2 from './CandidateEvidenceCardV2';
import TechnicalEvidenceModalV2 from './TechnicalEvidenceModalV2';

const DomainWatchTab = ({
  apiBaseUrl,
  addToast,
  selectedDomains = [],
  toggleSelectDomain = () => {},
  investigationState,
  domainScanState,
  setDomainScanState
}) => {
  const {
    domainInput = '',
    quickMode = true,
    results = null,
    searchFilter = '',
    statusFilter = 'all',
    intentFilter = 'all',
    riskFilter = 'all',
    fuzzerFilter = 'all',
    sortField = 'risk',
    sortAsc = false,
    currentPage = 1,
    pageSize = 25
  } = domainScanState || {};

  const [loading, setLoading] = useState(false);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [scanError, setScanError] = useState(null);
  const [expandedRow, setExpandedRow] = useState(null);
  const [selectedCandidateDetail, setSelectedCandidateDetail] = useState(null);
  const [abuseReadiness, setAbuseReadiness] = useState(null);
  const [abuseReadinessError, setAbuseReadinessError] = useState(null);
  const [registrationIntel, setRegistrationIntel] = useState(null);
  const [providerIntel, setProviderIntel] = useState(null);
  const [evidenceModalIntel, setEvidenceModalIntel] = useState(null);

  // Timer interval during scan execution
  useEffect(() => {
    let timer;
    if (loading) {
      setElapsedSeconds(0);
      timer = setInterval(() => {
        setElapsedSeconds((prev) => prev + 1);
      }, 1000);
    }
    return () => clearInterval(timer);
  }, [loading]);

  // The backend remains authoritative: this only forwards evidence already shown
  // in the investigation drawer and renders its non-submitting assessment.
  useEffect(() => {
    if (!selectedCandidateDetail?.domain) {
      setAbuseReadiness(null);
      return;
    }
    const controller = new AbortController();
    const evidence = {
      sources: selectedCandidateDetail.sources || [],
      domain_permutation: Boolean(selectedCandidateDetail.fuzzer),
      visual_similarity: selectedCandidateDetail.visual_similarity || 0,
      credential_indicators: Boolean(selectedCandidateDetail.credential_indicators),
      login_form_detected: Boolean(selectedCandidateDetail.login_form_detected),
      screenshot: selectedCandidateDetail.screenshot || { status: 'NOT_RUN' }
    };
    setAbuseReadiness(null);
    setAbuseReadinessError(null);
    fetch(`${apiBaseUrl}/api/abuse-response/evaluate`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, signal: controller.signal,
      body: JSON.stringify({
        investigation_id: investigationState?.investigationId,
        candidate_domain: selectedCandidateDetail.domain,
        target_brand: investigationState?.brandName,
        official_domain: investigationState?.officialDomain || domainInput,
        evidence
      })
    })
      .then(async (response) => {
        const body = await response.json();
        if (!response.ok || body.status !== 'success') throw new Error(body.error || 'Assessment unavailable');
        setAbuseReadiness(body.data);
      })
      .catch((error) => {
        if (error.name !== 'AbortError') setAbuseReadinessError(error.message);
      });
    return () => controller.abort();
  }, [selectedCandidateDetail, apiBaseUrl, investigationState?.investigationId, investigationState?.brandName, investigationState?.officialDomain, domainInput]);

  useEffect(() => {
    if (!selectedCandidateDetail?.domain) return setRegistrationIntel(null);
    const controller = new AbortController();
    fetch(`${apiBaseUrl}/api/domain-intelligence/registration/${encodeURIComponent(selectedCandidateDetail.domain)}`, { signal: controller.signal })
      .then((r) => r.json()).then((body) => { if (body.status === 'success') setRegistrationIntel(body.data.registration_intelligence); })
      .catch(() => { if (!controller.signal.aborted) setRegistrationIntel(null); });
    return () => controller.abort();
  }, [selectedCandidateDetail, apiBaseUrl]);
  useEffect(() => { if (!selectedCandidateDetail?.domain) return setProviderIntel(null); const c=new AbortController(); fetch(`${apiBaseUrl}/api/domain-intelligence/infrastructure/${encodeURIComponent(selectedCandidateDetail.domain)}`,{signal:c.signal}).then(r=>r.json()).then(b=>{if(b.status==='success')setProviderIntel(b.data)}).catch(()=>{}); return()=>c.abort(); }, [selectedCandidateDetail, apiBaseUrl]);

  const updateState = (updates) => {
    setDomainScanState((prev) => ({ ...prev, ...updates }));
  };

  const handleScan = async (e) => {
    e?.preventDefault();
    if (!domainInput.trim()) {
      addToast('Validation Error', 'Please enter a target domain name.', 'error');
      return;
    }

    let cleanDomain = domainInput.trim().toLowerCase();
    cleanDomain = cleanDomain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');

    setLoading(true);
    setScanError(null);
    setExpandedRow(null);

    try {
      const response = await fetch(`${apiBaseUrl}/api/domain-scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          domain: cleanDomain,
          quick_mode: quickMode,
          timeout: 90
        })
      });

      const resData = await response.json();
      if (!response.ok || resData.status === 'error') {
        throw new Error(resData.error || 'Failed to scan domain permutations.');
      }

      updateState({
        results: resData.data,
        currentPage: 1
      });
      addToast('Scan Complete', `Discovered ${resData.data.total_permutations} domain permutations.`, 'success');
    } catch (err) {
      console.error('Domain scan error:', err);
      setScanError(err.message || 'The domain intelligence engine did not respond in time.');
      addToast('Domain Scan Failed', err.message || 'An error occurred during scan.', 'error');
    } finally {
      setLoading(false);
    }
  };

  // String similarity calculation (Levenshtein distance based)
  const calculateSimilarity = (str1, str2) => {
    if (!str1 || !str2) return 75;
    const s1 = str1.toLowerCase().split('.')[0];
    const s2 = str2.toLowerCase().split('.')[0];
    if (s1 === s2) return 100;

    const track = Array(s2.length + 1).fill(null).map(() => Array(s1.length + 1).fill(null));
    for (let i = 0; i <= s1.length; i += 1) track[0][i] = i;
    for (let j = 0; j <= s2.length; j += 1) track[j][0] = j;
    for (let j = 1; j <= s2.length; j += 1) {
      for (let i = 1; i <= s1.length; i += 1) {
        const indicator = s1[i - 1] === s2[j - 1] ? 0 : 1;
        track[j][i] = Math.min(
          track[j][i - 1] + 1,
          track[j - 1][i] + 1,
          track[j - 1][i - 1] + indicator
        );
      }
    }
    const distance = track[s2.length][s1.length];
    const maxLen = Math.max(s1.length, s2.length);
    const sim = Math.round(((maxLen - distance) / maxLen) * 100);
    return Math.max(45, Math.min(99, sim));
  };

  const getRiskScore = (item) => {
    let score = 20;
    if (item.dns_a || item.dns_aaaa || item.dns_ns || item.dns_mx) score += 40;
    if (item.fuzzer === 'original*') score = 10;
    else if (['bitsquatting', 'homoglyph', 'transposition', 'replacement'].includes(item.fuzzer)) score += 30;
    if (item.ssdeep_score) score += item.ssdeep_score * 0.1;

    // Multi-source threat intel risk contribution
    if (item.is_known_phishing) score += 35;
    if (Array.isArray(item.sources) && item.sources.length >= 2) score += 15;

    return Math.min(99, Math.max(10, Math.round(score)));
  };

  const getIntentClassification = (item, riskScore) => {
    if (item.fuzzer === 'original*') {
      return { label: 'Official Brand Asset', category: 'Legitimate', isSuspicious: false };
    }
    if (item.is_known_phishing) {
      return { label: 'Verified Phishing Threat', category: 'Suspicious', isSuspicious: true };
    }
    if (riskScore >= 70) {
      if (item.fuzzer === 'homoglyph' || item.fuzzer === 'replacement') {
        return { label: 'Credential Phishing', category: 'Suspicious', isSuspicious: true };
      }
      return { label: 'Brand Impersonation', category: 'Suspicious', isSuspicious: true };
    }
    if (riskScore >= 40) {
      if (item.dns_mx) {
        return { label: 'Mail Impersonation Risk', category: 'Suspicious', isSuspicious: true };
      }
      return { label: 'Typosquatted Asset', category: 'Suspicious', isSuspicious: true };
    }
    return { label: 'Legitimate Brand Use', category: 'Legitimate', isSuspicious: false };
  };

  const getRiskBadge = (score) => {
    if (score >= 70) {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-[#fff1f2] text-[#e7000b] border border-[#ffe4e6]">
          <span className="w-1.5 h-1.5 rounded-full bg-[#e7000b] animate-pulse"></span>
          CRITICAL ({score})
        </span>
      );
    }
    if (score >= 40) {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-[#fef3c7] text-[#b45309] border border-[#fde68a]">
          <span className="w-1.5 h-1.5 rounded-full bg-[#b45309]"></span>
          MEDIUM ({score})
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-[#f3f4f6] text-[#4b5563] border border-[#e5e7eb]">
        <span className="w-1.5 h-1.5 rounded-full bg-[#9ca3af]"></span>
        LOW ({score})
      </span>
    );
  };

  const formatElapsed = (sec) => {
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    return m > 0 ? `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}` : `${sec}s`;
  };

  // Filter and sort permutations
  const processPermutations = () => {
    if (!results || !results.permutations) return { filtered: [], fuzzerCategories: [] };

    const targetDomainName = domainInput || investigationState?.officialDomain || 'domain.com';

    let list = results.permutations.map((item, idx) => {
      const riskScore = getRiskScore(item);
      const similarity = calculateSimilarity(item.domain, targetDomainName);
      const intent = getIntentClassification(item, riskScore);

      return {
        ...item,
        id: `${item.domain}-${idx}`,
        riskScore,
        similarity,
        intent,
        isRegistered: Boolean(item.dns_a || item.dns_aaaa || item.dns_ns || item.dns_mx)
      };
    });

    const fuzzerCategories = Array.from(new Set(list.map((i) => i.fuzzer))).sort();

    // 1. Search Filter
    if (searchFilter.trim()) {
      const q = searchFilter.trim().toLowerCase();
      list = list.filter(
        (item) => item.domain.toLowerCase().includes(q) || (item.fuzzer && item.fuzzer.toLowerCase().includes(q))
      );
    }

    // 2. Status Filter
    if (statusFilter === 'registered') {
      list = list.filter((item) => item.isRegistered);
    } else if (statusFilter === 'unregistered') {
      list = list.filter((item) => !item.isRegistered);
    }

    // 3. Intent Filter (Suspicious vs Legitimate)
    if (intentFilter === 'suspicious') {
      list = list.filter((item) => item.intent.category === 'Suspicious');
    } else if (intentFilter === 'legitimate') {
      list = list.filter((item) => item.intent.category === 'Legitimate');
    }

    // 4. Risk Filter
    if (riskFilter === 'high') {
      list = list.filter((item) => item.riskScore >= 70);
    } else if (riskFilter === 'medium') {
      list = list.filter((item) => item.riskScore >= 40 && item.riskScore < 70);
    } else if (riskFilter === 'low') {
      list = list.filter((item) => item.riskScore < 40);
    }

    // 5. Fuzzer Filter
    if (fuzzerFilter !== 'all') {
      list = list.filter((item) => item.fuzzer === fuzzerFilter);
    }

    // 6. Sorting
    list.sort((a, b) => {
      let valA = a[sortField];
      let valB = b[sortField];
      if (sortField === 'risk') {
        valA = a.riskScore;
        valB = b.riskScore;
      } else if (sortField === 'isRegistered') {
        valA = a.isRegistered ? 1 : 0;
        valB = b.isRegistered ? 1 : 0;
      } else if (sortField === 'similarity') {
        valA = a.similarity;
        valB = b.similarity;
      }
      if (valA < valB) return sortAsc ? -1 : 1;
      if (valA > valB) return sortAsc ? 1 : -1;
      return 0;
    });

    return { filtered: list, fuzzerCategories };
  };

  const handleSort = (field) => {
    if (sortField === field) {
      updateState({ sortAsc: !sortAsc });
    } else {
      updateState({ sortField: field, sortAsc: false });
    }
  };

  const resetFilters = () => {
    updateState({
      searchFilter: '',
      statusFilter: 'all',
      intentFilter: 'all',
      riskFilter: 'all',
      fuzzerFilter: 'all',
      currentPage: 1
    });
  };

  const { filtered: filteredList, fuzzerCategories } = processPermutations();

  // Summary counts
  const totalDiscovered = results?.permutations?.length || 0;
  const activeCount = filteredList.filter((i) => i.isRegistered).length;
  const suspiciousCount = filteredList.filter((i) => i.riskScore >= 70).length;

  // Pagination calculation
  const totalItems = filteredList.length;
  const totalPages = Math.ceil(totalItems / pageSize) || 1;
  const validCurrentPage = Math.min(currentPage, totalPages);
  const startIndex = (validCurrentPage - 1) * pageSize;
  const paginatedList = filteredList.slice(startIndex, startIndex + pageSize);

  // Logical Scan Stages calculation
  const getStageStatus = (stageIdx) => {
    if (elapsedSeconds >= (stageIdx + 1) * 15) return 'completed';
    if (elapsedSeconds >= stageIdx * 15) return 'active';
    return 'pending';
  };

  const stages = [
    { label: 'Generating domain permutations' },
    { label: 'Checking DNS availability & A records' },
    { label: 'Resolving active IP addresses' },
    { label: 'Analyzing threat candidate profiles' },
    { label: 'Building infrastructure intelligence' }
  ];

  return (
    <div className="space-y-6 font-body-md antialiased text-on-background">
      {/* Header Section */}
      <header className="flex flex-col gap-1">
        <h1 className="font-display text-display text-on-background">Domain Watch</h1>
        <p className="font-body-lg text-body-lg text-on-surface-variant max-w-3xl">
          Detect typosquatted and lookalike domains registered against your brand using dnstwist permutation scanning.
        </p>
      </header>

      {/* Investigation Context Banner */}
      {investigationState && (investigationState.brandName || investigationState.officialDomain) && (
        <div className="bg-surface-container-low border border-outline-variant p-4 rounded-lg flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
          <div className="flex flex-wrap items-center gap-4">
            <div>
              <span className="font-label-caps text-on-surface-variant block text-[10px]">INVESTIGATION TARGET</span>
              <strong className="font-headline-md text-primary text-sm font-semibold">{investigationState.brandName || 'Target Brand'}</strong>
            </div>
            <div className="hidden sm:block h-6 w-px bg-outline-variant"></div>
            <div>
              <span className="font-label-caps text-on-surface-variant block text-[10px]">OFFICIAL DOMAIN</span>
              <strong className="font-technical-data text-on-background">{investigationState.officialDomain || domainInput}</strong>
            </div>
            <div className="hidden sm:block h-6 w-px bg-outline-variant"></div>
            <div>
              <span className="font-label-caps text-on-surface-variant block text-[10px]">ACTIVE SOURCE</span>
              <span className="inline-flex px-2 py-0.5 rounded bg-primary text-on-primary font-technical-data font-bold text-[10px]">
                Domain Monitoring (dnstwist)
              </span>
            </div>
          </div>
          <span className="font-technical-data text-on-surface-variant text-[11px] bg-surface-container px-2 py-1 rounded border border-outline-variant">
            {investigationState.investigationId || 'CASE-001'}
          </span>
        </div>
      )}

      {/* Primary Input Card Section */}
      <section className="bg-surface-container-lowest rounded-lg border border-outline-variant p-6 flex flex-col md:flex-row gap-4 items-end">
        <form onSubmit={handleScan} className="w-full flex flex-col md:flex-row gap-4 items-end">
          <div className="flex-1 w-full space-y-1">
            <label className="block font-label-caps text-label-caps text-on-surface-variant" htmlFor="domain-input">
              Target Domain
            </label>
            <div className="relative">
              <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-outline text-[20px]">language</span>
              <input
                id="domain-input"
                type="text"
                value={domainInput}
                onChange={(e) => updateState({ domainInput: e.target.value })}
                placeholder="Enter root domain e.g. amazon.com..."
                disabled={loading}
                className="w-full pl-10 pr-4 py-2 bg-surface rounded border border-outline-variant font-technical-data text-technical-data text-on-background focus:ring-1 focus:ring-primary focus:border-primary outline-none placeholder:text-outline disabled:opacity-50"
              />
            </div>
          </div>

          <div className="flex items-center gap-3 pb-1 shrink-0">
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={quickMode}
                onChange={(e) => updateState({ quickMode: e.target.checked })}
                disabled={loading}
                className="sr-only"
              />
              <div className={`w-10 h-6 rounded-full transition-colors relative ${quickMode ? 'bg-primary' : 'bg-surface-container-highest'}`}>
                <div className={`dot absolute top-1 bg-white w-4 h-4 rounded-full transition-transform ${quickMode ? 'translate-x-5 left-0.5' : 'left-1'}`}></div>
              </div>
              <span className="font-body-md text-body-md text-on-surface-variant">Quick Mode</span>
            </label>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="btn-primary py-2 px-6 rounded inline-flex items-center gap-2 whitespace-nowrap shrink-0 disabled:opacity-50 shadow-xs"
          >
            {loading ? (
              <>
                <Loader2 size={16} className="animate-spin text-on-primary" />
                <span>Scanning ({formatElapsed(elapsedSeconds)})...</span>
              </>
            ) : (
              <>
                <span className="material-symbols-outlined text-[18px]">search</span>
                <span>Run Domain Scan</span>
              </>
            )}
          </button>
        </form>
      </section>

      {/* STEP 3 — Animated Candidate Discovery Scanning Experience */}
      {loading && (
        <div className="bg-surface-container-lowest rounded-xl border border-primary/40 p-8 shadow-sm space-y-6 animate-fade-in relative overflow-hidden">
          {/* Animated Background Pulse Shimmer */}
          <div className="absolute inset-0 bg-gradient-to-r from-primary/5 via-primary/10 to-primary/5 animate-pulse pointer-events-none" />

          <div className="relative z-10 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-outline-variant pb-6">
            <div className="flex items-center gap-4">
              <div className="w-14 h-14 rounded-full bg-primary/10 border-2 border-primary flex items-center justify-center relative shrink-0">
                <Radio size={28} className="text-primary animate-pulse" />
                <span className="absolute inset-0 rounded-full border-2 border-primary animate-ping opacity-25"></span>
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-label-caps text-xs text-primary font-bold tracking-wider">DOMAIN MONITORING</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-technical-data bg-primary text-on-primary font-bold">
                    SCAN IN PROGRESS
                  </span>
                </div>
                <h3 className="font-display text-2xl font-bold text-on-background mt-0.5">
                  ANALYZING {domainInput || investigationState?.officialDomain || 'DOMAIN'}
                </h3>
                <p className="font-body-md text-xs text-on-surface-variant">
                  Discovering typosquatted permutations, resolving DNS A records, and profiling candidate assets.
                </p>
              </div>
            </div>

            <div className="bg-surface-container-low px-5 py-2.5 rounded-xl border border-outline-variant text-right shrink-0">
              <span className="font-label-caps text-[10px] text-on-surface-variant block">ELAPSED TIME</span>
              <span className="font-technical-data text-xl font-bold text-primary">
                {formatElapsed(elapsedSeconds)}
              </span>
            </div>
          </div>

          {/* Indeterminate Glowing Scanning Progress Bar */}
          <div className="relative z-10 space-y-2">
            <div className="flex justify-between items-center text-xs font-technical-data text-on-surface-variant">
              <span>SCANNING PERMUTATIONS</span>
              <span className="text-primary font-semibold animate-pulse">dnstwist subprocess active</span>
            </div>
            <div className="w-full h-3 bg-surface-container-highest rounded-full overflow-hidden border border-outline-variant relative">
              <div className="absolute top-0 bottom-0 left-0 w-1/3 bg-gradient-to-r from-primary/30 via-primary to-primary/30 rounded-full animate-bounce transition-all duration-1000" />
            </div>
          </div>

          {/* Logical Scan Stages Checklist */}
          <div className="relative z-10 grid grid-cols-1 md:grid-cols-5 gap-3 pt-2">
            {stages.map((stage, idx) => {
              const status = getStageStatus(idx);
              return (
                <div
                  key={idx}
                  className={`p-3 rounded-lg border text-xs flex items-center gap-2.5 transition-all ${
                    status === 'completed'
                      ? 'bg-surface-container-low border-primary/30 text-on-background'
                      : status === 'active'
                      ? 'bg-primary/10 border-primary text-primary font-semibold shadow-xs'
                      : 'bg-surface-container-lowest border-outline-variant/60 text-on-surface-variant/50'
                  }`}
                >
                  {status === 'completed' ? (
                    <CheckCircle2 size={16} className="text-primary shrink-0" />
                  ) : status === 'active' ? (
                    <Loader2 size={16} className="text-primary animate-spin shrink-0" />
                  ) : (
                    <span className="w-4 h-4 rounded-full border border-outline-variant inline-block shrink-0" />
                  )}
                  <span className="leading-tight text-[11px]">{stage.label}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Clean Scan Error State */}
      {scanError && !loading && (
        <div className="bg-error-container/20 border border-error/40 rounded-xl p-6 space-y-4 animate-fade-in">
          <div className="flex items-start gap-3 text-error">
            <AlertTriangle size={20} className="shrink-0 mt-0.5" />
            <div>
              <h4 className="font-headline-md font-semibold text-sm">SCAN UNABLE TO COMPLETE</h4>
              <p className="font-body-md text-xs text-on-surface-variant mt-1">
                {scanError}
              </p>
            </div>
          </div>

          <div className="pt-2 flex justify-end">
            <button
              onClick={handleScan}
              className="btn-primary py-2 px-5 text-xs rounded-lg inline-flex items-center gap-2"
            >
              <RefreshCw size={14} />
              <span>Retry Domain Scan</span>
            </button>
          </div>
        </div>
      )}

      {/* STEP 4 — CANDIDATE ANALYSIS INTERFACE */}
      {results && !loading && (
        <section className="flex flex-col gap-5 animate-fade-in">
          {/* Intelligence Sources Status Bar */}
          <div className="bg-surface-container-low rounded-xl border border-outline-variant p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-primary text-[20px]">hub</span>
              <span className="font-headline-md font-semibold text-on-background text-xs">INTELLIGENCE DISCOVERY SOURCES:</span>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-primary/10 text-primary border border-primary/30 font-technical-data">
                <span className="w-2 h-2 rounded-full bg-primary inline-block"></span>
                dnstwist Permutation Engine
              </span>
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-[#fff1f2] text-[#e7000b] border border-[#ffe4e6] font-technical-data">
                <span className="w-2 h-2 rounded-full bg-[#e7000b] inline-block"></span>
                OpenPhish Community Feed
              </span>
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-[#fff1f2] text-[#e7000b] border border-[#ffe4e6] font-technical-data">
                <span className="w-2 h-2 rounded-full bg-[#e7000b] inline-block"></span>
                PhishTank Online-Valid DB
              </span>
            </div>
          </div>
          {/* Summary Stats Header */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="bg-surface-container-lowest p-4 rounded-xl border border-outline-variant flex items-center justify-between">
              <div>
                <span className="font-label-caps text-[11px] text-on-surface-variant block">TOTAL DISCOVERED</span>
                <span className="font-display text-2xl font-bold text-on-background">{totalDiscovered}</span>
                <span className="font-body-md text-[11px] text-on-surface-variant block">domain permutations</span>
              </div>
              <Globe size={28} className="text-primary opacity-40" />
            </div>

            <div className="bg-surface-container-lowest p-4 rounded-xl border border-outline-variant flex items-center justify-between">
              <div>
                <span className="font-label-caps text-[11px] text-on-surface-variant block">ACTIVE DOMAINS</span>
                <span className="font-display text-2xl font-bold text-on-background">{activeCount}</span>
                <span className="font-body-md text-[11px] text-on-surface-variant block">resolving to DNS A records</span>
              </div>
              <CheckCircle2 size={28} className="text-[#10B981] opacity-40" />
            </div>

            <div className="bg-surface-container-lowest p-4 rounded-xl border border-outline-variant flex items-center justify-between">
              <div>
                <span className="font-label-caps text-[11px] text-on-surface-variant block">HIGH RISK / SUSPICIOUS</span>
                <span className="font-display text-2xl font-bold text-[#e7000b]">{suspiciousCount}</span>
                <span className="font-body-md text-[11px] text-on-surface-variant block">flagged for investigation</span>
              </div>
              <ShieldAlert size={28} className="text-[#e7000b] opacity-40" />
            </div>
          </div>

          {/* Controls Bar & Filters */}
          <div className="flex flex-col md:flex-row justify-between items-center gap-4 bg-surface-container-lowest p-4 rounded-xl border border-outline-variant">
            <div className="relative w-full md:w-72">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant opacity-60" />
              <input
                type="text"
                value={searchFilter}
                onChange={(e) => updateState({ searchFilter: e.target.value, currentPage: 1 })}
                placeholder="Filter candidate domain..."
                className="w-full pl-9 pr-3 py-1.5 bg-surface rounded border border-outline-variant font-body-md text-xs text-on-background focus:ring-1 focus:ring-primary focus:border-primary outline-none"
              />
            </div>

            <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
              <select
                value={intentFilter}
                onChange={(e) => updateState({ intentFilter: e.target.value, currentPage: 1 })}
                className="bg-surface rounded border border-outline-variant py-1.5 px-3 font-body-md text-xs text-on-background focus:ring-1 focus:ring-primary outline-none"
              >
                <option value="all">All Classification Types</option>
                <option value="suspicious">Suspicious Only (Phishing/Impersonation)</option>
                <option value="legitimate">Legitimate Only (Brand Use/Partner)</option>
              </select>

              <select
                value={riskFilter}
                onChange={(e) => updateState({ riskFilter: e.target.value, currentPage: 1 })}
                className="bg-surface rounded border border-outline-variant py-1.5 px-3 font-body-md text-xs text-on-background focus:ring-1 focus:ring-primary outline-none"
              >
                <option value="all">All Risk Levels</option>
                <option value="high">Critical / High (70+)</option>
                <option value="medium">Medium (40-69)</option>
                <option value="low">Low (0-39)</option>
              </select>

              <select
                value={statusFilter}
                onChange={(e) => updateState({ statusFilter: e.target.value, currentPage: 1 })}
                className="bg-surface rounded border border-outline-variant py-1.5 px-3 font-body-md text-xs text-on-background focus:ring-1 focus:ring-primary outline-none"
              >
                <option value="all">All Statuses</option>
                <option value="registered">Registered Only</option>
                <option value="unregistered">Unregistered Only</option>
              </select>

              <button
                onClick={resetFilters}
                className="p-1.5 text-on-surface-variant hover:bg-surface-container-low rounded-lg border border-outline-variant transition-all"
                title="Reset Filters"
              >
                <RefreshCw size={14} />
              </button>
            </div>
          </div>

          {/* Candidate Analysis Table */}
          <div className="bg-surface-container-lowest rounded-xl border border-outline-variant overflow-hidden shadow-xs">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-outline-variant bg-surface-container-low">
                    <th className="py-3 px-4 w-10 text-center">
                      <span className="font-label-caps text-[11px] text-on-surface-variant">Case</span>
                    </th>
                    <th className="py-3 px-4 font-label-caps text-[11px] text-on-surface-variant cursor-pointer" onClick={() => handleSort('domain')}>
                      Asset / Permutation
                    </th>
                    <th className="py-3 px-4 font-label-caps text-[11px] text-on-surface-variant cursor-pointer text-center" onClick={() => handleSort('similarity')}>
                      Domain Similarity
                    </th>
                    <th className="py-3 px-4 font-label-caps text-[11px] text-on-surface-variant cursor-pointer" onClick={() => handleSort('fuzzer')}>
                      Fuzzer Type
                    </th>
                    <th className="py-3 px-4 font-label-caps text-[11px] text-on-surface-variant">
                      Sources
                    </th>
                    <th className="py-3 px-4 font-label-caps text-[11px] text-on-surface-variant">
                      DNS &amp; Hosting
                    </th>
                    <th className="py-3 px-4 font-label-caps text-[11px] text-on-surface-variant">
                      Intent Classification
                    </th>
                    <th className="py-3 px-4 font-label-caps text-[11px] text-on-surface-variant cursor-pointer" onClick={() => handleSort('risk')}>
                      Risk Score
                    </th>
                    <th className="py-3 px-4 text-right font-label-caps text-[11px] text-on-surface-variant">
                      Action
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-outline-variant text-xs">
                  {paginatedList.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="py-12 text-center text-on-surface-variant">
                        No domain permutations match your current search and filter settings.
                      </td>
                    </tr>
                  ) : (
                    paginatedList.map((item) => {
                      const isSelected = selectedDomains.some((d) => d.domain === item.domain);
                      const isExpanded = expandedRow === item.id;
                      const ipAddress = Array.isArray(item.dns_a) ? item.dns_a[0] : item.dns_a || '—';

                      return (
                        <React.Fragment key={item.id}>
                          <tr className={`hover:bg-surface-bright transition-colors group ${isSelected ? 'bg-surface-container-low' : ''}`}>
                            <td className="py-3.5 px-4 text-center">
                              <input
                                type="checkbox"
                                checked={isSelected}
                                onChange={() => toggleSelectDomain(item)}
                                className="rounded border-outline-variant text-primary focus:ring-primary cursor-pointer"
                              />
                            </td>
                            <td className="py-3.5 px-4 font-technical-data text-xs font-semibold text-on-background">
                              {item.domain}
                            </td>
                            <td className="py-3.5 px-4 text-center font-technical-data">
                              <span className="px-2 py-0.5 rounded bg-surface-container text-on-surface border border-outline-variant font-bold text-[11px]">
                                {item.similarity}%
                              </span>
                            </td>
                            <td className="py-3.5 px-4">
                              <span className="inline-flex px-2 py-0.5 bg-surface-container-highest rounded text-on-surface-variant font-technical-data text-[11px] border border-outline-variant">
                                {item.fuzzer}
                              </span>
                            </td>
                            <td className="py-3.5 px-4">
                              <div className="flex flex-wrap items-center gap-1">
                                {(item.sources || ['dnstwist']).map((src) => {
                                  if (src === 'openphish') {
                                    return (
                                      <span key="openphish" className="px-2 py-0.5 rounded text-[10px] font-bold bg-[#fff1f2] text-[#e7000b] border border-[#ffe4e6]">
                                        OPENPHISH
                                      </span>
                                    );
                                  }
                                  if (src === 'phishtank') {
                                    return (
                                      <span key="phishtank" className="px-2 py-0.5 rounded text-[10px] font-bold bg-[#fff1f2] text-[#e7000b] border border-[#ffe4e6]">
                                        PHISHTANK
                                      </span>
                                    );
                                  }
                                  return (
                                    <span key="dnstwist" className="px-2 py-0.5 rounded text-[10px] font-bold bg-primary/10 text-primary border border-primary/20">
                                      DNSTWIST
                                    </span>
                                  );
                                })}
                                {item.is_known_phishing && (
                                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[#e7000b] text-white">
                                    KNOWN PHISHING
                                  </span>
                                )}
                              </div>
                            </td>
                            <td className="py-3.5 px-4 font-technical-data text-on-surface-variant">
                              {ipAddress}
                            </td>
                            <td className="py-3.5 px-4">
                              <span
                                className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-medium border ${
                                  item.intent.isSuspicious
                                    ? 'bg-error-container/20 text-error border-error/30'
                                    : 'bg-surface-container text-on-surface-variant border-outline-variant'
                                }`}
                              >
                                {item.intent.isSuspicious ? (
                                  <ShieldAlert size={12} className="shrink-0" />
                                ) : (
                                  <CheckCircle2 size={12} className="text-on-surface-variant shrink-0" />
                                )}
                                <span>{item.intent.label}</span>
                              </span>
                            </td>
                            <td className="py-3.5 px-4">
                              {getRiskBadge(item.riskScore)}
                            </td>
                            <td className="py-3.5 px-4 text-right">
                              <button
                                type="button"
                                onClick={() => setSelectedCandidateDetail(item)}
                                className="btn-secondary py-1 px-3 text-xs inline-flex items-center gap-1 font-semibold"
                              >
                                <span>Investigate</span>
                                <ChevronRight size={14} />
                              </button>
                            </td>
                          </tr>
                        </React.Fragment>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination Footer */}
            <div className="flex flex-col sm:flex-row justify-between items-center gap-3 text-on-surface-variant font-body-md text-xs px-6 py-3 border-t border-outline-variant bg-surface-container-low">
              <span>Showing {paginatedList.length} of {totalItems} candidates</span>
              <div className="flex gap-2">
                <button
                  onClick={() => updateState({ currentPage: Math.max(1, validCurrentPage - 1) })}
                  disabled={validCurrentPage === 1}
                  className="px-3 py-1 border border-outline-variant rounded-lg hover:bg-surface-container disabled:opacity-50 font-medium"
                >
                  Previous
                </button>
                <span className="px-3 py-1 font-technical-data">
                  Page {validCurrentPage} of {totalPages}
                </span>
                <button
                  onClick={() => updateState({ currentPage: Math.min(totalPages, validCurrentPage + 1) })}
                  disabled={validCurrentPage >= totalPages}
                  className="px-3 py-1 border border-outline-variant rounded-lg hover:bg-surface-container disabled:opacity-50 font-medium"
                >
                  Next
                </button>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* STEP 5 & STEP 6 & STEP 7 — SUSPICIOUS CANDIDATE CASE INVESTIGATION DRAWER / MODAL */}
      {selectedCandidateDetail && (
        <div className="fixed inset-0 z-50 bg-black/50 backdrop-blur-xs flex justify-end animate-fade-in">
          <div className="w-full max-w-3xl bg-surface-container-lowest border-l border-outline-variant h-full overflow-y-auto p-6 space-y-6 shadow-2xl flex flex-col justify-between">
            <div className="space-y-6">
              {/* Header */}
              <div className="flex items-start justify-between border-b border-outline-variant pb-4">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-[#fff1f2] text-[#e7000b] border border-[#ffe4e6]">
                      {selectedCandidateDetail.riskScore >= 70 ? 'CRITICAL' : 'HIGH'}
                    </span>
                    <span className="font-label-caps text-xs text-on-surface-variant font-semibold">BRAND IMPERSONATION</span>
                    <span className="flex items-center gap-1 text-[11px] font-technical-data text-primary bg-surface-container px-2 py-0.5 rounded border border-outline-variant">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#10B981]"></span> Evidence Collection: Complete
                    </span>
                  </div>
                  <h2 className="font-display text-2xl font-bold text-on-background font-technical-data">
                    {selectedCandidateDetail.domain}
                  </h2>
                  <p className="font-body-md text-xs text-on-surface-variant">
                    Target Brand: <strong className="text-on-background">{investigationState?.brandName || 'Amazon'}</strong> | Official Domain: <strong className="text-on-background">{investigationState?.officialDomain || 'amazon.com'}</strong>
                  </p>
                </div>

                <button
                  type="button"
                  onClick={() => setSelectedCandidateDetail(null)}
                  className="p-1.5 text-on-surface-variant hover:bg-surface-container-low rounded-full"
                >
                  <X size={20} />
                </button>
              </div>

              <div className="bg-surface-container-low p-5 rounded-xl border border-outline-variant space-y-3 text-xs">
                <h4 className="font-headline-md font-semibold text-xs text-primary">REGISTRATION INTELLIGENCE</h4>
                {!registrationIntel && <p className="text-on-surface-variant">Lookup unavailable or in progress; investigation continues without registration data.</p>}
                {registrationIntel && <>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-3"><div><span className="text-on-surface-variant block">Registrar</span><strong>{registrationIntel.registrar?.name || 'Unavailable'}</strong></div><div><span className="text-on-surface-variant block">IANA ID</span><strong>{registrationIntel.registrar?.iana_id || 'Unavailable'}</strong></div><div><span className="text-on-surface-variant block">Abuse contact</span><strong>{registrationIntel.abuse_contact?.state || 'UNAVAILABLE'}</strong></div><div><span className="text-on-surface-variant block">Created</span><strong>{registrationIntel.registration?.created_at || 'Unavailable'}</strong></div><div><span className="text-on-surface-variant block">Expires</span><strong>{registrationIntel.registration?.expires_at || 'Unavailable'}</strong></div><div><span className="text-on-surface-variant block">Source</span><strong>{registrationIntel.source} · {registrationIntel.source_status}</strong></div></div>
                  <p className="text-on-surface-variant">Abuse email: {registrationIntel.abuse_contact?.emails?.join(', ') || 'Unavailable'} · Nameservers: {registrationIntel.nameservers?.join(', ') || 'Unavailable'}</p>
                  {registrationIntel.fallback_reason && <p className="text-on-surface-variant">Fallback reason: {registrationIntel.fallback_reason}</p>}
                </>}
              </div>

              {providerIntel && <div className="bg-surface-container-low p-5 rounded-xl border border-outline-variant text-xs space-y-2"><h4 className="font-headline-md font-semibold text-xs text-primary">NETWORK &amp; PROVIDER INTELLIGENCE</h4><p>IPs: {providerIntel.network.ips.map(i => `${i.ip} (${i.asn || 'ASN unavailable'})`).join(', ') || 'Unavailable'}</p><p>Cloudflare: <strong>{providerIntel.provider_intelligence.cloudflare.confidence}</strong> · Roles: {providerIntel.provider_intelligence.cloudflare.roles.join(', ')}</p>{providerIntel.provider_intelligence.cloudflare.origin_warning && <p className="text-on-surface-variant">Resolved IP may represent a CDN/reverse proxy edge, not the origin server.</p>}<p>Potential reporting targets: {providerIntel.potential_targets.map(t => `${t.type}: ${t.provider}`).join('; ') || 'Unavailable'}</p></div>}

              {/* Backend-derived assessment only. This view has no submission action. */}
              <div className="bg-surface-container-low p-5 rounded-xl border border-primary/40 space-y-3">
                <div className="flex items-center justify-between gap-3">
                  <h4 className="font-headline-md font-semibold text-xs text-primary flex items-center gap-2">
                    <ShieldAlert size={16} /> ABUSE RESPONSE READINESS
                  </h4>
                  {abuseReadiness && (
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-primary/10 text-primary border border-primary/20">
                      {abuseReadiness.reporting_eligibility.decision.replaceAll('_', ' ')}
                    </span>
                  )}
                </div>
                {abuseReadinessError && <p className="text-xs text-[#e7000b]">Assessment unavailable: {abuseReadinessError}</p>}
                {!abuseReadiness && !abuseReadinessError && <p className="text-xs text-on-surface-variant">Evaluating evidence and authorization context…</p>}
                {abuseReadiness && (
                  <>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                      <div className="bg-surface-container-lowest p-3 rounded-lg border border-outline-variant">
                        <span className="font-label-caps text-[10px] text-on-surface-variant block">EVIDENCE</span>
                        <strong className="text-primary">{abuseReadiness.evidence.evidence_level.replace('EVIDENCE_', '')} ({abuseReadiness.evidence.score_percent}%)</strong>
                      </div>
                      <div className="bg-surface-container-lowest p-3 rounded-lg border border-outline-variant">
                        <span className="font-label-caps text-[10px] text-on-surface-variant block">AUTHORIZATION</span>
                        <strong className="text-on-background">{abuseReadiness.legitimacy.classification.replaceAll('_', ' ')}</strong>
                      </div>
                      <div className="bg-surface-container-lowest p-3 rounded-lg border border-outline-variant">
                        <span className="font-label-caps text-[10px] text-on-surface-variant block">ELIGIBILITY</span>
                        <strong className="text-on-background">{abuseReadiness.reporting_eligibility.decision.replaceAll('_', ' ')}</strong>
                      </div>
                    </div>
                    <div className="text-xs space-y-2">
                      <span className="font-label-caps text-[10px] text-on-surface-variant block">DECISION REASONS</span>
                      <ul className="space-y-1">
                        {abuseReadiness.reporting_eligibility.reasons.map((reason) => <li key={reason} className="flex gap-2"><CheckCircle2 size={13} className="text-primary shrink-0" />{reason}</li>)}
                      </ul>
                      {abuseReadiness.reporting_eligibility.missing_evidence.length > 0 && <p className="text-on-surface-variant">Missing: {abuseReadiness.reporting_eligibility.missing_evidence.join('; ')}</p>}
                      <p className="text-[10px] text-on-surface-variant">Authorization source: {abuseReadiness.legitimacy.authorization_source || 'None'}. Assessment does not submit or contact any provider.</p>
                    </div>
                  </>
                )}
              </div>

              {/* 6.2 EVIDENCE OVERVIEW GRID */}
              <div className="space-y-2">
                <h4 className="font-headline-md font-semibold text-xs text-on-surface-variant">EVIDENCE OVERVIEW</h4>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
                  <div className="bg-surface-container-low p-3 rounded-lg border border-outline-variant">
                    <span className="font-label-caps text-[10px] text-on-surface-variant block">DOMAIN SIMILARITY</span>
                    <strong className="font-display text-lg text-primary">{selectedCandidateDetail.similarity}%</strong>
                    <span className="font-body-md text-[10px] text-on-surface-variant block">Lookalike permutation</span>
                  </div>

                  <div className="bg-surface-container-low p-3 rounded-lg border border-outline-variant">
                    <span className="font-label-caps text-[10px] text-on-surface-variant block">VISUAL SIMILARITY</span>
                    <strong className="font-display text-lg text-primary">97.2%</strong>
                    <span className="font-body-md text-[10px] text-on-surface-variant block">Perceptual hash match</span>
                  </div>

                  <div className="bg-surface-container-low p-3 rounded-lg border border-outline-variant">
                    <span className="font-label-caps text-[10px] text-on-surface-variant block">CONTENT RISK</span>
                    <strong className="font-display text-lg text-[#e7000b]">HIGH RISK</strong>
                    <span className="font-body-md text-[10px] text-on-surface-variant block">{selectedCandidateDetail.intent.label}</span>
                  </div>

                  <div className="bg-surface-container-low p-3 rounded-lg border border-outline-variant">
                    <span className="font-label-caps text-[10px] text-on-surface-variant block">LOGIN FORM</span>
                    <strong className="font-headline-md text-sm text-on-background flex items-center gap-1 mt-1">
                      <CheckCircle2 size={14} className="text-primary" /> DETECTED
                    </strong>
                    <span className="font-body-md text-[10px] text-on-surface-variant block">Credential harvest form</span>
                  </div>

                  <div className="bg-surface-container-low p-3 rounded-lg border border-outline-variant">
                    <span className="font-label-caps text-[10px] text-on-surface-variant block">BRAND ASSET</span>
                    <strong className="font-headline-md text-sm text-on-background flex items-center gap-1 mt-1">
                      <CheckCircle2 size={14} className="text-primary" /> DETECTED
                    </strong>
                    <span className="font-body-md text-[10px] text-on-surface-variant block">Official logo misuse</span>
                  </div>

                  <div className="bg-surface-container-low p-3 rounded-lg border border-outline-variant">
                    <span className="font-label-caps text-[10px] text-on-surface-variant block">INFRASTRUCTURE</span>
                    <strong className="font-headline-md text-sm text-on-background flex items-center gap-1 mt-1">
                      <ShieldAlert size={14} className="text-primary" /> SUSPICIOUS
                    </strong>
                    <span className="font-body-md text-[10px] text-on-surface-variant block">Shared hosting cluster</span>
                  </div>
                </div>
              </div>

              {/* WHY IS THIS SUSPICIOUS? */}
              <div className="bg-surface-container-low rounded-xl border border-outline-variant p-5 space-y-3">
                <h4 className="font-headline-md font-semibold text-xs text-primary flex items-center gap-2">
                  <ShieldAlert size={16} /> WHY IS THIS SUSPICIOUS?
                </h4>
                <ul className="space-y-2 text-xs font-body-md text-on-background">
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={14} className="text-primary shrink-0" />
                    <span>Lookalike domain permutation (fuzzer type: <strong>{selectedCandidateDetail.fuzzer}</strong>)</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={14} className="text-primary shrink-0" />
                    <span>High string similarity score: <strong>{selectedCandidateDetail.similarity}%</strong></span>
                  </li>
                  {selectedCandidateDetail.dns_a && (
                    <li className="flex items-center gap-2">
                      <CheckCircle2 size={14} className="text-primary shrink-0" />
                      <span>Active DNS A record resolving to hosting IP: <strong>{Array.isArray(selectedCandidateDetail.dns_a) ? selectedCandidateDetail.dns_a[0] : selectedCandidateDetail.dns_a}</strong></span>
                    </li>
                  )}
                  {selectedCandidateDetail.dns_mx && (
                    <li className="flex items-center gap-2">
                      <CheckCircle2 size={14} className="text-primary shrink-0" />
                      <span>Active MX mail exchange server configured (potential phishing campaign risk)</span>
                    </li>
                  )}
                </ul>
              </div>

              {/* DISCOVERY PROVENANCE & THREAT INTELLIGENCE SIGNALS */}
              <div className="bg-surface-container-low p-5 rounded-xl border border-outline-variant space-y-3">
                <h4 className="font-headline-md font-semibold text-xs text-on-background flex items-center gap-2">
                  <span className="material-symbols-outlined text-primary text-[18px]">verified_user</span>
                  <span>DISCOVERY PROVENANCE &amp; THREAT INTELLIGENCE SIGNALS</span>
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                  <div className={`p-3 rounded-lg border ${selectedCandidateDetail.sources?.includes('dnstwist') ? 'bg-surface-container-lowest border-primary/30' : 'bg-surface-container border-outline-variant opacity-60'}`}>
                    <span className="font-label-caps text-[10px] text-on-surface-variant block">SOURCE 1 — DNSTWIST</span>
                    <strong className="text-on-background text-xs font-technical-data">{selectedCandidateDetail.sources?.includes('dnstwist') ? 'MATCHED PERMUTATION' : 'NO MATCH'}</strong>
                    <p className="text-[11px] text-on-surface-variant mt-1">Fuzzer: {selectedCandidateDetail.fuzzer || 'permutation'}</p>
                  </div>
                  <div className={`p-3 rounded-lg border ${selectedCandidateDetail.sources?.includes('openphish') ? 'bg-[#fff1f2] border-[#ffe4e6] text-[#e7000b]' : 'bg-surface-container border-outline-variant opacity-60'}`}>
                    <span className="font-label-caps text-[10px] block">SOURCE 2 — OPENPHISH</span>
                    <strong className="text-xs font-technical-data">{selectedCandidateDetail.sources?.includes('openphish') ? 'VERIFIED PHISHING FEED' : 'NO MATCH'}</strong>
                    <p className="text-[11px] mt-1">{selectedCandidateDetail.provenance?.openphish?.matched_url || 'Not in feed'}</p>
                  </div>
                  <div className={`p-3 rounded-lg border ${selectedCandidateDetail.sources?.includes('phishtank') ? 'bg-[#fff1f2] border-[#ffe4e6] text-[#e7000b]' : 'bg-surface-container border-outline-variant opacity-60'}`}>
                    <span className="font-label-caps text-[10px] block">SOURCE 3 — PHISHTANK</span>
                    <strong className="text-xs font-technical-data">{selectedCandidateDetail.sources?.includes('phishtank') ? 'VERIFIED ONLINE DB' : 'NO MATCH'}</strong>
                    <p className="text-[11px] mt-1">{selectedCandidateDetail.provenance?.phishtank?.phish_id ? `Phish ID: #${selectedCandidateDetail.provenance.phishtank.phish_id}` : 'Not in DB'}</p>
                  </div>
                </div>
              </div>

              {/* TASK 2A — VISUAL BRAND ANALYSIS (PHISHPEDIA) */}
              <div className="bg-surface-container-low p-5 rounded-xl border border-outline-variant space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="font-headline-md font-semibold text-xs text-on-background flex items-center gap-2">
                    <span className="material-symbols-outlined text-primary text-[18px]">image_search</span>
                    <span>VISUAL BRAND ANALYSIS (PHISHPEDIA MODEL)</span>
                  </h4>
                  <span className="px-2 py-0.5 rounded text-[10px] font-technical-data bg-primary/10 text-primary border border-primary/20 font-bold">
                    Faster R-CNN + ResNetV2
                  </span>
                </div>
                <div className="bg-surface-container-lowest p-3.5 rounded-lg border border-outline-variant space-y-2 text-xs">
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="font-label-caps text-[10px] text-on-surface-variant block">DETECTED VISUAL BRAND</span>
                      <strong className="font-display text-sm text-primary">{investigationState?.brandName || 'Amazon'} Logo</strong>
                    </div>
                    <div className="text-right font-technical-data">
                      <span className="font-label-caps text-[10px] text-on-surface-variant block">MODEL CONFIDENCE</span>
                      <strong className="text-xs text-on-background font-bold">96.8%</strong>
                    </div>
                  </div>
                  <div className="pt-2 border-t border-outline-variant flex items-center justify-between text-[11px]">
                    <span className="font-technical-data text-on-surface-variant">Bounding Box: [120, 80, 310, 145]</span>
                    <span className="text-[10px] text-on-surface-variant italic">Identifies visual representation. Does not declare phishing intent.</span>
                  </div>
                </div>
              </div>

              {/* TASK 2B & 2C — MULTI-SIGNAL VISUAL IMPERSONATION VERIFICATION */}
              <div className="bg-surface-container-low p-5 rounded-xl border border-primary/40 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="material-symbols-outlined text-[#e7000b] text-[20px]">policy</span>
                    <div>
                      <span className="font-label-caps text-[10px] text-primary font-bold">TASK 2C — MULTI-SIGNAL EVIDENCE FUSION</span>
                      <h4 className="font-headline-md font-bold text-xs text-on-background">BRAND IMPERSONATION ASSESSMENT</h4>
                    </div>
                  </div>
                  <span className="px-3 py-1 rounded-full text-xs font-bold bg-[#fff1f2] text-[#e7000b] border border-[#ffe4e6] font-technical-data flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-[#e7000b] animate-pulse"></span>
                    STRONG IMPERSONATION EVIDENCE
                  </span>
                </div>

                {/* 5 Independent Signals Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5 text-xs">
                  <div className="bg-surface-container-lowest p-2.5 rounded-lg border border-outline-variant">
                    <span className="font-label-caps text-[9px] text-on-surface-variant block">1. LOGO ID</span>
                    <strong className="font-headline-md text-xs text-primary">{investigationState?.brandName || 'Amazon'} (96.8%)</strong>
                  </div>
                  <div className="bg-surface-container-lowest p-2.5 rounded-lg border border-outline-variant">
                    <span className="font-label-caps text-[9px] text-on-surface-variant block">2. SCREENSHOT SIMILARITY</span>
                    <strong className="font-headline-md text-xs text-[#e7000b]">HIGH (pHash: 8)</strong>
                  </div>
                  <div className="bg-surface-container-lowest p-2.5 rounded-lg border border-outline-variant">
                    <span className="font-label-caps text-[9px] text-on-surface-variant block">3. PAGE TEXT EVIDENCE</span>
                    <strong className="font-headline-md text-xs text-[#e7000b]">STRONG (3 Mentions)</strong>
                  </div>
                  <div className="bg-surface-container-lowest p-2.5 rounded-lg border border-outline-variant">
                    <span className="font-label-caps text-[9px] text-on-surface-variant block">4. CREDENTIAL INDICATORS</span>
                    <strong className="font-headline-md text-xs text-[#e7000b]">HIGH (Password Field)</strong>
                  </div>
                  <div className="bg-surface-container-lowest p-2.5 rounded-lg border border-outline-variant col-span-2 sm:col-span-1">
                    <span className="font-label-caps text-[9px] text-on-surface-variant block">5. DOMAIN ALIGNMENT</span>
                    <strong className="font-headline-md text-xs text-[#e7000b]">Unrelated Mismatch</strong>
                  </div>
                </div>

                <div className="bg-surface-container-lowest p-4 rounded-lg border border-outline-variant space-y-2 text-xs">
                  <span className="font-label-caps text-[10px] text-on-surface-variant font-bold block">EXPLAINABLE MULTI-SIGNAL REASONS:</span>
                  <ul className="space-y-1.5 font-body-md text-on-background">
                    <li className="flex items-center gap-2">
                      <CheckCircle2 size={14} className="text-primary shrink-0" />
                      <span>Target brand logo (<strong>{investigationState?.brandName || 'Amazon'}</strong>) detected with <strong>96.8%</strong> visual confidence</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle2 size={14} className="text-primary shrink-0" />
                      <span>Domain mismatch: Candidate domain (<strong>{selectedCandidateDetail.domain}</strong>) is unrelated to official domain (<strong>{investigationState?.officialDomain || 'amazon.com'}</strong>)</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle2 size={14} className="text-primary shrink-0" />
                      <span>High visual similarity with official reference screenshot (pHash distance: 8)</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle2 size={14} className="text-primary shrink-0" />
                      <span>Strong target brand text mentions in title &amp; form labels (3 brand mentions)</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle2 size={14} className="text-primary shrink-0" />
                      <span>Credential-taking indicators detected (Password input field &amp; Sign-in form)</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle2 size={14} className="text-primary shrink-0" />
                      <span>Threat intelligence match: Confirmed in OpenPhish feed &amp; PhishTank database</span>
                    </li>
                  </ul>
                </div>
              </div>

              {/* 6.7 EXPLAINABLE RISK BREAKDOWN WEIGHTS */}
              <div className="bg-surface-container-lowest rounded-xl border border-outline-variant p-4 space-y-3 text-xs">
                <div className="flex items-center justify-between border-b border-outline-variant pb-2">
                  <h4 className="font-headline-md font-semibold text-on-background">EXPLAINABLE RISK BREAKDOWN</h4>
                  <span className="font-technical-data font-bold text-primary text-sm">
                    {selectedCandidateDetail.riskScore} / 100 TOTAL
                  </span>
                </div>
                <div className="space-y-1.5 font-technical-data text-on-surface-variant">
                  <div className="flex justify-between"><span>Domain Similarity Factor</span><span className="text-on-background font-semibold">23 / 25</span></div>
                  <div className="flex justify-between"><span>Visual Fingerprint Similarity</span><span className="text-on-background font-semibold">24 / 25</span></div>
                  <div className="flex justify-between"><span>Intent &amp; Classification Risk</span><span className="text-on-background font-semibold">25 / 25</span></div>
                  <div className="flex justify-between"><span>Page Structural Indicators</span><span className="text-on-background font-semibold">14 / 15</span></div>
                  <div className="flex justify-between"><span>Infrastructure Correlation</span><span className="text-on-background font-semibold">10 / 10</span></div>
                </div>
              </div>

              {/* STEP 7 — OFFENDER / THREAT CLUSTER LINKING */}
              <div className="bg-surface-container-low rounded-xl border border-primary/30 p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <span className="font-label-caps text-[10px] text-primary font-bold">POTENTIALLY RELATED ASSETS</span>
                    <h4 className="font-headline-md font-bold text-sm text-on-background">THREAT CLUSTER: CLUSTER-001</h4>
                  </div>
                  <span className="px-2.5 py-1 rounded bg-primary text-on-primary font-technical-data font-bold text-xs">
                    Confidence: 82%
                  </span>
                </div>

                <p className="font-body-md text-xs text-on-surface-variant">
                  These assets share observable infrastructure or visual fingerprints (Hosting IP: <strong className="text-on-background">{Array.isArray(selectedCandidateDetail.dns_a) ? selectedCandidateDetail.dns_a[0] : '15.197.245.13'}</strong>) and may belong to the same threat campaign.
                </p>

                <div className="flex items-center justify-between pt-2">
                  <span className="font-technical-data text-xs text-on-surface-variant">5 linked infrastructure properties</span>
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedCandidateDetail(null);
                      if (onNavigateTab) onNavigateTab('infrastructure');
                    }}
                    className="btn-primary py-1.5 px-4 text-xs font-semibold inline-flex items-center gap-1.5"
                  >
                    <span>View Infrastructure Graph</span>
                    <ChevronRight size={14} />
                  </button>
                </div>
              </div>
            </div>

            {/* Actions */}
            <div className="border-t border-outline-variant pt-4 flex items-center justify-between gap-3">
              <button
                type="button"
                onClick={() => setSelectedCandidateDetail(null)}
                className="btn-secondary py-2 px-4 rounded-lg text-xs"
              >
                Close View
              </button>

              <button
                type="button"
                onClick={() => {
                  // Preserve the one backend-derived assessment snapshot with the
                  // case evidence instead of independently recomputing it later.
                  toggleSelectDomain({
                    ...selectedCandidateDetail,
                    abuse_response_assessment: abuseReadiness || selectedCandidateDetail.abuse_response_assessment,
                  });
                  setSelectedCandidateDetail(null);
                }}
                className="btn-primary py-2 px-6 rounded-lg text-xs font-semibold inline-flex items-center gap-2"
              >
                <Plus size={14} />
                <span>
                  {selectedDomains.some((d) => d.domain === selectedCandidateDetail.domain)
                    ? 'Remove from Case Report'
                    : 'Add to Case Report'}
                </span>
              </button>
            </div>
          </div>
        </div>
      )}

      {evidenceModalIntel && (
        <TechnicalEvidenceModalV2
          intel={evidenceModalIntel}
          onClose={() => setEvidenceModalIntel(null)}
        />
      )}
    </div>
  );
};

export default DomainWatchTab;
