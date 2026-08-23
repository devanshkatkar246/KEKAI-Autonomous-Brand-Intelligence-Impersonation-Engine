import React, { useState, useEffect, useRef } from 'react';
import ErrorBoundary from './components/ErrorBoundary';
import Toast from './components/Toast';
import Footer from './components/Footer';
import OnboardingPage from './components/OnboardingPage';
import DomainWatchTab from './components/DomainWatchTab';
import LogoMatchTab from './components/LogoMatchTab';
import CaseReportTab from './components/CaseReportTab';
import VisualPhishingTab from './components/VisualPhishingTab';
import LinkedInfrastructureTab from './components/LinkedInfrastructureTab';
import MarketplaceListingsTab from './components/MarketplaceListingsTab';
import SocialWatchTab from './components/SocialWatchTab';
import AbuseControlSection from './components/AbuseControlSection';
import WorkflowAutomationTab from './components/WorkflowAutomationTab';
import DemoControllerBar from './components/DemoControllerBar';
import DemoScenarioModal from './components/DemoScenarioModal';
import { apiFetch } from './api';
import { ShieldAlert, Image as ImageIcon, FileCheck, Eye, Activity, Shield, Network, ShoppingBag, Share2, WifiOff, Plus } from 'lucide-react';

const API_BASE_URL = 'http://localhost:8000';

function Dashboard() {
  const [theme, setTheme] = useState(() => {
    return localStorage.getItem('keikai-theme') || 'light';
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    document.documentElement.classList.toggle('dark', theme === 'dark');
    try {
      localStorage.setItem('keikai-theme', theme);
    } catch {}
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'light' ? 'dark' : 'light'));
  };

  const [activeTab, setActiveTab] = useState('home');
  const [toasts, setToasts] = useState([]);
  const [apiOnline, setApiOnline] = useState(true);
  
  // Shared state for compiled case report items with localStorage persistence
  const [selectedDomains, setSelectedDomains] = useState(() => {
    try {
      const saved = localStorage.getItem('bp_selected_domains');
      return saved ? JSON.parse(saved) : [];
    } catch { return []; }
  });

  const [selectedLogos, setSelectedLogos] = useState(() => {
    try {
      const saved = localStorage.getItem('bp_selected_logos');
      return saved ? JSON.parse(saved) : [];
    } catch { return []; }
  });

  const [selectedVisualPhishing, setSelectedVisualPhishing] = useState(() => {
    try {
      const saved = localStorage.getItem('bp_selected_visual_phishing');
      return saved ? JSON.parse(saved) : [];
    } catch { return []; }
  });

  const [selectedListings, setSelectedListings] = useState(() => {
    try {
      const saved = localStorage.getItem('bp_selected_listings');
      return saved ? JSON.parse(saved) : [];
    } catch { return []; }
  });

  const [selectedSocialProfiles, setSelectedSocialProfiles] = useState(() => {
    try {
      const saved = localStorage.getItem('bp_selected_social_profiles');
      return saved ? JSON.parse(saved) : [];
    } catch { return []; }
  });

  const [brandName, setBrandName] = useState(() => {
    return localStorage.getItem('bp_brand_name') || '';
  });

  const [investigationState, setInvestigationState] = useState(() => {
    try {
      const init = localStorage.getItem('keikai_investigation_initialized') === 'true' || localStorage.getItem('ikigai_investigation_initialized') === 'true';
      return {
        isInitialized: init,
        investigationId: localStorage.getItem('keikai_investigation_id') || localStorage.getItem('ikigai_investigation_id') || '',
        brandName: localStorage.getItem('bp_brand_name') || '',
        officialDomain: localStorage.getItem('keikai_official_domain') || localStorage.getItem('ikigai_official_domain') || '',
        source: 'domain_monitoring'
      };
    } catch {
      return { isInitialized: false, investigationId: '', brandName: '', officialDomain: '', source: 'domain_monitoring' };
    }
  });

  const [notes, setNotes] = useState(() => {
    return localStorage.getItem('bp_notes') || 'Flagged typosquatting domain lookalikes, logo misuse, counterfeit marketplace listings, and social media impersonation for executive review.';
  });

  // Save selected listings & social profiles to localStorage
  useEffect(() => {
    try {
      localStorage.setItem('bp_selected_listings', JSON.stringify(selectedListings));
    } catch {}
  }, [selectedListings]);

  useEffect(() => {
    try {
      localStorage.setItem('bp_selected_social_profiles', JSON.stringify(selectedSocialProfiles));
    } catch {}
  }, [selectedSocialProfiles]);

  const toggleSelectProfile = (item) => {
    setSelectedSocialProfiles((prev) => {
      const exists = prev.some((s) => s.profile_id === item.profile_id);
      if (exists) {
        addToast('Removed from Case', `Removed social profile ${item.handle}`, 'info');
        return prev.filter((s) => s.profile_id !== item.profile_id);
      } else {
        addToast('Added to Case Report', `Social profile ${item.handle} added to case.`, 'success');
        return [...prev, item];
      }
    });
  };

  // Save selected listings to localStorage
  useEffect(() => {
    try {
      localStorage.setItem('bp_selected_listings', JSON.stringify(selectedListings));
    } catch {}
  }, [selectedListings]);

  const toggleSelectListing = (item) => {
    setSelectedListings((prev) => {
      const exists = prev.some((l) => l.listing_id === item.listing_id);
      if (exists) {
        addToast('Removed from Case', `Removed listing ${item.title}`, 'info');
        return prev.filter((l) => l.listing_id !== item.listing_id);
      } else {
        addToast('Added to Case Report', `Listing ${item.title} added to case.`, 'success');
        return [...prev, item];
      }
    });
  };

  // Persistent tab states for Domain Watch & Logo Match
  const [domainScanState, setDomainScanState] = useState({
    domainInput: '',
    quickMode: true,
    results: null,
    searchFilter: '',
    statusFilter: 'all',
    riskFilter: 'all',
    fuzzerFilter: 'all',
    sortField: 'risk',
    sortAsc: false,
    currentPage: 1,
    pageSize: 25
  });

  const [logoMatchState, setLogoMatchState] = useState({
    refFile: null,
    candidateFiles: [],
    threshold: 10,
    batchResults: null
  });

  const handleStartInvestigation = (params) => {
    const { investigationId, brandName, officialDomain, logoFile, logoPreview, source } = params;

    // Save to localStorage
    localStorage.setItem('keikai_investigation_initialized', 'true');
    localStorage.setItem('keikai_investigation_id', investigationId);
    localStorage.setItem('bp_brand_name', brandName);
    localStorage.setItem('keikai_official_domain', officialDomain);

    // Clear old evidence items for fresh investigation
    setSelectedDomains([]);
    setSelectedLogos([]);
    setSelectedVisualPhishing([]);
    setSelectedListings([]);
    setSelectedSocialProfiles([]);
    try {
      localStorage.removeItem('bp_selected_domains');
      localStorage.removeItem('bp_selected_logos');
      localStorage.removeItem('bp_selected_visual_phishing');
      localStorage.removeItem('bp_selected_listings');
      localStorage.removeItem('bp_selected_social_profiles');
    } catch (e) {}

    setInvestigationState({
      isInitialized: true,
      investigationId,
      brandName,
      officialDomain,
      source: source || 'domain_monitoring'
    });

    setBrandName(brandName);

    // Pre-populate domain input in Domain Watch
    setDomainScanState((prev) => ({
      ...prev,
      domainInput: officialDomain,
      results: null
    }));

    if (logoFile) {
      setLogoMatchState((prev) => ({
        ...prev,
        refFile: logoFile
      }));
    }

    setActiveTab('domain');
    addToast('Investigation Created', `Initialized ${investigationId} for brand '${brandName}'.`, 'success');
  };

  // Sync case state to localStorage
  useEffect(() => {
    try {
      localStorage.setItem('bp_selected_domains', JSON.stringify(selectedDomains));
    } catch (e) { console.error('Failed to save domains:', e); }
  }, [selectedDomains]);

  useEffect(() => {
    try {
      localStorage.setItem('bp_selected_logos', JSON.stringify(selectedLogos));
    } catch (e) { console.error('Failed to save logos:', e); }
  }, [selectedLogos]);

  useEffect(() => {
    try {
      localStorage.setItem('bp_selected_visual_phishing', JSON.stringify(selectedVisualPhishing));
    } catch (e) { console.error('Failed to save visual phishing:', e); }
  }, [selectedVisualPhishing]);

  useEffect(() => {
    localStorage.setItem('bp_brand_name', brandName);
  }, [brandName]);

  useEffect(() => {
    localStorage.setItem('bp_notes', notes);
  }, [notes]);

  const toastHistoryRef = React.useRef([]);

  const addToast = (title, message, type = 'info', duration = 5000) => {
    const now = Date.now();
    const isDuplicate = toastHistoryRef.current.some(
      (t) => t.title === title && t.message === message && now - t.timestamp < 2500
    );
    if (isDuplicate) return;

    toastHistoryRef.current.push({ title, message, timestamp: now });
    if (toastHistoryRef.current.length > 20) {
      toastHistoryRef.current.shift();
    }

    const id = now + Math.random().toString(36).substring(2, 5);
    setToasts((prev) => [...prev, { id, title, message, type, duration }]);
  };

  const removeToast = (id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  // Health check — runs on mount, and retries every 8s while offline so
  // the banner self-heals the moment the backend comes back up.
  const healthRetryRef = useRef(null);

  const checkHealth = async () => {
    try {
      const res = await apiFetch(`${API_BASE_URL}/api/health`);
      const data = await res.json();
      const online = data.status === 'success';
      setApiOnline(online);

      if (online && data.data?.server_instance_id) {
        const currentInstance = data.data.server_instance_id;
        const storedInstance = sessionStorage.getItem('keikai_server_instance_id');
        if (storedInstance && storedInstance !== currentInstance) {
          console.log('[KEIKAI] Server restart detected! Initializing fresh investigation session.');
          try {
            localStorage.removeItem('keikai_investigation_initialized');
            localStorage.removeItem('ikigai_investigation_initialized');
            localStorage.removeItem('keikai_investigation_id');
            localStorage.removeItem('ikigai_investigation_id');
            localStorage.removeItem('bp_brand_name');
            localStorage.removeItem('keikai_official_domain');
            localStorage.removeItem('ikigai_official_domain');
            localStorage.removeItem('bp_selected_domains');
            localStorage.removeItem('bp_selected_logos');
            localStorage.removeItem('bp_selected_visual_phishing');
            localStorage.removeItem('bp_selected_listings');
            localStorage.removeItem('bp_selected_social_profiles');
          } catch {}

          setSelectedDomains([]);
          setSelectedLogos([]);
          setSelectedVisualPhishing([]);
          setSelectedListings([]);
          setSelectedSocialProfiles([]);
          setBrandName('');
          setInvestigationState({
            isInitialized: false,
            investigationId: '',
            brandName: '',
            officialDomain: '',
            source: 'domain_monitoring'
          });
          setActiveTab('home');
        }
        sessionStorage.setItem('keikai_server_instance_id', currentInstance);
      }

      if (online && healthRetryRef.current) {
        clearInterval(healthRetryRef.current);
        healthRetryRef.current = null;
      }
    } catch (err) {
      console.warn('Backend API health check failed:', err.message);
      setApiOnline(false);
      // Start polling every 8 s to auto-recover without a full page refresh
      if (!healthRetryRef.current) {
        healthRetryRef.current = setInterval(checkHealth, 8000);
      }
    }
  };

  useEffect(() => {
    checkHealth();
    return () => {
      if (healthRetryRef.current) clearInterval(healthRetryRef.current);
    };
  }, []);

  const logRemoteEvent = (eventType, description) => {
    fetch(`${API_BASE_URL}/api/case/default/event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event_type: eventType, description })
    }).catch((err) => console.warn('Failed to log remote timeline event:', err));
  };

  const toggleSelectDomain = (item) => {
    setSelectedDomains((prev) => {
      const exists = prev.some((d) => d.domain === item.domain);
      if (exists) {
        addToast('Removed from Case', `Removed domain ${item.domain}`, 'info');
        return prev.filter((d) => d.domain !== item.domain);
      } else {
        addToast('Added to Case Report', `Flagged domain ${item.domain} added to case.`, 'success');
        logRemoteEvent('evidence_added', `Domain evidence added: ${item.domain} (Fuzzer: ${item.fuzzer || 'homoglyph'})`);
        return [...prev, item];
      }
    });
  };

  const toggleSelectLogo = (item) => {
    setSelectedLogos((prev) => {
      const exists = prev.some((l) => l.candidate_filename === item.candidate_filename);
      if (exists) {
        addToast('Removed from Case', `Removed logo match ${item.candidate_filename}`, 'info');
        return prev.filter((l) => l.candidate_filename !== item.candidate_filename);
      } else {
        addToast('Added to Case Report', `Flagged logo ${item.candidate_filename} added to case.`, 'success');
        logRemoteEvent('evidence_added', `Logo match evidence added: ${item.candidate_filename} (${item.combined_similarity_percentage?.toFixed(1)}% sim)`);
        return [...prev, item];
      }
    });
  };

  const toggleSelectVisualPhishing = (item) => {
    setSelectedVisualPhishing((prev) => {
      const key = item.key || item.id || item.url;
      const exists = prev.some((vp) => (vp.key || vp.id || vp.url) === key);
      if (exists) {
        addToast('Removed from Case', `Removed visual phishing evidence for ${item.url}`, 'info');
        return prev.filter((vp) => (vp.key || vp.id || vp.url) !== key);
      } else {
        addToast('Added to Case Report', `Visual phishing evidence for ${item.url} added to case.`, 'success');
        logRemoteEvent('evidence_added', `Visual phishing evidence added for ${item.url} (Target: ${item.target_brand || 'Threat'})`);
        return [...prev, item];
      }
    });
  };

  // Add all cluster assets to Case Report in one click
  const handleAddClusterToCase = (cluster) => {
    if (!cluster || !cluster.assets) return;

    logRemoteEvent('cluster_linked', `Offender cluster ${cluster.cluster_id} linked with ${cluster.asset_count} assets (${cluster.confidence} confidence).`);

    const newDomains = [...selectedDomains];
    const newLogos = [...selectedLogos];
    const newPhish = [...selectedVisualPhishing];

    cluster.assets.forEach((a) => {
      if (a.asset_type === 'domain' && !newDomains.some((d) => d.domain === a.asset_id)) {
        newDomains.push({
          domain: a.asset_id,
          fuzzer: 'cluster_linked',
          isRegistered: true,
          riskScore: 85,
          dns_a: a.ip_address ? [a.ip_address] : []
        });
      } else if (a.asset_type === 'logo' && !newLogos.some((l) => l.candidate_filename === a.asset_id)) {
        newLogos.push({
          candidate_filename: a.asset_id,
          phash_distance: 2,
          dhash_distance: 3,
          combined_similarity_percentage: 88.5,
          likely_match: true
        });
      } else if (a.asset_type === 'visual_phishing' && !newPhish.some((vp) => vp.url === a.asset_id)) {
        const itemKey = `vp-${a.asset_id}-cluster`;
        newPhish.push({
          id: itemKey,
          key: itemKey,
          type: 'visual_phishing',
          url: a.asset_id,
          verdict: 'Phishing',
          target_brand: a.target_brand || 'Threat Operator',
          confidence: 90.0,
          matched_domain: null,
          isFallback: false,
          timestamp: new Date().toISOString()
        });
      }
    });

    setSelectedDomains(newDomains);
    setSelectedLogos(newLogos);
    setSelectedVisualPhishing(newPhish);
  };

  const handleClearCase = () => {
    setSelectedDomains([]);
    setSelectedLogos([]);
    setSelectedVisualPhishing([]);
    setBrandName('Acme Corporate Brand');
    setNotes('');
    try {
      localStorage.removeItem('bp_selected_domains');
      localStorage.removeItem('bp_selected_logos');
      localStorage.removeItem('bp_selected_visual_phishing');
      localStorage.removeItem('bp_brand_name');
      localStorage.removeItem('bp_notes');
    } catch {}
    addToast('Case Cleared', 'All compiled evidence items and investigator notes have been reset.', 'info');
  };

  const totalSelectedCount = selectedDomains.length + selectedLogos.length + selectedVisualPhishing.length;

  const hasDomain = selectedDomains.length > 0;
  const hasLogo = selectedLogos.length > 0;
  const hasPhish = selectedVisualPhishing.length > 0;
  const hasNotes = notes.trim().length > 0;
  const categoriesCount = (hasDomain ? 1 : 0) + (hasLogo ? 1 : 0) + (hasPhish ? 1 : 0) + (hasNotes ? 1 : 0);
  const completenessPercent = Math.round((categoriesCount / 4) * 100);

  // DEMO MODE STATE
  const [isDemoRunning, setIsDemoRunning] = useState(false);
  const [demoStage, setDemoStage] = useState(-1); // -1 = closed, 0 = intro launcher, 1..6 = stages, 7 = summary
  const [isDemoPaused, setIsDemoPaused] = useState(false);

  const handleRunFullDemoScenario = () => {
    // Open Launcher Modal Stage 0
    setDemoStage(0);
  };

  const handleStartDemo = () => {
    // Initialize Amazon Demo Scenario
    setBrandName('Amazon');
    setInvestigationState({
      isInitialized: true,
      investigationId: 'CASE-AMAZON-DEMO-092',
      brandName: 'Amazon',
      officialDomain: 'amazon.com',
      source: 'Domain Monitoring',
      timestamp: new Date().toISOString()
    });

    // Seed deterministic evidence items for Amazon
    const demoDomains = [{
      domain: 'amazon-security-login.example',
      risk_score: 92,
      risk_category: 'CRITICAL',
      evidence_quality: 91,
      investigation_quality: 'COMPLETE',
      relationship: 'LOOKALIKE',
      phishpedia_confidence: 0.968,
      ocr_matched: true,
      threat_feeds: ['dnstwist', 'openphish', 'phishtank'],
      timestamp: new Date().toISOString()
    }];

    setSelectedDomains(demoDomains);
    setSelectedLogos([]);
    setSelectedVisualPhishing([]);
    setIsDemoRunning(true);
    setDemoStage(1);
    setIsDemoPaused(false);
    setActiveTab('domain');
    addToast('Demo Started', 'Live investigation simulation initialized for Amazon (amazon.com).', 'info');
  };

  const handleNextDemoStage = () => {
    if (demoStage < 6) {
      const next = demoStage + 1;
      setDemoStage(next);
      if (next === 4) setActiveTab('infrastructure');
      if (next === 5) setActiveTab('case');
      if (next === 6) setActiveTab('workflows');
    } else if (demoStage === 6) {
      setDemoStage(7); // Show final summary screen
    }
  };

  // If no investigation has been initialized at all, show full-screen onboarding
  if (!investigationState.isInitialized && activeTab !== 'home') {
    setActiveTab('home');
  }

  return (
    <div className="min-h-screen bg-background text-on-background flex flex-col font-body-md antialiased">
      {/* Top Notification Toast Container */}
      <Toast toasts={toasts} removeToast={removeToast} />

      <div className="flex-1">
        {/* Stitch Top Navigation Bar */}
        <nav className="bg-surface-container-lowest border-b border-outline-variant sticky top-0 z-50">
          <div className="max-w-[1440px] mx-auto w-full px-4 sm:px-6 lg:px-8 flex justify-between items-center h-[64px]">
            <div className="flex items-center gap-4 lg:gap-6 min-w-0">
              {/* Clickable Brand Home Button */}
              <button
                type="button"
                onClick={() => setActiveTab('home')}
                className="flex items-center gap-2 hover:opacity-80 transition-opacity cursor-pointer text-left shrink-0"
                title="Return to Home / Start Investigation"
              >
                <span className="material-symbols-outlined text-primary text-[28px] fill-icon">shield</span>
                <span className="font-headline-md text-[20px] font-bold text-primary tracking-tight">KEIKAI</span>
              </button>

              <div className="hidden md:flex items-center gap-2 lg:gap-4 h-[64px] min-w-0 overflow-x-auto no-scrollbar">
                <button
                  type="button"
                  onClick={() => setActiveTab('domain')}
                  className={`h-full flex items-center gap-1.5 px-2 text-xs lg:text-sm font-medium transition-all whitespace-nowrap ${
                    activeTab === 'domain'
                      ? 'text-primary border-b-2 border-primary font-bold'
                      : 'text-on-surface-variant hover:text-primary'
                  }`}
                >
                  <span className="material-symbols-outlined text-[18px]">security</span>
                  <span>Domain Watch</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveTab('logo')}
                  className={`h-full flex items-center gap-1.5 px-2 text-xs lg:text-sm font-medium transition-all whitespace-nowrap ${
                    activeTab === 'logo'
                      ? 'text-primary border-b-2 border-primary font-bold'
                      : 'text-on-surface-variant hover:text-primary'
                  }`}
                >
                  <span className="material-symbols-outlined text-[18px]">image</span>
                  <span>Logo Match</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveTab('infrastructure')}
                  className={`h-full flex items-center gap-1.5 px-2 text-xs lg:text-sm font-medium transition-all whitespace-nowrap ${
                    activeTab === 'infrastructure'
                      ? 'text-primary border-b-2 border-primary font-bold'
                      : 'text-on-surface-variant hover:text-primary'
                  }`}
                >
                  <span className="material-symbols-outlined text-[18px]">hub</span>
                  <span>Linked Infrastructure</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveTab('case')}
                  className={`h-full flex items-center gap-1.5 px-2 text-xs lg:text-sm font-medium transition-all whitespace-nowrap relative ${
                    activeTab === 'case'
                      ? 'text-primary border-b-2 border-primary font-bold'
                      : 'text-on-surface-variant hover:text-primary'
                  }`}
                >
                  <span className="material-symbols-outlined text-[18px]">assignment</span>
                  <span>Case Report ({selectedDomains.length + selectedLogos.length + selectedVisualPhishing.length})</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveTab('takedown')}
                  className={`h-full flex items-center gap-1.5 px-2 text-xs lg:text-sm font-medium transition-all whitespace-nowrap ${
                    activeTab === 'takedown'
                      ? 'text-primary border-b-2 border-primary font-bold'
                      : 'text-on-surface-variant hover:text-primary'
                  }`}
                >
                  <span className="material-symbols-outlined text-[18px]">gavel</span>
                  <span>Takedown / Abuse Response</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveTab('workflows')}
                  className={`h-full flex items-center gap-1.5 px-2 text-xs lg:text-sm font-medium transition-all whitespace-nowrap ${
                    activeTab === 'workflows'
                      ? 'text-primary border-b-2 border-primary font-bold'
                      : 'text-on-surface-variant hover:text-primary'
                  }`}
                >
                  <span className="material-symbols-outlined text-[18px]">bolt</span>
                  <span>Automation / Workflows</span>
                </button>
              </div>
            </div>

            <div className="flex items-center gap-2.5 shrink-0">
              {/* New Investigation Button in Navbar */}
              <button
                type="button"
                onClick={() => {
                  setInvestigationState((prev) => ({ ...prev, isInitialized: false }));
                  setActiveTab('home');
                }}
                className="btn-secondary text-xs font-semibold py-1.5 px-3 rounded-full flex items-center gap-1.5 whitespace-nowrap"
                title="Start a new investigation"
              >
                <Plus size={14} />
                <span className="hidden sm:inline">New Investigation</span>
              </button>

              {/* Demo Scenario Button */}
              <button
                type="button"
                onClick={handleRunFullDemoScenario}
                className="btn-primary text-xs font-semibold py-1.5 px-3 rounded-full flex items-center gap-1.5 shadow-xs whitespace-nowrap"
              >
                <span className="material-symbols-outlined text-[16px]">play_circle</span>
                <span className="hidden lg:inline">Run Demo Scenario</span>
              </button>

              {/* API Status Indicator Pill */}
              <div className="hidden xl:flex items-center gap-1.5 px-2.5 py-1 bg-surface-container-low rounded-full border border-outline-variant text-xs shrink-0">
                <span className={`w-2 h-2 rounded-full ${apiOnline ? 'bg-[#10B981]' : 'bg-error'}`}></span>
                <span className="text-on-surface-variant font-technical-data text-[11px]">
                  API: {apiOnline ? 'Online' : 'Offline'}
                </span>
              </div>

              {/* Global Theme Toggle Button */}
              <button
                type="button"
                onClick={toggleTheme}
                className="p-1.5 text-on-surface-variant hover:bg-surface-container-low rounded-full transition-all flex items-center justify-center"
                title={`Switch to ${theme === 'light' ? 'Dark' : 'Light'} Mode`}
              >
                <span className="material-symbols-outlined text-[20px]">{theme === 'light' ? 'dark_mode' : 'light_mode'}</span>
              </button>
            </div>
          </div>
        </nav>

        {/* Persistent Backend Unreachable Banner */}
        {!apiOnline && (
          <div className="bg-[#fff7ed] border-b border-[#fed7aa] px-4 sm:px-6 lg:px-8 py-2">
            <div className="max-w-[1440px] mx-auto flex items-center justify-between gap-4 text-xs">
              <div className="flex items-center gap-2 text-[#c2410c] font-semibold">
                <span className="material-symbols-outlined text-[16px]">wifi_off</span>
                <span>Backend Unreachable &mdash; Cannot connect to http://localhost:8000. Auto-retrying...</span>
              </div>
              <button
                onClick={checkHealth}
                className="px-3 py-1 bg-white border border-[#fed7aa] hover:bg-[#fff7ed] text-[#c2410c] rounded text-xs font-semibold"
              >
                Retry Now
              </button>
            </div>
          </div>
        )}

        {/* Investigation Context Banner Bar */}
        {investigationState.isInitialized && activeTab !== 'home' && (
          <div className="bg-surface-container-lowest border-b border-outline-variant px-4 sm:px-6 lg:px-8 py-2.5">
          <div className="max-w-[1440px] mx-auto flex flex-col sm:flex-row items-center justify-between gap-3 text-xs">
            <div className="flex flex-wrap items-center gap-3 text-xs font-body-md">
              <span className="flex items-center gap-1.5 text-on-background font-semibold">
                <span className="w-2 h-2 rounded-full bg-primary inline-block"></span>
                INVESTIGATION: <strong className="text-primary font-headline-md">{investigationState.brandName || brandName || 'Active Case'}</strong>
              </span>
              <span className="text-outline-variant">|</span>
              <span className="text-on-surface-variant font-technical-data">
                OFFICIAL DOMAIN: <strong className="text-on-background">{investigationState.officialDomain || domainScanState.domainInput || 'N/A'}</strong>
              </span>
              <span className="text-outline-variant">|</span>
              <span className="text-on-surface-variant">
                SOURCE: <strong className="text-on-background">Domain Monitoring</strong>
              </span>
              <span className="text-outline-variant">|</span>
              <span className="font-technical-data text-[11px] bg-surface-container px-2 py-0.5 rounded text-on-surface border border-outline-variant">
                {investigationState.investigationId || 'CASE-001'}
              </span>
            </div>

            <div className="flex items-center gap-2">
              <div className="w-28 bg-surface-container-highest h-2 rounded-full overflow-hidden border border-outline-variant">
                <div className="bg-primary h-full transition-all duration-300" style={{ width: `${completenessPercent}%` }}></div>
              </div>
              <span className="font-technical-data font-semibold text-primary">{completenessPercent}% Complete</span>
            </div>
          </div>
        </div>
        )}

        {/* Main Canvas Workspace Container */}
        <main className="max-w-[1440px] mx-auto w-full px-4 sm:px-6 lg:px-8 py-6 flex flex-col gap-6">
          {activeTab === 'home' && (
            <OnboardingPage
              onStartInvestigation={handleStartInvestigation}
              addToast={addToast}
            />
          )}

          {activeTab === 'domain' && (
            <DomainWatchTab
              apiBaseUrl={API_BASE_URL}
              addToast={addToast}
              selectedDomains={selectedDomains}
              toggleSelectDomain={toggleSelectDomain}
              domainScanState={domainScanState}
              setDomainScanState={setDomainScanState}
              investigationState={investigationState}
              onNavigateTab={setActiveTab}
            />
          )}

          {activeTab === 'logo' && (
            <LogoMatchTab
              apiBaseUrl={API_BASE_URL}
              addToast={addToast}
              selectedLogos={selectedLogos}
              toggleSelectLogo={toggleSelectLogo}
              logoMatchState={logoMatchState}
              setLogoMatchState={setLogoMatchState}
              investigationState={investigationState}
              setInvestigationState={setInvestigationState}
              onInvestigateCandidate={(item) => {
                setDomainScanState((prev) => ({ ...prev, selectedCandidateDetail: item }));
                setActiveTab('domain');
              }}
            />
          )}

          {activeTab === 'phishing' && (
            <VisualPhishingTab
              apiBaseUrl={API_BASE_URL}
              addToast={addToast}
              selectedVisualPhishing={selectedVisualPhishing}
              toggleSelectVisualPhishing={toggleSelectVisualPhishing}
            />
          )}

          {activeTab === 'listings' && (
            <MarketplaceListingsTab
              apiBaseUrl={API_BASE_URL}
              addToast={addToast}
              selectedListings={selectedListings}
              toggleSelectListing={toggleSelectListing}
            />
          )}

          {activeTab === 'social' && (
            <SocialWatchTab
              apiBaseUrl={API_BASE_URL}
              addToast={addToast}
              selectedSocialProfiles={selectedSocialProfiles}
              toggleSelectProfile={toggleSelectProfile}
            />
          )}

          {activeTab === 'infrastructure' && (
            <LinkedInfrastructureTab
              apiBaseUrl={API_BASE_URL}
              addToast={addToast}
              selectedDomains={selectedDomains}
              selectedLogos={selectedLogos}
              selectedVisualPhishing={selectedVisualPhishing}
              brandName={brandName}
              handleAddClusterToCase={handleAddClusterToCase}
              toggleSelectDomain={toggleSelectDomain}
            />
          )}

          {activeTab === 'case' && (
            <CaseReportTab
              apiBaseUrl={API_BASE_URL}
              addToast={addToast}
              selectedDomains={selectedDomains}
              setSelectedDomains={setSelectedDomains}
              selectedLogos={selectedLogos}
              setSelectedLogos={setSelectedLogos}
              selectedVisualPhishing={selectedVisualPhishing}
              setSelectedVisualPhishing={setSelectedVisualPhishing}
              selectedListings={selectedListings}
              setSelectedListings={setSelectedListings}
              selectedSocialProfiles={selectedSocialProfiles}
              setSelectedSocialProfiles={setSelectedSocialProfiles}
              brandName={brandName}
              setBrandName={setBrandName}
              notes={notes}
              setNotes={setNotes}
              handleClearCase={handleClearCase}
            />
          )}

          {activeTab === 'takedown' && (
            <AbuseControlSection
              apiBaseUrl={API_BASE_URL}
              caseId={investigationState.investigationId || 'default'}
              candidateDomain={selectedDomains[0]?.domain || 'amaz0n-security-login.xyz'}
              targetBrand={brandName || 'Amazon'}
              officialDomain={investigationState.officialDomain || 'amazon.com'}
              addToast={addToast}
            />
          )}

          {activeTab === 'workflows' && (
            <WorkflowAutomationTab
              apiBaseUrl={API_BASE_URL}
              addToast={addToast}
              onNavigateTab={setActiveTab}
            />
          )}
        </main>

        {/* DEMO SCENARIO OVERLAYS */}
        {demoStage >= 0 && (
          <DemoScenarioModal
            stage={demoStage}
            onStartDemo={handleStartDemo}
            onClose={() => { setDemoStage(-1); setIsDemoRunning(false); }}
            onNextStage={handleNextDemoStage}
            onNavigateTab={setActiveTab}
          />
        )}

        {isDemoRunning && (
          <DemoControllerBar
            currentStage={demoStage > 0 && demoStage <= 6 ? demoStage : 1}
            totalStages={6}
            isPaused={isDemoPaused}
            onTogglePause={() => setIsDemoPaused(!isDemoPaused)}
            onNextStage={handleNextDemoStage}
            onRestart={handleStartDemo}
            onExit={() => { setIsDemoRunning(false); setDemoStage(-1); }}
          />
        )}
      </div>
    </div>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <Dashboard />
    </ErrorBoundary>
  );
}
