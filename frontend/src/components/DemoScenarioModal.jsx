import React from 'react';
import {
  ShieldAlert, ShieldCheck, CheckCircle2, AlertTriangle, ArrowRight, Play, X, Sparkles,
  Image as ImageIcon, Globe, Server, Key, Lock, FileText, Zap, ChevronRight, RefreshCw, Eye
} from 'lucide-react';

const DemoScenarioModal = ({
  stage = 0,
  onStartDemo = () => {},
  onClose = () => {},
  onNextStage = () => {},
  onNavigateTab = () => {}
}) => {
  if (stage < 0 || stage > 7) return null;

  // STAGE 0: INTRO LAUNCHER MODAL
  if (stage === 0) {
    return (
      <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-md flex items-center justify-center p-4 animate-fade-in font-body-md">
        <div className="bg-surface-container-lowest border border-primary/40 rounded-2xl max-w-xl w-full p-6 shadow-2xl space-y-6 relative overflow-hidden">
          <div className="absolute -right-12 -top-12 w-40 h-40 bg-primary/10 rounded-full blur-2xl pointer-events-none"></div>

          <div className="flex items-center justify-between border-b border-outline-variant pb-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/30 flex items-center justify-center">
                <Sparkles size={22} className="text-primary" />
              </div>
              <div>
                <span className="font-technical-data text-[10px] font-bold text-primary tracking-wider uppercase block">
                  Interactive Judge Demo
                </span>
                <h2 className="font-headline-md font-bold text-xl text-on-background">
                  LIVE INVESTIGATION SIMULATION
                </h2>
              </div>
            </div>
            <button
              type="button"
              onClick={onClose}
              className="p-1.5 text-on-surface-variant hover:bg-surface-container-low rounded-lg transition-all"
            >
              <X size={18} />
            </button>
          </div>

          <div className="space-y-4 text-xs leading-relaxed text-on-surface-variant">
            <p>
              We will demonstrate how KEIKAI executes an end-to-end brand protection investigation across 6 key stages:
            </p>

            <div className="grid grid-cols-2 gap-2.5 font-technical-data">
              {[
                { num: '1', title: 'DISCOVER', desc: 'Permutations & Threat Feeds' },
                { num: '2', title: 'VERIFY', desc: '96.8% Logo & OCR Match' },
                { num: '3', title: 'CORRELATE', desc: 'Multi-Signal Evidence Chain' },
                { num: '4', title: 'INVESTIGATE', desc: 'Infrastructure Graph' },
                { num: '5', title: 'RESPOND', desc: 'Human Approval Safety Gate' },
                { num: '6', title: 'AUTOMATE', desc: 'viaSocket Event Dispatch' }
              ].map((s) => (
                <div key={s.num} className="bg-surface-container-low p-2.5 rounded-lg border border-outline-variant flex items-start gap-2">
                  <span className="w-5 h-5 rounded bg-primary text-on-primary font-bold text-[10px] flex items-center justify-center shrink-0">
                    {s.num}
                  </span>
                  <div>
                    <strong className="text-on-background block text-[11px]">{s.title}</strong>
                    <span className="text-[10px] text-on-surface-variant">{s.desc}</span>
                  </div>
                </div>
              ))}
            </div>

            <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3 text-[11px] text-amber-700 dark:text-amber-300 flex items-center gap-2">
              <AlertTriangle size={15} className="shrink-0" />
              <span>Demo data is simulated. No real takedowns or external emails will be sent during this scenario.</span>
            </div>
          </div>

          <div className="flex items-center justify-end gap-3 pt-2 border-t border-outline-variant">
            <button
              type="button"
              onClick={onClose}
              className="btn-secondary text-xs px-4 py-2 font-semibold"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={onStartDemo}
              className="btn-primary text-xs px-5 py-2 font-bold flex items-center gap-2 shadow-md"
            >
              <Play size={14} />
              <span>START DEMONSTRATION</span>
            </button>
          </div>
        </div>
      </div>
    );
  }

  // STAGE 7: FINAL DEMO SUMMARY OVERLAY
  if (stage === 7) {
    return (
      <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-lg flex items-center justify-center p-4 animate-fade-in font-body-md">
        <div className="bg-surface-container-lowest border border-primary/50 rounded-3xl max-w-2xl w-full p-8 shadow-2xl text-center space-y-6 relative overflow-hidden">
          <div className="w-16 h-16 rounded-2xl bg-primary/10 border border-primary/30 flex items-center justify-center mx-auto shadow-inner">
            <ShieldCheck size={36} className="text-primary animate-pulse" />
          </div>

          <div>
            <span className="font-headline-md font-bold text-2xl text-primary tracking-tight block">KEIKAI</span>
            <h2 className="font-headline-md font-extrabold text-xl text-on-background mt-1">
              BRAND PROTECTION INVESTIGATION COMPLETE
            </h2>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-technical-data text-xs text-left">
            <div className="bg-surface-container-low p-3 rounded-xl border border-outline-variant">
              <span className="text-[10px] text-on-surface-variant block font-bold">DISCOVERED</span>
              <strong className="text-sm font-bold text-on-background">7 Candidates</strong>
            </div>

            <div className="bg-surface-container-low p-3 rounded-xl border border-outline-variant">
              <span className="text-[10px] text-on-surface-variant block font-bold">VERIFIED</span>
              <strong className="text-sm font-bold text-primary">1 Impersonation</strong>
            </div>

            <div className="bg-surface-container-low p-3 rounded-xl border border-outline-variant">
              <span className="text-[10px] text-on-surface-variant block font-bold">VISUAL MATCH</span>
              <strong className="text-sm font-bold text-emerald-600">96.8% Match</strong>
            </div>

            <div className="bg-surface-container-low p-3 rounded-xl border border-outline-variant">
              <span className="text-[10px] text-on-surface-variant block font-bold">EVIDENCE QUALITY</span>
              <strong className="text-sm font-bold text-on-background">91/100 (COMPLETE)</strong>
            </div>
          </div>

          <div className="bg-surface-container-low p-4 rounded-xl border border-outline-variant text-xs text-left space-y-2 font-technical-data">
            <div className="flex justify-between items-center border-b border-outline-variant pb-1.5">
              <span>RESPONSE READINESS</span>
              <span className="font-bold text-emerald-600">HUMAN APPROVAL REQUIRED</span>
            </div>
            <div className="flex justify-between items-center">
              <span>ORCHESTRATION ENGINE</span>
              <span className="font-bold text-primary">viaSocket Delivered ✓</span>
            </div>
          </div>

          <div className="py-3 px-4 bg-primary/10 border border-primary/30 rounded-xl text-sm font-bold text-primary tracking-wide italic">
            "KEIKAI doesn't just detect threats. It builds the evidence to act on them."
          </div>

          <div className="flex items-center justify-center gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="btn-secondary text-xs px-6 py-2.5 font-bold"
            >
              Exit Demo
            </button>
            <button
              type="button"
              onClick={onStartDemo}
              className="btn-primary text-xs px-6 py-2.5 font-bold flex items-center gap-2"
            >
              <RefreshCw size={14} />
              <span>Replay Demo</span>
            </button>
          </div>
        </div>
      </div>
    );
  }

  // STAGES 1 - 6 STAGE CARDS OVERLAY
  const renderStageCard = () => {
    switch (stage) {
      case 1:
        return (
          <div className="space-y-4">
            <div className="flex justify-between items-center border-b border-outline-variant pb-2">
              <span className="font-technical-data text-[10px] font-bold text-primary">STAGE 1 &middot; DISCOVER</span>
              <span className="text-xs font-bold text-emerald-600">7 Candidates Discovered</span>
            </div>

            <p className="text-xs text-on-surface-variant leading-relaxed">
              KEIKAI queries dnstwist permutation generators and multi-source threat feeds (OpenPhish, PhishTank) to identify potential brand impersonation assets.
            </p>

            <div className="bg-surface-container-low p-3.5 rounded-xl border border-outline-variant space-y-2 font-technical-data text-xs">
              <div className="flex justify-between items-center">
                <span className="flex items-center gap-1.5"><Globe size={14} className="text-primary" /> Target Brand</span>
                <strong className="text-on-background">Amazon (amazon.com)</strong>
              </div>
              <div className="flex justify-between items-center border-t border-outline-variant pt-2">
                <span>Top Candidate Domain</span>
                <strong className="text-primary">amazon-security-login.example</strong>
              </div>
              <div className="flex justify-between items-center pt-1">
                <span>Threat Feed Presence</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-600 border border-emerald-500/20">3 / 3 FEEDS CONFIRMED</span>
              </div>
            </div>
          </div>
        );

      case 2:
        return (
          <div className="space-y-4">
            <div className="flex justify-between items-center border-b border-outline-variant pb-2">
              <span className="font-technical-data text-[10px] font-bold text-primary">STAGE 2 &middot; VERIFY</span>
              <span className="text-xs font-bold text-primary">Phishpedia Model Verified</span>
            </div>

            <p className="text-xs text-on-surface-variant leading-relaxed">
              Live screenshot acquisition triggers 8 visual logo fallback layers, extracting perceptual hashes, feature embeddings, and OCR text.
            </p>

            {/* SIDE-BY-SIDE VISUAL LOGO MOMENT */}
            <div className="bg-surface-container-low p-4 rounded-xl border border-outline-variant space-y-3 font-technical-data text-xs">
              <div className="text-[10px] font-bold text-on-surface-variant flex items-center gap-1">
                <ImageIcon size={13} className="text-primary" /> VISUAL LOGO IDENTITY CORRELATION MOMENT
              </div>

              <div className="grid grid-cols-2 gap-4 text-center">
                <div className="bg-surface p-3 rounded-lg border border-outline-variant flex flex-col items-center justify-center gap-2">
                  <span className="text-[10px] text-on-surface-variant font-bold">OFFICIAL BRAND LOGO</span>
                  <div className="w-24 h-12 bg-white rounded p-1 flex items-center justify-center border border-outline-variant shadow-xs">
                    <span className="font-bold text-xl text-black tracking-tight font-serif">amazon</span>
                  </div>
                  <span className="text-[10px] font-bold text-on-background">Target: Amazon</span>
                </div>

                <div className="bg-surface p-3 rounded-lg border border-primary/40 flex flex-col items-center justify-center gap-2 ring-1 ring-primary/20">
                  <span className="text-[10px] text-primary font-bold">DETECTED ASSET LOGO</span>
                  <div className="w-24 h-12 bg-white rounded p-1 flex items-center justify-center border border-outline-variant shadow-xs">
                    <span className="font-bold text-xl text-black tracking-tight font-serif">amazon</span>
                  </div>
                  <span className="text-[10px] font-bold text-primary">Candidate Screenshot</span>
                </div>
              </div>

              {/* SIMILARITY METER */}
              <div className="space-y-1.5 pt-1">
                <div className="flex justify-between items-center text-[11px]">
                  <span className="font-bold text-on-background">Visual Brand Similarity</span>
                  <span className="font-bold text-emerald-600 text-sm">96.8% MATCH</span>
                </div>
                <div className="w-full bg-surface-container-highest h-2.5 rounded-full overflow-hidden border border-outline-variant">
                  <div className="bg-emerald-500 h-full rounded-full transition-all duration-700" style={{ width: '96.8%' }}></div>
                </div>
              </div>
            </div>
          </div>
        );

      case 3:
        return (
          <div className="space-y-4">
            <div className="flex justify-between items-center border-b border-outline-variant pb-2">
              <span className="font-technical-data text-[10px] font-bold text-primary">STAGE 3 &middot; CORRELATE</span>
              <span className="text-xs font-bold text-primary">Evidence Chain Built</span>
            </div>

            <p className="text-xs text-on-surface-variant leading-relaxed">
              Multi-signal correlation combines lexical domain analysis, visual logo similarity, OCR brand text, threat intel feeds, and credential form indicators into an unbroken evidence chain.
            </p>

            {/* EVIDENCE CHAIN VISUALIZER */}
            <div className="bg-surface-container-low p-4 rounded-xl border border-outline-variant space-y-2 font-technical-data text-[11px]">
              <div className="text-[10px] font-bold text-on-surface-variant mb-2">MULTI-SIGNAL EVIDENCE CHAIN</div>

              <div className="space-y-1.5">
                {[
                  { step: 'LOOKALIKE DOMAIN', val: 'amazon-security-login.example', badge: 'TYPOSQUAT' },
                  { step: 'LOGO MATCH', val: 'Phishpedia Model', badge: '96.8%' },
                  { step: 'OCR BRAND TEXT', val: 'Extracted String "Amazon"', badge: 'MATCHED' },
                  { step: 'LOGIN FORM', val: 'Password Input Detected', badge: 'CREDENTIAL' },
                  { step: 'THREAT INTEL', val: 'OpenPhish + PhishTank Feeds', badge: '3 SOURCES' },
                  { step: 'INFRASTRUCTURE', val: '4 Linked Cluster Assets', badge: '2 SHARED IPS' }
                ].map((item, i) => (
                  <div key={i} className="flex items-center justify-between bg-surface p-2 rounded border border-outline-variant">
                    <span className="text-on-surface-variant">{item.step}</span>
                    <span className="font-bold text-on-background truncate max-w-[160px]">{item.val}</span>
                    <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-primary/10 text-primary border border-primary/20">{item.badge}</span>
                  </div>
                ))}
              </div>

              <div className="pt-2 text-center">
                <span className="px-3 py-1 bg-emerald-500/10 text-emerald-600 border border-emerald-500/30 rounded-full font-bold text-xs">
                  VERDICT: HIGH-CONFIDENCE IMPERSONATION (RISK 92/100)
                </span>
              </div>
            </div>
          </div>
        );

      case 4:
        return (
          <div className="space-y-4">
            <div className="flex justify-between items-center border-b border-outline-variant pb-2">
              <span className="font-technical-data text-[10px] font-bold text-primary">STAGE 4 &middot; INVESTIGATE</span>
              <span className="text-xs font-bold text-primary">Infrastructure Graph Loaded</span>
            </div>

            <p className="text-xs text-on-surface-variant leading-relaxed">
              KEIKAI correlates candidate IP resolution, MX mail servers, and shared SSL/logo fingerprints across database clusters to reveal operator infrastructure networks.
            </p>

            <div className="bg-surface-container-low p-4 rounded-xl border border-outline-variant space-y-3 font-technical-data text-xs">
              <div className="flex justify-between items-center">
                <span>Cluster ID</span>
                <strong className="text-primary font-bold">CLUSTER-AMAZON-092</strong>
              </div>
              <div className="flex justify-between items-center">
                <span>Shared Infrastructure Assets</span>
                <strong className="text-on-background">4 Related Domains</strong>
              </div>
              <div className="flex justify-between items-center">
                <span>Hosting IP Address</span>
                <strong className="text-on-background font-mono">104.21.48.91 (Cloudflare)</strong>
              </div>

              <div className="flex items-center gap-2 pt-2 border-t border-outline-variant justify-center">
                <button
                  type="button"
                  onClick={() => onNavigateTab('infrastructure')}
                  className="btn-secondary text-xs px-3 py-1.5 font-bold flex items-center gap-1"
                >
                  <Eye size={13} /> View Infrastructure Graph
                </button>
              </div>
            </div>
          </div>
        );

      case 5:
        return (
          <div className="space-y-4">
            <div className="flex justify-between items-center border-b border-outline-variant pb-2">
              <span className="font-technical-data text-[10px] font-bold text-primary">STAGE 5 &middot; RESPOND (SAFETY GATE)</span>
              <span className="text-xs font-bold text-emerald-600">HUMAN APPROVAL MANDATORY</span>
            </div>

            <p className="text-xs text-on-surface-variant leading-relaxed">
              Task 5/6 security control plane creates a persistent frozen evidence snapshot and computes SHA-256 integrity hashes. External takedowns strictly require human analyst approval.
            </p>

            <div className="bg-surface-container-low p-4 rounded-xl border border-outline-variant space-y-2.5 font-technical-data text-xs">
              <div className="flex justify-between items-center border-b border-outline-variant pb-2">
                <span>Evidence Integrity Hash</span>
                <span className="font-mono text-[10px] text-primary font-bold">SHA-256 VERIFIED ✓</span>
              </div>
              <div className="flex justify-between items-center">
                <span>Frozen Snapshot ID</span>
                <strong className="text-on-background">SNAP-2026-0823-921</strong>
              </div>
              <div className="flex justify-between items-center">
                <span>Resolved Provider Route</span>
                <strong className="text-on-background">Cloudflare Abuse Form (DRY_RUN)</strong>
              </div>

              <div className="bg-amber-500/10 border border-amber-500/30 p-2.5 rounded-lg text-[11px] text-amber-700 dark:text-amber-300 font-bold text-center">
                HUMAN APPROVAL BOUNDARY ENFORCED &mdash; No autonomous takedown dispatched without analyst review.
              </div>
            </div>
          </div>
        );

      case 6:
        return (
          <div className="space-y-4">
            <div className="flex justify-between items-center border-b border-outline-variant pb-2">
              <span className="font-technical-data text-[10px] font-bold text-primary">STAGE 6 &middot; AUTOMATE (viaSOCKET)</span>
              <span className="text-xs font-bold text-primary">Event Delivered ✓</span>
            </div>

            <p className="text-xs text-on-surface-variant leading-relaxed">
              viaSocket orchestrates investigation notifications and case status updates while KEIKAI backend retains strict authority over approval boundaries.
            </p>

            <div className="bg-surface-container-low p-4 rounded-xl border border-outline-variant space-y-2 font-technical-data text-xs">
              <div className="flex justify-between items-center">
                <span>Event Type</span>
                <strong className="text-primary">IMPERSONATION_CONFIRMED</strong>
              </div>
              <div className="flex justify-between items-center">
                <span>Delivery Status</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-600 border border-emerald-500/20">DELIVERED</span>
              </div>
              <div className="flex justify-between items-center">
                <span>Payload Sanitation</span>
                <span className="text-on-surface-variant font-bold">API Keys & Credentials Stripped</span>
              </div>
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-md flex items-center justify-center p-4 animate-fade-in font-body-md">
      <div className="bg-surface-container-lowest border border-primary/40 rounded-2xl max-w-xl w-full p-6 shadow-2xl space-y-5 relative overflow-hidden">
        <div className="flex items-center justify-between border-b border-outline-variant pb-3">
          <div className="flex items-center gap-2">
            <Sparkles size={18} className="text-primary animate-pulse" />
            <h3 className="font-headline-md font-bold text-base text-on-background">
              LIVE INVESTIGATION DEMONSTRATION &middot; STAGE {stage} OF 6
            </h3>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1 text-on-surface-variant hover:bg-surface-container-low rounded-lg transition-all"
          >
            <X size={16} />
          </button>
        </div>

        {renderStageCard()}

        <div className="flex items-center justify-between pt-3 border-t border-outline-variant">
          <button
            type="button"
            onClick={onClose}
            className="btn-secondary text-xs px-3 py-1.5 font-bold"
          >
            Close
          </button>
          <button
            type="button"
            onClick={onNextStage}
            className="btn-primary text-xs px-4 py-1.5 font-bold flex items-center gap-1.5"
          >
            <span>{stage === 6 ? 'VIEW FINAL SUMMARY' : 'CONTINUE TO NEXT STAGE'}</span>
            <ArrowRight size={14} />
          </button>
        </div>
      </div>
    </div>
  );
};

export default DemoScenarioModal;
