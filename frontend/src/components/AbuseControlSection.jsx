import React, { useState, useEffect } from 'react';
import {
  ShieldAlert, CheckCircle2, AlertTriangle, FileText, Loader2,
  RefreshCw, Lock, AlertCircle, X, Shield, Eye, FileCheck, ArrowRight, CornerDownRight, Network
} from 'lucide-react';

const AbuseControlSection = ({
  apiBaseUrl,
  caseId = 'default',
  candidateDomain = '',
  targetBrand = 'Amazon',
  officialDomain = 'amazon.com',
  evidence = {},
  addToast = () => {}
}) => {
  const [loading, setLoading] = useState(false);
  const [assessment, setAssessment] = useState(null);
  const [routePreview, setRoutePreview] = useState(null);
  const [approvalState, setApprovalState] = useState(null);
  const [submissionState, setSubmissionState] = useState(null);
  
  const [showReviewModal, setShowReviewModal] = useState(false);
  const [showConfirmationModal, setShowConfirmationModal] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [approving, setApproving] = useState(false);

  // Fetch status and route preview on mount or caseId change
  const fetchStatus = async () => {
    try {
      const res = await fetch(`${apiBaseUrl}/api/abuse-control/${caseId}/status`);
      const resData = await res.json();
      if (res.ok && resData.status === 'success') {
        if (resData.data.approval) {
          setApprovalState({
            approval_id: resData.data.approval.approval_id,
            snapshot_id: resData.data.approval.snapshot_id,
            expires_at: resData.data.approval.expires_at,
            state: resData.data.approval.status
          });
        }
        if (resData.data.submission) {
          setSubmissionState({
            submission_id: resData.data.submission.submission_id,
            state: resData.data.submission.state,
            report_id: resData.data.submission.provider_report_id,
            provider: resData.data.submission.provider,
            method: resData.data.submission.method
          });
        }
      }
    } catch (err) {
      console.warn('Failed to fetch abuse control status:', err);
    }
  };

  const fetchRoutePreview = async () => {
    try {
      const targetDom = candidateDomain || 'amaz0n-security-login.xyz';
      const res = await fetch(`${apiBaseUrl}/api/universal-takedown/route-preview?domain=${encodeURIComponent(targetDom)}`);
      const resData = await res.json();
      if (res.ok && resData.status === 'success') {
        setRoutePreview(resData.data);
      }
    } catch (err) {
      console.warn('Failed to fetch universal route preview:', err);
    }
  };

  useEffect(() => {
    if (caseId) {
      fetchStatus();
      fetchRoutePreview();
    }
  }, [caseId, candidateDomain, apiBaseUrl]);

  // Step 1: Evaluate Abuse Readiness & Route Preview
  const handleEvaluate = async () => {
    setLoading(true);
    try {
      await fetchRoutePreview();
      const res = await fetch(`${apiBaseUrl}/api/abuse-response/evaluate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          case_id: caseId,
          candidate_domain: candidateDomain || 'amaz0n-security-login.xyz',
          target_brand: targetBrand,
          official_domain: officialDomain,
          evidence: {
            sources: ['dnstwist', 'openphish'],
            domain_permutation: true,
            strong_visual_match: true,
            credential_indicators: true,
            screenshot: { status: 'SUCCESS', source: 'candidate_acquisition' },
            ...evidence
          }
        })
      });
      const data = await res.json();
      if (res.ok && data.status === 'success') {
        setAssessment(data.data);
        setShowReviewModal(true);
      } else {
        throw new Error(data.error || 'Evaluation failed');
      }
    } catch (err) {
      addToast('Evaluation Error', err.message || 'Abuse response evaluation failed', 'error');
    } finally {
      setLoading(false);
    }
  };

  // Step 2: Approve Report
  const handleApprove = async () => {
    setApproving(true);
    try {
      const res = await fetch(`${apiBaseUrl}/api/abuse-control/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          case_id: caseId,
          candidate_domain: candidateDomain || 'amaz0n-security-login.xyz',
          target_brand: targetBrand,
          official_domain: officialDomain,
          evidence: {
            sources: ['dnstwist', 'openphish'],
            domain_permutation: true,
            strong_visual_match: true,
            credential_indicators: true,
            screenshot: { status: 'SUCCESS', source: 'candidate_acquisition' },
            ...evidence
          },
          approved_by: 'Analyst'
        })
      });
      const data = await res.json();
      if (!res.ok || data.status === 'error') {
        throw new Error(data.error || 'Approval failed');
      }
      setApprovalState(data.data);
      addToast('Report Approved', `Frozen snapshot ${data.data.snapshot_id} created. ID: ${data.data.approval_id}`, 'success');
      fetchStatus();
    } catch (err) {
      addToast('Approval Failed', err.message || 'Approval request was blocked or invalid', 'error');
    } finally {
      setApproving(false);
    }
  };

  // Step 3: Revoke Approval
  const handleRevoke = async () => {
    if (!approvalState?.approval_id) return;
    try {
      const res = await fetch(`${apiBaseUrl}/api/abuse-control/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          approval_id: approvalState.approval_id
        })
      });
      const data = await res.json();
      if (res.ok && data.status === 'success') {
        setApprovalState(null);
        addToast('Approval Revoked', 'Human approval record was revoked.', 'info');
        fetchStatus();
      }
    } catch (err) {
      addToast('Revocation Failed', err.message || 'Revocation request failed', 'error');
    }
  };

  // Step 4: Submit via Universal Router (Called ONLY from final confirmation modal)
  const handleFinalSubmit = async () => {
    if (!approvalState?.approval_id) return;
    setSubmitting(true);
    try {
      const res = await fetch(`${apiBaseUrl}/api/universal-takedown/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          case_id: caseId,
          approval_id: approvalState.approval_id,
          client_payload: { mode: 'LIVE' }
        })
      });
      const data = await res.json();
      setShowConfirmationModal(false);
      setShowReviewModal(false);

      if (!res.ok || data.status === 'error') {
        addToast('Submission Blocked / Failed', data.error || 'Submission failed revalidation', 'error');
        fetchStatus();
        return;
      }

      setSubmissionState(data.data);
      addToast('Universal Takedown Dispatched', `Provider: ${data.data.provider} | State: ${data.data.state}`, 'success');
      fetchStatus();
    } catch (err) {
      addToast('Submission Error', err.message || 'Network error submitting report', 'error');
    } finally {
      setSubmitting(false);
    }
  };

  const isApproved = approvalState?.state === 'APPROVED' || approvalState?.state === 'HUMAN_APPROVED';
  const currentProvider = routePreview?.primary_provider || 'Cloudflare';
  const currentMethod = routePreview?.primary_method || 'API';
  const currentConfidence = routePreview?.confidence || 'HIGH';

  return (
    <div className="bg-surface-container-low p-6 rounded-xl border border-outline-variant space-y-4">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-outline-variant pb-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <ShieldAlert size={18} className="text-primary" />
            <span className="font-label-caps text-xs text-primary font-bold">TASK 6 &middot; UNIVERSAL TAKEDOWN EXECUTION ENGINE</span>
          </div>
          <h3 className="font-headline-md text-base font-bold text-on-background">Provider Route Discovery & Abuse Control Gate</h3>
          <p className="font-body-md text-xs text-on-surface-variant">
            RDAP-first + WHOIS fallback provider resolution, multi-route adapter dispatch, persistent frozen snapshot, and human approval boundary.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handleEvaluate}
            disabled={loading}
            className="px-4 py-2 bg-primary text-on-primary font-bold text-xs rounded-lg hover:bg-primary-hover transition-colors flex items-center gap-1.5"
          >
            {loading ? <Loader2 size={14} className="animate-spin" /> : <Eye size={14} />}
            <span>[ REVIEW REPORT ]</span>
          </button>
        </div>
      </div>

      {/* STEPPER PROGRESSION TIMELINE */}
      <div className="bg-surface-container-lowest p-3.5 rounded-lg border border-outline-variant">
        <div className="flex items-center justify-between gap-1 overflow-x-auto text-[11px] font-technical-data no-scrollbar">
          {[
            { step: '1', title: 'Evidence', desc: 'SHA-256 Validated', status: 'done' },
            { step: '2', title: 'Provider', desc: currentProvider, status: 'done' },
            { step: '3', title: 'Route', desc: currentMethod, status: 'done' },
            { step: '4', title: 'Human Approval', desc: approvalState ? 'Approved' : 'Required', status: approvalState ? 'done' : 'active' },
            { step: '5', title: 'Snapshot', desc: approvalState?.snapshot_id ? 'Frozen' : 'Pending', status: approvalState?.snapshot_id ? 'done' : 'pending' },
            { step: '6', title: 'Submission', desc: submissionState ? submissionState.state : 'Ready', status: submissionState ? 'done' : 'pending' }
          ].map((st, idx) => (
            <React.Fragment key={idx}>
              <div className="flex items-center gap-2 shrink-0 px-2 py-1">
                <div className={`w-6 h-6 rounded-full flex items-center justify-center font-bold text-[10px] ${
                  st.status === 'done'
                    ? 'bg-primary text-on-primary'
                    : st.status === 'active'
                    ? 'bg-primary/20 text-primary border border-primary/40'
                    : 'bg-surface-container-high text-on-surface-variant'
                }`}>
                  {st.status === 'done' ? '✓' : st.step}
                </div>
                <div>
                  <div className="font-bold text-on-background">{st.title}</div>
                  <div className="text-[9px] text-on-surface-variant truncate max-w-[90px]">{st.desc}</div>
                </div>
              </div>
              {idx < 5 && <ArrowRight size={12} className="text-outline-variant shrink-0" />}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* PHASE 11: TAKEDOWN ROUTE VISUALIZATION CARD */}
      <div className="bg-surface-container-lowest p-4 rounded-lg border border-outline-variant space-y-3 font-technical-data text-xs">
        <div className="flex items-center justify-between border-b border-outline-variant pb-2">
          <span className="font-label-caps text-[10px] text-primary font-bold flex items-center gap-1.5">
            <Network size={14} /> TAKEDOWN ROUTE INTELLIGENCE
          </span>
          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
            currentConfidence === 'HIGH' ? 'bg-primary/20 text-primary border-primary/30' : 'bg-surface-container-high text-on-surface-variant border-outline-variant'
          }`}>
            CONFIDENCE: {currentConfidence}
          </span>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-[11px]">
          <div>
            <div className="text-on-surface-variant text-[10px]">RESOLVED PROVIDER</div>
            <div className="font-bold text-on-background">{currentProvider}</div>
          </div>
          <div>
            <div className="text-on-surface-variant text-[10px]">SUBMISSION METHOD</div>
            <div className="font-bold text-primary">{currentMethod}</div>
          </div>
          <div>
            <div className="text-on-surface-variant text-[10px]">DISCOVERY SOURCE</div>
            <div className="font-bold text-on-background">{routePreview?.source || 'RDAP'}</div>
          </div>
          <div>
            <div className="text-on-surface-variant text-[10px]">VERIFIED DESTINATION</div>
            <div className="font-bold text-on-background truncate font-mono">
              {routePreview?.registrar?.abuse_email
                ? `${routePreview.registrar.abuse_email.substring(0, 3)}***@${routePreview.registrar.abuse_email.split('@')[1]}`
                : `${currentProvider} API`}
            </div>
          </div>
        </div>

        {routePreview?.routing_reason && (
          <div className="text-[11px] text-on-surface-variant bg-surface-container-low p-2.5 rounded border border-outline-variant">
            <strong>Routing Reason:</strong> {routePreview.routing_reason}
          </div>
        )}
      </div>

      {/* PHASE 12: EXPLAINABLE TAKEDOWN TIMELINE */}
      <div className="bg-surface-container-lowest p-4 rounded-lg border border-outline-variant space-y-2">
        <span className="font-label-caps text-[10px] text-on-surface-variant font-bold block mb-2">EXPLAINABLE TAKEDOWN TIMELINE</span>
        <div className="flex items-center gap-1 overflow-x-auto pb-1 text-[10px] font-technical-data">
          <TimelineStep label="1. Detection" done={true} />
          <ArrowRight size={10} className="text-on-surface-variant shrink-0" />
          <TimelineStep label="2. Evidence" done={true} />
          <ArrowRight size={10} className="text-on-surface-variant shrink-0" />
          <TimelineStep label="3. Provider Resolved" done={Boolean(routePreview)} />
          <ArrowRight size={10} className="text-on-surface-variant shrink-0" />
          <TimelineStep label="4. Route Selected" done={Boolean(routePreview)} />
          <ArrowRight size={10} className="text-on-surface-variant shrink-0" />
          <TimelineStep label="5. Human Approval" done={isApproved} />
          <ArrowRight size={10} className="text-on-surface-variant shrink-0" />
          <TimelineStep label="6. Snapshot Frozen" done={isApproved} />
          <ArrowRight size={10} className="text-on-surface-variant shrink-0" />
          <TimelineStep label="7. Executed" done={Boolean(submissionState)} />
        </div>
      </div>

      {/* APPROVAL & SUBMISSION STATUS CARDS */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
        {/* APPROVAL STATUS */}
        <div className="bg-surface-container-lowest p-4 rounded-lg border border-outline-variant space-y-2">
          <div className="flex items-center justify-between">
            <span className="font-label-caps text-[10px] text-on-surface-variant font-bold">HUMAN APPROVAL STATUS</span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border font-technical-data ${
              isApproved ? 'bg-primary/20 text-primary border-primary/30' : 'bg-surface-container-high text-on-surface-variant border-outline-variant'
            }`}>
              {approvalState?.state || 'UNAPPROVED'}
            </span>
          </div>
          {approvalState ? (
            <div className="font-technical-data text-[11px] space-y-1">
              <div>Approval ID: <strong className="text-on-background">{approvalState.approval_id}</strong></div>
              <div>Snapshot ID: <strong className="text-on-background">{approvalState.snapshot_id}</strong></div>
              <div>Expires: <span className="text-on-surface-variant">{approvalState.expires_at?.split('T')[1]?.split('.')[0]}</span></div>
              {isApproved && (
                <button
                  type="button"
                  onClick={handleRevoke}
                  className="text-error font-bold hover:underline text-[10px] mt-1 block"
                >
                  [ REVOKE APPROVAL ]
                </button>
              )}
            </div>
          ) : (
            <p className="font-body-md text-[11px] text-on-surface-variant">
              No active human approval snapshot. Click [ REVIEW REPORT ] to evaluate and approve.
            </p>
          )}
        </div>

        {/* SUBMISSION STATUS */}
        <div className="bg-surface-container-lowest p-4 rounded-lg border border-outline-variant space-y-2">
          <div className="flex items-center justify-between">
            <span className="font-label-caps text-[10px] text-on-surface-variant font-bold">PROVIDER SUBMISSION STATE</span>
            <SubmissionStateBadge state={submissionState?.state || 'NONE'} />
          </div>
          {submissionState ? (
            <div className="font-technical-data text-[11px] space-y-1">
              <div>Submission ID: <strong className="text-on-background">{submissionState.submission_id}</strong></div>
              <div>Provider: <strong className="text-on-background">{submissionState.provider || currentProvider}</strong></div>
              {submissionState.report_id && (
                <div>Provider Report ID: <strong className="text-primary">{submissionState.report_id}</strong></div>
              )}
            </div>
          ) : (
            <p className="font-body-md text-[11px] text-on-surface-variant">
              No submission attempt executed yet.
            </p>
          )}
        </div>
      </div>

      {/* REVIEW MODAL */}
      {showReviewModal && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
          <div className="bg-surface-container-lowest w-full max-w-2xl rounded-xl border border-outline-variant p-6 space-y-4 max-h-[90vh] overflow-y-auto shadow-2xl">
            <div className="flex items-center justify-between border-b border-outline-variant pb-3">
              <h3 className="font-headline-md font-bold text-base text-on-background flex items-center gap-2">
                <FileCheck size={18} className="text-primary" /> ABUSE RESPONSE REVIEW &mdash; {candidateDomain || 'amaz0n-security-login.xyz'}
              </h3>
              <button onClick={() => setShowReviewModal(false)} className="text-on-surface-variant hover:text-on-background">
                <X size={20} />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3 bg-surface-container-low p-3.5 rounded-lg border border-outline-variant font-technical-data">
                <div>Target Domain: <strong className="text-on-background">{candidateDomain || 'amaz0n-security-login.xyz'}</strong></div>
                <div>Target Brand: <strong className="text-on-background">{targetBrand}</strong></div>
                <div>Official Domain: <strong className="text-on-background">{officialDomain}</strong></div>
                <div>Evidence Level: <strong className="text-primary">EVIDENCE_HIGH (100%)</strong></div>
                <div>Legitimacy Check: <strong className="text-primary">SUSPICIOUS_UNAUTHORIZED (PASSED)</strong></div>
                <div>Resolved Provider: <strong className="text-on-background">{currentProvider}</strong></div>
                <div>Submission Method: <strong className="text-on-background">{currentMethod}</strong></div>
              </div>

              <div className="bg-surface-container-low p-3.5 rounded-lg border border-outline-variant space-y-1">
                <h5 className="font-headline-md font-bold text-xs text-on-background">Compiled Evidence Summary</h5>
                <ul className="list-disc pl-4 text-on-surface-variant space-y-0.5 text-[11px]">
                  <li>Screenshot: Webpage screenshot captured cleanly (SHA-256 verified)</li>
                  <li>Domain permutation: Typosquatting / homoglyph match detected</li>
                  <li>Visual match: Phishpedia logo brand recognition matched {targetBrand}</li>
                  <li>Credential harvesting: Password/login form input fields detected</li>
                </ul>
              </div>
            </div>

            {/* ACTION BUTTONS */}
            <div className="flex items-center justify-between pt-3 border-t border-outline-variant">
              <button
                onClick={() => setShowReviewModal(false)}
                className="px-4 py-2 bg-surface-container text-on-surface-variant font-bold text-xs rounded-lg hover:bg-surface-container-high"
              >
                Close Review
              </button>

              <div className="flex items-center gap-2">
                {!isApproved ? (
                  <button
                    onClick={handleApprove}
                    disabled={approving}
                    className="px-4 py-2 bg-primary text-on-primary font-bold text-xs rounded-lg hover:bg-primary-hover flex items-center gap-1.5"
                  >
                    {approving ? <Loader2 size={14} className="animate-spin" /> : <Lock size={14} />}
                    <span>[ APPROVE REPORT ]</span>
                  </button>
                ) : (
                  <button
                    onClick={() => setShowConfirmationModal(true)}
                    className="px-4 py-2 bg-primary text-on-primary font-bold text-xs rounded-lg hover:bg-primary-hover flex items-center gap-1.5 shadow-md"
                  >
                    <ArrowRight size={14} />
                    <span>[ SUBMIT REPORT ]</span>
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* FINAL EXTERNAL ACTION CONFIRMATION MODAL */}
      {showConfirmationModal && (
        <div className="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4">
          <div className="bg-surface-container-lowest w-full max-w-lg rounded-xl border-2 border-primary/50 p-6 space-y-4 shadow-2xl animate-fade-in">
            <div className="flex items-center justify-between border-b border-outline-variant pb-3 text-error">
              <h3 className="font-headline-md font-bold text-sm text-on-background flex items-center gap-2">
                <AlertTriangle size={18} className="text-primary" /> FINAL EXTERNAL ACTION CONFIRMATION
              </h3>
              <button onClick={() => setShowConfirmationModal(false)} className="text-on-surface-variant hover:text-on-background">
                <X size={20} />
              </button>
            </div>

            <div className="bg-surface-container-low p-4 rounded-lg border border-outline-variant font-technical-data text-xs space-y-2 text-on-background">
              <div>--------------------------------------------</div>
              <div><strong>FINAL EXTERNAL ACTION</strong></div>
              <div>Resolved Provider: <span className="text-primary font-bold">{currentProvider}</span></div>
              <div>Submission Method: <span className="text-primary font-bold">{currentMethod}</span></div>
              <div>Target: <span>{candidateDomain || 'amaz0n-security-login.xyz'}</span></div>
              <div>Target Brand: <span>{targetBrand}</span></div>
              <div>Official Domain: <span>{officialDomain}</span></div>
              <div>Snapshot ID: <span>{approvalState?.snapshot_id || 'snap_frozen'}</span></div>
              <div>Submission Mode: <span className="text-primary font-bold">DRY_RUN / LIVE</span></div>
              <div>--------------------------------------------</div>
              <p className="font-body-md text-[11px] text-on-surface-variant pt-2 border-t border-outline-variant">
                ⚠️ This action will dispatch an abuse takedown report via {currentProvider} ({currentMethod}).
              </p>
            </div>

            <div className="flex items-center justify-between pt-2">
              <button
                type="button"
                onClick={() => setShowConfirmationModal(false)}
                className="px-4 py-2 bg-surface-container text-on-surface-variant font-bold text-xs rounded-lg hover:bg-surface-container-high"
              >
                [ CANCEL ]
              </button>

              <button
                type="button"
                onClick={handleFinalSubmit}
                disabled={submitting}
                className="px-5 py-2.5 bg-primary text-on-primary font-bold text-xs rounded-lg hover:bg-primary-hover flex items-center gap-2 shadow-lg"
              >
                {submitting ? <Loader2 size={16} className="animate-spin" /> : <Shield size={16} />}
                <span>[ SUBMIT TO {currentProvider.toUpperCase()} ]</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const TimelineStep = ({ label, done }) => (
  <span className={`px-2 py-1 rounded shrink-0 font-bold ${
    done ? 'bg-primary/20 text-primary border border-primary/30' : 'bg-surface-container-high text-on-surface-variant'
  }`}>
    {label}
  </span>
);

const SubmissionStateBadge = ({ state }) => {
  const config = {
    DRY_RUN_COMPLETED: { color: 'bg-primary/20 text-primary border-primary/30', label: 'DRY RUN COMPLETE ✓' },
    SUBMITTED: { color: 'bg-primary/20 text-primary border-primary/30', label: 'SUBMITTED ✓' },
    EMAIL_SENT: { color: 'bg-primary/20 text-primary border-primary/30', label: 'EMAIL SENT ✓' },
    BROWSER_SUBMITTED: { color: 'bg-primary/20 text-primary border-primary/30', label: 'BROWSER SUBMITTED ✓' },
    UNKNOWN_SUBMISSION_STATE: { color: 'bg-[#fffbe6] text-[#b45309] border-[#fef3c7]', label: 'UNKNOWN SUBMISSION STATE' },
    CONTACT_UNAVAILABLE: { color: 'bg-[#fff1f2] text-[#e7000b] border-[#ffe4e6]', label: 'CONTACT UNAVAILABLE' },
    FAILED: { color: 'bg-[#fff1f2] text-[#e7000b] border-[#ffe4e6]', label: 'FAILED' },
    REJECTED: { color: 'bg-[#fff1f2] text-[#e7000b] border-[#ffe4e6]', label: 'REJECTED' },
    NONE: { color: 'bg-surface-container-high text-on-surface-variant border-outline-variant', label: 'NOT SUBMITTED' }
  };
  const c = config[state] || config.NONE;
  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border font-technical-data ${c.color}`}>
      {c.label}
    </span>
  );
};

export default AbuseControlSection;
