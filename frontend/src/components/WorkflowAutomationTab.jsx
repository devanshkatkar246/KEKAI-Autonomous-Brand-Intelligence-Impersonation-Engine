import React, { useState } from 'react';
import {
  Workflow, Zap, Play, CheckCircle2, AlertTriangle, ShieldCheck, Loader2, RefreshCw, Send, ShieldAlert, FileText, ArrowRight
} from 'lucide-react';

const WorkflowAutomationTab = ({ apiBaseUrl, addToast = () => {}, onNavigateTab = () => {} }) => {
  const [runningDemo, setRunningDemo] = useState(false);
  const [demoReport, setDemoReport] = useState(null);
  const [eventLog, setEventLog] = useState([
    { event: 'INVESTIGATION_STARTED', case_id: 'case_demo_amazon_001', time: 'Just now', status: 'EMITTED' },
    { event: 'IMPERSONATION_CONFIRMED', case_id: 'case_demo_amazon_001', time: 'Just now', status: 'EMITTED' },
    { event: 'TAKEDOWN_ROUTE_RESOLVED', case_id: 'case_demo_amazon_001', time: 'Just now', status: 'EMITTED' },
    { event: 'APPROVAL_GRANTED', case_id: 'case_demo_amazon_001', time: 'Just now', status: 'EMITTED' },
    { event: 'TAKEDOWN_SUBMITTED', case_id: 'case_demo_amazon_001', time: 'Just now', status: 'DELIVERED' }
  ]);

  const handleRunDemo = async () => {
    setRunningDemo(true);
    try {
      const res = await fetch(`${apiBaseUrl}/api/demo/run-scenario?brand=Amazon&domain=amaz0n-security-login.xyz`, {
        method: 'POST'
      });
      const data = await res.json();
      if (res.ok && data.status === 'success') {
        setDemoReport(data.data);
        addToast('Sponsor Demo Executed', 'Deterministic Amazon brand impersonation workflow completed in DRY_RUN mode.', 'success');
      } else {
        throw new Error(data.error || 'Demo scenario failed');
      }
    } catch (err) {
      addToast('Demo Failed', err.message || 'Error executing demo scenario', 'error');
    } finally {
      setRunningDemo(false);
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* HEADER BANNER */}
      <div className="bg-surface-container-low p-6 rounded-xl border border-outline-variant flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Zap size={20} className="text-primary" />
            <span className="font-label-caps text-xs text-primary font-bold">TASK 7 &middot; AUTONOMOUS RESPONSE ORCHESTRATION & VIASOCKET</span>
          </div>
          <h2 className="font-headline-md text-xl font-bold text-on-background">Workflow Automation & viaSocket Integration</h2>
          <p className="font-body-md text-xs text-on-surface-variant max-w-2xl mt-1">
            viaSocket orchestrates investigation notifications, high-confidence alerts, and status updates while KEIKAI backend retains strict authority over human approvals and frozen evidence integrity.
          </p>
        </div>

        <button
          type="button"
          onClick={handleRunDemo}
          disabled={runningDemo}
          className="px-5 py-2.5 bg-primary text-on-primary font-bold text-xs rounded-lg hover:bg-primary-hover flex items-center gap-2 shadow-lg shrink-0"
        >
          {runningDemo ? <Loader2 size={16} className="animate-spin" /> : <Play size={16} />}
          <span>[ RUN DEMO SCENARIO ]</span>
        </button>
      </div>

      {/* SPONSOR DEMO REPORT CARD (If executed) */}
      {demoReport && (
        <div className="bg-surface-container-lowest p-6 rounded-xl border-2 border-primary/40 space-y-4 shadow-xl">
          <div className="flex items-center justify-between border-b border-outline-variant pb-3">
            <h3 className="font-headline-md font-bold text-base text-on-background flex items-center gap-2">
              <ShieldCheck size={18} className="text-primary" /> DETERMINISTIC DEMO SCENARIO &mdash; EXECUTIVE CASE REPORT
            </h3>
            <span className="font-technical-data text-xs bg-primary/20 text-primary border border-primary/30 px-3 py-1 rounded font-bold">
              RISK SCORE: {demoReport.risk_score}/100 (HIGH CONFIDENCE)
            </span>
          </div>

          <p className="font-body-md text-xs text-on-surface-variant bg-surface-container-low p-3.5 rounded-lg border border-outline-variant">
            {demoReport.executive_summary}
          </p>

          {/* RISK BREAKDOWN */}
          <div className="space-y-2">
            <h4 className="font-headline-md text-xs font-bold text-on-background">Explainable Risk Score Breakdown</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-technical-data">
              {demoReport.risk_breakdown?.map((item, idx) => (
                <div key={idx} className="bg-surface-container-low p-2.5 rounded border border-outline-variant flex items-center justify-between">
                  <div>
                    <span className="font-bold text-on-background">{item.signal}</span>
                    <p className="text-[10px] text-on-surface-variant">{item.reason}</p>
                  </div>
                  <span className="text-primary font-bold text-sm shrink-0">+{item.points}</span>
                </div>
              ))}
            </div>
          </div>

          {/* CASE INTELLIGENCE GRAPH VISUALIZATION */}
          <div className="space-y-2 pt-2">
            <h4 className="font-headline-md text-xs font-bold text-on-background">Case Intelligence Graph</h4>
            <div className="bg-surface-container-low p-4 rounded-lg border border-outline-variant font-technical-data text-xs space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                {demoReport.case_graph?.nodes?.map((node, i) => (
                  <React.Fragment key={node.id}>
                    <span className="px-2.5 py-1 bg-surface-container-lowest text-on-background rounded border border-outline-variant font-bold text-[11px]">
                      {node.label}
                    </span>
                    {i < demoReport.case_graph.nodes.length - 1 && (
                      <ArrowRight size={12} className="text-primary shrink-0" />
                    )}
                  </React.Fragment>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* VIASOCKET EVENT LOG & STATUS */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-surface-container-lowest p-6 rounded-xl border border-outline-variant space-y-4">
          <div className="flex items-center justify-between border-b border-outline-variant pb-3">
            <h3 className="font-headline-md font-bold text-sm text-on-background flex items-center gap-2">
              <Workflow size={16} className="text-primary" /> viaSocket Safe Event Log
            </h3>
            <span className="text-[10px] font-technical-data text-on-surface-variant">BOUNDED &middot; NON-BLOCKING</span>
          </div>

          <div className="space-y-2 font-technical-data text-xs">
            {eventLog.map((ev, idx) => (
              <div key={idx} className="bg-surface-container-low p-3 rounded-lg border border-outline-variant flex items-center justify-between">
                <div>
                  <span className="font-bold text-primary">{ev.event}</span>
                  <div className="text-[10px] text-on-surface-variant">Case: {ev.case_id} &middot; {ev.time}</div>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-primary/20 text-primary border border-primary/30">
                  {ev.status}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* VIASOCKET WORKFLOW ORCHESTRATION RULES */}
        <div className="bg-surface-container-lowest p-6 rounded-xl border border-outline-variant space-y-4">
          <div className="border-b border-outline-variant pb-3">
            <h3 className="font-headline-md font-bold text-sm text-on-background flex items-center gap-2">
              <ShieldCheck size={16} className="text-primary" /> viaSocket Safety & Authority Matrix
            </h3>
          </div>

          <ul className="space-y-2.5 text-xs text-on-surface-variant font-body-md">
            <li className="flex items-start gap-2">
              <CheckCircle2 size={16} className="text-primary shrink-0 mt-0.5" />
              <span><strong>Orchestration Only:</strong> viaSocket receives event alerts (`IMPERSONATION_CONFIRMED`, `APPROVAL_REQUIRED`, `TAKEDOWN_SUBMITTED`) to trigger analyst notifications.</span>
            </li>
            <li className="flex items-start gap-2">
              <CheckCircle2 size={16} className="text-primary shrink-0 mt-0.5" />
              <span><strong>Backend Authority:</strong> Human approval, frozen evidence snapshots, SHA-256 validation, and takedown execution remain 100% inside KEIKAI backend.</span>
            </li>
            <li className="flex items-start gap-2">
              <CheckCircle2 size={16} className="text-primary shrink-0 mt-0.5" />
              <span><strong>Sanitized Payloads:</strong> API keys, headers, tokens, and credentials are stripped from event payloads before dispatch.</span>
            </li>
            <li className="flex items-start gap-2">
              <CheckCircle2 size={16} className="text-primary shrink-0 mt-0.5" />
              <span><strong>Fault Tolerance:</strong> If viaSocket is offline, network error occurs, or times out (&gt;2.0s), KEIKAI continues running without interruption.</span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default WorkflowAutomationTab;
