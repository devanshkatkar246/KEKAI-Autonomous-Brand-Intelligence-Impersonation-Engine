import React, { useState, useEffect } from 'react';
import { Eye, Upload, Loader2, AlertCircle, CheckCircle2, RefreshCw, ShieldAlert, FileText, WifiOff } from 'lucide-react';
import { apiFetch } from '../api';

const VisualPhishingTab = ({
  apiBaseUrl,
  addToast,
  selectedVisualPhishing,
  toggleSelectVisualPhishing
}) => {
  const [url, setUrl] = useState('');
  const [screenshotFile, setScreenshotFile] = useState(null);
  const [statusInfo, setStatusInfo] = useState(null);
  const [checkingStatus, setCheckingStatus] = useState(true);
  const [backendUnreachable, setBackendUnreachable] = useState(false);

  const [loading, setLoading] = useState(false);
  const [pollingJobId, setPollingJobId] = useState(null);
  const [pollingElapsedSeconds, setPollingElapsedSeconds] = useState(0);
  const [resultData, setResultData] = useState(null);

  const fetchStatus = async () => {
    setCheckingStatus(true);
    console.info(`[VisualPhishing] ${new Date().toISOString()} GET /api/visual-phishing-status — initiating`);
    try {
      const res = await apiFetch(`${apiBaseUrl}/api/visual-phishing-status`);
      const data = await res.json();
      console.info(`[VisualPhishing] ${new Date().toISOString()} GET /api/visual-phishing-status — HTTP ${res.status}`);
      setBackendUnreachable(false);
      if (data && data.data) {
        setStatusInfo(data.data);
        if (data.data.weights_loaded) {
          addToast('Phishpedia Ready', 'Model weights verified. Full deep learning inference active.', 'success');
        } else {
          addToast('Weights Missing', 'Phishpedia model weights not found. You can run in Fallback Mode.', 'info');
        }
      }
    } catch (err) {
      console.warn(`[VisualPhishing] ${new Date().toISOString()} GET /api/visual-phishing-status — FAILED:`, err.message);
      if (err.isNetworkError) {
        // Backend is not running — distinct state from "weights missing"
        setBackendUnreachable(true);
        setStatusInfo(null);
      } else {
        // Server returned an error response — keep fallback info
        setBackendUnreachable(false);
        setStatusInfo({
          weights_loaded: false,
          weights_missing: ['models/rcnn_bet365.pth', 'models/resnetv2_rgb_new.pth.tar'],
          message: 'Phishpedia weights not loaded.'
        });
      }
    } finally {
      setCheckingStatus(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, [apiBaseUrl]);

  // Timer interval for job polling
  useEffect(() => {
    let timer;
    if (pollingJobId) {
      setPollingElapsedSeconds(0);
      timer = setInterval(() => {
        setPollingElapsedSeconds((prev) => prev + 1);
      }, 1000);
    }
    return () => clearInterval(timer);
  }, [pollingJobId]);

  // Poll job status if pollingJobId is active
  useEffect(() => {
    if (!pollingJobId) return;

    const interval = setInterval(async () => {
      try {
        const response = await fetch(`${apiBaseUrl}/api/visual-phishing-check/${pollingJobId}`);
        const resData = await response.json();

        if (response.ok && resData.status === 'success') {
          const job = resData.data;
          if (job.status === 'completed') {
            clearInterval(interval);
            setLoading(false);
            setPollingJobId(null);
            setResultData(job.result);
            addToast(
              'Phishing Analysis Complete',
              `Verdict: ${job.result.verdict}${job.result.target_brand ? ` (Target: ${job.result.target_brand})` : ''}`,
              job.result.verdict === 'Phishing' ? 'error' : 'success'
            );
          } else if (job.status === 'failed') {
            clearInterval(interval);
            setLoading(false);
            setPollingJobId(null);
            addToast('Analysis Failed', job.error || 'Phishpedia inference failed.', 'error');
          }
        }
      } catch (err) {
        console.error('Job polling error:', err);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [pollingJobId, apiBaseUrl, addToast]);

  const handleScreenshotUpload = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      if (!file.type.startsWith('image/')) {
        addToast('Validation Error', 'Please upload a valid PNG or JPG image file.', 'error');
        return;
      }
      setScreenshotFile(file);
    }
  };

  const handleRunCheck = async (e, forceFallback = false) => {
    e?.preventDefault();
    if (!url.trim()) {
      addToast('Validation Error', 'Please enter the target webpage URL.', 'error');
      return;
    }
    if (!screenshotFile) {
      addToast('Validation Error', 'Please upload or paste a webpage screenshot image.', 'error');
      return;
    }

    setLoading(true);
    setResultData(null);
    const ts = new Date().toISOString();
    console.info(`[VisualPhishing] ${ts} POST /api/visual-phishing-check — url=${url.trim()} forceFallback=${forceFallback}`);

    try {
      const formData = new FormData();
      formData.append('url', url.trim());
      formData.append('screenshot', screenshotFile);
      if (forceFallback || !weightsLoaded) {
        formData.append('fallback', 'true');
      }

      const response = await apiFetch(`${apiBaseUrl}/api/visual-phishing-check`, {
        method: 'POST',
        body: formData
      });

      console.info(`[VisualPhishing] ${new Date().toISOString()} POST /api/visual-phishing-check — HTTP ${response.status}`);
      setBackendUnreachable(false);
      const resData = await response.json();

      if (response.status === 503 || resData.status === 'error') {
        throw new Error(resData.error || 'Phishpedia weights not loaded.');
      }

      const jobId = resData.data.job_id;
      setPollingJobId(jobId);
      addToast('Job Queued', 'Visual phishing check submitted. Polling for results...', 'info');
    } catch (err) {
      console.error(`[VisualPhishing] ${new Date().toISOString()} POST /api/visual-phishing-check — FAILED:`, err.message);
      setLoading(false);
      if (err.isNetworkError) {
        setBackendUnreachable(true);
        // Do NOT show a generic "Check Failed" toast — the persistent banner is the signal
      } else {
        addToast('Check Failed', err.message || 'An error occurred during submission.', 'error');
      }
    }
  };

  const weightsLoaded = statusInfo?.weights_loaded ?? false;

  return (
    <div className="space-y-6 font-['Geist',sans-serif]">
      {/* Header Card */}
      <div className="card-paper p-6 space-y-5">
        <div>
          <h2 className="text-xl font-semibold text-[#0a0a0a] tracking-tight mb-1 flex items-center gap-2">
            <Eye size={20} className="text-[#0a0a0a]" /> Visual Phishing &amp; Brand Identity Recognition
          </h2>
          <p className="text-sm text-[#737373]">
            Powered by <code className="bg-[#f5f5f5] text-[#0a0a0a] px-1.5 py-0.5 rounded-[6px] font-mono border border-[#e5e5e5]">Phishpedia</code> (USENIX Security '21). Analyzes webpage screenshots with Faster R-CNN logo detection and Siamese neural network brand matching.
          </p>
        </div>

        {/* ── BACKEND UNREACHABLE BANNER (distinct from weights-missing) ── */}
        {!checkingStatus && backendUnreachable && (
          <div className="p-4 bg-[#fff7ed] border border-[#fed7aa] rounded-[18px] flex items-center justify-between gap-3">
            <div className="flex items-center gap-2 text-[#c2410c] text-xs font-semibold">
              <WifiOff size={16} className="shrink-0" />
              <div>
                <span className="block font-bold text-sm">Backend Unreachable</span>
                <span className="text-[#92400e] font-normal">
                  Cannot connect to API server at <code className="font-mono bg-[#ffedd5] px-1 rounded">http://localhost:8000</code>.
                  Run <code className="font-mono bg-[#ffedd5] px-1 rounded">python steps.py</code> or <code className="font-mono bg-[#ffedd5] px-1 rounded">uvicorn main:app --reload</code>.
                </span>
              </div>
            </div>
            <button
              type="button"
              onClick={fetchStatus}
              disabled={checkingStatus}
              className="shrink-0 px-3 py-1 bg-[#ffffff] hover:bg-[#fafafa] text-[#0a0a0a] rounded-[18px] border border-[#e5e5e5] text-xs font-semibold inline-flex items-center gap-1.5 transition-all shadow-sm"
            >
              <RefreshCw size={12} className={checkingStatus ? 'animate-spin' : ''} />
              <span>Retry Connection</span>
            </button>
          </div>
        )}

        {/* Readiness Callout — only shown when backend is reachable */}
        {!checkingStatus && !backendUnreachable && weightsLoaded && (
          <div className="p-4 bg-[#ecfdf5] border border-[#a7f3d0] rounded-[18px] flex items-center justify-between gap-3 text-[#059669]">
            <div className="flex items-center gap-2 text-xs font-semibold">
              <CheckCircle2 size={16} className="text-[#059669]" />
              <span>Full AI Inference Active (Faster R-CNN Logo Detection + ResNetV2 Siamese Brand Matching)</span>
            </div>
            <button
              type="button"
              onClick={fetchStatus}
              className="px-2.5 py-1 bg-[#ffffff] hover:bg-[#fafafa] text-[#0a0a0a] rounded-[18px] border border-[#e5e5e5] text-[11px] font-semibold inline-flex items-center gap-1 transition-all shadow-sm"
            >
              <RefreshCw size={11} className={checkingStatus ? 'animate-spin' : ''} />
              <span>Re-verify</span>
            </button>
          </div>
        )}

        {/* Weights Missing — only shown when backend IS reachable but weights absent */}
        {!checkingStatus && !backendUnreachable && !weightsLoaded && (
          <div className="p-5 bg-[#fff1f2] border border-[#ffe4e6] rounded-[18px] space-y-3">
            <div className="flex items-center justify-between gap-2 text-[#e7000b] font-medium text-sm">
              <div className="flex items-center gap-2">
                <AlertCircle size={18} />
                <span>Phishpedia Model Weights Not Loaded</span>
              </div>
              <button
                type="button"
                onClick={fetchStatus}
                disabled={checkingStatus}
                className="px-3 py-1 bg-[#ffffff] hover:bg-[#fafafa] text-[#0a0a0a] rounded-[18px] border border-[#e5e5e5] text-xs font-semibold inline-flex items-center gap-1.5 transition-all shadow-sm"
              >
                <RefreshCw size={12} className={checkingStatus ? 'animate-spin' : ''} />
                <span>Check Again</span>
              </button>
            </div>

            <p className="text-xs text-[#737373] leading-relaxed">
              Deep learning model weights (`rcnn_bet365.pth` and `resnetv2_rgb_new.pth.tar`) are missing from <code className="font-mono text-[#0a0a0a]">./Phishpedia/models/</code>.
              Run <code className="font-mono text-[#0a0a0a]">python scripts/download_phishpedia_weights.py</code> to download full weights.
              <br />
              <strong className="text-[#0a0a0a]">Fallback Mode Active:</strong> Running lightweight perceptual hash visual check.
            </p>
          </div>
        )}

        {/* Form Controls */}
        <form onSubmit={(e) => handleRunCheck(e, false)} className="space-y-5">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {/* URL Input */}
            <div className="space-y-2">
              <label className="text-xs font-medium text-[#0a0a0a]">Target Webpage URL:</label>
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="e.g. https://paypal-verify-account-security.com/login"
                disabled={loading}
                className="input-field w-full"
              />
            </div>

            {/* Screenshot Upload Zone */}
            <div className="space-y-2">
              <label className="text-xs font-medium text-[#0a0a0a] flex items-center justify-between">
                <span>Webpage Screenshot</span>
                {screenshotFile && <span className="text-[#0a0a0a] font-semibold text-[11px]">✓ Uploaded</span>}
              </label>
              <div className="relative border-2 border-dashed border-[#e5e5e5] hover:border-[#0a0a0a] rounded-[18px] p-3.5 transition-all bg-[#f5f5f5] text-center flex flex-col items-center justify-center min-h-[120px]">
                <input
                  type="file"
                  accept="image/*"
                  onChange={handleScreenshotUpload}
                  disabled={loading}
                  className="absolute inset-0 opacity-0 cursor-pointer w-full h-full z-10"
                />
                {screenshotFile ? (
                  <div className="flex items-center gap-3">
                    <img
                      src={URL.createObjectURL(screenshotFile)}
                      alt="Screenshot"
                      className="h-16 max-w-full object-contain rounded-[6px] border border-[#e5e5e5] bg-[#ffffff] p-1"
                    />
                    <span className="text-xs text-[#0a0a0a] font-mono truncate max-w-[200px]">{screenshotFile.name}</span>
                  </div>
                ) : (
                  <div className="flex flex-col items-center gap-1.5 text-[#737373]">
                    <Upload className="text-[#0a0a0a]" size={20} />
                    <span className="text-xs font-medium text-[#0a0a0a]">Click or Drag &amp; Drop Page Screenshot</span>
                    <span className="text-[11px] text-[#737373]">PNG or JPG screenshot image</span>
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="flex items-center justify-between pt-2 border-t border-[#e5e5e5]">
            <span className="text-xs text-[#737373]">
              {weightsLoaded ? (
                <span className="text-[#059669] font-medium flex items-center gap-1">
                  <CheckCircle2 size={13} className="text-[#059669]" /> Full Deep Learning AI Active
                </span>
              ) : (
                <span className="text-[#737373] flex items-center gap-1">
                  <AlertCircle size={13} /> Fallback Perceptual Hash Mode
                </span>
              )}
            </span>

            <div className="flex items-center gap-3">
              {!weightsLoaded ? (
                <button
                  type="button"
                  onClick={(e) => handleRunCheck(e, true)}
                  disabled={loading || !url.trim() || !screenshotFile}
                  className="btn-primary px-6 py-2.5 inline-flex items-center justify-center gap-2 disabled:opacity-40 shadow-sm shrink-0"
                >
                  {loading ? (
                    <>
                      <Loader2 size={16} className="animate-spin" />
                      <span>Analyzing ({pollingElapsedSeconds}s)...</span>
                    </>
                  ) : (
                    <span>Run Fallback Check (Hash-Based)</span>
                  )}
                </button>
              ) : (
                <button
                  type="submit"
                  disabled={loading || !url.trim() || !screenshotFile}
                  className="btn-primary px-6 py-2.5 inline-flex items-center justify-center gap-2 disabled:opacity-40 shadow-sm shrink-0"
                >
                  {loading ? (
                    <>
                      <Loader2 size={16} className="animate-spin" />
                      <span>Analyzing ({pollingElapsedSeconds}s)...</span>
                    </>
                  ) : (
                    <span>Run Phishpedia Check</span>
                  )}
                </button>
              )}
            </div>
          </div>
        </form>

        {loading && (
          <div className="p-4 bg-[#fafafa] border border-[#e5e5e5] rounded-[18px] flex items-center justify-between gap-3 text-xs text-[#737373] animate-pulse">
            <div className="flex items-center gap-3">
              <Loader2 size={16} className="animate-spin text-[#0a0a0a] shrink-0" />
              <span>
                Processing visual features (Faster R-CNN logo recognition &amp; Siamese brand matching). Inference in progress...
              </span>
            </div>
            <span className="font-mono text-[#0a0a0a] font-semibold">{pollingElapsedSeconds}s elapsed</span>
          </div>
        )}
      </div>

      {/* Inference Results Card */}
      {resultData && (
        <div className="card-paper p-6 space-y-6">
          <div className="flex items-center justify-between border-b border-[#e5e5e5] pb-4">
            <div>
              <h3 className="font-semibold text-[#0a0a0a] text-base tracking-tight flex items-center gap-2">
                Detection Result
                {resultData.is_fallback && (
                  <span className="px-2.5 py-0.5 rounded-[18px] text-[10px] font-semibold bg-[#f5f5f5] text-[#737373] border border-[#e5e5e5]">
                    Fallback Mode: Hash-based check (Not full Phishpedia ML)
                  </span>
                )}
              </h3>
              <p className="text-xs text-[#737373]">
                Target URL: <span className="font-mono text-[#0a0a0a]">{url}</span>
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span
                className={`px-3 py-1 rounded-[18px] text-xs font-semibold border ${
                  resultData.verdict === 'Phishing'
                    ? 'bg-[#fff1f2] text-[#e7000b] border-[#ffe4e6]'
                    : 'bg-[#f5f5f5] text-[#0a0a0a] border-[#e5e5e5]'
                }`}
              >
                Verdict: {resultData.verdict}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Metadata Summary */}
            <div className="space-y-4">
              <div className="bg-[#fafafa] p-4 rounded-[10px] border border-[#e5e5e5] space-y-3 text-xs">
                <div className="flex justify-between items-center border-b border-[#e5e5e5] pb-2">
                  <span className="text-[#737373]">Phishing Verdict:</span>
                  <span
                    className={`font-bold ${
                      resultData.verdict === 'Phishing' ? 'text-[#e7000b]' : 'text-[#0a0a0a]'
                    }`}
                  >
                    {resultData.verdict}
                  </span>
                </div>

                <div className="flex justify-between items-center border-b border-[#e5e5e5] pb-2">
                  <span className="text-[#737373]">Identified Target Brand:</span>
                  <span className="font-semibold text-[#0a0a0a]">
                    {resultData.target_brand || 'None Detected'}
                  </span>
                </div>

                <div className="flex justify-between items-center border-b border-[#e5e5e5] pb-2">
                  <span className="text-[#737373]">Matching Confidence:</span>
                  <span className="font-semibold text-[#0a0a0a]">
                    {resultData.confidence !== null ? `${resultData.confidence}%` : 'N/A'}
                  </span>
                </div>

                <div className="flex justify-between items-center">
                  <span className="text-[#737373]">Matched Brand Domain:</span>
                  <span className="font-mono text-[#0a0a0a]">
                    {resultData.matched_domain || 'N/A'}
                  </span>
                </div>
              </div>

              {/* Add to Case Button */}
              {(() => {
                const itemKey = `vp-${url}-${resultData.target_brand || 'brand'}`;
                const isSelected = selectedVisualPhishing.some((item) => item.key === itemKey);

                return (
                  <button
                    onClick={() =>
                      toggleSelectVisualPhishing({
                        id: itemKey,
                        key: itemKey,
                        type: 'visual_phishing',
                        url,
                        verdict: resultData.verdict,
                        target_brand: resultData.target_brand,
                        confidence: resultData.confidence,
                        matched_domain: resultData.matched_domain,
                        isFallback: Boolean(resultData.is_fallback),
                        timestamp: new Date().toISOString()
                      })
                    }
                    className={`w-full py-2.5 rounded-[18px] text-xs font-medium transition-colors ${
                      isSelected ? 'bg-[#0a0a0a] text-[#ffffff]' : 'btn-secondary border border-[#e5e5e5]'
                    }`}
                  >
                    {isSelected ? '✓ Added to Case Report' : 'Add to Case Report'}
                  </button>
                );
              })()}
            </div>

            {/* Bounding Box Annotated Screenshot Preview */}
            <div className="space-y-2">
              <span className="text-xs font-medium text-[#737373] block">
                Annotated Screenshot (Bounding Boxes &amp; Brand Identification):
              </span>
              <div className="bg-[#f5f5f5] p-3 rounded-[10px] border border-[#e5e5e5] flex items-center justify-center min-h-[200px]">
                {resultData.annotated_image_url ? (
                  <img
                    src={`${apiBaseUrl}${resultData.annotated_image_url}`}
                    alt="Annotated Screenshot"
                    className="max-h-[260px] object-contain rounded-[6px] border border-[#e5e5e5]"
                  />
                ) : (
                  <div className="text-center text-xs text-[#737373] space-y-1">
                    <p>{resultData.is_fallback ? 'Fallback mode active (No bounding boxes).' : 'No logo bounding box detected.'}</p>
                    <p className="text-[11px]">The webpage does not contain protected target brand logos.</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default VisualPhishingTab;
