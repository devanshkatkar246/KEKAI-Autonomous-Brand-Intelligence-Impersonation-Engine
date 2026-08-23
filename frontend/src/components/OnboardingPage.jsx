import React, { useState } from 'react';
import { Shield, Plus, ArrowRight, Upload, Globe, CheckCircle2, AlertCircle, Sparkles, Image as ImageIcon } from 'lucide-react';

const OnboardingPage = ({ onStartInvestigation, addToast }) => {
  const [showForm, setShowForm] = useState(false);
  const [brandName, setBrandName] = useState('');
  const [officialDomain, setOfficialDomain] = useState('');
  const [logoFile, setLogoFile] = useState(null);
  const [logoPreview, setLogoPreview] = useState(null);
  const [domainError, setDomainError] = useState('');

  const validateDomain = (domain) => {
    const clean = domain.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
    const regex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$|^[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;
    return regex.test(clean);
  };

  const handleLogoChange = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      if (file.size > 5 * 1024 * 1024) {
        addToast('File Too Large', 'Brand logo must be smaller than 5MB.', 'error');
        return;
      }
      setLogoFile(file);
      const reader = new FileReader();
      reader.onloadend = () => {
        setLogoPreview(reader.result);
      };
      reader.readAsDataURL(file);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();

    if (!brandName.trim()) {
      addToast('Validation Error', 'Please enter a target brand name.', 'error');
      return;
    }

    const cleanDomain = officialDomain.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
    if (!cleanDomain || !validateDomain(cleanDomain)) {
      setDomainError('Please enter a valid domain name (e.g. amazon.com)');
      addToast('Validation Error', 'Please enter a valid official domain (e.g. amazon.com).', 'error');
      return;
    }

    setDomainError('');
    const caseId = `CASE-${cleanDomain.split('.')[0].toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`;

    onStartInvestigation({
      investigationId: caseId,
      brandName: brandName.trim(),
      officialDomain: cleanDomain,
      logoFile,
      logoPreview,
      source: 'domain_monitoring'
    });
  };

  return (
    <div className="min-h-screen bg-background text-on-background flex flex-col items-center justify-center p-6 antialiased font-body-md relative overflow-hidden">
      {/* Subtle Ambient Radial Glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-primary/5 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-3xl space-y-8 relative z-10">
        {/* Hero Section */}
        <div className="text-center space-y-4">
          <h1 className="font-display text-5xl font-extrabold tracking-tight text-on-background animate-arrive-1">
            KEIKAI
          </h1>

          <div className="animate-arrive-2 space-y-3">
            <h2 className="font-headline-md text-xl text-on-surface-variant font-semibold">
              Autonomous Brand Intelligence &amp; Anti-Impersonation Engine
            </h2>

            <p className="font-body-lg text-body-lg text-on-surface-variant max-w-xl mx-auto leading-relaxed">
              Detect suspicious brand impersonation, investigate malicious assets, connect related infrastructure, and generate explainable evidence from a single investigation.
            </p>
          </div>

          {!showForm && (
            <div className="pt-4 animate-arrive-2">
              <button
                type="button"
                onClick={() => setShowForm(true)}
                className="btn-primary py-3 px-8 text-base rounded-full inline-flex items-center gap-2 shadow-md hover:shadow-lg transition-all font-semibold"
              >
                <Plus size={18} />
                <span>Create New Investigation</span>
              </button>
            </div>
          )}
        </div>

        {/* Investigation Setup Interface */}
        {showForm && (
          <div className="bg-surface-container-lowest rounded-xl border border-outline-variant p-8 space-y-6 shadow-sm animate-arrive-3">
            <div className="border-b border-outline-variant pb-4 flex items-center justify-between">
              <div>
                <h3 className="font-headline-md text-lg font-semibold text-on-background">
                  Investigation Setup
                </h3>
                <p className="font-body-md text-xs text-on-surface-variant">
                  Define the target brand parameters to launch your intelligence collection.
                </p>
              </div>
              <span className="font-label-caps text-[11px] px-2.5 py-1 rounded-full bg-surface-container text-primary font-semibold border border-outline-variant">
                STEP 1 OF 2
              </span>
            </div>

            <form onSubmit={handleSubmit} className="space-y-6">
              {/* Target Brand & Official Domain inputs */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-1.5">
                  <label className="block font-label-caps text-label-caps text-on-surface-variant" htmlFor="brand-name">
                    Target Brand <span className="text-error">*</span>
                  </label>
                  <input
                    id="brand-name"
                    type="text"
                    required
                    value={brandName}
                    onChange={(e) => setBrandName(e.target.value)}
                    placeholder="Enter brand name (e.g. Amazon)"
                    className="w-full px-4 py-2.5 bg-surface rounded-lg border border-outline-variant font-body-md text-on-background focus:ring-2 focus:ring-primary/20 focus:border-primary outline-none transition-all"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="block font-label-caps text-label-caps text-on-surface-variant" htmlFor="official-domain">
                    Official Domain <span className="text-error">*</span>
                  </label>
                  <div className="relative">
                    <input
                      id="official-domain"
                      type="text"
                      required
                      value={officialDomain}
                      onChange={(e) => {
                        setOfficialDomain(e.target.value);
                        if (domainError) setDomainError('');
                      }}
                      placeholder="Enter official domain (e.g. amazon.com)"
                      className={`w-full px-4 py-2.5 bg-surface rounded-lg border font-technical-data text-on-background focus:ring-2 focus:ring-primary/20 outline-none transition-all ${
                        domainError ? 'border-error focus:border-error' : 'border-outline-variant focus:border-primary'
                      }`}
                    />
                    <Globe size={16} className="absolute right-3 top-3 text-on-surface-variant opacity-50" />
                  </div>
                  {domainError && (
                    <p className="text-xs text-error flex items-center gap-1 font-body-md">
                      <AlertCircle size={12} /> {domainError}
                    </p>
                  )}
                </div>
              </div>

              {/* Brand Logo Upload */}
              <div className="space-y-1.5">
                <label className="block font-label-caps text-label-caps text-on-surface-variant">
                  Brand Logo <span className="text-on-surface-variant/60 font-normal">(Optional for Logo Match pipeline)</span>
                </label>
                <div className="border-2 border-dashed border-outline-variant rounded-lg p-4 bg-surface-container-low hover:bg-surface-bright transition-colors flex flex-col md:flex-row items-center justify-between gap-4">
                  <div className="flex items-center gap-3">
                    {logoPreview ? (
                      <img src={logoPreview} alt="Logo Preview" className="w-12 h-12 object-contain rounded border border-outline-variant bg-surface" />
                    ) : (
                      <div className="w-12 h-12 rounded border border-outline-variant bg-surface flex items-center justify-center text-on-surface-variant">
                        <ImageIcon size={20} />
                      </div>
                    )}
                    <div>
                      <p className="font-body-md text-xs font-semibold text-on-background">
                        {logoFile ? logoFile.name : 'Upload Primary Brand Logo'}
                      </p>
                      <p className="font-body-md text-[11px] text-on-surface-variant">
                        PNG, JPG, or WEBP up to 5MB
                      </p>
                    </div>
                  </div>

                  <label className="btn-secondary py-1.5 px-4 rounded-lg text-xs cursor-pointer inline-flex items-center gap-1.5">
                    <Upload size={14} />
                    <span>{logoFile ? 'Change File' : 'Browse File'}</span>
                    <input type="file" accept="image/png,image/jpeg,image/webp" onChange={handleLogoChange} className="hidden" />
                  </label>
                </div>
              </div>

              {/* Intelligence Source Selection */}
              <div className="space-y-2 pt-2 border-t border-outline-variant">
                <label className="block font-label-caps text-label-caps text-on-surface-variant">
                  Intelligence Source
                </label>
                <div className="bg-surface-container-low border-2 border-primary rounded-lg p-4 flex items-start justify-between gap-4">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-headline-md font-semibold text-sm text-on-background">DOMAIN MONITORING</span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-technical-data bg-primary text-on-primary font-bold">
                        dnstwist
                      </span>
                    </div>
                    <p className="font-body-md text-xs text-on-surface-variant leading-relaxed">
                      Look for typosquatted and lookalike domains using domain permutation and live DNS analysis.
                    </p>
                  </div>
                  <CheckCircle2 size={20} className="text-primary shrink-0 mt-1" />
                </div>
              </div>

              {/* Form Action */}
              <div className="pt-4 flex items-center justify-between">
                <button
                  type="button"
                  onClick={() => setShowForm(false)}
                  className="btn-secondary py-2 px-4 rounded-lg text-xs font-medium"
                >
                  Cancel
                </button>

                <button
                  type="submit"
                  className="btn-primary py-2.5 px-6 rounded-lg text-sm inline-flex items-center gap-2 shadow-xs"
                >
                  <span>Start Investigation</span>
                  <ArrowRight size={16} />
                </button>
              </div>
            </form>
          </div>
        )}
      </div>
    </div>
  );
};

export default OnboardingPage;
