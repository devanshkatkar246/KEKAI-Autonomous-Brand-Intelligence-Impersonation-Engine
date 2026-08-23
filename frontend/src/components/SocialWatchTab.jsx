import React, { useState, useMemo } from 'react';
import { Share2, Upload, Loader2, AlertCircle, CheckCircle2, RefreshCw, UserCheck, UserX, ShieldAlert, Tag, User, Building2, Sparkles } from 'lucide-react';

const BRAND_ENTITIES = [
  'Rolex', 'Apple', 'Nike', 'Louis Vuitton', 'Ray-Ban', 'Gucci', 'Samsung', 'Sony'
];

const CREATOR_ENTITIES = [
  { name: 'Alex Rivers (Tech Creator - Demo)', handle: '@alexrivers_tech' },
  { name: 'Samantha Vance (Gaming Streamer - Demo)', handle: '@samanthavance_live' },
  { name: 'Dr. Aris Thorne (Finance Influencer - Demo)', handle: '@dr_aris_thorne' },
  { name: 'Marcus Chen (Crypto Educator - Demo)', handle: '@marcuschen_crypto' },
  { name: 'Elena Rostova (Fitness Influencer - Demo)', handle: '@elena_rostova_fit' },
];

const SocialWatchTab = ({
  apiBaseUrl,
  addToast,
  selectedSocialProfiles,
  toggleSelectProfile
}) => {
  const [platform, setPlatform] = useState('Instagram');
  const [handle, setHandle] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [entityType, setEntityType] = useState('brand'); // 'brand' | 'individual'
  const [targetEntity, setTargetEntity] = useState('Rolex');
  const [officialHandle, setOfficialHandle] = useState('');
  const [bioText, setBioText] = useState('');
  const [followerCount, setFollowerCount] = useState('');
  const [accountAgeDays, setAccountAgeDays] = useState('');
  const [profileImage, setProfileImage] = useState(null);

  const [loading, setLoading] = useState(false);
  const [loadingSamples, setLoadingSamples] = useState(false);
  const [profilesData, setProfilesData] = useState([]);

  // When switching entityType, update targetEntity default
  const handleEntityTypeChange = (newType) => {
    setEntityType(newType);
    if (newType === 'brand') {
      setTargetEntity('Rolex');
      setOfficialHandle('');
    } else {
      setTargetEntity(CREATOR_ENTITIES[0].name);
      setOfficialHandle(CREATOR_ENTITIES[0].handle);
    }
  };

  const handleEntitySelectChange = (e) => {
    const val = e.target.value;
    setTargetEntity(val);
    if (entityType === 'individual') {
      const match = CREATOR_ENTITIES.find((c) => c.name === val);
      if (match) setOfficialHandle(match.handle);
    }
  };

  const handleImageUpload = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      if (!file.type.startsWith('image/')) {
        addToast('Validation Error', 'Please upload a valid profile image.', 'error');
        return;
      }
      setProfileImage(file);
    }
  };

  const handleRunAnalysis = async (e) => {
    e?.preventDefault();
    if (!handle.trim()) {
      addToast('Validation Error', 'Please enter account handle (e.g. @rolex_support).', 'error');
      return;
    }

    setLoading(true);
    try {
      const formData = new FormData();
      formData.append('platform', platform);
      formData.append('handle', handle.trim());
      if (displayName) formData.append('display_name', displayName.trim());
      if (bioText) formData.append('bio_text', bioText.trim());
      if (followerCount) formData.append('follower_count', followerCount.toString());
      if (accountAgeDays) formData.append('account_age_days', accountAgeDays.toString());
      formData.append('entity_type', entityType);
      formData.append('protected_entity', targetEntity.trim());
      formData.append('target_brand', targetEntity.trim());
      if (officialHandle) formData.append('official_handle', officialHandle.trim());
      if (profileImage) formData.append('profile_image', profileImage);

      const response = await fetch(`${apiBaseUrl}/api/social-profile-check`, {
        method: 'POST',
        body: formData
      });

      const resData = await response.json();

      if (response.ok && resData.status === 'success') {
        const item = resData.data;
        setProfilesData((prev) => [item, ...prev]);
        addToast(
          'Social Profile Analyzed',
          `Verdict: ${item.verdict} (${item.risk_rating}% risk).`,
          item.risk_rating >= 70 ? 'error' : 'success'
        );
      } else {
        throw new Error(resData.detail || 'Social profile analysis failed.');
      }
    } catch (err) {
      addToast('Analysis Error', err.message || 'An error occurred during analysis.', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleLoadSampleProfiles = async () => {
    setLoadingSamples(true);
    try {
      const response = await fetch(`${apiBaseUrl}/api/social-profile-sample-data`);
      const resData = await response.json();

      if (response.ok && resData.status === 'success') {
        const samples = resData.data.sample_profiles || [];
        setProfilesData(samples);
        const creatorCount = samples.filter((s) => s.entity_type === 'individual').length;
        const brandCount = samples.filter((s) => s.entity_type !== 'individual').length;
        addToast(
          'Sample Data Loaded',
          `Loaded ${samples.length} demo profiles (${brandCount} brand impersonations, ${creatorCount} creator giveaway scams).`,
          'info'
        );
      }
    } catch (err) {
      addToast('Sample Load Error', 'Failed to fetch sample social profiles.', 'error');
    } finally {
      setLoadingSamples(false);
    }
  };

  const handleToggleVerifiedOverride = async (item) => {
    const newStatus = !item.is_verified_official;
    try {
      const response = await fetch(`${apiBaseUrl}/api/social-profile-verify-override`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ handle: item.handle, is_verified: newStatus })
      });

      const resData = await response.json();
      if (response.ok && resData.status === 'success') {
        item.is_verified_official = newStatus;
        if (newStatus) {
          item.verdict = 'Verified Official Account';
          item.risk_rating = 0.0;
          item.intent_label = item.entity_type === 'individual' ? 'Verified Official Profile' : 'Official/verified brand presence';
        } else {
          item.verdict = 'Suspicious Profile';
          item.risk_rating = 65.0;
        }
        setProfilesData([...profilesData]);
        addToast('Verification Updated', resData.data.message, 'success');
      }
    } catch (err) {
      addToast('Override Error', 'Failed to update handle verification status.', 'error');
    }
  };

  return (
    <div className="space-y-6 font-['Geist',sans-serif]">
      {/* Header Card */}
      <div className="card-paper p-6 space-y-5">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <h2 className="text-xl font-semibold text-[#0a0a0a] tracking-tight mb-1 flex items-center gap-2">
              <Share2 size={20} className="text-[#0a0a0a]" /> Social Media Impersonation &amp; Creator Protection
            </h2>
            <p className="text-sm text-[#737373]">
              Detects impersonation accounts &amp; fake giveaway scams targeting both <strong>Corporate Brands</strong> and <strong>Public Figures / Content Creators</strong> across Instagram, X, YouTube, TikTok, &amp; LinkedIn.
            </p>
          </div>

          <button
            type="button"
            onClick={handleLoadSampleProfiles}
            disabled={loadingSamples}
            className="btn-secondary px-4 py-2 text-xs font-semibold inline-flex items-center gap-2 shrink-0 border border-[#e5e5e5]"
          >
            <RefreshCw size={13} className={loadingSamples ? 'animate-spin' : ''} />
            <span>{loadingSamples ? 'Loading Demo Data...' : 'Load Sample Profiles (Brands + Creators)'}</span>
          </button>
        </div>

        {/* Form Inputs */}
        <form onSubmit={handleRunAnalysis} className="space-y-4 pt-2 border-t border-[#e5e5e5]">
          {/* Entity Type Selector Toggle */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#fafafa] p-3 rounded-[10px] border border-[#e5e5e5]">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-[#0a0a0a]">Protected Entity Type:</span>
              <div className="flex rounded-[8px] border border-[#e5e5e5] overflow-hidden bg-[#ffffff]">
                <button
                  type="button"
                  onClick={() => handleEntityTypeChange('brand')}
                  disabled={loading}
                  className={`px-3 py-1.5 text-xs font-semibold flex items-center gap-1.5 transition-all ${
                    entityType === 'brand'
                      ? 'bg-[#0a0a0a] text-[#ffffff]'
                      : 'text-[#737373] hover:text-[#0a0a0a]'
                  }`}
                >
                  <Building2 size={13} />
                  <span>Corporate Brand</span>
                </button>
                <button
                  type="button"
                  onClick={() => handleEntityTypeChange('individual')}
                  disabled={loading}
                  className={`px-3 py-1.5 text-xs font-semibold flex items-center gap-1.5 transition-all ${
                    entityType === 'individual'
                      ? 'bg-[#0a0a0a] text-[#ffffff]'
                      : 'text-[#737373] hover:text-[#0a0a0a]'
                  }`}
                >
                  <User size={13} />
                  <span>Public Figure / Creator</span>
                </button>
              </div>
            </div>
            <span className="text-[11px] text-[#737373] italic">
              {entityType === 'individual'
                ? '👤 Evaluates creator giveaway scams, handle spoofing, & VIP crypto bot signals'
                : '🏢 Evaluates brand impersonation, fake customer support, & logo misuse'}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-[#0a0a0a]">Social Platform</label>
              <select
                value={platform}
                onChange={(e) => setPlatform(e.target.value)}
                disabled={loading}
                className="input-field w-full text-xs"
              >
                <option value="Instagram">Instagram</option>
                <option value="X (Twitter)">X (Twitter)</option>
                <option value="YouTube">YouTube</option>
                <option value="TikTok">TikTok</option>
                <option value="Facebook">Facebook</option>
                <option value="LinkedIn">LinkedIn</option>
              </select>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-[#0a0a0a]">Account Handle *</label>
              <input
                type="text"
                value={handle}
                onChange={(e) => setHandle(e.target.value)}
                placeholder={entityType === 'individual' ? 'e.g. @alexrivers_tech_giveaway' : 'e.g. @rolex_official_support'}
                disabled={loading}
                className="input-field w-full text-xs font-mono"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-[#0a0a0a]">Display Name</label>
              <input
                type="text"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder={entityType === 'individual' ? 'e.g. Alex Rivers — Tech Giveaway' : 'e.g. Rolex Official Support'}
                disabled={loading}
                className="input-field w-full text-xs"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-[#0a0a0a]">
                {entityType === 'individual' ? 'Protected Public Figure' : 'Target Brand'}
              </label>
              <select
                value={targetEntity}
                onChange={handleEntitySelectChange}
                disabled={loading}
                className="input-field w-full text-xs"
              >
                {entityType === 'brand' ? (
                  BRAND_ENTITIES.map((b) => (
                    <option key={b} value={b}>{b}</option>
                  ))
                ) : (
                  CREATOR_ENTITIES.map((c) => (
                    <option key={c.name} value={c.name}>{c.name}</option>
                  ))
                )}
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="md:col-span-2 space-y-1.5">
              <label className="text-xs font-medium text-[#0a0a0a]">Profile Bio Text</label>
              <textarea
                value={bioText}
                onChange={(e) => setBioText(e.target.value)}
                placeholder={entityType === 'individual'
                  ? 'Official tech giveaway page! Send ETH/SOL or DM for instant whitelist prize...'
                  : 'Official support channel, giveaway details, DM for customer care...'}
                disabled={loading}
                rows={2}
                className="input-field w-full text-xs"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-[#0a0a0a]">Follower Count</label>
              <input
                type="number"
                value={followerCount}
                onChange={(e) => setFollowerCount(e.target.value)}
                placeholder="e.g. 150"
                disabled={loading}
                className="input-field w-full text-xs font-mono"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-[#0a0a0a]">Account Age (Days)</label>
              <input
                type="number"
                value={accountAgeDays}
                onChange={(e) => setAccountAgeDays(e.target.value)}
                placeholder="e.g. 14"
                disabled={loading}
                className="input-field w-full text-xs font-mono"
              />
            </div>
          </div>

          <div className="flex items-center justify-between pt-2">
            <div className="flex items-center gap-2">
              <label className="text-xs font-medium text-[#0a0a0a]">Profile Picture:</label>
              <input
                type="file"
                accept="image/*"
                onChange={handleImageUpload}
                disabled={loading}
                className="text-xs text-[#737373]"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary px-5 py-2 text-xs font-semibold inline-flex items-center gap-2 shadow-sm"
            >
              {loading ? (
                <>
                  <Loader2 size={14} className="animate-spin" />
                  <span>Analyzing Profile...</span>
                </>
              ) : (
                <>
                  <Share2 size={14} />
                  <span>Analyze Social Profile</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Results Section */}
      <div className="card-paper p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-[#0a0a0a] text-sm flex items-center gap-2">
            <UserX size={16} className="text-[#0a0a0a]" /> Analyzed Social Profiles ({profilesData.length})
          </h3>
          <span className="text-xs text-[#737373]">
            {selectedSocialProfiles.length} selected for Case Report
          </span>
        </div>

        {profilesData.length === 0 ? (
          <div className="p-8 text-center bg-[#fafafa] rounded-[10px] border border-[#e5e5e5] space-y-2">
            <Share2 size={28} className="mx-auto text-[#737373]" />
            <p className="text-xs font-medium text-[#0a0a0a]">No Social Profiles Analyzed Yet</p>
            <p className="text-[11px] text-[#737373]">
              Submit a profile above or click <strong className="text-[#0a0a0a]">&quot;Load Sample Profiles&quot;</strong> to load brand &amp; creator demo data.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto border border-[#e5e5e5] rounded-[10px]">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-[#f5f5f5] text-[#171717] font-semibold border-b border-[#e5e5e5]">
                  <th className="p-3.5 text-center w-10">Select</th>
                  <th className="p-3.5">Platform &amp; Handle</th>
                  <th className="p-3.5">Protected Entity</th>
                  <th className="p-3.5">Account Signals</th>
                  <th className="p-3.5">Intent Classification</th>
                  <th className="p-3.5">Verification</th>
                  <th className="p-3.5">Risk Rating</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#e5e5e5] font-sans">
                {profilesData.map((item, idx) => {
                  const isSelected = selectedSocialProfiles.some((s) => s.profile_id === item.profile_id);
                  const isCreator = item.entity_type === 'individual';

                  return (
                    <tr key={idx} className={`hover:bg-[#fafafa] transition-colors ${isSelected ? 'bg-[#f5f5f5]' : ''}`}>
                      <td className="p-3.5 text-center">
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => toggleSelectProfile(item)}
                          className="rounded-[4px] bg-[#ffffff] border-[#e5e5e5] text-[#0a0a0a] cursor-pointer"
                        />
                      </td>
                      <td className="p-3.5 font-medium text-[#0a0a0a] max-w-[240px]">
                        <div className="space-y-1">
                          <div className="flex items-center gap-1.5">
                            <span className="bg-[#f5f5f5] text-[#171717] px-2 py-0.5 rounded-[18px] text-[10px] font-mono border border-[#e5e5e5]">
                              {item.platform}
                            </span>
                            <span className="font-semibold text-xs text-[#0a0a0a]">{item.display_name}</span>
                          </div>
                          <span className="font-mono text-xs text-[#737373] block">{item.handle}</span>
                        </div>
                      </td>
                      <td className="p-3.5">
                        <div className="space-y-1">
                          <span className={`px-2 py-0.5 rounded-[18px] text-[10px] font-semibold border inline-flex items-center gap-1 ${
                            isCreator
                              ? 'bg-[#fef3c7] text-[#92400e] border-[#fde68a]'
                              : 'bg-[#eff6ff] text-[#1d4ed8] border-[#bfdbfe]'
                          }`}>
                            {isCreator ? <User size={10} /> : <Building2 size={10} />}
                            <span>{isCreator ? 'Creator / Public Figure' : 'Corporate Brand'}</span>
                          </span>
                          <span className="text-[11px] font-medium text-[#0a0a0a] block">
                            {item.protected_entity || item.target_brand}
                          </span>
                        </div>
                      </td>
                      <td className="p-3.5">
                        <div className="space-y-0.5 text-[11px]">
                          <span className="text-[#737373] block">
                            Followers: <strong className="text-[#0a0a0a]">{item.follower_count?.toLocaleString() || 'N/A'}</strong>
                          </span>
                          <span className="text-[#737373] block">
                            Age: <strong className="text-[#0a0a0a]">{item.account_age_days ? `${item.account_age_days} days` : 'N/A'}</strong>
                            {item.age_penalty && <span className="text-[#e7000b] font-bold ml-1">(NEW)</span>}
                          </span>
                          {item.handle_spoof_penalty && (
                            <span className="text-[#e7000b] text-[10px] font-bold block bg-[#fff1f2] px-1.5 py-0.5 rounded border border-[#ffe4e6]">
                              ⚠ Spoofed Handle Signal
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="p-3.5">
                        <span className={`px-2 py-0.5 rounded-[18px] text-[11px] font-semibold border ${
                          item.is_legitimate ? 'bg-[#ecfdf5] text-[#059669] border-[#a7f3d0]' : 'bg-[#fff1f2] text-[#e7000b] border-[#ffe4e6]'
                        }`}>
                          {item.intent_label}
                        </span>
                      </td>
                      <td className="p-3.5">
                        <button
                          type="button"
                          onClick={() => handleToggleVerifiedOverride(item)}
                          className={`px-2.5 py-1 rounded-[18px] text-[10px] font-semibold border inline-flex items-center gap-1 transition-all ${
                            item.is_verified_official
                              ? 'bg-[#ecfdf5] text-[#059669] border-[#a7f3d0]'
                              : 'bg-[#ffffff] text-[#737373] hover:text-[#0a0a0a] border-[#e5e5e5]'
                          }`}
                        >
                          {item.is_verified_official ? <UserCheck size={12} /> : <UserX size={12} />}
                          <span>{item.is_verified_official ? 'Verified Official' : 'Mark as Verified'}</span>
                        </button>
                      </td>
                      <td className="p-3.5">
                        <span className={`px-2.5 py-1 rounded-[18px] text-xs font-bold border ${
                          item.risk_rating >= 70
                            ? 'bg-[#fff1f2] text-[#e7000b] border-[#ffe4e6]'
                            : item.risk_rating >= 40
                            ? 'bg-[#fffbe6] text-[#d97706] border-[#fef3c7]'
                            : 'bg-[#ecfdf5] text-[#059669] border-[#a7f3d0]'
                        }`}>
                          {item.verdict} ({item.risk_rating}%)
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default SocialWatchTab;
