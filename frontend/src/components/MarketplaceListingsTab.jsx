import React, { useState, useMemo } from 'react';
import { ShoppingBag, Upload, Loader2, AlertCircle, CheckCircle2, RefreshCw, DollarSign, Tag, ShieldAlert, IndianRupee } from 'lucide-react';

// ─── Currency utilities ──────────────────────────────────────────────────────

const CURRENCY_META = {
  USD: { symbol: '$', label: 'USD — US Dollar',    flag: '🇺🇸' },
  INR: { symbol: '₹', label: 'INR — Indian Rupee', flag: '🇮🇳' },
};

// Indian MSRP figures shown in the brand dropdown (realistic India retail prices)
const BRAND_MSRP = {
  Rolex:          { usd: 10000,   inr: 1050000 },
  Apple:          { usd: 999,     inr: 89900   },
  Nike:           { usd: 150,     inr: 10295   },
  'Louis Vuitton':{ usd: 2500,    inr: 305000  },
  'Ray-Ban':      { usd: 180,     inr: 15490   },
  Gucci:          { usd: 1800,    inr: 195000  },
  Samsung:        { usd: 899,     inr: 74999   },
  Sony:           { usd: 399,     inr: 34990   },
};

/** Format a price using Indian lakh/crore comma grouping for INR. */
function formatPrice(amount, currency) {
  if (amount == null) return 'N/A';
  const sym = CURRENCY_META[currency]?.symbol ?? '$';
  if (currency === 'INR') {
    // Indian number system: 1,05,000.00
    const str = Math.abs(amount).toFixed(2);
    const [intPart, dec] = str.split('.');
    let s = intPart;
    let result = s.slice(-3);
    s = s.slice(0, -3);
    while (s.length > 0) {
      result = s.slice(-2) + ',' + result;
      s = s.slice(0, -2);
    }
    return `${sym}${result}.${dec}`;
  }
  return `${sym}${Number(amount).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

/** Returns a best-guess default currency based on browser locale. */
function detectDefaultCurrency() {
  try {
    const locale = navigator.language || '';
    if (locale.startsWith('en-IN') || locale === 'hi' || locale.startsWith('hi-')) return 'INR';
  } catch (_) {}
  return 'USD';
}

// ─────────────────────────────────────────────────────────────────────────────

const MarketplaceListingsTab = ({
  apiBaseUrl,
  addToast,
  selectedListings,
  toggleSelectListing,
}) => {
  const [title, setTitle]               = useState('');
  const [sellerName, setSellerName]     = useState('');
  const [targetBrand, setTargetBrand]   = useState('Rolex');
  const [price, setPrice]               = useState('');
  const [currency, setCurrency]         = useState(() => detectDefaultCurrency());
  const [description, setDescription]   = useState('');
  const [productImage, setProductImage] = useState(null);

  const [loading, setLoading]             = useState(false);
  const [loadingSamples, setLoadingSamples] = useState(false);
  const [listingsData, setListingsData]   = useState([]);

  // Current brand MSRP for selected currency — shown live in the label
  const currentMsrp = useMemo(() => {
    const entry = BRAND_MSRP[targetBrand];
    if (!entry) return null;
    return formatPrice(entry[currency.toLowerCase()], currency);
  }, [targetBrand, currency]);

  const handleImageUpload = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      if (!file.type.startsWith('image/')) {
        addToast('Validation Error', 'Please upload a valid product image.', 'error');
        return;
      }
      setProductImage(file);
    }
  };

  const handleRunAnalysis = async (e) => {
    e?.preventDefault();
    if (!title.trim() || !sellerName.trim()) {
      addToast('Validation Error', 'Please enter listing title and seller name.', 'error');
      return;
    }

    setLoading(true);
    try {
      const formData = new FormData();
      formData.append('title', title.trim());
      formData.append('seller_name', sellerName.trim());
      if (description) formData.append('description', description.trim());
      if (price)       formData.append('price', price.toString());
      formData.append('currency', currency);
      if (targetBrand)   formData.append('target_brand', targetBrand.trim());
      if (productImage)  formData.append('image', productImage);

      const response = await fetch(`${apiBaseUrl}/api/listing-check`, {
        method: 'POST',
        body: formData,
      });

      const resData = await response.json();

      if (response.ok && resData.status === 'success') {
        const item = resData.data;
        setListingsData((prev) => [item, ...prev]);
        addToast(
          'Listing Analysis Complete',
          `Verdict: ${item.verdict} (${item.risk_rating}% risk).`,
          item.risk_rating >= 70 ? 'error' : 'success'
        );
      } else {
        throw new Error(resData.detail || 'Listing analysis failed.');
      }
    } catch (err) {
      addToast('Analysis Error', err.message || 'An error occurred during listing analysis.', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleLoadSampleListings = async () => {
    setLoadingSamples(true);
    try {
      const response = await fetch(`${apiBaseUrl}/api/listing-sample-data`);
      const resData  = await response.json();

      if (response.ok && resData.status === 'success') {
        const samples = resData.data.sample_listings || [];
        setListingsData(samples);
        const inrCount = samples.filter((s) => s.currency === 'INR').length;
        const usdCount = samples.filter((s) => s.currency === 'USD').length;
        addToast(
          'Sample Data Loaded',
          `Loaded ${samples.length} demo listings: ${usdCount} USD, ${inrCount} INR (mix of counterfeit & genuine).`,
          'info'
        );
      }
    } catch (err) {
      addToast('Sample Load Error', 'Failed to fetch sample marketplace listings.', 'error');
    } finally {
      setLoadingSamples(false);
    }
  };

  return (
    <div className="space-y-6 font-['Geist',sans-serif]">
      {/* Header Card */}
      <div className="card-paper p-6 space-y-5">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <h2 className="text-xl font-semibold text-[#0a0a0a] tracking-tight mb-1 flex items-center gap-2">
              <ShoppingBag size={20} className="text-[#0a0a0a]" /> Counterfeit Marketplace Listing Detection
            </h2>
            <p className="text-sm text-[#737373]">
              Detects counterfeit brand product listings, seller impersonation, price anomalies (≤&nbsp;50% MSRP), and image hash likeness. Supports <strong>USD</strong> and <strong>INR</strong> market evidence.
            </p>
          </div>

          <button
            type="button"
            onClick={handleLoadSampleListings}
            disabled={loadingSamples}
            className="btn-secondary px-4 py-2 text-xs font-semibold inline-flex items-center gap-2 shrink-0 border border-[#e5e5e5]"
          >
            <RefreshCw size={13} className={loadingSamples ? 'animate-spin' : ''} />
            <span>{loadingSamples ? 'Loading Demo Data...' : 'Load Sample Listings (USD + INR)'}</span>
          </button>
        </div>

        {/* Form Inputs */}
        <form onSubmit={handleRunAnalysis} className="space-y-4 pt-2 border-t border-[#e5e5e5]">
          {/* Row 1: Title, Seller, Brand, Currency+Price */}
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-[#0a0a0a]">Listing Title *</label>
              <input
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="e.g. Rolex Submariner Brand New Replica"
                disabled={loading}
                className="input-field w-full text-xs"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-[#0a0a0a]">Seller Username *</label>
              <input
                type="text"
                value={sellerName}
                onChange={(e) => setSellerName(e.target.value)}
                placeholder="e.g. LuxuryDiscounts_Direct"
                disabled={loading}
                className="input-field w-full text-xs font-mono"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-[#0a0a0a]">Target Brand</label>
              <select
                value={targetBrand}
                onChange={(e) => setTargetBrand(e.target.value)}
                disabled={loading}
                className="input-field w-full text-xs"
              >
                {Object.entries(BRAND_MSRP).map(([brand, msrp]) => (
                  <option key={brand} value={brand}>
                    {brand} (MSRP {formatPrice(msrp[currency.toLowerCase()], currency)})
                  </option>
                ))}
              </select>
            </div>

            {/* Price + Currency selector — side by side */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-[#0a0a0a] flex items-center justify-between">
                <span>
                  Price
                  {currentMsrp && (
                    <span className="ml-1.5 text-[#737373] font-normal">
                      (MSRP {currentMsrp})
                    </span>
                  )}
                </span>
              </label>
              <div className="flex gap-1.5">
                {/* Currency toggle */}
                <div className="flex rounded-[8px] border border-[#e5e5e5] overflow-hidden shrink-0">
                  {Object.keys(CURRENCY_META).map((cur) => (
                    <button
                      key={cur}
                      type="button"
                      onClick={() => setCurrency(cur)}
                      disabled={loading}
                      title={CURRENCY_META[cur].label}
                      className={`px-2.5 py-1.5 text-[11px] font-bold transition-all ${
                        currency === cur
                          ? 'bg-[#0a0a0a] text-[#ffffff]'
                          : 'bg-[#f5f5f5] text-[#737373] hover:text-[#0a0a0a]'
                      }`}
                    >
                      {CURRENCY_META[cur].symbol}
                    </button>
                  ))}
                </div>
                <input
                  type="number"
                  step="0.01"
                  value={price}
                  onChange={(e) => setPrice(e.target.value)}
                  placeholder={currency === 'INR' ? 'e.g. 4999' : 'e.g. 249.99'}
                  disabled={loading}
                  className="input-field flex-1 text-xs font-mono min-w-0"
                />
              </div>
              {/* Locale hint */}
              <p className="text-[10px] text-[#737373]">
                {currency === 'INR'
                  ? '🇮🇳 Indian market — comparing vs India retail MSRP (incl. GST/duty)'
                  : '🇺🇸 US market — comparing vs USD MSRP'}
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="md:col-span-2 space-y-1.5">
              <label className="text-xs font-medium text-[#0a0a0a]">Item Description</label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Item description, quality notes, box set details..."
                disabled={loading}
                rows={2}
                className="input-field w-full text-xs"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-[#0a0a0a]">Product Image</label>
              <div className="relative border-2 border-dashed border-[#e5e5e5] hover:border-[#0a0a0a] rounded-[10px] p-2 bg-[#f5f5f5] text-center flex items-center justify-center min-h-[60px]">
                <input
                  type="file"
                  accept="image/*"
                  onChange={handleImageUpload}
                  disabled={loading}
                  className="absolute inset-0 opacity-0 cursor-pointer w-full h-full"
                />
                <span className="text-xs text-[#737373] truncate max-w-[200px]">
                  {productImage ? productImage.name : 'Click to Upload Product Image'}
                </span>
              </div>
            </div>
          </div>

          <div className="flex justify-end pt-2">
            <button
              type="submit"
              disabled={loading}
              className="btn-primary px-5 py-2 text-xs font-semibold inline-flex items-center gap-2 shadow-sm"
            >
              {loading ? (
                <>
                  <Loader2 size={14} className="animate-spin" />
                  <span>Analyzing Listing...</span>
                </>
              ) : (
                <>
                  <ShoppingBag size={14} />
                  <span>Analyze Marketplace Listing</span>
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
            <Tag size={16} className="text-[#0a0a0a]" /> Analyzed Marketplace Listings ({listingsData.length})
          </h3>
          <span className="text-xs text-[#737373]">
            {selectedListings.length} selected for Case Report
          </span>
        </div>

        {listingsData.length === 0 ? (
          <div className="p-8 text-center bg-[#fafafa] rounded-[10px] border border-[#e5e5e5] space-y-2">
            <ShoppingBag size={28} className="mx-auto text-[#737373]" />
            <p className="text-xs font-medium text-[#0a0a0a]">No Marketplace Listings Analyzed Yet</p>
            <p className="text-[11px] text-[#737373]">
              Submit a listing above or click <strong className="text-[#0a0a0a]">&quot;Load Sample Listings&quot;</strong> to load 5 USD + 3 INR demo listings.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto border border-[#e5e5e5] rounded-[10px]">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-[#f5f5f5] text-[#171717] font-semibold border-b border-[#e5e5e5]">
                  <th className="p-3.5 text-center w-10">Select</th>
                  <th className="p-3.5">Listing Title</th>
                  <th className="p-3.5">Seller</th>
                  <th className="p-3.5">Listed Price vs MSRP</th>
                  <th className="p-3.5">Intent Classification</th>
                  <th className="p-3.5">Risk Rating</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#e5e5e5] font-sans">
                {listingsData.map((item, idx) => {
                  const isSelected = selectedListings.some((l) => l.listing_id === item.listing_id);
                  const itemCurrency = item.currency || 'USD';
                  const priceStr    = formatPrice(item.price, itemCurrency);
                  const msrpStr     = item.msrp != null ? formatPrice(item.msrp, itemCurrency) : null;

                  return (
                    <tr key={idx} className={`hover:bg-[#fafafa] transition-colors ${isSelected ? 'bg-[#f5f5f5]' : ''}`}>
                      <td className="p-3.5 text-center">
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => toggleSelectListing(item)}
                          className="rounded-[4px] bg-[#ffffff] border-[#e5e5e5] text-[#0a0a0a] cursor-pointer"
                        />
                      </td>
                      <td className="p-3.5 font-medium text-[#0a0a0a] max-w-[260px]">
                        <div className="space-y-0.5">
                          <span className="font-semibold text-xs text-[#0a0a0a] block">{item.title}</span>
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <span className="bg-[#f5f5f5] text-[#171717] px-2 py-0.5 rounded-[18px] text-[10px] font-mono border border-[#e5e5e5]">
                              Brand: {item.target_brand}
                            </span>
                            {/* Currency badge */}
                            <span className={`px-2 py-0.5 rounded-[18px] text-[10px] font-bold border ${
                              itemCurrency === 'INR'
                                ? 'bg-[#fef3c7] text-[#92400e] border-[#fde68a]'
                                : 'bg-[#eff6ff] text-[#1d4ed8] border-[#bfdbfe]'
                            }`}>
                              {CURRENCY_META[itemCurrency]?.symbol}{itemCurrency}
                            </span>
                          </div>
                        </div>
                      </td>
                      <td className="p-3.5 font-mono text-[#171717] font-medium">
                        {item.seller_name}
                      </td>
                      <td className="p-3.5">
                        <div className="space-y-1">
                          <span className="font-mono font-bold text-[#0a0a0a] text-xs">
                            {priceStr}
                          </span>
                          {item.price_anomaly ? (
                            <span className="block text-[10px] font-semibold text-[#e7000b] bg-[#fff1f2] px-2 py-0.5 rounded-[18px] border border-[#ffe4e6]">
                              ALERT: {item.discount_percentage}% off MSRP {msrpStr ? `(${msrpStr})` : ''}
                            </span>
                          ) : (
                            <span className="block text-[10px] text-[#737373]">
                              MSRP: {msrpStr ?? 'N/A'}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="p-3.5">
                        <span className={`px-2 py-0.5 rounded-[18px] text-[11px] font-semibold border ${
                          item.is_legitimate
                            ? 'bg-[#ecfdf5] text-[#059669] border-[#a7f3d0]'
                            : 'bg-[#fff1f2] text-[#e7000b] border-[#ffe4e6]'
                        }`}>
                          {item.intent_label}
                        </span>
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

export default MarketplaceListingsTab;
