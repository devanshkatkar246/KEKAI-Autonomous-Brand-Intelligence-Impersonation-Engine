import React, { useState, useEffect, useRef } from 'react';
import {
  GitFork,
  Network,
  ShieldAlert,
  Loader2,
  RefreshCw,
  PlusCircle,
  ExternalLink,
  Layers,
  Activity,
  AlertTriangle,
  Info,
  X,
  HelpCircle,
  Sparkles,
  ShoppingBag,
  Share2,
  FileText,
  Image as ImageIcon
} from 'lucide-react';
import NetworkIntelligenceSection from './NetworkIntelligenceSection';

const NODE_COLORS = {
  domain: { bg: '#0a0a0a', border: '#333333', label: 'Domain Asset', icon: FileText },
  logo: { bg: '#7c3aed', border: '#6d28d9', label: 'Logo Match Asset', icon: ImageIcon },
  visual_phishing: { bg: '#059669', border: '#047857', label: 'Visual Phishing Check', icon: ShieldAlert },
  listing: { bg: '#d97706', border: '#b45309', label: 'Marketplace Listing', icon: ShoppingBag },
  social_profile: { bg: '#e11d48', border: '#be123c', label: 'Social Media Profile', icon: Share2 }
};

const LinkedInfrastructureTab = ({
  apiBaseUrl,
  addToast,
  selectedDomains = [],
  selectedLogos = [],
  selectedVisualPhishing = [],
  brandName = '',
  handleAddClusterToCase = () => {},
  toggleSelectDomain = () => {}
}) => {
  const [activeView, setActiveView] = useState('clusters'); // 'clusters' or 'case'
  const [loading, setLoading] = useState(false);
  const [clusterData, setClusterData] = useState(null);
  const [perCaseData, setPerCaseData] = useState(null);
  const [selectedClusterIndex, setSelectedClusterIndex] = useState(0);

  const [dismissInfoPanel, setDismissInfoPanel] = useState(false);
  const [showConfidenceExplainer, setShowConfidenceExplainer] = useState(false);

  const canvasRef = useRef(null);
  const [lastClustersRefresh, setLastClustersRefresh] = useState(new Date().toLocaleTimeString());

  const [zoomScale, setZoomScale] = useState(1.0);
  const [hoveredNode, setHoveredNode] = useState(null);
  const [hoveredEdge, setHoveredEdge] = useState(null);

  // Derive active brand context
  const activeBrand = selectedDomains.length > 0 && selectedDomains[0].domain
    ? selectedDomains[0].domain.split('.')[0]
    : brandName && !brandName.includes('Acme')
    ? brandName.split(' ')[0]
    : '';

  // Fetch offender clusters
  const fetchClusters = async () => {
    setLoading(true);
    try {
      const clusterApiUrl = activeBrand
        ? `${apiBaseUrl}/api/offender-clusters?brand=${encodeURIComponent(activeBrand)}`
        : `${apiBaseUrl}/api/offender-clusters`;

      console.log('[KEIKAI] Active brand:', activeBrand);
      console.log('[KEIKAI] Graph API URL:', clusterApiUrl);

      const res = await fetch(clusterApiUrl);
      const data = await res.json();
      if (res.ok && data.status === 'success') {
        setClusterData(data.data);
        setSelectedClusterIndex(0); // Auto-select top matching cluster returned by backend
        setLastClustersRefresh(new Date().toLocaleTimeString());
      }
    } catch (err) {
      console.error('Failed to fetch offender clusters:', err);
      addToast('Error', 'Failed to load offender clusters.', 'error');
    } finally {
      setLoading(false);
    }
  };

  // Fetch per-case linked infrastructure
  const fetchCaseLinks = async () => {
    if (selectedDomains.length === 0 && selectedLogos.length === 0 && selectedVisualPhishing.length === 0) {
      setPerCaseData({ total_linked_assets: 0, linked_assets: [] });
      return;
    }

    try {
      const payload = {
        evidence_domains: selectedDomains,
        evidence_logos: selectedLogos,
        evidence_visual_phishing: selectedVisualPhishing
      };

      const res = await fetch(`${apiBaseUrl}/api/link-infrastructure`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (res.ok && data.status === 'success') {
        setPerCaseData(data.data);
      }
    } catch (err) {
      console.error('Failed to fetch case linked infrastructure:', err);
    }
  };

  useEffect(() => {
    fetchClusters();
  }, [apiBaseUrl, activeBrand]);

  useEffect(() => {
    fetchCaseLinks();
  }, [selectedDomains, selectedLogos, selectedVisualPhishing, apiBaseUrl]);

  // Render Canvas Network Graph
  useEffect(() => {
    if (!clusterData || !clusterData.clusters || clusterData.clusters.length === 0) return;
    const currentCluster = clusterData.clusters[selectedClusterIndex] || clusterData.clusters[0];
    if (!currentCluster || !currentCluster.nodes) return;

    console.log('[KEIKAI] Selected cluster:', currentCluster.cluster_id);
    console.log('[KEIKAI] Requested graph cluster:', currentCluster.cluster_id);

    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;

    ctx.clearRect(0, 0, width, height);

    ctx.save();
    ctx.translate(width / 2, height / 2);
    ctx.scale(zoomScale, zoomScale);
    ctx.translate(-width / 2, -height / 2);

    const nodes = currentCluster.nodes.map((n, idx) => {
      const angle = (idx / currentCluster.nodes.length) * 2 * Math.PI;
      const radius = Math.min(width, height) * 0.32;
      return {
        ...n,
        x: width / 2 + radius * Math.cos(angle),
        y: height / 2 + radius * Math.sin(angle)
      };
    });

    // Draw Edges
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const isHovered = hoveredEdge && ((hoveredEdge.source === nodes[i].id && hoveredEdge.target === nodes[j].id) || (hoveredEdge.source === nodes[j].id && hoveredEdge.target === nodes[i].id));

        ctx.lineWidth = isHovered ? 3.0 : 1.5;
        ctx.strokeStyle = isHovered ? '#e7000b' : '#d4d4d4';
        ctx.beginPath();
        ctx.moveTo(nodes[i].x, nodes[i].y);
        ctx.lineTo(nodes[j].x, nodes[j].y);
        ctx.stroke();

        // Edge Relationship Pill Label
        const midX = (nodes[i].x + nodes[j].x) / 2;
        const midY = (nodes[i].y + nodes[j].y) / 2;

        const relLabel = currentCluster.edges?.[0]?.relationship || 'Shared Fingerprint';
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(midX - 55, midY - 9, 110, 18);
        ctx.lineWidth = 1;
        ctx.strokeStyle = '#e5e5e5';
        ctx.strokeRect(midX - 55, midY - 9, 110, 18);

        ctx.fillStyle = '#525252';
        ctx.font = '9px Geist, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(relLabel.length > 22 ? relLabel.substring(0, 20) + '...' : relLabel, midX, midY + 3);
      }
    }

    // Draw Nodes
    nodes.forEach((node) => {
      const isHovered = hoveredNode && hoveredNode.id === node.id;
      const radius = isHovered ? 22 : 18;
      const colorEntry = NODE_COLORS[node.type] || NODE_COLORS.domain;

      ctx.beginPath();
      ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI);
      ctx.fillStyle = colorEntry.bg;
      ctx.fill();

      ctx.lineWidth = isHovered ? 3 : 2;
      ctx.strokeStyle = isHovered ? '#38bdf8' : '#ffffff';
      ctx.stroke();

      // Node Label
      ctx.fillStyle = '#0a0a0a';
      ctx.font = isHovered ? 'bold 12px Geist, sans-serif' : '11px Geist, sans-serif';
      ctx.textAlign = 'center';
      const label = node.label.length > 22 ? node.label.substring(0, 20) + '...' : node.label;
      ctx.fillText(label, node.x, node.y + radius + 14);
    });

    ctx.restore();
  }, [clusterData, selectedClusterIndex, zoomScale, hoveredNode, hoveredEdge]);

  const activeClusters = clusterData?.clusters || [];
  const currentCluster = activeClusters[selectedClusterIndex];

  return (
    <div className="space-y-6 font-body-md antialiased text-on-background">
      {/* Header Section */}
      <header className="flex flex-col gap-1">
        <h1 className="font-display text-display text-on-background">Linked Infrastructure</h1>
        <p className="font-body-lg text-body-lg text-on-surface-variant max-w-3xl">
          Fingerprint threat operators by correlation across IP addresses, MX servers, SSL certificates, and shared logo assets.
        </p>
      </header>

      {/* Top Controls & View Switcher */}
      <section className="bg-surface-container-lowest rounded-lg border border-outline-variant p-6 space-y-4">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <h2 className="font-headline-md font-semibold text-on-background text-lg flex items-center gap-2">
              <span className="material-symbols-outlined text-primary">hub</span> Threat Correlation Engine
            </h2>
            <p className="font-body-md text-on-surface-variant text-xs">
              Maps technical overlap across registered domains, IPs, mail servers, and visual logo assets.
            </p>
          </div>

          <div className="flex items-center gap-2 bg-surface-container-low p-1 rounded-full border border-outline-variant">
            <button
              onClick={() => setActiveView('clusters')}
              className={`px-4 py-1.5 rounded-full text-xs font-medium transition-all ${
                activeView === 'clusters'
                  ? 'bg-primary text-on-primary shadow-xs'
                  : 'text-on-surface-variant hover:text-on-background'
              }`}
            >
              Offender Clusters ({activeClusters.length})
            </button>
            <button
              onClick={() => setActiveView('case')}
              className={`px-4 py-1.5 rounded-full text-xs font-medium transition-all ${
                activeView === 'case'
                  ? 'bg-primary text-on-primary shadow-xs'
                  : 'text-on-surface-variant hover:text-on-background'
              }`}
            >
              Case Related Assets ({perCaseData?.total_linked_assets || 0})
            </button>
          </div>
        </div>

        {/* Info Banner */}
        {!dismissInfoPanel && (
          <div className="bg-surface-container p-4 rounded-lg border border-outline-variant relative flex items-start gap-3">
            <span className="material-symbols-outlined text-primary text-[20px] mt-0.5">info</span>
            <div className="space-y-1 pr-6 text-xs text-on-surface">
              <h4 className="font-headline-md font-semibold text-on-background">How Infrastructure Clustering Works:</h4>
              <p className="font-body-md text-on-surface-variant">
                When multiple flagged items share technical fingerprints (like hosting IP or logo image), we group them into a cluster — revealing when one operator is likely running multiple fake properties.
              </p>
            </div>
            <button
              type="button"
              onClick={() => setDismissInfoPanel(true)}
              className="absolute top-3 right-3 text-on-surface-variant hover:text-on-background"
            >
              <X size={15} />
            </button>
          </div>
        )}
      </section>

      {/* TASK 3B: NETWORK INTELLIGENCE & INFRASTRUCTURE RESOLUTION */}
      <NetworkIntelligenceSection
        apiBaseUrl={apiBaseUrl}
        initialDomain={selectedDomains[0]?.domain || ''}
        addToast={addToast}
      />

      {/* VIEW 1: OFFENDER CLUSTER OVERVIEW & GRAPH */}
      {activeView === 'clusters' && (
        <div className="space-y-6">
          {loading ? (
            <div className="bg-surface-container-lowest rounded-lg border border-outline-variant p-12 text-center text-xs text-on-surface-variant animate-pulse">
              <Loader2 size={24} className="animate-spin text-primary mx-auto mb-2" />
              <span>Correlating technical fingerprints across database...</span>
            </div>
          ) : activeClusters.length === 0 ? (
            <div className="bg-surface-container-lowest rounded-lg border border-outline-variant p-12 text-center text-xs text-on-surface-variant space-y-2">
              <span className="material-symbols-outlined text-outline text-[40px]">hub</span>
              <h3 className="font-headline-md font-semibold text-on-background text-sm">No Offender Clusters Detected Yet</h3>
              <p>Run domain scans, logo comparisons, or visual phishing checks to build the fingerprint store.</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 min-w-0">
              {/* Cluster Selection Sidebar */}
              <div className="space-y-4 lg:col-span-4 min-w-0">
                <div className="flex items-center justify-between px-1">
                  <div>
                    <h3 className="font-headline-md font-semibold text-on-background text-sm">
                      Threat Clusters ({activeClusters.length})
                    </h3>
                    <span className="font-technical-data text-[10px] text-on-surface-variant block">
                      Updated: {lastClustersRefresh}
                    </span>
                  </div>
                  <button
                    onClick={fetchClusters}
                    className="btn-secondary py-1 px-3 text-xs inline-flex items-center gap-1"
                  >
                    <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
                    <span>Refresh</span>
                  </button>
                </div>

                <div className="space-y-3 max-h-[600px] overflow-y-auto pr-1">
                  {activeClusters.map((cluster, idx) => {
                    const isSelected = selectedClusterIndex === idx;
                    return (
                      <div
                        key={cluster.cluster_id}
                        onClick={() => setSelectedClusterIndex(idx)}
                        className={`bg-surface-container-lowest rounded-lg border border-outline-variant p-4 cursor-pointer transition-all space-y-3 ${
                          isSelected ? 'ring-2 ring-primary bg-surface-container-low' : 'hover:bg-surface-bright'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-technical-data font-bold text-xs text-on-background">
                            {cluster.cluster_id}
                          </span>
                          <span className="px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-error-container text-on-error-container border border-error/20 font-label-caps">
                            {cluster.confidence} Confidence ({cluster.confidence_score}%)
                          </span>
                        </div>

                        {cluster.plain_language_summary && (
                          <p className="font-body-md text-[11px] text-on-surface-variant leading-relaxed">
                            {cluster.plain_language_summary}
                          </p>
                        )}

                        <div className="flex flex-wrap gap-1 pt-1">
                          {cluster.shared_signals.map((sig, sIdx) => (
                            <span
                              key={sIdx}
                              className="bg-surface-container text-on-background text-[10px] px-2 py-0.5 rounded border border-outline-variant font-technical-data"
                            >
                              {sig}
                            </span>
                          ))}
                        </div>

                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleAddClusterToCase(cluster);
                            addToast('Cluster Added', `Added all ${cluster.asset_count} assets from ${cluster.cluster_id} to Case Report.`, 'success');
                          }}
                          className="w-full btn-secondary py-1.5 text-xs inline-flex items-center justify-center gap-1.5"
                        >
                          <PlusCircle size={13} />
                          <span>Link Entire Cluster to Case</span>
                        </button>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Main Graph & Asset Table */}
              <div className="space-y-6 lg:col-span-8 min-w-0">
                {currentCluster && (
                  <>
                    <div className="bg-surface-container-lowest rounded-lg border border-outline-variant p-5 space-y-4 min-w-0">
                      <div className="flex flex-wrap items-center justify-between border-b border-outline-variant pb-3 gap-2">
                        <h3 className="font-headline-md font-semibold text-on-background text-sm flex items-center gap-2">
                          <span className="material-symbols-outlined text-primary">hub</span> Infrastructure Graph &mdash; {currentCluster.cluster_id}
                        </h3>
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => setZoomScale((z) => Math.min(2.0, z + 0.15))}
                            className="px-2.5 py-1 rounded border border-outline-variant bg-surface hover:bg-surface-container-high font-technical-data text-xs"
                            title="Zoom In"
                          >
                            +
                          </button>
                          <button
                            type="button"
                            onClick={() => setZoomScale((z) => Math.max(0.5, z - 0.15))}
                            className="px-2.5 py-1 rounded border border-outline-variant bg-surface hover:bg-surface-container-high font-technical-data text-xs"
                            title="Zoom Out"
                          >
                            -
                          </button>
                          <button
                            type="button"
                            onClick={() => setZoomScale(1.0)}
                            className="px-2.5 py-1 rounded border border-outline-variant bg-surface hover:bg-surface-container-high font-technical-data text-xs"
                            title="Fit to View"
                          >
                            Fit
                          </button>
                          <span className="font-technical-data text-xs text-on-surface-variant ml-1">
                            Nodes: <strong className="text-on-background">{currentCluster.nodes?.length}</strong>
                          </span>
                        </div>
                      </div>

                      <div className="bg-surface-container-low rounded border border-outline-variant p-2 flex items-center justify-center relative overflow-hidden w-full min-w-0">
                        <canvas
                          ref={canvasRef}
                          width={700}
                          height={360}
                          className="w-full max-w-full h-[360px] cursor-pointer block"
                        />
                      </div>
                    </div>

                    <div className="bg-surface-container-lowest rounded-lg border border-outline-variant overflow-hidden">
                      <div className="p-4 bg-surface-container-low border-b border-outline-variant">
                        <h3 className="font-headline-md font-semibold text-on-background text-sm">
                          Cluster Infrastructure Assets ({currentCluster.assets?.length})
                        </h3>
                      </div>

                      <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                          <thead>
                            <tr className="border-b border-outline-variant bg-surface-container-low font-label-caps text-label-caps text-on-surface-variant">
                              <th className="py-2.5 px-4">Asset Identifier</th>
                              <th className="py-2.5 px-4">Type</th>
                              <th className="py-2.5 px-4">Hosting IP</th>
                              <th className="py-2.5 px-4">Target Brand</th>
                              <th className="py-2.5 px-4 text-right">Action</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-outline-variant">
                            {currentCluster.assets?.map((a, aIdx) => (
                              <tr key={aIdx} className="hover:bg-surface-bright transition-colors">
                                <td className="py-3 px-4 font-technical-data text-technical-data text-on-background">{a.asset_id}</td>
                                <td className="py-3 px-4">
                                  <span className="inline-flex px-2 py-0.5 bg-surface-container-highest rounded text-on-surface-variant font-body-md text-[12px] border border-outline-variant">
                                    {a.asset_type}
                                  </span>
                                </td>
                                <td className="py-3 px-4 font-technical-data text-technical-data text-on-surface-variant">{a.ip_address || '-'}</td>
                                <td className="py-3 px-4 font-body-md text-on-background">{a.target_brand || '-'}</td>
                                <td className="py-3 px-4 text-right">
                                  <button
                                    onClick={() => {
                                      toggleSelectDomain({ domain: a.asset_id, riskScore: 85, isRegistered: true, dns_a: a.ip_address ? [a.ip_address] : [] });
                                    }}
                                    className="text-primary font-label-caps text-label-caps hover:underline"
                                  >
                                    ADD TO CASE
                                  </button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* VIEW 2: PER-CASE LINKED INFRASTRUCTURE */}
      {activeView === 'case' && (
        <div className="bg-surface-container-lowest rounded-lg border border-outline-variant overflow-hidden">
          <div className="p-5 bg-surface-container-low border-b border-outline-variant">
            <h3 className="font-headline-md font-semibold text-on-background text-base">
              Case Related Infrastructure ({perCaseData?.total_linked_assets || 0} discovered)
            </h3>
            <p className="font-body-md text-xs text-on-surface-variant">
              Assets sharing technical fingerprints with active Case Report evidence.
            </p>
          </div>

          {!perCaseData || perCaseData.linked_assets.length === 0 ? (
            <div className="p-12 text-center text-xs text-on-surface-variant space-y-2">
              <span className="material-symbols-outlined text-outline text-[32px]">hub</span>
              <p className="font-headline-md font-semibold text-on-background">No Related Assets Found for Current Case</p>
              <p>Add evidence items to the Case Report tab to discover overlapping infrastructure.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-outline-variant bg-surface-container-low font-label-caps text-label-caps text-on-surface-variant">
                    <th className="py-2.5 px-4">Asset Identifier</th>
                    <th className="py-2.5 px-4">Type</th>
                    <th className="py-2.5 px-4">Hosting IP</th>
                    <th className="py-2.5 px-4">Matched Signals</th>
                    <th className="py-2.5 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-outline-variant">
                  {perCaseData.linked_assets.map((item, idx) => (
                    <tr key={idx} className="hover:bg-surface-bright transition-colors">
                      <td className="py-3 px-4 font-technical-data text-technical-data text-on-background">{item.asset_id}</td>
                      <td className="py-3 px-4">
                        <span className="inline-flex px-2 py-0.5 bg-surface-container-highest rounded text-on-surface-variant font-body-md text-[12px] border border-outline-variant">
                          {item.asset_type}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-technical-data text-technical-data text-on-surface-variant">{item.ip_address || '-'}</td>
                      <td className="py-3 px-4">
                        <div className="flex flex-wrap gap-1">
                          {item.matched_signals.map((sig, sIdx) => (
                            <span
                              key={sIdx}
                              className="px-2 py-0.5 rounded-full bg-error-container text-on-error-container border border-error/20 font-label-caps text-[10px]"
                            >
                              {sig}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => {
                            toggleSelectDomain({ domain: item.asset_id, riskScore: 80, isRegistered: true, dns_a: item.ip_address ? [item.ip_address] : [] });
                          }}
                          className="btn-secondary py-1 px-3 text-xs inline-flex items-center gap-1"
                        >
                          <PlusCircle size={13} />
                          <span>Add to Case</span>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default LinkedInfrastructureTab;

