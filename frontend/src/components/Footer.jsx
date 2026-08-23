import React from 'react';
import { ShieldCheck, Cpu } from 'lucide-react';

const Footer = ({ apiBaseUrl }) => {
  const activeEngines = [
    { name: 'dnstwist', role: 'Domain Typosquatting Permutations' },
    { name: 'imagehash', role: 'Perceptual Hash & Color Similarity' },
    { name: 'Intent Classifier', role: 'Zero-Shot MNLI Intent Analysis' },
    { name: 'Graph Core', role: 'Offender Fingerprinting & Threat Linkage' }
  ];

  return (
    <footer className="w-full bg-[#ffffff] border-t border-[#e5e5e5] px-6 py-5 mt-12 font-['Geist',sans-serif]">
      <div className="max-w-[1280px] mx-auto flex flex-col md:flex-row items-center justify-between gap-4 text-xs">
        {/* Left Branding */}
        <div className="flex items-center gap-2 text-[#737373]">
          <ShieldCheck size={16} className="text-[#0a0a0a]" />
          <span>
            KEIKAI — Anti-Impersonation Engine (Brand Protection Baseline).
          </span>
        </div>

        {/* Right Active Engine Badges */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[#737373] font-medium flex items-center gap-1">
            <Cpu size={14} className="text-[#0a0a0a]" /> Active Demo Engines:
          </span>

          {activeEngines.map((item) => (
            <span
              key={item.name}
              className="inline-flex items-center gap-1 px-2.5 py-1 bg-[#f5f5f5] text-[#0a0a0a] rounded-[18px] border border-[#e5e5e5] font-mono text-[10px]"
              title={item.role}
            >
              <strong className="font-semibold">{item.name}</strong>:
              <span className="text-[#737373]">{item.role}</span>
            </span>
          ))}
        </div>
      </div>
    </footer>
  );
};

export default Footer;
