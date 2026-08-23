import React, { useEffect } from 'react';
import { AlertCircle, CheckCircle2, Info, X } from 'lucide-react';

const Toast = ({ toasts, removeToast }) => {
  return (
    <div className="fixed top-5 right-5 z-50 flex flex-col gap-3 max-w-sm w-full pointer-events-none">
      {toasts.map((toast) => (
        <ToastItem key={toast.id} toast={toast} removeToast={removeToast} />
      ))}
    </div>
  );
};

const ToastItem = ({ toast, removeToast }) => {
  useEffect(() => {
    const timer = setTimeout(() => {
      removeToast(toast.id);
    }, toast.duration || 5000);
    return () => clearTimeout(timer);
  }, [toast, removeToast]);

  const icons = {
    error: <AlertCircle className="text-[#e7000b] shrink-0" size={18} />,
    success: <CheckCircle2 className="text-[#0a0a0a] shrink-0" size={18} />,
    info: <Info className="text-[#737373] shrink-0" size={18} />
  };

  const borderColors = {
    error: 'border-[#fca5a5] bg-[#ffffff] text-[#0a0a0a]',
    success: 'border-[#e5e5e5] bg-[#ffffff] text-[#0a0a0a]',
    info: 'border-[#e5e5e5] bg-[#ffffff] text-[#0a0a0a]'
  };

  return (
    <div
      className={`pointer-events-auto p-4 rounded-[18px] border shadow-sm flex items-start gap-3 transition-all duration-300 ${
        borderColors[toast.type] || borderColors.info
      }`}
    >
      {icons[toast.type] || icons.info}
      <div className="flex-1 text-sm">
        {toast.title && <div className="font-medium text-[#0a0a0a] mb-0.5">{toast.title}</div>}
        <div className="text-xs text-[#737373]">{toast.message}</div>
      </div>
      <button
        onClick={() => removeToast(toast.id)}
        className="text-[#737373] hover:text-[#0a0a0a] transition-colors p-1"
      >
        <X size={14} />
      </button>
    </div>
  );
};

export default Toast;
