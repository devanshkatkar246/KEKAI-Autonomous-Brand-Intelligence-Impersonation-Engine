import React from 'react';
import { AlertCircle, RefreshCw } from 'lucide-react';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('ErrorBoundary caught an error:', error, errorInfo);
    this.setState({ errorInfo });
  }

  handleReload = () => {
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#f5f5f5] text-[#0a0a0a] flex items-center justify-center p-6 font-['Geist',sans-serif]">
          <div className="card-paper p-8 max-w-lg w-full text-center border border-[#e5e5e5]">
            <div className="w-14 h-14 bg-[#fff1f2] rounded-[18px] flex items-center justify-center mx-auto mb-4 border border-[#ffe4e6] text-[#e7000b]">
              <AlertCircle size={28} />
            </div>
            <h2 className="text-xl font-semibold text-[#0a0a0a] mb-2 tracking-tight">System Error Occurred</h2>
            <p className="text-sm text-[#737373] mb-6">
              An unexpected application error was trapped by the error boundary.
            </p>
            {this.state.error && (
              <div className="bg-[#f5f5f5] p-3 rounded-[10px] text-left text-xs font-mono text-[#e7000b] overflow-x-auto mb-6 max-h-40 border border-[#e5e5e5]">
                {this.state.error.toString()}
              </div>
            )}
            <button
              onClick={this.handleReload}
              className="btn-primary px-6 py-2.5 inline-flex items-center justify-center gap-2 shadow-sm"
            >
              <RefreshCw size={15} /> Reload Dashboard
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
