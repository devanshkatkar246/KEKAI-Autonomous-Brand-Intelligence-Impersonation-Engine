import React from 'react';
import { Play, Pause, SkipForward, RotateCcw, X, Sparkles } from 'lucide-react';

const DemoControllerBar = ({
  currentStage = 1,
  totalStages = 6,
  isPaused = false,
  onTogglePause = () => {},
  onNextStage = () => {},
  onRestart = () => {},
  onExit = () => {}
}) => {
  const stageNames = [
    { num: 1, name: 'DISCOVER' },
    { num: 2, name: 'VERIFY' },
    { num: 3, name: 'CORRELATE' },
    { num: 4, name: 'INVESTIGATE' },
    { num: 5, name: 'RESPOND' },
    { num: 6, name: 'AUTOMATE' }
  ];

  return (
    <div className="fixed bottom-4 left-1/2 -translate-x-1/2 z-50 max-w-4xl w-[92%] bg-surface-container-lowest/95 backdrop-blur-md border border-primary/40 rounded-2xl shadow-2xl p-3 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs animate-arrive-1 font-body-md">
      {/* DEMO BADGE & CURRENT STAGE */}
      <div className="flex items-center gap-2.5 min-w-0">
        <span className="px-2.5 py-1 rounded-full bg-primary/10 text-primary border border-primary/30 font-bold font-technical-data text-[10px] flex items-center gap-1.5 shrink-0">
          <Sparkles size={12} className="animate-spin text-primary" style={{ animationDuration: '4s' }} />
          DEMO SCENARIO &middot; SIMULATED DATA
        </span>

        <span className="text-on-surface-variant font-technical-data text-[11px] truncate hidden md:inline">
          Target: <strong className="text-primary font-bold">Amazon (amazon.com)</strong>
        </span>
      </div>

      {/* STAGE STEPPER PILLS */}
      <div className="flex items-center gap-1 overflow-x-auto no-scrollbar py-0.5">
        {stageNames.map((st) => {
          const isActive = currentStage === st.num;
          const isDone = currentStage > st.num;

          return (
            <div
              key={st.num}
              className={`px-2.5 py-1 rounded-full text-[10px] font-bold font-technical-data transition-all shrink-0 flex items-center gap-1 ${
                isActive
                  ? 'bg-primary text-on-primary shadow-xs ring-2 ring-primary/40'
                  : isDone
                  ? 'bg-emerald-500/10 text-emerald-600 border border-emerald-500/20'
                  : 'bg-surface-container-high text-on-surface-variant'
              }`}
            >
              <span>{isDone ? '✓' : st.num}</span>
              <span>{st.name}</span>
            </div>
          );
        })}
      </div>

      {/* PRESENTER CONTROLS */}
      <div className="flex items-center gap-1.5 shrink-0">
        <button
          type="button"
          onClick={onTogglePause}
          className="p-1.5 bg-surface-container hover:bg-surface-container-high text-on-surface rounded-lg border border-outline-variant font-bold transition-all"
          title={isPaused ? 'Resume Demonstration' : 'Pause Demonstration'}
        >
          {isPaused ? <Play size={13} className="text-primary" /> : <Pause size={13} />}
        </button>

        <button
          type="button"
          onClick={onNextStage}
          className="px-2.5 py-1.5 bg-primary/10 hover:bg-primary/20 text-primary border border-primary/30 font-bold rounded-lg transition-all flex items-center gap-1 text-[11px]"
          title="Advance to Next Stage"
        >
          <span>NEXT</span>
          <SkipForward size={13} />
        </button>

        <button
          type="button"
          onClick={onRestart}
          className="p-1.5 bg-surface-container hover:bg-surface-container-high text-on-surface rounded-lg border border-outline-variant transition-all"
          title="Restart Demonstration"
        >
          <RotateCcw size={13} />
        </button>

        <button
          type="button"
          onClick={onExit}
          className="p-1.5 bg-error-container/20 hover:bg-error-container/40 text-on-error-container rounded-lg border border-error/20 transition-all ml-1"
          title="Exit Demonstration Mode"
        >
          <X size={13} />
        </button>
      </div>
    </div>
  );
};

export default DemoControllerBar;
