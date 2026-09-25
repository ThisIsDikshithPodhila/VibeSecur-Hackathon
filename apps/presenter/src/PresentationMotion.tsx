import { useState } from 'react';
import { AnimatePresence, LayoutGroup, MotionConfig, motion, useReducedMotion } from 'motion/react';
import { Activity, ArrowRight, Layers3, SearchCheck } from 'lucide-react';
import type { ReactNode } from 'react';
import './presenter-guidance.css';

export function PresentationMotion({ children }: { children: ReactNode }) {
  return <MotionConfig reducedMotion="user" transition={{ duration: .24, ease: [.22, 1, .36, 1] }}>{children}</MotionConfig>;
}

export function ChangingValue({ value, className = '' }: { value: string; className?: string }) {
  const reduce = useReducedMotion();
  return <span className={`changing-value ${className}`}>
    <AnimatePresence initial={false} mode="popLayout">
      <motion.span key={value} initial={{ opacity: 0, y: reduce ? 0 : 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: reduce ? 0 : -4 }} transition={{ duration: .18 }}>{value}</motion.span>
    </AnimatePresence>
  </span>;
}

export type PresenterSection = 'business-state' | 'evidence-trail' | 'recovery-proof';
export type PresenterTarget = 'protected-transaction' | 'protected-receipt' | 'repair-record' | 'verifier-record' | 'resume-control';
export type PresenterCue = {
  id: string;
  chapter: string;
  title: string;
  detail: string;
  destination: PresenterSection | 'mission-start';
  target?: PresenterTarget;
  link: string;
  tone?: 'attention' | 'complete';
};

export function PresenterGuidance({ cue, savedState, onNavigate, children }: {
  cue: PresenterCue;
  savedState: string;
  onNavigate: (destination: PresenterCue['destination'], keyboard: boolean, target?: PresenterTarget) => void;
  children: ReactNode;
}) {
  const reduce = useReducedMotion();
  return <div className="presenter-guidance" data-tone={cue.tone ?? 'neutral'} data-testid="presenter-guidance">
    <div className="presenter-guidance__copy" role="status" aria-live="polite" aria-atomic="true">
      <div className="presenter-guidance__context"><span className="eyebrow">{cue.chapter} · Next step</span><span className="presenter-guidance__state">Saved state <strong>{savedState}</strong></span></div>
      <div className="presenter-guidance__message">
        <motion.div key={cue.id} initial={{ opacity: reduce ? 1 : .8, y: reduce ? 0 : 4 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: reduce ? 0 : .18 }}>
          <h2 id="presenter-guidance-title">{cue.title}</h2><p>{cue.detail}</p>
        </motion.div>
      </div>
    </div>
    <div className="presenter-guidance__controls">
      <button className="presenter-guidance__next" aria-controls={cue.target ?? (cue.destination === 'mission-start' ? 'mode' : cue.destination)} onClick={event => onNavigate(cue.destination, event.detail === 0, cue.target)}><span>{cue.link}</span><ArrowRight size={17} aria-hidden="true" /></button>
      {children}
    </div>
  </div>;
}

const sections: { id: PresenterSection; number: string; label: string; detail: string; icon: typeof Activity }[] = [
  { id: 'business-state', number: '01', label: 'Business', detail: 'Invoice & payments', icon: Activity },
  { id: 'evidence-trail', number: '02', label: 'Investigation', detail: 'Events & explanation', icon: Layers3 },
  { id: 'recovery-proof', number: '03', label: 'Recovery', detail: 'Repair & proof', icon: SearchCheck },
];

export function ChapterNavigation({ selected, onNavigate }: { selected: PresenterSection; onNavigate: (id: PresenterSection, keyboard: boolean) => void }) {
  const [keyboard, setKeyboard] = useState(false);
  const reduce = useReducedMotion();
  return <LayoutGroup id="presenter-chapters"><nav className="chapter-nav" aria-label="Mission sections">
    {sections.map(section => <button key={section.id} className={selected === section.id ? 'chapter-link is-selected' : 'chapter-link'} aria-current={selected === section.id ? 'location' : undefined} onClick={event => {
      const instant = event.detail === 0;
      setKeyboard(instant);
      onNavigate(section.id, instant);
    }}>
      {selected === section.id && <motion.span className="chapter-selection" layoutId="chapter-selection" transition={keyboard || reduce ? { duration: 0 } : { type: 'spring', stiffness: 380, damping: 34 }} />}
      <span className="chapter-number">{section.number}</span><section.icon size={19} aria-hidden="true" />
      <span className="chapter-copy"><strong>{section.label}</strong><small>{section.detail}</small></span>
      <ArrowRight className="chapter-arrow" size={17} aria-hidden="true" />
    </button>)}
  </nav></LayoutGroup>;
}
