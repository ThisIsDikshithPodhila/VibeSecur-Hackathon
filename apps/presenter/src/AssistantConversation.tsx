import { Fragment, useMemo, useRef, useState, type ReactNode } from 'react';
import {
  AssistantRuntimeProvider, ComposerPrimitive, MessagePrimitive, ThreadPrimitive,
  useExternalStoreRuntime, type AppendMessage, type ReasoningMessagePartComponent, type TextMessagePartComponent,
  type ThreadMessageLike, type ToolCallMessagePartComponent,
} from '@assistant-ui/react';
import { ArrowUp, Brain, Check, CreditCard, FileText, Globe, Loader2, Receipt, Search, ShieldCheck, SquareTerminal, Wifi, X } from 'lucide-react';
import { motion } from 'motion/react';
import type { EmployeeConversationEntry, WorkflowSuggestion, WorkflowSuggestionKind } from './employeeView';

export type ConversationMarker = { id: string; sequence: number; content: ReactNode };
type Props = {
  messages: EmployeeConversationEntry[];
  markers: ConversationMarker[];
  replay: boolean;
  busy: boolean;
  offline: boolean;
  running: boolean;
  empty: ReactNode;
  feedback?: ReactNode;
  suggestions: WorkflowSuggestion[];
  onSend: (text: string) => Promise<unknown>;
};
const suggestionIcons: Record<WorkflowSuggestionKind, typeof FileText> = {
  pay: CreditCard, inspect: FileText, explain: ShieldCheck, receipt: Receipt, investigate: Search,
};
const toolLabels: Record<string, { label: string; Icon: typeof FileText }> = {
  browser: { label: 'Browser', Icon: Globe },
  terminal: { label: 'Terminal', Icon: SquareTerminal },
  file_editor: { label: 'File editor', Icon: FileText },
};
const TextPart: TextMessagePartComponent = ({ text, status }) => text || status.type === 'running'
  ? <p className="employee-message__text">{text}{status.type === 'running' && <span className="employee-caret" aria-hidden="true"/>}</p>
  : null;
const ReasoningPart: ReasoningMessagePartComponent = ({ text, status }) => <details className="employee-reasoning" open={status.type === 'running'}>
  <summary><Brain size={14} aria-hidden="true"/><span className={status.type === 'running' ? 'employee-shimmer' : ''}>{status.type === 'running' ? 'Thinking…' : 'Thought'}</span></summary>
  <p>{text}</p>
</details>;
const ToolPart: ToolCallMessagePartComponent = ({ toolName, argsText, result }) => {
  const { label, Icon } = toolLabels[toolName] ?? { label: toolName, Icon: FileText };
  const outcome = typeof result === 'object' && result ? result as { status?: string; output?: string } : undefined;
  const state = outcome?.status ?? 'started';
  return <motion.div className={`employee-tool is-${state}`} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.2 }}>
    <div className="employee-tool__head"><Icon size={15} aria-hidden="true"/><strong>{label}</strong>
      <span className="employee-tool__state" role="status">{state === 'started' ? <><Loader2 size={14} className="employee-spin" aria-hidden="true"/>Running</> : state === 'failed' ? <><X size={14} aria-hidden="true"/>Failed</> : <><Check size={14} aria-hidden="true"/>Done</>}</span></div>
    {argsText && <code className="employee-tool__detail">{argsText}</code>}
    {outcome?.output && <details className="employee-tool__result"><summary>Output</summary><pre>{outcome.output}</pre></details>}
  </motion.div>;
};
const partComponents = { Text: TextPart, Reasoning: ReasoningPart, tools: { Fallback: ToolPart } };

function contentOf(entry: EmployeeConversationEntry): ThreadMessageLike['content'] {
  const parts: Exclude<ThreadMessageLike['content'], string>[number][] = [];
  for (const step of entry.steps ?? []) {
    if (step.thought) parts.push({ type: 'reasoning', text: step.thought });
    parts.push({ type: 'tool-call', toolCallId: step.toolCallId, toolName: step.tool, argsText: step.detail ?? '',
      args: { detail: step.detail ?? '' },
      ...(step.status === 'started' ? {} : { result: { status: step.status, output: step.result ?? '' } }) });
  }
  if (entry.reasoning) parts.push({ type: 'reasoning', text: entry.reasoning });
  if (entry.text || entry.streaming) parts.push({ type: 'text', text: entry.text });
  return parts;
}
const messageDate = (value: number | string): Date | undefined => {
  const date = typeof value === 'number' ? new Date(value < 1e12 ? value * 1000 : value) : new Date(value);
  return Number.isFinite(date.getTime()) ? date : undefined;
};

export function AssistantConversation({ messages, markers, replay, busy, offline, running, empty, feedback, suggestions, onSend }: Props) {
  const [sending, setSending] = useState(false);
  const [sendError, setSendError] = useState<string | null>(null);
  const input = useRef<HTMLTextAreaElement>(null);
  const orderedMarkers = useMemo(() => [...markers].sort((a, b) => a.sequence - b.sequence), [markers]);
  const runtime = useExternalStoreRuntime({
    messages,
    convertMessage: (entry: EmployeeConversationEntry): ThreadMessageLike => ({
      id: entry.id,
      role: entry.role === 'maya' ? 'assistant' : 'user',
      createdAt: messageDate(entry.timestamp),
      content: contentOf(entry),
      status: entry.streaming ? { type: 'running' } : { type: 'complete', reason: 'stop' },
    }),
    // Replies come from the durable feed and the live worker stream; nothing is synthesized here.
    isRunning: messages.some(entry => entry.streaming),
    isDisabled: busy || sending,
    isSendDisabled: offline || running || replay,
    onNew: async (message: AppendMessage): Promise<void> => {
      const text = message.content.flatMap(part => part.type === 'text' ? [part.text] : []).join('\n').trim();
      if (!text || busy || sending || offline || replay || running) return;
      setSending(true);
      setSendError(null);
      try { await onSend(text); }
      catch {
        setSendError('The message was not sent. Your draft is ready to try again.');
        requestAnimationFrame(() => { runtime.thread.composer.setText(text); input.current?.focus(); });
      } finally { setSending(false); }
    },
  });
  const firstSequence = messages[0]?.sequence ?? Infinity;
  return <AssistantRuntimeProvider runtime={runtime}>
    <ThreadPrimitive.Root className="employee-thread">
      <ThreadPrimitive.Viewport className="employee-chat-body" scrollToBottomOnInitialize={false} scrollToBottomOnThreadSwitch={false}>
        <div className="employee-conversation" role="log" aria-label="Saved conversation with Maya" aria-live="polite" aria-relevant="additions">
          {messages.length === 0 && markers.length === 0 && empty}
          {orderedMarkers.filter(marker => marker.sequence < firstSequence).map(marker => <Fragment key={marker.id}>{marker.content}</Fragment>)}
          <ThreadPrimitive.Messages>{({ message }) => {
            const index = messages.findIndex(entry => entry.id === message.id);
            const entry = messages[index];
            if (!entry) return null;
            const nextSequence = messages[index + 1]?.sequence ?? Infinity;
            return <>
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.25, ease: 'easeOut' }}>
              <MessagePrimitive.Root className={`employee-message is-${entry.role}${entry.streaming ? ' is-streaming' : ''}`}>
                <span className="employee-message__avatar" aria-hidden="true">{entry.role === 'maya' ? 'M' : 'Y'}</span>
                <div className="employee-message__content">
                  <div className="employee-message__meta"><strong>{entry.role === 'maya' ? 'Maya' : 'You'}</strong><time>{entry.timeLabel}</time></div>
                  {entry.streaming && !entry.text && !entry.reasoning && !(entry.steps?.length) && <p className="employee-thinking" role="status"><span/><span/><span/>Maya is reading the workspace…</p>}
                  <MessagePrimitive.Parts components={partComponents}/>
                </div>
              </MessagePrimitive.Root>
              </motion.div>
              {orderedMarkers.filter(marker => marker.sequence >= entry.sequence && marker.sequence < nextSequence).map(marker => <Fragment key={marker.id}>{marker.content}</Fragment>)}
            </>;
          }}</ThreadPrimitive.Messages>
          {running && !messages.some(entry => entry.streaming) && <p className="employee-turn-status" role="status"><span aria-hidden="true"/>Maya is working on your request.</p>}
          {feedback}
          {sendError && <p className="employee-feedback is-error" role="alert">{sendError}</p>}
        </div>
      </ThreadPrimitive.Viewport>
      <div className="employee-composer-area">
        <div className="employee-suggestions" aria-label="Message suggestions">
          {suggestions.map(({ text, kind }) => { const Icon = suggestionIcons[kind]; return <ThreadPrimitive.Suggestion key={text} prompt={text} send={false} disabled={busy || sending}
            onClick={() => { setSendError(null); requestAnimationFrame(() => input.current?.focus()); }}>
            <Icon size={17} aria-hidden="true"/>{text}
          </ThreadPrimitive.Suggestion>; })}
        </div>
        <ComposerPrimitive.Root className="employee-composer" aria-busy={sending}>
          <label className="visually-hidden" htmlFor="employee-message">Message Maya</label>
          <ComposerPrimitive.Input ref={input} id="employee-message" placeholder={replay ? 'Saved replay · open live work to message Maya' : 'Message Maya…'} rows={1} maxLength={2000} submitMode="none" cancelOnEscape={false} addAttachmentOnPaste={false} />
          <ComposerPrimitive.Send className="employee-send-button" aria-label={sending ? 'Sending message' : 'Send message'}><ArrowUp size={22} aria-hidden="true"/></ComposerPrimitive.Send>
        </ComposerPrimitive.Root>
        {replay && <p className="employee-composer-note">Deterministic replay · saved messages and activity.</p>}
        {offline && <p className="employee-offline-note"><Wifi size={15} aria-hidden="true"/>Offline. Your draft stays here until you reconnect.</p>}
      </div>
    </ThreadPrimitive.Root>
  </AssistantRuntimeProvider>;
}
