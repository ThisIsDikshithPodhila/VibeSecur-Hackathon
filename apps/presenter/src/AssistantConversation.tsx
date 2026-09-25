import { Fragment, useMemo, useRef, useState, type ReactNode } from 'react';
import {
  AssistantRuntimeProvider, ComposerPrimitive, MessagePrimitive, ThreadPrimitive,
  useExternalStoreRuntime, type AppendMessage, type ThreadMessageLike,
} from '@assistant-ui/react';
import { ArrowUp, CreditCard, FileText, Receipt, Search, ShieldCheck, Wifi } from 'lucide-react';
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
      content: [{ type: 'text', text: entry.text }],
    }),
    // The durable feed supplies replies. An in-flight turn must not create a synthetic reply.
    isRunning: false,
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
              <MessagePrimitive.Root className={`employee-message is-${entry.role}`}>
                <span className="employee-message__avatar" aria-hidden="true">{entry.role === 'maya' ? 'M' : 'Y'}</span>
                <div className="employee-message__content">
                  <div className="employee-message__meta"><strong>{entry.role === 'maya' ? 'Maya' : 'You'}</strong><time>{entry.timeLabel}</time></div>
                  <p className="employee-message__text">{entry.text}</p>
                </div>
              </MessagePrimitive.Root>
              {orderedMarkers.filter(marker => marker.sequence >= entry.sequence && marker.sequence < nextSequence).map(marker => <Fragment key={marker.id}>{marker.content}</Fragment>)}
            </>;
          }}</ThreadPrimitive.Messages>
          {running && <p className="employee-turn-status" role="status"><span aria-hidden="true"/>Maya is working on your request.</p>}
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
