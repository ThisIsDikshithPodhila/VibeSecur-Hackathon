# Employee integration contract v1.1

Approved continuation, 25 September 2026. Additive to v1; this document
supersedes its preset-chat and unbound-plan limitations. Preserve old replay
records. API and shared types follow this contract.

## Conversation

Run.conversation = {conversationId, status, activeTurnId, turns:[]}; optional
for legacy records. A turn is {turnId,clientMessageId,text,scope,status,
createdAt,startedAt?,finishedAt?,error?}. Scope is pending|read_only|
pay_approved|clarification. Status queued|running|succeeded|failed|held|cancelled.
Conversation IDs and turn IDs are UUID strings. One active turn per run.

Store.enqueue_turn(run_id, owner, text, client_message_id) -> RunView:
atomic user event + queued turn; exact duplicate returns existing, changed
text with the same client ID conflicts. Only live runs accept employee work.
Store.claim_turn(run_id, owner) -> Turn|None: atomic claim, refuses a second
active turn. Store.set_turn_scope(run_id, owner, turn_id, scope) -> RunView:
active running turn only, pending -> declared narrowed scope once.
Store.finish_turn(run_id, owner, turn_id, status, error=None) -> RunView:
terminal transition, preserve completed result on duplicate, clear active ID.
Restart reconciliation never blindly reruns a running effectful turn.

Controller.submit_message(run_id,owner,text,client_message_id) -> RunView:
enqueue and schedule owned background queue. WorkerAdapter.run_turn(run,turn,
on_event) -> result, protected environment only; start() remains trial adapter.
run_turn consumes workerModelToken on run (fresh lease supplied by controller
using modelTokenFactory) and returns real final assistantText, job/artifacts.
Do not synthesize an assistant success if no message exists.

Standing synthetic authorization is explicitly provisioned trusted demo
configuration, exact one-use transaction/mission/owner/version/expiry, never
created by supplier/model content. Root supplies Azure intent interpreter;
only authenticated user text + trusted mandate enter it. It can narrow an
existing grant to read_only/pay_approved or clarify, never expand authority.
Ambiguous/failed interpretation holds. A summary turn cannot commit a payment.
No extra approval dialog for an unchanged, already authorized transaction.

POST messages retains {text,channel}; Maya accepts clientMessageId (otherwise
the authenticated Idempotency-Key) and returns {accepted:true,run} HTTP202.
Existing polling reads durable events while the turn runs. No frontend timer
can create progress. Reset/cancel revoke active authority before fresh work.

## Public event and outcome projection

Existing Event envelope stays {eventId,sequence,timestamp,kind,data}.
conversation.user / conversation.maya carry text,channel,turnId.
worker.activity data carries turnId,toolCallId,tool,status,title,description;
statuses started|succeeded|failed. Host sanitizes observations. Workers cannot
attest ledger outcomes. No reasoning, secrets or raw SDK traces in public feed.

payment.decision is emitted by the trusted effect store for denial and commit:
{decisionId,environmentId,operationId,attemptId,approvalId,decision,reason,
 attemptedTransaction,authorizedTransaction,transactionDigest,priorDecisionId?}.
Immutable rejection is committed before responding; repeat operation identity
cannot change transaction. Corrected proposal has a distinct operation ID.
Run.paymentDecisions retains decisions; receipt and incident history coexist.
All original exact-transaction, race, scope, expiry and uniqueness checks stay.

Investigation.disposition = unresolved|course_corrected_no_repair|recovery_required.
Only trusted denial + distinct authorized receipt + scoped evidence supporting
healthy application can establish course correction. Proven vulnerable source
or baseline effect remains recovery_required even after legitimate completion.
Otherwise unresolved. Legacy incident.status remains readable, not live proof.

## Repair binding

Store.bind_remediation_plan(run_id,owner,expected_version,
 expected_text_digest,approval_id) -> RunView performs one transaction:
owner/current plan SHA256/current incident/recovery eligibility/state checks,
plan.executorBound=true, binding={approvalId,version,textDigest,boundAt},
repair authority/job intent and repairing state/event. Same exact binding is
idempotent. Stale edit/digest, no-repair/unresolved, cancelled run fail closed.
Legacy reproduced incidents require their existing confirmed investigation.
Plan limits4000 characters, explicit errors, existing longer plans readable.
Controller starts only committed mission intents. Scope/verification contract
remain immutable. Candidate != verified != deployed != resumed.

## Laya / operating constraints

Actual pinned inference observes relevant source/tool context and sensitive
payment proposals through trusted boundary. Exact mission/action/provenance,
512-token checkpoint budget, no silent truncation, raw scores uncalibrated.
Ten-second warm assessment budget; unavailable/malformed/oversized holds
sensitive action, allows independent safe reads. Laya never grants authority.
Initial suitability:16 examples/8 pairs; >=12 correct and >=6 whole pairs,
all outputs available; not a benchmark. Positive live paths separately pass.
No silent model/checkpoint/framework replacement. No Daybreak.

Preserve owned synthetic defensive scope. No third-party targets. No local
model loads, browser launches, image builds, broad process kills or terminal
restart. VM heavy slots bounded/serial; no resource/spend increase. Max5 workers.
