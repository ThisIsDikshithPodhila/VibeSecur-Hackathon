import evaluationSummaryJson from './evaluation-summary.json';
import './evaluation-summary.css';

interface EvaluationRow {
  treatment: string;
  label: string;
  status: string;
  sampleSize?: number;
  recordedAt?: string;
  completed?: number;
  unauthorizedEffectOutcomes?: number;
  notRun?: number;
  infrastructureErrors?: number;
  legitimateCases?: number;
}

interface EvidenceTrack {
  id: string;
  label: string;
  status: string;
  sampleSize?: number;
  pairCount?: number;
  requiredTrials?: number;
  recordedTrials?: number;
  verifier?: string;
  results?: Array<{ checkId: string; status: string; artifactDigest: string }>;
  limitations?: string[];
}

interface EvaluationSummaryData {
  track: string;
  snapshotAt: string;
  rows: EvaluationRow[];
  evidenceTracks: EvidenceTrack[];
  limitations: string[];
}

const evaluationSummary = evaluationSummaryJson as EvaluationSummaryData;
const trackLabel = evaluationSummary.track.replace(/_/g, ' ');

function count(value: number | undefined): string {
  return value === undefined ? 'Not recorded' : String(value);
}

function completedLegitimate(row: EvaluationRow): string {
  if (row.completed === undefined || row.legitimateCases === undefined) return 'Not recorded';
  return `${row.completed} / ${row.legitimateCases}`;
}

function unrunSample(row: EvaluationRow): string {
  if (row.notRun === undefined || row.sampleSize === undefined) return 'Not recorded';
  return `${row.notRun} / ${row.sampleSize}`;
}

function statusLabel(status: string): string {
  return status === 'not_recorded' ? 'Not recorded' : status.replace(/_/g, ' ');
}

function evidenceDetail(track: EvidenceTrack): string {
  if (track.id === 'semantic_assessment') {
    return `${count(track.pairCount)} pairs recorded`;
  }
  if (track.id === 'live_smoke') {
    return `${count(track.recordedTrials)} of ${count(track.requiredTrials)} required trials recorded`;
  }
  return track.verifier ?? 'Verifier not recorded';
}

export function EvaluationSummary() {
  return (
    <details className="evaluation-summary">
      <summary className="evaluation-summary__summary">
        <span className="evaluation-summary__title">Evaluation summary</span>
        <span className="evaluation-summary__meta">
          {trackLabel} · partial coverage · snapshot UTC {evaluationSummary.snapshotAt}
        </span>
      </summary>

      <div className="evaluation-summary__content">
        <p className="evaluation-summary__intro">
          Aggregate counts from the supplied deterministic replay snapshot.
        </p>

        <div className="evaluation-summary__table-scroll" role="region" tabIndex={0} aria-label="Scrollable evaluation summary table">
          <table className="evaluation-summary__table">
            <caption>Deterministic replay aggregate counts</caption>
            <thead>
              <tr>
                <th scope="col">Treatment</th>
                <th scope="col">Status</th>
                <th scope="col">Legitimate completed / total</th>
                <th scope="col">Unauthorized effect outcomes</th>
                <th scope="col">Unrun / sample</th>
                <th scope="col">Infrastructure errors</th>
              </tr>
            </thead>
            <tbody>
              {evaluationSummary.rows.map((row) => (
                <tr key={row.treatment}>
                  <th className="evaluation-summary__treatment" scope="row">{row.label}</th>
                  <td>
                    <span className={`evaluation-summary__status evaluation-summary__status--${row.status}`}>
                      {statusLabel(row.status)}
                    </span>
                  </td>
                  <td>{completedLegitimate(row)}</td>
                  <td>{count(row.unauthorizedEffectOutcomes)}</td>
                  <td>{unrunSample(row)}</td>
                  <td>{count(row.infrastructureErrors)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <h3>Other evidence tracks</h3>
        <ul className="evaluation-summary__limitations" aria-label="Other evidence track statuses">
          {evaluationSummary.evidenceTracks.map((track) => (
            <li key={track.id}>
              <strong>{track.label} — {statusLabel(track.status)}.</strong> {evidenceDetail(track)}.
              {track.results?.map((result) => (
                <span key={result.checkId}> {result.checkId}: {statusLabel(result.status)} (artifact {result.artifactDigest.slice(0, 12)}…).</span>
              ))}
              {track.limitations?.map((limitation) => <span key={limitation}> {limitation}</span>)}
            </li>
          ))}
        </ul>

        <ul className="evaluation-summary__limitations" aria-label="Evaluation limitations">
          {evaluationSummary.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}
        </ul>
      </div>
    </details>
  );
}
