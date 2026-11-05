import { dateLabel, sharingExplanation } from './domain';
import { Icon } from './icons';
import type { Workflow } from './types';

const processingLabels = { PENDING: 'Awaiting processing', PROCESSING: 'Processing', DONE: 'Processing complete', FAILED: 'Processing failed' };
const reviewLabels = { NOT_READY: 'Not ready for review', AWAITING_REVIEW: 'Awaiting human review', APPROVED: 'Review approved', RETURNED: 'Returned for correction', REJECTED: 'Review rejected' };
const sharingLabels = { NOT_SHARED: 'Not shared', AVAILABLE: 'Currently available', WITHDRAWN: 'Withdrawn', SUPERSEDED: 'Superseded', UNAVAILABLE: 'Currently unavailable' };

export default function WorkflowTimeline({ workflow }: { workflow: Workflow }) {
  return <section className="card workflow-card" aria-labelledby="workflow-heading">
    <div className="card-heading"><div><h3 id="workflow-heading">Workflow progress</h3><p>Revision {workflow.revision_no} · {workflow.is_current ? 'Current source revision' : 'Historical source revision'}</p></div><span className="card-icon"><Icon name="clock" /></span></div>
    <ol className="workflow-timeline">
      <li className="complete"><span className="workflow-step"><Icon name="check" size={18} /></span><div><h4>Delivery receipt</h4><strong>Received by server</strong><p>{dateLabel(workflow.received_at, true)}</p><p>The immutable acceptance receipt remains unchanged.</p></div></li>
      <li className={workflow.processing.state === 'DONE' ? 'complete' : workflow.processing.state === 'FAILED' ? 'attention' : ''}><span className="workflow-step"><Icon name="report" size={18} /></span><div><h4>Processing</h4><strong>{processingLabels[workflow.processing.state]}</strong><p>{workflow.processing.attempts} processing {workflow.processing.attempts === 1 ? 'attempt' : 'attempts'}</p>{workflow.processing.state === 'FAILED' && <p>The source stays private.</p>}</div></li>
      <li className={workflow.review.state === 'APPROVED' ? 'complete' : ['RETURNED', 'REJECTED'].includes(workflow.review.state) ? 'attention' : ''}><span className="workflow-step"><Icon name="review" size={18} /></span><div><h4>Human review</h4><strong>{reviewLabels[workflow.review.state]}</strong>{workflow.review.prepared_at && <p>Prepared {dateLabel(workflow.review.prepared_at, true)}</p>}{workflow.review.decided_at && <p>Decision recorded {dateLabel(workflow.review.decided_at, true)}</p>}</div></li>
      <li className={workflow.sharing.state === 'AVAILABLE' ? 'complete' : ['WITHDRAWN', 'UNAVAILABLE'].includes(workflow.sharing.state) ? 'attention' : ''}><span className="workflow-step"><Icon name="shield" size={18} /></span><div><h4>Sharing</h4><strong>{sharingLabels[workflow.sharing.state]}</strong><p>{sharingExplanation(workflow.sharing.state)}</p>{workflow.sharing.published_at && <p>Publication recorded {dateLabel(workflow.sharing.published_at, true)}</p>}</div></li>
    </ol>
  </section>;
}
