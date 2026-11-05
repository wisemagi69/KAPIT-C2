import { useEffect, useRef, useState } from 'react';
import type { KeyboardEvent } from 'react';
import { Icon } from './icons';
import type { IconName } from './icons';
import heroImage from './assets/field-command-hero.webp';
import './landing.css';

const stages: { title: string; subtitle: string; description: string; icon: IconName; label: string }[] = [
  { title: 'Capture the original.', subtitle: '01 / REPORT', description: 'Record the maintenance issue in a structured report. The original stays private, with a clear receipt and its own history.', icon: 'report', label: 'Private capture' },
  { title: 'Put judgment first.', subtitle: '02 / REVIEW', description: 'An assigned reviewer compares the original and proposed shared version, then explicitly approves, returns or rejects it.', icon: 'review', label: 'Human review' },
  { title: 'Share with purpose.', subtitle: '03 / SHARE', description: 'Eligible recipients see the approved version for their channel. The private original stays with the people authorized to review it.', icon: 'feed', label: 'Controlled sharing' },
];

// Illustrative history lines; each workflow stage reveals the entries up to it.
const events = [
  { time: '09:41:07', text: 'Operation received · receipt issued', stage: 0 },
  { time: '09:41:07', text: 'Source revision 1 stored privately', stage: 0 },
  { time: '09:41:12', text: 'Reduced candidate prepared', stage: 1 },
  { time: '09:52:30', text: 'Review opened by assigned reviewer', stage: 1 },
  { time: '09:53:04', text: 'Decision recorded · approve', stage: 2 },
  { time: '09:53:04', text: 'Released to channel recipients', stage: 2 },
];

// Properties of the system itself, not performance claims.
const facts = [
  { value: '04', label: 'SEPARATE ROLES', text: 'Submitter, reviewer, recipient and administrator each hold distinct authority.' },
  { value: '03', label: 'REVIEW OUTCOMES', text: 'Approve, return for correction or reject. Nothing is shared by default.' },
  { value: '00', label: 'AUTONOMOUS RELEASES', text: 'Every shared version follows an explicit, recorded human decision.' },
  { value: '03', label: 'DISCLOSURE PROFILES', text: 'Full, reduced and summary views. Each recipient sees only what their profile allows.' },
];

const capabilities: { icon: IconName; title: string; text: string }[] = [
  { icon: 'report', title: 'Structured capture', text: 'Template-based maintenance reports with required fields, bounded input and an immediate receipt.' },
  { icon: 'lock', title: 'Immutable originals', text: 'Submitted revisions never change. Corrections become new revisions linked to the full history.' },
  { icon: 'cpu', title: 'Reduced candidates', text: 'A background worker prepares a reduced version for sharing while the original stays private.' },
  { icon: 'link', title: 'Bound approvals', text: 'Approval covers the exact revision, candidate, policy and channel. Change any input and review starts again.' },
  { icon: 'feed', title: 'Scoped delivery', text: 'Recipients read only approved versions for their current channel, with access checked on every view.' },
  { icon: 'database', title: 'Accountable history', text: 'Receipts, decisions and access changes are kept in an append-only audit trail.' },
];

const roles: { icon: IconName; title: string; username: string; summary: string; can: string[]; cannot: string[] }[] = [
  { icon: 'report', title: 'Submitter', username: 'submitter', summary: 'Captures maintenance issues from the field.', can: ['Create structured reports', 'Correct reports returned to them', 'Track receipts and workflow stage'], cannot: ['Review or share any report'] },
  { icon: 'review', title: 'Reviewer', username: 'reviewer', summary: 'Makes the human decision before anything is shared.', can: ['Compare original and candidate', 'Approve, return or reject'], cannot: ['Edit the original report', 'Approve changed inputs'] },
  { icon: 'feed', title: 'Recipient', username: 'recipient', summary: 'Reads approved updates for an assigned channel.', can: ['Browse and search approved versions', 'Filter by category and urgency'], cannot: ['See private originals', 'Read other channels'] },
  { icon: 'users', title: 'Administrator', username: 'administrator', summary: 'Manages accounts, roles and assignments.', can: ['Create and update accounts', 'Change access and reset passwords'], cannot: ['Review or approve reports'] },
];

const safeguards: { icon: IconName; title: string; text: string }[] = [
  { icon: 'shield', title: 'No autonomous release', text: 'Nothing reaches recipients without an explicit human approval.' },
  { icon: 'link', title: 'Approval is exact', text: 'A changed source, candidate, policy or audience requires a new decision.' },
  { icon: 'alert', title: 'Failures stay private', text: 'If processing fails, the report remains private and is never shared.' },
  { icon: 'refresh', title: 'Safe retries', text: 'Retries keep their operation ID. Conflicting content is rejected, not merged.' },
  { icon: 'eye', title: 'Scope on every surface', text: 'Lists, counts, details and errors all respect current access.' },
  { icon: 'layers', title: 'Training and evaluation', text: 'Built for exercises and evaluation. Not connected to any operational system.' },
];

const questions = [
  { question: 'Is this connected to a real system?', answer: 'No. KAPIT-C2 is a locally hosted training and evaluation system for maintenance reporting. It is not an operational reporting system.' },
  { question: 'How do I get an account?', answer: 'Accounts are issued individually by the exercise administrator. Each account opens only the tools for its role.' },
  { question: 'Why can’t a reviewer edit the original?', answer: 'Originals are preserved as submitted. A reviewer can return a report for correction, which creates a new revision while the original stays intact.' },
  { question: 'What happens if access changes during a session?', answer: 'Access is checked on every request. If a role, channel or account status changes, the workspace closes and asks for a fresh sign-in.' },
];

function Wordmark() {
  return <span className="landing-wordmark"><svg viewBox="0 0 32 32" aria-hidden="true"><path d="M6 5v22M14 5v22M26 5 15 16l11 11" /></svg><span>KAPIT<span className="landing-wordmark-c2">C2</span></span></span>;
}

function SectionLabel({ number, children }: { number: string; children: string }) {
  return <p className="landing-section-label"><span>{number}</span><span>{children}</span></p>;
}

function WorkflowVisual({ stage }: { stage: number }) {
  return <div className={'landing-flow-visual landing-flow-stage-' + stage}>
    <div className="landing-flow-topline"><span className="landing-mono">MAINTENANCE / REPORT</span><span className="landing-mono">RPT-0142</span></div>
    <div className="landing-flow-nodes" aria-hidden="true">{stages.map((item, index) => <span key={item.label} className={index <= stage ? 'is-active' : ''}><Icon name={item.icon} size={19} />{index < 2 && <i />}</span>)}</div>
    <div className="landing-sample" key={stage}>
      <div className="landing-sample-heading"><span className="landing-mono">{stage === 0 ? 'SOURCE REPORT' : stage === 1 ? 'REVIEW WORKSPACE' : 'RECIPIENT VIEW'}</span><Icon name={stage === 2 ? 'feed' : 'lock'} size={17} /></div>
      <div className="landing-sample-body"><span className={'landing-sample-status ' + (stage === 2 ? 'is-approved' : '')}><span />{stage === 0 ? 'Private original' : stage === 1 ? 'Awaiting human decision' : 'Approved version'}</span>
        <h3>Water pump maintenance</h3>
        <p>{stage === 0 ? 'A damaged water pump requires repair assistance. Details are recorded for the assigned reviewer.' : stage === 1 ? 'Compare the source with the proposed shared version. Confirm the content and its intended channel.' : 'A support unit reports a damaged water pump in Area C. Repair assistance is requested.'}</p>
        <div className="landing-sample-fields"><div><span>Category</span><strong>Maintenance</strong></div><div><span>{stage === 2 ? 'Channel' : 'Sharing'}</span><strong>{stage === 2 ? 'Sharing channel' : 'Not published'}</strong></div></div>
        {stage === 1 && <div className="landing-review-options" aria-label="Illustrative review options"><span><Icon name="check" size={13} />Approve</span><span>Return</span><span>Reject</span></div>}
        {stage === 0 && <div className="landing-sample-note"><Icon name="lock" size={13} /><span>Original preserved. Recipient access closed.</span></div>}
        {stage === 2 && <div className="landing-sample-note"><Icon name="shield" size={14} /><span>Only the approved information is shared.</span></div>}
      </div>
    </div>
    <ol className="landing-flow-log" aria-label="Illustrative history">{events.filter(event => event.stage <= stage).map((event, index, shown) => <li key={event.text} className={index >= shown.length - 2 ? 'is-latest' : ''}><span>{event.time}</span>{event.text}</li>)}</ol>
    <div className="landing-flow-bottomline"><span><span className="landing-square" />{stage === 0 ? 'CAPTURED ≠ SHARED' : stage === 1 ? 'HUMAN DECISION REQUIRED' : 'CURRENT ACCESS CHECKED'}</span><span>0{stage + 1} / 03</span></div>
  </div>;
}

function ConsoleIllustration() {
  return <figure className="landing-console" data-reveal aria-labelledby="landing-console-caption">
    <p className="landing-visually-hidden">The illustration shows a reviewer comparing a private original report with its reduced candidate. Reporter and site details are withheld from the candidate, and the approval is bound to the source revision, policy, sharing profile and channel.</p>
    <div className="landing-console-frame" aria-hidden="true">
      <div className="landing-console-titlebar"><span className="landing-console-dots"><i /><i /><i /></span><span className="landing-mono">KAPIT-C2 / REVIEW WORKSPACE</span><span className="landing-console-chip">PRIVATE</span></div>
      <div className="landing-console-body">
        <div className="landing-console-side"><span className="landing-mono">WORKSPACE</span><span><Icon name="overview" size={15} />Overview</span><span className="is-active"><Icon name="review" size={15} />Review queue</span><span><Icon name="lock" size={15} />Account security</span><span className="landing-console-side-note">Human review before sharing</span></div>
        <div className="landing-console-main">
          <div className="landing-console-head"><span>Review queue <Icon name="chevron" size={12} /> <strong>RPT-0142</strong></span><span className="landing-console-status"><span />Awaiting decision</span></div>
          <div className="landing-console-compare">
            <div className="landing-console-pane"><span className="landing-mono">ORIGINAL REPORT · PRIVATE</span><dl><div><dt>Reporter</dt><dd>Team lead, Unit 2</dd></div><div><dt>Site</dt><dd>Pump station 3</dd></div><div><dt>Area</dt><dd>Area C</dd></div><div><dt>Narrative</dt><dd>Damaged water pump at the north tank. Repair assistance requested.</dd></div></dl><i className="landing-console-marker">A</i></div>
            <div className="landing-console-pane is-candidate"><span className="landing-mono">REDUCED CANDIDATE · TO SHARE</span><dl><div><dt>Reporter</dt><dd><b className="landing-console-withheld">Withheld</b></dd></div><div><dt>Site</dt><dd><b className="landing-console-withheld">Withheld</b></dd></div><div><dt>Area</dt><dd>Area C</dd></div><div><dt>Text</dt><dd>A support unit reports a damaged water pump in Area C. Repair assistance is requested.</dd></div></dl><i className="landing-console-marker">B</i></div>
          </div>
          <div className="landing-console-binding"><span>REVISION 1</span><span>POLICY V1</span><span>PROFILE REDUCED</span><span>CHANNEL 01</span><i className="landing-console-marker">C</i></div>
          <div className="landing-console-actions"><span className="landing-console-check"><Icon name="check" size={12} />I have checked the complete candidate, source revision, policy and audience.</span><span className="landing-console-buttons"><span className="is-primary">Approve &amp; share</span><span>Return</span><span>Reject</span></span></div>
        </div>
      </div>
    </div>
    <figcaption id="landing-console-caption" className="landing-illustration-note">Illustrative review workspace</figcaption>
  </figure>;
}

export default function Landing() {
  const [menuOpen, setMenuOpen] = useState(false);
  const [stage, setStage] = useState(0);
  const root = useRef<HTMLDivElement>(null);
  const menuTrigger = useRef<HTMLButtonElement>(null);
  const tabList = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const currentTitle = document.title;
    document.title = 'KAPIT-C2 — Clarity in the field';
    return () => { document.title = currentTitle; };
  }, []);

  useEffect(() => {
    const media = window.matchMedia('(prefers-reduced-motion: reduce)');
    if (!('IntersectionObserver' in window) || media.matches) return;
    const elements = root.current?.querySelectorAll<HTMLElement>('[data-reveal]') ?? [];
    const observer = new IntersectionObserver(entries => {
      entries.forEach(entry => { if (entry.isIntersecting) { entry.target.classList.remove('reveal-waiting'); observer.unobserve(entry.target); } });
    }, { threshold: 0.08, rootMargin: '0px 0px -24px 0px' });
    elements.forEach(element => { element.classList.add('reveal-waiting'); observer.observe(element); });
    const showAll = () => { if (media.matches) elements.forEach(element => element.classList.remove('reveal-waiting')); };
    media.addEventListener('change', showAll);
    return () => { observer.disconnect(); media.removeEventListener('change', showAll); elements.forEach(element => element.classList.remove('reveal-waiting')); };
  }, []);

  useEffect(() => {
    const media = window.matchMedia('(min-width: 961px)');
    const resize = () => { if (media.matches) setMenuOpen(false); };
    const escape = (event: globalThis.KeyboardEvent) => { if (event.key === 'Escape' && menuOpen) { setMenuOpen(false); menuTrigger.current?.focus(); } };
    media.addEventListener('change', resize); document.addEventListener('keydown', escape);
    return () => { media.removeEventListener('change', resize); document.removeEventListener('keydown', escape); };
  }, [menuOpen]);

  const selectTab = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    let next = index;
    if (event.key === 'ArrowDown' || event.key === 'ArrowRight') next = (index + 1) % stages.length;
    else if (event.key === 'ArrowUp' || event.key === 'ArrowLeft') next = (index + stages.length - 1) % stages.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = stages.length - 1;
    else return;
    event.preventDefault(); setStage(next); tabList.current?.querySelectorAll<HTMLButtonElement>('[role="tab"]')[next]?.focus();
  };
  const closeMenu = () => setMenuOpen(false);

  return <div className="landing" ref={root}>
    <a className="landing-skip" href="#landing-main">Skip to content</a>
    <div className="landing-utility"><div className="landing-container landing-utility-inner"><p><span className="landing-square" /><strong>TRAINING &amp; EVALUATION</strong><span className="landing-utility-detail">For exercises and evaluation only. Not an operational system.</span></p><a href="#start">Run it locally<Icon name="arrow" size={14} /></a></div></div>
    <header className="landing-header">
      <a className="landing-home" href="/" aria-label="KAPIT-C2 home"><Wordmark /></a>
      <button className="landing-menu-toggle" ref={menuTrigger} aria-label={menuOpen ? 'Close navigation' : 'Open navigation'} aria-expanded={menuOpen} aria-controls="landing-navigation" onClick={() => setMenuOpen(value => !value)}><Icon name={menuOpen ? 'close' : 'menu'} size={24} /></button>
      <nav id="landing-navigation" className={'landing-navigation ' + (menuOpen ? 'is-open' : '')} aria-label="Main navigation">
        <a href="#platform" onClick={closeMenu}>The platform</a><a href="#workflow" onClick={closeMenu}>How it works</a><a href="#roles" onClick={closeMenu}>Roles</a><a href="#safeguards" onClick={closeMenu}>Safeguards</a><a href="#start" onClick={closeMenu}>Get started</a>
        <a className="landing-nav-cta" href="/workspace">Open workspace<Icon name="arrow" size={17} /></a>
      </nav>
    </header>

    <main id="landing-main" tabIndex={-1}>
      <section className="landing-hero" aria-labelledby="landing-title">
        <img className="landing-hero-image" src={heroImage} width={1672} height={941} alt="Illustrative field-support specialist documenting a report above misty mountain terrain." fetchPriority="high" />
        <div className="landing-hero-shade" aria-hidden="true" />
        <div className="landing-hero-grid" aria-hidden="true" />
        <div className="landing-hero-frame" aria-hidden="true"><i /><i /><i /><i /><span className="landing-mono">FIELD VIEW · ILLUSTRATIVE</span></div>
        <div className="landing-hero-inner landing-container">
          <div className="landing-hero-content">
            <p className="landing-hero-kicker"><span className="landing-square" />CONNECTED TEAMS. CONSIDERED DECISIONS.</p>
            <h1 id="landing-title">Clarity in the field.<br />Confidence in<br /><em>every decision.</em></h1>
            <p className="landing-hero-description">From the first report to the shared picture. A disciplined path for maintenance information — captured privately, reviewed by people and shared only once approved.</p>
            <div className="landing-hero-actions"><a className="landing-button landing-button-lime" href="/workspace">Enter the workspace<Icon name="arrow" size={20} /></a><a className="landing-text-link" href="#workflow">Explore the workflow<span className="landing-down-arrow"><Icon name="arrow" size={19} /></span></a></div>
          </div>
          <aside className="landing-hud" aria-label="Illustrative report status">
            <div className="landing-hud-head"><span className="landing-mono">RPT-0142</span><span className="landing-hud-chip"><span />IN REVIEW</span></div>
            <p className="landing-hud-title">Water pump maintenance</p>
            <p className="landing-hud-meta">Area C · Water supply · Routine</p>
            <ol className="landing-hud-steps">
              <li className="is-done"><span className="landing-hud-mark"><Icon name="check" size={12} /></span><span>Received</span><span className="landing-mono">09:41</span></li>
              <li className="is-done"><span className="landing-hud-mark"><Icon name="check" size={12} /></span><span>Candidate prepared</span><span className="landing-mono">09:41</span></li>
              <li className="is-current"><span className="landing-hud-mark" /><span>Human review</span><span className="landing-mono">PENDING</span></li>
              <li><span className="landing-hud-mark" /><span>Shared</span><span className="landing-mono">LOCKED</span></li>
            </ol>
            <p className="landing-hud-foot"><Icon name="lock" size={14} />Recipient access closed until approval.</p>
            <p className="landing-hud-note">Illustrative status</p>
          </aside>
        </div>
        <div className="landing-hero-footer landing-container"><span>FIELD REPORTING / HUMAN REVIEW / CONTROLLED SHARING</span><a href="#platform" aria-label="Scroll to the platform"><span>SCROLL TO EXPLORE</span><Icon name="arrow" size={17} /></a></div>
      </section>

      <section className="landing-facts" aria-labelledby="landing-facts-title">
        <div className="landing-container">
          <h2 id="landing-facts-title" className="landing-visually-hidden">KAPIT-C2 at a glance</h2>
          <ul className="landing-facts-grid" data-reveal>{facts.map((fact, index) => <li key={fact.label}><span className="landing-facts-label"><span>0{index + 1}</span>{fact.label}</span><strong>{fact.value}</strong><p>{fact.text}</p></li>)}</ul>
        </div>
      </section>

      <section id="platform" className="landing-platform landing-section" aria-labelledby="landing-platform-title">
        <div className="landing-container">
          <div className="landing-section-heading" data-reveal><SectionLabel number="01">THE PLATFORM</SectionLabel><div><h2 id="landing-platform-title">The right information.<br /><span>In the right hands.</span></h2><p>Good coordination starts with a clear account of what happened. KAPIT-C2 connects private reporting, careful review and purposeful sharing in one focused workspace.</p></div></div>
          <div className="landing-platform-grid">
            <div className="landing-capabilities" data-reveal>{capabilities.map((item, index) => <article key={item.title}><div className="landing-capability-top"><span className="landing-capability-icon"><Icon name={item.icon} size={24} /></span><span className="landing-capability-number">/0{index + 1}</span></div><h3>{item.title}</h3><p>{item.text}</p></article>)}</div>
            <div className="landing-boundary-diagram" data-reveal aria-label="Illustration: a private original passes through human review before an approved version reaches recipients.">
              <div className="landing-diagram-top"><span className="landing-mono">INFORMATION WITH BOUNDARIES</span><span aria-hidden="true">+</span></div>
              <div className="landing-orbits" aria-hidden="true"><span /><span /><span /><i /></div>
              <div className="landing-diagram-source"><Icon name="lock" size={19} /><span>PRIVATE ORIGINAL</span><span className="landing-diagram-lines"><i /><i /><i /></span></div>
              <div className="landing-diagram-gate"><span className="landing-diagram-gate-icon"><Icon name="review" size={26} /></span><span>HUMAN REVIEW</span></div>
              <div className="landing-diagram-recipients"><span><Icon name="feed" size={19} />APPROVED VERSION</span><span className="landing-diagram-branches" aria-hidden="true"><i /><i /><i /></span><span>AUTHORIZED RECIPIENTS</span></div>
              <div className="landing-diagram-foot"><span className="landing-square" />Access follows purpose.</div>
            </div>
          </div>
        </div>
      </section>

      <section id="workflow" className="landing-workflow landing-section" aria-labelledby="landing-workflow-title">
        <div className="landing-container">
          <div className="landing-section-heading" data-reveal><SectionLabel number="02">THE WORKFLOW</SectionLabel><div><h2 id="landing-workflow-title">A clear path.<br /><span>No skipped steps.</span></h2><p>One maintenance report. Three distinct stages. Explore how information moves, and who makes the call.</p></div></div>
          <div className="landing-workflow-grid" data-reveal>
            <div className="landing-workflow-tabs" role="tablist" aria-label="Reporting workflow stages" aria-orientation="vertical" ref={tabList}>{stages.map((item, index) => <button type="button" role="tab" id={'workflow-tab-' + index} aria-controls="workflow-panel" aria-selected={stage === index} tabIndex={stage === index ? 0 : -1} key={item.label} className={stage === index ? 'is-selected' : ''} onClick={() => setStage(index)} onKeyDown={event => selectTab(event, index)}><span className="landing-tab-number">0{index + 1}</span><span><span className="landing-tab-kicker">{item.label}</span><span className="landing-tab-title">{item.title}</span><span className="landing-tab-description">{item.description}</span></span><span className="landing-tab-arrow"><Icon name="arrow" size={21} /></span></button>)}</div>
            <div id="workflow-panel" className="landing-workflow-panel" role="tabpanel" aria-labelledby={'workflow-tab-' + stage} tabIndex={0}><WorkflowVisual stage={stage} /><p className="landing-illustration-note">Illustrative interface</p></div>
          </div>
        </div>
      </section>

      <section id="interface" className="landing-interface landing-section" aria-labelledby="landing-interface-title">
        <div className="landing-container">
          <div className="landing-section-heading" data-reveal><SectionLabel number="03">THE INTERFACE</SectionLabel><div><h2 id="landing-interface-title">One workspace.<br /><span>Every handoff accounted for.</span></h2><p>Reviewers see exactly what would be shared, beside the original it came from, before anything leaves the private record.</p></div></div>
          <ConsoleIllustration />
          <ol className="landing-callouts" data-reveal>
            <li><span>A</span><div><h3>Side-by-side comparison</h3><p>The private original and the proposed shared version are reviewed together, never in isolation.</p></div></li>
            <li><span>B</span><div><h3>Withheld details stay private</h3><p>Reporter and site details remain in the original. Recipients only ever see the reduced version.</p></div></li>
            <li><span>C</span><div><h3>Approval bound to exact inputs</h3><p>The decision records the revision, policy, profile and channel it applies to.</p></div></li>
          </ol>
        </div>
      </section>

      <section id="roles" className="landing-roles landing-section" aria-labelledby="landing-roles-title">
        <div className="landing-container">
          <div className="landing-section-heading" data-reveal><SectionLabel number="04">THE ROLES</SectionLabel><div><h2 id="landing-roles-title">Four roles.<br /><span>Separate authority.</span></h2><p>Every account is issued for one job. Action permission, organization scope and channel access are checked independently on every request.</p></div></div>
          <div className="landing-roles-grid" data-reveal>{roles.map((role, index) => <article key={role.title}>
            <div className="landing-role-top"><span className="landing-mono">ROLE / 0{index + 1}</span><span className="landing-role-icon"><Icon name={role.icon} size={22} /></span></div>
            <h3>{role.title}</h3><p className="landing-role-summary">{role.summary}</p>
            <p className="landing-role-label">CAN</p><ul className="landing-role-list">{role.can.map(item => <li key={item}><Icon name="check" size={14} />{item}</li>)}</ul>
            <p className="landing-role-label">CANNOT</p><ul className="landing-role-list is-denied">{role.cannot.map(item => <li key={item}><Icon name="close" size={14} />{item}</li>)}</ul>
            <p className="landing-role-account">Issued account per person</p>
          </article>)}</div>
        </div>
      </section>

      <section id="safeguards" className="landing-principles" aria-labelledby="landing-principles-title">
        <div className="landing-container landing-principles-inner">
          <div className="landing-principles-copy" data-reveal><SectionLabel number="05">THE SAFEGUARDS</SectionLabel><h2 id="landing-principles-title">Technology supports.<br /><em>People decide.</em></h2><p>Context cannot be automated away. KAPIT-C2 keeps human responsibility at the center, with private originals, explicit approvals and a traceable history.</p><div className="landing-principles-mark" aria-hidden="true"><svg viewBox="0 0 180 180" fill="none"><path d="M20 24h140v90l-70 43-70-43V24Z" /><path d="m57 84 22 22 46-48" /><path d="M8 8h20M8 8v20M172 8h-20M172 8v20M8 172h20M8 172v-20M172 172h-20M172 172v-20" /></svg></div></div>
          <ul className="landing-safeguards" data-reveal>{safeguards.map((item, index) => <li key={item.title}><div className="landing-safeguard-top"><Icon name={item.icon} size={22} /><span className="landing-mono">S/0{index + 1}</span></div><h3>{item.title}</h3><p>{item.text}</p></li>)}</ul>
        </div>
      </section>

      <section id="start" className="landing-start landing-section" aria-labelledby="landing-start-title">
        <div className="landing-container">
          <div className="landing-section-heading" data-reveal><SectionLabel number="06">GET STARTED</SectionLabel><div><h2 id="landing-start-title">Running locally<br /><span>in three steps.</span></h2><p>The full workspace runs on this computer with its own database. Nothing is published outside it.</p></div></div>
          <div className="landing-start-grid">
            <ol className="landing-steps" data-reveal>
              <li><span className="landing-step-number">01</span><div><h3>Start the local stack</h3><p>Double-click <code>infra\Start KAPIT.cmd</code>, or run the command below from the project folder. Setup checks dependencies and the database, then runs the acceptance checks.</p><code className="landing-command"><Icon name="terminal" size={15} />python infra/start_local.py</code></div></li>
              <li><span className="landing-step-number">02</span><div><h3>Keep the window open</h3><p>The website and its worker run from that terminal. Your local data is kept between runs.</p></div></li>
              <li><span className="landing-step-number">03</span><div><h3>Sign in by role</h3><p>Open the workspace and sign in with the account issued to you. Your role decides which tools you see.</p><a className="landing-inline-cta" href="/workspace">Go to sign in<Icon name="arrow" size={16} /></a></div></li>
            </ol>
            <div id="faq" className="landing-faq" data-reveal><p className="landing-mono landing-faq-title">COMMON QUESTIONS</p>{questions.map(item => <details key={item.question}><summary>{item.question}<span aria-hidden="true"><Icon name="plus" size={18} /></span></summary><p>{item.answer}</p></details>)}</div>
          </div>
        </div>
      </section>

      <section className="landing-closing landing-container" aria-labelledby="landing-closing-title">
        <div data-reveal><p className="landing-hero-kicker"><span className="landing-square" />PURPOSE IN EVERY HANDOFF.</p><h2 id="landing-closing-title">Build the<br /><em>shared picture.</em></h2><p>Step inside the KAPIT-C2 workspace.</p></div><a className="landing-closing-cta" href="/workspace" data-reveal><span>Open workspace</span><Icon name="arrow" size={40} /></a>
      </section>
    </main>

    <footer className="landing-footer">
      <div className="landing-container">
        <div className="landing-footer-main">
          <div className="landing-footer-brand"><a href="/" aria-label="KAPIT-C2 home"><Wordmark /></a><p>Clarity. Responsibility. Connection.</p><p className="landing-footer-notice">Maintenance-reporting training and evaluation system. Illustrative imagery.</p></div>
          <nav className="landing-footer-links" aria-label="Footer navigation">
            <div><p className="landing-mono">PLATFORM</p><a href="#platform">Capabilities</a><a href="#workflow">Workflow stages</a><a href="#interface">Review interface</a></div>
            <div><p className="landing-mono">GOVERNANCE</p><a href="#roles">Roles &amp; authority</a><a href="#safeguards">Safeguards</a><a href="#faq">Common questions</a></div>
            <div><p className="landing-mono">WORKSPACE</p><a href="/workspace">Sign in</a><a href="#start">Local setup</a><a href="#landing-title">Back to top</a></div>
          </nav>
        </div>
        <div className="landing-footer-bottom"><span>KAPIT-C2 / LOCAL EDITION</span><span>Not an operational system. No official endorsement implied.</span></div>
      </div>
      <div className="landing-footer-giant" aria-hidden="true">KAPIT-C2</div>
    </footer>
  </div>;
}
