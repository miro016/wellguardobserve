import { ChangeDetectionStrategy, Component } from '@angular/core';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'wg-landing',
  imports: [RouterLink],
  template: `
    <div class="landing-shell">
      <header class="public-nav wrap">
        <a class="wordmark" routerLink="/" aria-label="Wellguard Observe home">
          <span class="brand-mark" aria-hidden="true"><i></i></span>
          <span>wellguard<em>observe</em></span>
        </a>
        <nav aria-label="Main navigation">
          <a href="#coverage">Coverage</a>
          <a href="#method">How it works</a>
          <a href="#principles">Principles</a>
        </nav>
        <a class="button button-quiet nav-login" routerLink="/login">Private access <span>↗</span></a>
      </header>

      <main>
        <section class="landing-hero wrap">
          <div class="hero-copy reveal">
            <div class="eyebrow"><span class="pulse-dot"></span> Your public edge, continuously observed</div>
            <h1>Know what your server <em>tells</em> the internet.</h1>
            <p class="hero-lede">An AI investigator looks at your infrastructure like an outsider would—finding forgotten services, aging software and quiet configuration leaks before they become incidents.</p>
            <div class="hero-actions">
              <a class="button button-primary" routerLink="/app">Explore the live workspace <span>→</span></a>
              <a class="text-link" href="#method">See how observation works <span>↓</span></a>
            </div>
            <div class="trust-line">
              <span>Reconnaissance only</span><span>Ownership required</span><span>No exploitation</span>
            </div>
          </div>

          <div class="exposure-instrument reveal delay-1" aria-label="Illustration of an external exposure scan">
            <div class="instrument-label"><span>Observation 01</span><span class="live-label">live surface</span></div>
            <div class="radar-stage">
              <div class="radar-grid"></div>
              <div class="radar-sweep"></div>
              <div class="core-node">
                <span class="node-icon">W</span>
                <strong>your edge</strong>
                <small>authorized scope</small>
              </div>
              <div class="signal-node node-tls"><span></span><strong>443</strong><small>TLS healthy</small></div>
              <div class="signal-node node-panel"><span></span><strong>control UI</strong><small>review exposure</small></div>
              <div class="signal-node node-service"><span></span><strong>8443</strong><small>investigating</small></div>
              <svg class="trace-lines" viewBox="0 0 640 520" aria-hidden="true">
                <path d="M320 260 C390 210 430 150 500 112" />
                <path d="M320 260 C215 225 170 188 110 166" />
                <path d="M320 260 C360 330 420 365 502 390" />
              </svg>
            </div>
            <div class="instrument-footer">
              <div><span>04</span><small>assets mapped</small></div>
              <div><span>01</span><small>needs attention</small></div>
              <p>Last observation <strong>37 sec ago</strong></p>
            </div>
          </div>
        </section>

        <section class="manifesto-strip">
          <div class="wrap strip-grid">
            <p>Not another vulnerability dump.</p>
            <blockquote>“Show me what changed, why it matters, and what evidence supports it.”</blockquote>
          </div>
        </section>

        <section class="coverage-section wrap" id="coverage">
          <div class="section-intro">
            <span class="section-index">The outside view</span>
            <h2>Small clues reveal large blind spots.</h2>
            <p>Wellguard follows the evidence across protocols, metadata and public sources. It does not need to know your stack in advance.</p>
          </div>
          <div class="coverage-grid">
            <article class="coverage-card feature-card">
              <div class="card-signal"><span></span><span></span><span></span></div>
              <p class="card-kicker">Unexpected reachability</p>
              <h3>Services you stopped thinking about</h3>
              <p>New ports, old dashboards, development tools and management surfaces that quietly remained online.</p>
              <div class="evidence-chip"><i></i> Change detected on :8443</div>
            </article>
            <article class="coverage-card">
              <div class="glyph glyph-certificate"><i>✓</i></div>
              <p class="card-kicker">Transport health</p>
              <h3>TLS validity and identity</h3>
              <p>Expiry, hostname coverage, trust chain, protocol and certificate changes—explained without certificate jargon.</p>
            </article>
            <article class="coverage-card">
              <div class="glyph glyph-fingerprint"><i></i></div>
              <p class="card-kicker">Software intelligence</p>
              <h3>Products, versions and public history</h3>
              <p>Service fingerprints are correlated with vendor documentation and reviewed security advisories.</p>
            </article>
            <article class="coverage-card">
              <div class="glyph glyph-leak"><span>10.0</span><i>↗</i></div>
              <p class="card-kicker">Information disclosure</p>
              <h3>Details that should have stayed inside</h3>
              <p>Origin addresses, internal names, debug metadata and endpoints embedded in responses or redirects.</p>
            </article>
          </div>
        </section>

        <section class="method-section" id="method">
          <div class="wrap">
            <div class="section-intro method-heading">
              <span class="section-index">An investigation, not a checklist</span>
              <h2>The next question depends on the last answer.</h2>
            </div>
            <div class="investigation-board">
              <div class="method-rail" aria-label="Investigation phases">
                <div class="method-step active"><span>Observe</span><p>Map the authorized public surface.</p></div>
                <div class="method-step"><span>Question</span><p>Choose the strongest clue to pursue.</p></div>
                <div class="method-step"><span>Corroborate</span><p>Consult public, reliable sources.</p></div>
                <div class="method-step"><span>Explain</span><p>Show evidence, confidence and action.</p></div>
              </div>
              <div class="agent-terminal">
                <div class="terminal-head"><span><i></i><i></i><i></i></span><strong>Investigation trace</strong><small>read-only</small></div>
                <div class="terminal-body">
                  <p><time>09:41:02</time><b>observe</b> HTTPS responded on the expected host</p>
                  <p><time>09:41:03</time><b>evidence</b> Page identifies an infrastructure control surface</p>
                  <p><time>09:41:04</time><b>reason</b> Public administration deserves closer review</p>
                  <p><time>09:41:04</time><b>tool</b> inspect_tls(host, 443)</p>
                  <p><time>09:41:05</time><b>result</b> Certificate valid · 41 days remaining</p>
                  <p class="terminal-conclusion"><time>09:41:06</time><b>finding</b> One exposure needs attention <span class="cursor"></span></p>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section class="principles-section wrap" id="principles">
          <div class="principle-title">
            <span class="section-index">Built with boundaries</span>
            <h2>Curious by design.<br><em>Constrained on purpose.</em></h2>
          </div>
          <div class="principle-list">
            <article><span>Scope</span><h3>Only infrastructure you authorize</h3><p>Every tool call is resolved against a verified or administrator-approved target.</p></article>
            <article><span>Method</span><h3>Evidence without exploitation</h3><p>Safe protocol handshakes and public-source research. No credential attacks or exploit execution.</p></article>
            <article><span>Clarity</span><h3>Reasoning you can inspect</h3><p>Every conclusion retains the observations, sources and confidence behind it.</p></article>
          </div>
        </section>

        <section class="closing-section">
          <div class="wrap closing-grid">
            <div><span class="section-index">Private preview</span><h2>Your infrastructure is already speaking.</h2></div>
            <div><p>Wellguard helps you hear the parts that should make you pause.</p><a class="button button-light" routerLink="/app">Open the workspace <span>→</span></a></div>
          </div>
        </section>
      </main>

      <footer class="public-footer wrap">
        <a class="wordmark" routerLink="/"><span class="brand-mark"><i></i></span><span>wellguard<em>observe</em></span></a>
        <p>External exposure intelligence for people who build.</p>
        <span>Reconnaissance only · 2026</span>
      </footer>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class LandingComponent {}
