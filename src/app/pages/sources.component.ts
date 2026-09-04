import { ChangeDetectionStrategy, Component } from '@angular/core';
import { AppSidebarComponent } from '../components/app-sidebar.component';

interface Source { name: string; type: string; authority: string; use: string; url: string; mode: string; }
@Component({ selector: 'wg-sources', imports: [AppSidebarComponent], template: `
  <div class="app-layout"><wg-app-sidebar /><main class="app-main"><header class="app-header"><div><span class="app-breadcrumb">TRANSPARENCY / EVIDENCE SOURCES</span><h1>Evidence sources</h1><p>The direct observations and public intelligence the investigator is permitted to consult.</p></div><span class="scope-lock">{{ sources.length }} constrained sources</span></header>
  <section class="source-grid">@for (source of sources; track source.name) { <article class="panel source-card"><header><span class="source-icon">{{ glyph(source.type) }}</span><span class="state-pill" data-state="healthy">enabled</span></header><span class="section-index">{{ source.type }}</span><h2>{{ source.name }}</h2><p>{{ source.use }}</p><dl><div><dt>Authority</dt><dd>{{ source.authority }}</dd></div><div><dt>Access mode</dt><dd>{{ source.mode }}</dd></div></dl><a [href]="source.url" target="_blank" rel="noopener">View source ↗</a></article> }</section>
  <section class="callout-panel"><div><span>TRUST MODEL</span><h2>Sources provide evidence, never instructions.</h2></div><p>All remote content is size-bounded and treated as untrusted input. It cannot expand target scope or enable a new class of action.</p></section>
  </main></div>`, changeDetection: ChangeDetectionStrategy.OnPush })
export class SourcesComponent {
  protected readonly sources: Source[] = [
    { name: 'Public DNS', type: 'direct observation', authority: 'DNS hierarchy', use: 'A, AAAA, CNAME and public routing signals for authorized hosts.', url: 'https://www.iana.org/domains', mode: 'Read-only resolution' },
    { name: 'TLS handshake', type: 'direct observation', authority: 'Public certificate chain', use: 'Identity, validity dates, protocol, cipher and hostname coverage.', url: 'https://www.rfc-editor.org/rfc/rfc8446', mode: 'Single handshake' },
    { name: 'Certificate Transparency', type: 'public ledger', authority: 'crt.sh / public CT logs', use: 'Authorized hostnames appearing in publicly logged certificates.', url: 'https://crt.sh/', mode: 'Bounded HTTPS query' },
    { name: 'HackerTarget Host Search', type: 'passive discovery', authority: 'HackerTarget public API', use: 'Candidate subdomains from passive public data. Every candidate is actively verified and wildcard missing routes are discarded.', url: 'https://hackertarget.com/find-dns-host-records/', mode: 'One bounded public API query' },
    { name: 'CISA KEV', type: 'security intelligence', authority: 'US CISA', use: 'Confirms whether a concrete CVE is known to be exploited in the wild.', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', mode: 'Cached public feed' },
    { name: 'GitHub Advisories', type: 'security intelligence', authority: 'GitHub reviewed database', use: 'Details for concrete CVE or GHSA identifiers supported by observations.', url: 'https://github.com/advisories', mode: 'Public API' },
    { name: 'OSV.dev', type: 'security intelligence', authority: 'OpenSSF / Google', use: 'Package advisories only when package ecosystem, name and version are known.', url: 'https://osv.dev/', mode: 'Public API' },
    { name: 'GitHub Releases', type: 'version intelligence', authority: 'Selected official repository', use: 'Recent releases for an identified project; repositories are not guessed.', url: 'https://docs.github.com/en/rest/releases', mode: 'Public API' },
    { name: 'Vendor documentation', type: 'public research', authority: 'Investigator-selected vendor', use: 'Bounded official documentation used to corroborate product behavior.', url: 'https://www.cisa.gov/resources-tools/resources/secure-by-design', mode: 'Safe HTTPS GET' }
  ];
  protected glyph(type: string): string { return type.includes('direct') ? '◉' : type.includes('security') ? '◇' : type.includes('version') ? '↟' : '⊙'; }
}
