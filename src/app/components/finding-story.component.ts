import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import type { CustomerNarrative, Finding } from '../models';

@Component({
  selector: 'wg-finding-story',
  template: `
    <section class="finding-story" [class.compact]="compact()" aria-label="Potential incident path">
      <header><span>POTENTIAL INCIDENT PATH</span><b>SIMULATED · NOT EXECUTED</b></header>
      <ol>
        <li data-basis="observed"><i>1</i><div><small>Seen from the internet</small><p>{{ narrative().observed }}</p></div></li>
        <li data-basis="possible"><i>2</i><div><small>What someone could try next</small><p>{{ narrative().possibleAttack }}</p></div></li>
        <li data-basis="possible"><i>3</i><div><small>Possible business consequence</small><p>{{ narrative().businessImpact }}</p></div></li>
      </ol>
      <footer><strong>Evidence boundary</strong><span>{{ narrative().boundary }}</span></footer>
    </section>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class FindingStoryComponent {
  readonly finding = input.required<Finding>();
  readonly compact = input(false);
  protected readonly narrative = computed(() => this.finding().customerNarrative || fallback(this.finding()));
}

function fallback(finding: Finding): CustomerNarrative {
  const text = `${finding.title} ${finding.summary}`.toLowerCase();
  const management = /administration|admin(?:istrative)? surface|management (?:interface|surface)|login page|sign-in/.test(text);
  const identity = /user identifier|author enumeration|public user|email-like/.test(text);
  const sensitive = /credential|secret|\.env|git metadata|environment data/.test(text);
  return {
    observed: management ? 'A management or sign-in surface is reachable from the public internet.'
      : identity ? 'The service publishes names or account identifiers to anonymous visitors.'
        : sensitive ? 'An anonymous visitor can reach information that may contain operational or access details.'
          : firstSentence(finding.summary),
    possibleAttack: finding.severity === 'info' ? 'No attack path is claimed from this informational observation.'
      : management ? 'Someone could identify it as a high-value entry point and try stolen, reused, or unchanged credentials. Any next step would depend on the account permissions.'
        : identity ? 'Someone could use the published identities for convincing phishing, password reuse attempts, or more focused login targeting.'
          : sensitive ? 'Someone could use any still-valid detail to enter this service or another connected service, then look for broader access.'
            : 'Someone could use the exposed behavior as a starting point to map the service and look for a second weakness.',
    businessImpact: finding.severity === 'info' ? 'This is retained as inventory so the owner can notice future change.'
      : management ? 'If a valid account were obtained, the consequence could include configuration changes, data access, or control of functions available to that account.'
        : 'If combined with another weakness, the exposure could lead to data loss, account compromise, or service disruption.',
    boundary: 'This is a plausible consequence, not a performed exploit. Wellguard did not authenticate, upload files, run commands, elevate privileges, read private data, or prove the downstream steps.'
  };
}

function firstSentence(value: string): string {
  const clean = value.trim();
  const end = clean.search(/[.!?](?:\s|$)/);
  return (end >= 0 ? clean.slice(0, end + 1) : clean).slice(0, 360);
}
