import type { AgentFinding, CustomerNarrative } from './types';

type NarrativeInput = Pick<AgentFinding, 'title' | 'summary' | 'severity' | 'evidence'>;

export function customerNarrativeFor(finding: NarrativeInput): CustomerNarrative {
  const text = `${finding.title} ${finding.summary} ${finding.evidence.join(' ')}`.toLowerCase();
  if (finding.severity === 'info') return {
    observed: simpleObservation(text, finding.summary),
    possibleAttack: 'No attack path is claimed from this informational observation.',
    businessImpact: 'This evidence is retained to help the owner understand the public surface and notice future change.',
    boundary: boundary()
  };

  return {
    observed: simpleObservation(text, finding.summary),
    possibleAttack: possibleStep(text),
    businessImpact: impact(finding.severity, text),
    boundary: boundary()
  };
}

function simpleObservation(text: string, fallback: string): string {
  if (/administration|admin(?:istrative)? surface|management (?:interface|surface)|login page|sign-in/.test(text)) return 'A management or sign-in surface is reachable from the public internet.';
  if (/credential|secret|\.env|git metadata|terminal history|environment data/.test(text)) return 'An anonymous visitor can reach information that may contain operational or access details.';
  if (/user identifier|author enumeration|public user|email-like/.test(text)) return 'The service publishes names or account identifiers to anonymous visitors.';
  if (/cookie|session/.test(text)) return 'The application issued a browser session marker with a protection that needs review.';
  if (/cross-origin|\bcors\b/.test(text)) return 'The application trusted a browser request from the scanner’s unrelated test origin.';
  if (/rate limit|throttl|forwarded-for/.test(text)) return 'The application’s request-control behavior changed when a client-supplied network identity was used.';
  if (/version|outdated|\bcve-/.test(text)) return 'The public response revealed a specific software identity or version with security relevance.';
  if (/certificate|\btls\b/.test(text)) return 'The public connection exposed a certificate or transport condition that needs review.';
  if (/\bdns\b|dmarc|spf|mail policy/.test(text)) return 'Public domain or email-security configuration is weaker or less explicit than expected.';
  return firstSentence(fallback);
}

function possibleStep(text: string): string {
  if (/administration|admin(?:istrative)? surface|management (?:interface|surface)|login page|sign-in/.test(text)) return 'Someone could identify it as a high-value entry point and try stolen, reused, or unchanged credentials. If access existed, what they could do next would depend on that account’s permissions.';
  if (/credential|secret|\.env|git metadata|terminal history|environment data/.test(text)) return 'Someone could use any still-valid detail to enter this service or another connected service, then look for broader access.';
  if (/user identifier|author enumeration|public user|email-like/.test(text)) return 'Someone could use the published identities for convincing phishing, password reuse attempts, or more focused login targeting.';
  if (/cookie|session|cross-origin|\bcors\b/.test(text)) return 'Under additional conditions, a malicious site or an unsafe connection could interfere with a user’s authenticated browser session.';
  if (/rate limit|throttl|forwarded-for/.test(text)) return 'Automated login or scraping attempts might avoid an intended control if the application trusts a client-supplied identity.';
  if (/version|outdated|\bcve-/.test(text)) return 'Someone could look for attacks that specifically match the observed release instead of probing blindly.';
  if (/certificate|\btls\b/.test(text)) return 'Users or automated clients could lose trust in the connection, or traffic could become easier to disrupt under the observed condition.';
  if (/\bdns\b|dmarc|spf|mail policy/.test(text)) return 'Someone could have an easier time impersonating the organization or redirecting trust if other required conditions also align.';
  return 'Someone could use the exposed behavior as a starting point to map the service and look for a second weakness.';
}

function impact(severity: AgentFinding['severity'], text: string): string {
  if (/credential|secret|\.env|git metadata|terminal history/.test(text)) return 'If the exposed details remained valid, the consequence could extend beyond this service to data loss or access to connected systems.';
  if (/administration|management (?:interface|surface)/.test(text)) return 'If a valid account were obtained, the consequence could include configuration changes, data access, or control of functions available to that account.';
  if (severity === 'critical' || severity === 'high') return 'If the full path succeeded, it could lead to unauthorized control, sensitive-data exposure, or disruption of the service.';
  if (severity === 'medium') return 'If combined with another weakness, it could expose data, weaken account security, or help an attacker move toward a more important system.';
  return 'The immediate impact is limited, but it reduces uncertainty for an attacker and can make a later attack more focused.';
}

function boundary(): string {
  return 'This is a plausible consequence, not a performed exploit. Wellguard did not authenticate, upload files, run commands, elevate privileges, read private data, or prove the downstream steps.';
}

function firstSentence(value: string): string {
  const clean = value.trim();
  const end = clean.search(/[.!?](?:\s|$)/);
  return (end >= 0 ? clean.slice(0, end + 1) : clean).slice(0, 360);
}
