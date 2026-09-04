import { z } from 'zod';
import type { FrameworkReference } from './types';

export const COMPLIANCE_REFERENCES = {
  'WSTG-INPV-05': {
    framework: 'OWASP WSTG', control: 'WSTG-INPV-05', title: 'Testing for SQL Injection',
    url: 'https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection',
    relationship: 'test-method', note: 'The Wellguard check uses only a quoted-input error differential. It does not execute SQL or establish exploitability.'
  },
  'WSTG-SESS-02': {
    framework: 'OWASP WSTG', control: 'WSTG-SESS-02', title: 'Testing for Cookies Attributes',
    url: 'https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes',
    relationship: 'test-method', note: 'Wellguard observes cookie names and attributes only; values are never retained or replayed.'
  },
  'WSTG-CLNT-07': {
    framework: 'OWASP WSTG', control: 'WSTG-CLNT-07', title: 'Testing Cross Origin Resource Sharing',
    url: 'https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing',
    relationship: 'test-method', note: 'A fixed synthetic Origin is compared without credentials or a state-changing request.'
  },
  'v5.0.0-1.2.4': {
    framework: 'OWASP ASVS', control: 'v5.0.0-1.2.4', title: 'Injection prevention for database queries',
    url: 'https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x10-V1-Encoding-and-Sanitization.md#v12-injection-prevention',
    relationship: 'verification-requirement', note: 'External response evidence can identify a review need but cannot verify the application implementation by itself.'
  },
  'v5.0.0-2.4.1': {
    framework: 'OWASP ASVS', control: 'v5.0.0-2.4.1', title: 'Anti-automation controls for excessive calls',
    url: 'https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x11-V2-Validation-and-Business-Logic.md#v24-anti-automation',
    relationship: 'verification-requirement', note: 'A small anonymous burst is evidence about one endpoint, not a capacity or denial-of-service assessment.'
  },
  'v5.0.0-3.3.1': {
    framework: 'OWASP ASVS', control: 'v5.0.0-3.3.1', title: 'Secure cookie attribute and prefix',
    url: 'https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x12-V3-Web-Frontend-Security.md#v33-cookie-setup',
    relationship: 'verification-requirement', note: 'Observed Set-Cookie attributes provide endpoint-level evidence only.'
  },
  'v5.0.0-3.3.2': {
    framework: 'OWASP ASVS', control: 'v5.0.0-3.3.2', title: 'Purpose-appropriate SameSite cookies',
    url: 'https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x12-V3-Web-Frontend-Security.md#v33-cookie-setup',
    relationship: 'verification-requirement', note: 'Wellguard cannot determine a cookie purpose with certainty and marks missing SameSite as a review item.'
  },
  'v5.0.0-3.3.4': {
    framework: 'OWASP ASVS', control: 'v5.0.0-3.3.4', title: 'HttpOnly for script-inaccessible cookies',
    url: 'https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x12-V3-Web-Frontend-Security.md#v33-cookie-setup',
    relationship: 'verification-requirement', note: 'The finding is limited to cookies whose names strongly indicate session or authentication use.'
  },
  'v5.0.0-3.4.2': {
    framework: 'OWASP ASVS', control: 'v5.0.0-3.4.2', title: 'CORS origin allowlist validation',
    url: 'https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x12-V3-Web-Frontend-Security.md#v34-browser-security-header-fields',
    relationship: 'verification-requirement', note: 'The check only reports a strong signal when an arbitrary synthetic origin is reflected with credential support.'
  },
  'v5.0.0-15.3.4': {
    framework: 'OWASP ASVS', control: 'v5.0.0-15.3.4', title: 'Trusted original IP for security decisions',
    url: 'https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md#v153-security-architecture',
    relationship: 'verification-requirement', note: 'Forwarding-header comparison runs only after throttling was directly observed and uses reserved documentation addresses.'
  },
  'CRA-I-1': {
    framework: 'EU CRA', control: 'Annex I, Part I (1)', title: 'Risk-appropriate level of cybersecurity',
    url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02024R2847-20241120',
    relationship: 'regulatory-relevance', note: 'External evidence can support a product risk assessment; it is not a CRA conformity determination.'
  },
  'CRA-I-2b': {
    framework: 'EU CRA', control: 'Annex I, Part I (2)(b)', title: 'Secure-by-default configuration',
    url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02024R2847-20241120',
    relationship: 'regulatory-relevance', note: 'Observed public defaults are relevant evidence only; applicability and conformity require product and manufacturer context.'
  },
  'CRA-I-2d': {
    framework: 'EU CRA', control: 'Annex I, Part I (2)(d)', title: 'Protection from unauthorised access',
    url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02024R2847-20241120',
    relationship: 'regulatory-relevance', note: 'An external observation cannot verify the complete authentication and access-management design.'
  },
  'CRA-I-2h': {
    framework: 'EU CRA', control: 'Annex I, Part I (2)(h)', title: 'Availability and denial-of-service resilience',
    url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02024R2847-20241120',
    relationship: 'regulatory-relevance', note: 'The bounded throttle observation is not a load, capacity, resilience, or conformity test.'
  },
  'CRA-I-2j': {
    framework: 'EU CRA', control: 'Annex I, Part I (2)(j)', title: 'Limit attack surfaces and external interfaces',
    url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02024R2847-20241120',
    relationship: 'regulatory-relevance', note: 'Observed public exposure can inform attack-surface review but does not decide legal applicability or conformity.'
  },
  'CRA-II-3': {
    framework: 'EU CRA', control: 'Annex I, Part II (3)', title: 'Effective and regular security tests and reviews',
    url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02024R2847-20241120',
    relationship: 'regulatory-relevance', note: 'A Wellguard observation can be one input to a broader testing process; it is not sufficient evidence of conformity.'
  }
} as const satisfies Record<string, FrameworkReference>;

export type ComplianceReferenceId = keyof typeof COMPLIANCE_REFERENCES;
const referenceIds = Object.keys(COMPLIANCE_REFERENCES) as [ComplianceReferenceId, ...ComplianceReferenceId[]];

export const frameworkReferenceInputSchema = z.object({
  control: z.enum(referenceIds).describe('Use only a control identifier returned by list_security_framework_references.')
});

export const frameworkReferenceSchema = frameworkReferenceInputSchema.transform(({ control }) => ({ ...COMPLIANCE_REFERENCES[control] }));

export function frameworkReferences(...ids: ComplianceReferenceId[]): FrameworkReference[] {
  return ids.map((id) => ({ ...COMPLIANCE_REFERENCES[id] }));
}

export function frameworkReferenceInputs(value: unknown): Array<{ control: ComplianceReferenceId }> {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    if (!item || typeof item !== 'object') return [];
    const control = String((item as Record<string, unknown>)['control'] || '');
    if (control in COMPLIANCE_REFERENCES) return [{ control: control as ComplianceReferenceId }];
    const match = (Object.entries(COMPLIANCE_REFERENCES) as Array<[ComplianceReferenceId, FrameworkReference]>).find(([, reference]) => reference.control === control);
    return match ? [{ control: match[0] }] : [];
  }).slice(0, 8);
}

export function complianceCatalog() {
  return Object.entries(COMPLIANCE_REFERENCES).map(([id, reference]) => ({ id, ...reference }));
}
