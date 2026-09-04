import type { ScopeGuard } from '../security/scope-guard';
import { frameworkReferences } from '../compliance';
import { extractSignals, requestAuthorizedHttp, type AuthorizedHttpResponse } from '../tools/http';
import type { AdapterInput, AdapterResult, ServiceAdapter } from './types';

type EvidenceLocation = 'body' | 'title' | 'header' | 'cookie';
type ExposureKind = 'management' | 'data-api' | 'diagnostic' | 'login';

interface EvidenceSignature {
  location: EvidenceLocation;
  pattern: RegExp;
  header?: string;
  description: string;
}

interface VersionSignature {
  location: Exclude<EvidenceLocation, 'cookie'>;
  pattern: RegExp;
  header?: string;
}

interface AdapterProbe {
  path: string;
  purpose: string;
  signatures: EvidenceSignature[];
  exposure?: ExposureKind;
}

export interface DeclarativeAdapterDefinition {
  id: string;
  product: string;
  aliases: string[];
  sourceUrl: string;
  probes: AdapterProbe[];
  versions?: VersionSignature[];
}

const body = (pattern: RegExp, description: string): EvidenceSignature => ({ location: 'body', pattern, description });
const title = (pattern: RegExp, description: string): EvidenceSignature => ({ location: 'title', pattern, description });
const header = (name: string, pattern: RegExp, description: string): EvidenceSignature => ({ location: 'header', header: name, pattern, description });
const cookie = (pattern: RegExp, description: string): EvidenceSignature => ({ location: 'cookie', pattern, description });
const versionHeader = (name: string, pattern: RegExp): VersionSignature => ({ location: 'header', header: name, pattern });
const versionBody = (pattern: RegExp): VersionSignature => ({ location: 'body', pattern });

export const DECLARATIVE_ADAPTERS: readonly DeclarativeAdapterDefinition[] = [
  {
    id: 'wordpress', product: 'WordPress', aliases: ['wordpress'], sourceUrl: 'https://developer.wordpress.org/rest-api/',
    probes: [
      { path: '/', purpose: 'public application', signatures: [body(/\/wp-(?:content|includes)\//i, 'HTML referenced a WordPress content or includes path.'), header('x-redirect-by', /wordpress/i, 'The X-Redirect-By header identified WordPress.')] },
      { path: '/wp-login.php', purpose: 'sign-in surface', exposure: 'login', signatures: [body(/wp-login\.php|loginform|wordpress/i, 'The fixed sign-in path returned WordPress login markers.')] },
      { path: '/wp-json/', purpose: 'public REST index', signatures: [body(/"namespaces"\s*:|"routes"\s*:\s*\{/i, 'The fixed REST path returned a WordPress-style route index.')] }
    ], versions: [versionBody(/<meta[^>]+generator[^>]+WordPress\s+([0-9.]+)/i)]
  },
  {
    id: 'drupal', product: 'Drupal', aliases: ['drupal'], sourceUrl: 'https://www.drupal.org/docs/getting-started/system-requirements/web-server',
    probes: [
      { path: '/', purpose: 'public application', signatures: [body(/drupalSettings|Drupal\.settings|\/sites\/(?:default|all)\//i, 'HTML returned Drupal settings or site asset markers.'), body(/generator[^>]+Drupal\s*[0-9]*/i, 'The generator metadata identified Drupal.')] },
      { path: '/user/login', purpose: 'sign-in surface', exposure: 'login', signatures: [body(/user-login-form|data-drupal-selector|Drupal/i, 'The fixed login path returned Drupal form markers.')] }
    ], versions: [versionBody(/generator[^>]+Drupal\s*([0-9.]+)/i)]
  },
  {
    id: 'joomla', product: 'Joomla', aliases: ['joomla'], sourceUrl: 'https://docs.joomla.org/Administrator_(Application)',
    probes: [
      { path: '/', purpose: 'public application', signatures: [body(/generator[^>]+Joomla|\/media\/system\/js\//i, 'HTML returned Joomla generator or system-asset markers.')] },
      { path: '/administrator/', purpose: 'administration surface', exposure: 'management', signatures: [body(/com_login|Joomla! Administrator|mod-login-username/i, 'The fixed administration path returned Joomla administrator markers.')] }
    ], versions: [versionBody(/generator[^>]+Joomla!?\s*([0-9.]+)/i)]
  },
  {
    id: 'gitlab', product: 'GitLab', aliases: ['gitlab'], sourceUrl: 'https://docs.gitlab.com/user/profile/account/two_factor_authentication/',
    probes: [
      { path: '/', purpose: 'public application', signatures: [body(/gl-performance-bar|gon\.gitlab_url|assets\/webpack\/runtime/i, 'HTML returned GitLab application markers.')] },
      { path: '/users/sign_in', purpose: 'sign-in surface', exposure: 'management', signatures: [body(/new_user|user_login|GitLab/i, 'The fixed sign-in path returned GitLab account markers.')] },
      { path: '/-/health', purpose: 'health metadata', signatures: [body(/^GitLab OK\s*$/i, 'The fixed health path returned the GitLab health response.')] }
    ], versions: [versionBody(/GitLab(?: Community| Enterprise)? Edition\s+([0-9.]+)/i)]
  },
  {
    id: 'jenkins', product: 'Jenkins', aliases: ['jenkins'], sourceUrl: 'https://www.jenkins.io/doc/book/security/controller-isolation/',
    probes: [
      { path: '/', purpose: 'automation controller', exposure: 'management', signatures: [header('x-jenkins', /.+/, 'The X-Jenkins response header identified the controller.'), body(/jenkins-agent-protocols|adjuncts\/[a-f0-9]+\/org\/kohsuke\/stapler/i, 'HTML returned Jenkins controller assets.')] },
      { path: '/login', purpose: 'sign-in surface', signatures: [body(/j_username|Jenkins/i, 'The fixed sign-in path returned Jenkins login markers.')] },
      { path: '/api/json', purpose: 'public API metadata', signatures: [body(/"_class"\s*:\s*"hudson\.|"mode"\s*:\s*"(?:NORMAL|EXCLUSIVE)"/i, 'The fixed API path returned Jenkins object metadata.')] }
    ], versions: [versionHeader('x-jenkins', /^([0-9][0-9.]+)/)]
  },
  {
    id: 'grafana', product: 'Grafana', aliases: ['grafana'], sourceUrl: 'https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/',
    probes: [
      { path: '/', purpose: 'observability application', exposure: 'management', signatures: [body(/grafanaBootData|\/public\/build\/grafana/i, 'HTML returned Grafana boot or application assets.')] },
      { path: '/login', purpose: 'sign-in surface', signatures: [body(/grafanaBootData|Grafana/i, 'The fixed sign-in path returned Grafana markers.')] },
      { path: '/api/health', purpose: 'health metadata', signatures: [body(/"database"\s*:\s*"ok"|"version"\s*:\s*"[0-9.]+"/i, 'The fixed health path returned Grafana-style health metadata.')] }
    ], versions: [versionBody(/"version"\s*:\s*"([0-9.]+)"/i)]
  },
  {
    id: 'kibana', product: 'Kibana', aliases: ['kibana'], sourceUrl: 'https://www.elastic.co/docs/deploy-manage/security/secure-your-cluster-deployment',
    probes: [
      { path: '/', purpose: 'analytics application', exposure: 'management', signatures: [header('kbn-name', /.+/, 'The Kbn-Name header identified Kibana.'), body(/kbn-injected-metadata|kibanaWelcomeView/i, 'HTML returned Kibana boot markers.')] },
      { path: '/login', purpose: 'sign-in surface', signatures: [body(/kbn-injected-metadata|Kibana/i, 'The fixed sign-in path returned Kibana markers.')] },
      { path: '/api/status', purpose: 'status metadata', signatures: [body(/"name"\s*:\s*"kibana"|"overall"\s*:\s*\{/i, 'The fixed status path returned Kibana-style status metadata.')] }
    ], versions: [versionHeader('kbn-version', /^([0-9][0-9.]+)/), versionBody(/"version"\s*:\s*\{[^}]*"number"\s*:\s*"([0-9.]+)"/i)]
  },
  {
    id: 'prometheus', product: 'Prometheus', aliases: ['prometheus'], sourceUrl: 'https://prometheus.io/docs/prometheus/latest/configuration/https/',
    probes: [
      { path: '/', purpose: 'metrics application', exposure: 'management', signatures: [body(/Prometheus Time Series Collection and Processing Server|class="prometheus"/i, 'HTML returned Prometheus application markers.')] },
      { path: '/-/ready', purpose: 'readiness metadata', signatures: [body(/Prometheus Server is Ready/i, 'The fixed readiness path returned the Prometheus readiness response.')] },
      { path: '/api/v1/status/buildinfo', purpose: 'build metadata', signatures: [body(/"version"\s*:\s*"[0-9.]+"[^}]*"revision"/i, 'The fixed build-info API returned Prometheus version metadata.')] }
    ], versions: [versionBody(/"version"\s*:\s*"([0-9.]+)"/i)]
  },
  {
    id: 'rabbitmq-management', product: 'RabbitMQ Management', aliases: ['rabbitmq', 'rabbitmq management'], sourceUrl: 'https://www.rabbitmq.com/docs/management',
    probes: [
      { path: '/', purpose: 'broker management surface', exposure: 'management', signatures: [body(/RabbitMQ Management|rabbitmq-management/i, 'HTML returned RabbitMQ Management markers.'), header('www-authenticate', /realm="?RabbitMQ Management/i, 'The authentication challenge identified RabbitMQ Management.')] },
      { path: '/api/overview', purpose: 'broker metadata API', signatures: [body(/"rabbitmq_version"\s*:|"management_version"\s*:/i, 'The fixed overview API returned RabbitMQ metadata.'), header('www-authenticate', /RabbitMQ Management/i, 'The overview API authentication challenge identified RabbitMQ Management.')] }
    ], versions: [versionBody(/"rabbitmq_version"\s*:\s*"([0-9.]+)"/i)]
  },
  {
    id: 'portainer', product: 'Portainer', aliases: ['portainer'], sourceUrl: 'https://docs.portainer.io/admin/settings/authentication',
    probes: [
      { path: '/', purpose: 'container management surface', exposure: 'management', signatures: [body(/Portainer|portainer\.io|portainer-ui/i, 'HTML returned Portainer application markers.')] },
      { path: '/api/status', purpose: 'public status metadata', signatures: [body(/"Version"\s*:\s*"[0-9.]+"|"InstanceID"\s*:/i, 'The fixed status API returned Portainer-style metadata.')] }
    ], versions: [versionBody(/"Version"\s*:\s*"([0-9.]+)"/i)]
  },
  {
    id: 'file-browser', product: 'File Browser', aliases: ['filebrowser', 'file browser'], sourceUrl: 'https://filebrowser.org/configuration/authentication-method',
    probes: [
      { path: '/', purpose: 'file management surface', exposure: 'management', signatures: [title(/File Browser/i, 'The page title identified File Browser.'), body(/window\.FileBrowser|filebrowser\.svg|File Browser/i, 'HTML returned File Browser application markers.')] },
      { path: '/login', purpose: 'sign-in surface', signatures: [body(/File Browser|login-button|password/i, 'The fixed sign-in path returned File Browser markers.')] }
    ]
  },
  {
    id: 'phpmyadmin', product: 'phpMyAdmin', aliases: ['phpmyadmin'], sourceUrl: 'https://docs.phpmyadmin.net/en/latest/setup.html#securing-your-phpmyadmin-installation',
    probes: [
      { path: '/', purpose: 'database management surface', exposure: 'management', signatures: [body(/pmahomme|phpMyAdmin|pma_navigation/i, 'HTML returned phpMyAdmin interface markers.')] },
      { path: '/index.php', purpose: 'sign-in surface', signatures: [body(/pma_username|phpMyAdmin/i, 'The fixed entry path returned phpMyAdmin login markers.')] }
    ], versions: [versionBody(/phpMyAdmin\s+([0-9.]+)/i)]
  },
  {
    id: 'adminer', product: 'Adminer', aliases: ['adminer'], sourceUrl: 'https://www.adminer.org/en/security/',
    probes: [
      { path: '/', purpose: 'database management surface', exposure: 'management', signatures: [title(/Adminer/i, 'The page title identified Adminer.'), body(/<h1[^>]*>\s*Adminer|name="auth\[driver\]"/i, 'HTML returned Adminer login markers.')] }
    ], versions: [versionBody(/Adminer\s+([0-9.]+)/i)]
  },
  {
    id: 'elasticsearch', product: 'Elasticsearch', aliases: ['elasticsearch'], sourceUrl: 'https://www.elastic.co/docs/deploy-manage/security/secure-your-cluster-deployment',
    probes: [
      { path: '/', purpose: 'cluster API', exposure: 'data-api', signatures: [body(/"tagline"\s*:\s*"You Know, for Search"|"cluster_name"\s*:[\s\S]{0,500}"version"\s*:/i, 'The root API returned the Elasticsearch product document.'), header('x-elastic-product', /^Elasticsearch$/i, 'The X-Elastic-Product header identified Elasticsearch.')] }
    ], versions: [versionBody(/"number"\s*:\s*"([0-9.]+)"/i)]
  },
  {
    id: 'apache-solr', product: 'Apache Solr', aliases: ['solr', 'apache solr'], sourceUrl: 'https://solr.apache.org/guide/solr/latest/deployment-guide/securing-solr.html',
    probes: [
      { path: '/solr/', purpose: 'search administration surface', exposure: 'management', signatures: [body(/Solr Admin|solr-admin|Apache Solr/i, 'The fixed Solr path returned administration markers.')] },
      { path: '/solr/admin/info/system?wt=json', purpose: 'system metadata', exposure: 'diagnostic', signatures: [body(/"solr_home"\s*:|"lucene"\s*:\s*\{/i, 'The fixed system-info path returned Solr metadata.')] }
    ], versions: [versionBody(/"solr-spec-version"\s*:\s*"([0-9.]+)"/i)]
  },
  {
    id: 'apache-tomcat', product: 'Apache Tomcat', aliases: ['tomcat', 'apache tomcat'], sourceUrl: 'https://tomcat.apache.org/tomcat-11.0-doc/security-howto.html',
    probes: [
      { path: '/', purpose: 'application server', signatures: [body(/Apache Tomcat\/[0-9]|If you're seeing this, you've successfully installed Tomcat/i, 'The root page returned Apache Tomcat markers.')] },
      { path: '/manager/html', purpose: 'server management surface', exposure: 'management', signatures: [body(/Tomcat Web Application Manager|Manager App/i, 'The fixed manager path returned Tomcat Manager markers.'), header('www-authenticate', /Tomcat Manager Application/i, 'The authentication challenge identified Tomcat Manager.')] }
    ], versions: [versionBody(/Apache Tomcat\/([0-9.]+)/i)]
  },
  {
    id: 'spring-boot-actuator', product: 'Spring Boot Actuator', aliases: ['spring boot', 'spring actuator'], sourceUrl: 'https://docs.spring.io/spring-boot/reference/actuator/endpoints.html',
    probes: [
      { path: '/actuator', purpose: 'actuator index', exposure: 'diagnostic', signatures: [body(/"_links"\s*:\s*\{[\s\S]{0,400}"health"\s*:\s*\{[\s\S]{0,200}"href"/i, 'The fixed actuator index returned Spring Boot endpoint links.')] },
      { path: '/actuator/health', purpose: 'health metadata', signatures: [body(/^\s*\{\s*"status"\s*:\s*"(?:UP|DOWN|OUT_OF_SERVICE|UNKNOWN)"/i, 'The fixed actuator health path returned Spring-style health metadata.')] }
    ], versions: [versionBody(/"spring-boot"\s*:\s*"([0-9.]+)"/i)]
  },
  {
    id: 'traefik', product: 'Traefik', aliases: ['traefik'], sourceUrl: 'https://doc.traefik.io/traefik/operations/api/',
    probes: [
      { path: '/dashboard/', purpose: 'proxy dashboard', exposure: 'management', signatures: [body(/Traefik|traefik-ui|Dashboard - Traefik/i, 'The fixed dashboard path returned Traefik interface markers.')] },
      { path: '/api/version', purpose: 'proxy version API', exposure: 'diagnostic', signatures: [body(/"Version"\s*:\s*"v?[0-9.]+"|"Codename"\s*:/i, 'The fixed version API returned Traefik metadata.')] }
    ], versions: [versionBody(/"Version"\s*:\s*"v?([0-9.]+)"/i)]
  },
  {
    id: 'nextjs', product: 'Next.js', aliases: ['next.js', 'nextjs'], sourceUrl: 'https://nextjs.org/docs/app/guides/production-checklist',
    probes: [{ path: '/', purpose: 'web application', signatures: [body(/<script[^>]+id=["']__NEXT_DATA__["']|\/_next\//i, 'HTML returned Next.js data or asset markers.')] }],
    versions: [versionBody(/"nextVersion"\s*:\s*"([0-9.]+)"/i)]
  },
  {
    id: 'angular', product: 'Angular', aliases: ['angular'], sourceUrl: 'https://angular.dev/best-practices/security',
    probes: [{ path: '/', purpose: 'web application', signatures: [body(/<app-root(?:\s|>)|\bng-version=["'][^"']+["']/i, 'HTML returned an Angular root or version marker.')] }],
    versions: [versionBody(/\bng-version=["']([^"']+)["']/i)]
  },
  {
    id: 'express', product: 'Express', aliases: ['express', 'express.js'], sourceUrl: 'https://expressjs.com/en/advanced/best-practice-security.html',
    probes: [{ path: '/', purpose: 'web application server', signatures: [header('x-powered-by', /^Express$/i, 'The X-Powered-By header identified Express.'), body(/Cannot (?:GET|POST) \/[^<]*<\/pre>/i, 'The response returned the characteristic Express default route page.')] }]
  },
  {
    id: 'django', product: 'Django', aliases: ['django'], sourceUrl: 'https://docs.djangoproject.com/en/stable/topics/security/',
    probes: [
      { path: '/', purpose: 'web application', signatures: [cookie(/^csrftoken$/i, 'The response issued Django’s conventional CSRF cookie.'), body(/csrfmiddlewaretoken/i, 'HTML returned Django’s CSRF form marker.')] },
      { path: '/admin/login/', purpose: 'administration sign-in', exposure: 'management', signatures: [body(/Django administration|admin-login|csrfmiddlewaretoken/i, 'The fixed administration path returned Django login markers.')] }
    ]
  },
  {
    id: 'flask', product: 'Flask / Werkzeug', aliases: ['flask', 'werkzeug'], sourceUrl: 'https://flask.palletsprojects.com/en/stable/deploying/',
    probes: [{ path: '/', purpose: 'Python web application', signatures: [header('server', /Werkzeug\/[0-9.]+/i, 'The Server header identified Werkzeug.'), body(/Werkzeug Debugger|The debugger caught an exception/i, 'HTML returned Werkzeug debugger markers.')] }],
    versions: [versionHeader('server', /Werkzeug\/([0-9.]+)/i)]
  },
  {
    id: 'fastapi', product: 'FastAPI', aliases: ['fastapi'], sourceUrl: 'https://fastapi.tiangolo.com/deployment/concepts/',
    probes: [
      { path: '/docs', purpose: 'interactive API documentation', exposure: 'diagnostic', signatures: [title(/FastAPI\s*-\s*Swagger UI/i, 'The page title identified FastAPI Swagger UI.'), body(/url:\s*["']\/openapi\.json["'][\s\S]{0,300}SwaggerUIBundle/i, 'The fixed documentation path returned FastAPI’s conventional Swagger boot configuration.')] },
      { path: '/openapi.json', purpose: 'API schema', signatures: [body(/"openapi"\s*:\s*"3\.[0-9.]+"[\s\S]{0,500}"title"\s*:/i, 'The fixed schema path returned an OpenAPI 3 document.')] }
    ], versions: [versionBody(/"version"\s*:\s*"([0-9.]+)"/i)]
  },
  {
    id: 'laravel', product: 'Laravel', aliases: ['laravel'], sourceUrl: 'https://laravel.com/docs/deployment',
    probes: [{ path: '/', purpose: 'PHP web application', signatures: [cookie(/^laravel_session$/i, 'The response issued Laravel’s conventional session cookie.'), body(/Laravel(?: v?[0-9.]+)?|csrf-token["'][^>]+content=/i, 'HTML returned Laravel branding or framework metadata.')] }],
    versions: [versionBody(/Laravel\s+v?([0-9.]+)/i)]
  },
  {
    id: 'ruby-on-rails', product: 'Ruby on Rails', aliases: ['ruby on rails', 'rails'], sourceUrl: 'https://guides.rubyonrails.org/security.html',
    probes: [{ path: '/', purpose: 'Ruby web application', signatures: [header('x-powered-by', /Phusion Passenger/i, 'The X-Powered-By header identified Passenger, commonly serving Rails.'), body(/content=["']authenticity_token["']|Rails\.application/i, 'HTML returned Rails application markers.')] }],
    versions: [versionHeader('x-powered-by', /Phusion Passenger\s+([0-9.]+)/i)]
  },
  {
    id: 'nginx', product: 'nginx', aliases: ['nginx'], sourceUrl: 'https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens',
    probes: [{ path: '/', purpose: 'web server', signatures: [header('server', /^nginx(?:\/[0-9.]+)?$/i, 'The Server header identified nginx.')] }],
    versions: [versionHeader('server', /^nginx\/([0-9.]+)/i)]
  },
  {
    id: 'apache-httpd', product: 'Apache HTTP Server', aliases: ['apache', 'apache http server', 'httpd'], sourceUrl: 'https://httpd.apache.org/docs/2.4/misc/security_tips.html',
    probes: [{ path: '/', purpose: 'web server', signatures: [header('server', /^Apache(?:\/[0-9.]+)?(?:\s|$)/i, 'The Server header identified Apache HTTP Server.')] }],
    versions: [versionHeader('server', /^Apache\/([0-9.]+)/i)]
  },
  {
    id: 'microsoft-iis', product: 'Microsoft IIS', aliases: ['iis', 'microsoft-iis'], sourceUrl: 'https://learn.microsoft.com/en-us/iis/manage/configuring-security/',
    probes: [{ path: '/', purpose: 'web server', signatures: [header('server', /^Microsoft-IIS(?:\/[0-9.]+)?$/i, 'The Server header identified Microsoft IIS.'), header('x-powered-by', /ASP\.NET/i, 'The X-Powered-By header identified ASP.NET on the IIS surface.')] }],
    versions: [versionHeader('server', /^Microsoft-IIS\/([0-9.]+)/i)]
  }
] as const;

export function declarativeAdapters(): ServiceAdapter[] {
  return DECLARATIVE_ADAPTERS.map(makeDeclarativeAdapter);
}

function makeDeclarativeAdapter(definition: DeclarativeAdapterDefinition): ServiceAdapter {
  return {
    manifest: {
      id: definition.id,
      name: `${definition.product} evidence adapter`,
      version: '1.0.0',
      products: definition.aliases,
      capabilities: ['product-confirmation', 'version-evidence', 'public-surface-review'],
      methods: ['GET'],
      maxRequests: definition.probes.length,
      sourceUrl: definition.sourceUrl
    },
    async inspect(scope: ScopeGuard, input: AdapterInput): Promise<AdapterResult> {
      const hostname = scope.assertHostname(input.hostname);
      const basePath = scope.assertPath(input.basePath || '/');
      const responses = await Promise.all(definition.probes.map(async (probe) => ({ probe, response: await observe(scope, input, joinPath(basePath, probe.path)) })));
      const observations = responses.map(({ probe, response }) => {
        const signals = extractSignals(response.raw, response.headers);
        const matchedEvidence = probe.signatures.flatMap((signature) => matches(signature, response, signals.title) ? [signature.description] : []);
        return {
          purpose: probe.purpose,
          url: response.requestedUrl,
          status: response.status,
          title: signals.title,
          location: response.headers['location'] || '',
          server: response.headers['server'] || '',
          cookies: response.cookies.map((item) => item.name),
          matchedEvidence,
          exposure: probe.exposure || ''
        };
      });
      const identified = observations.some((item) => item.matchedEvidence.length > 0);
      const versions = identified ? findVersions(definition.versions || [], responses.map((item) => item.response)) : [];
      const matchedExposure = identified ? observations.find((item) => item.exposure && item.matchedEvidence.length && item.status > 0 && item.status < 500) : undefined;
      const serviceKey = `service:${hostname}:${input.port || (input.tls === false ? 80 : 443)}:${definition.id}`;
      const suggestedFindings = matchedExposure ? [surfaceFinding(definition, hostname, serviceKey, matchedExposure)] : [];
      return {
        adapter: { id: definition.id, version: '1.0.0', name: `${definition.product} evidence adapter` },
        hostname,
        identified,
        product: definition.product,
        observations: { probes: observations, versions },
        relations: [],
        suggestedFindings,
        note: `Only ${definition.probes.length} fixed anonymous GET request${definition.probes.length === 1 ? ' was' : 's were'} made. Product identity requires a declared response signature. Reachability is not an authentication bypass.`
      };
    }
  };
}

async function observe(scope: ScopeGuard, input: AdapterInput, path: string): Promise<AuthorizedHttpResponse & { error?: string }> {
  try { return await requestAuthorizedHttp(scope, { hostname: input.hostname, port: input.port, tls: input.tls, path }); }
  catch (error) { return { requestedUrl: path, status: 0, headers: {}, raw: '', truncated: false, cookies: [], error: error instanceof Error ? error.message : String(error) }; }
}

function matches(signature: EvidenceSignature, response: AuthorizedHttpResponse, pageTitle: string): boolean {
  const source = signature.location === 'body' ? response.raw
    : signature.location === 'title' ? pageTitle
      : signature.location === 'header' ? response.headers[signature.header || ''] || ''
        : response.cookies.map((item) => item.name).join('\n');
  signature.pattern.lastIndex = 0;
  return signature.pattern.test(source);
}

function findVersions(signatures: VersionSignature[], responses: AuthorizedHttpResponse[]): string[] {
  const values = signatures.flatMap((signature) => responses.flatMap((response) => {
    const source = signature.location === 'body' ? response.raw
      : signature.location === 'title' ? extractSignals(response.raw, response.headers).title
        : response.headers[signature.header || ''] || '';
    signature.pattern.lastIndex = 0;
    const value = signature.pattern.exec(source)?.[1]?.trim();
    return value ? [value.slice(0, 80)] : [];
  }));
  return [...new Set(values)].slice(0, 4);
}

function joinPath(base: string, child: string): string {
  if (base === '/') return child;
  if (child === '/') return base;
  return `${base.replace(/\/$/, '')}/${child.replace(/^\//, '')}`;
}

function surfaceFinding(definition: DeclarativeAdapterDefinition, hostname: string, serviceKey: string, observation: { purpose: string; url: string; status: number; exposure: string; matchedEvidence: string[] }) {
  const exposure = observation.exposure as ExposureKind;
  const impact = exposure === 'data-api' ? 'The response confirms that a data-oriented service API is directly reachable.'
    : exposure === 'diagnostic' ? 'The response confirms that diagnostic or operational metadata is directly reachable.'
      : exposure === 'login' ? 'A login page alone is not a weakness, but it makes an account entry point available to any internet visitor.'
        : 'A management surface alone is not an authentication bypass, but it is a high-value entry point that should be deliberately exposed.';
  return {
    title: `${definition.product} ${observation.purpose} is publicly reachable`,
    summary: `An anonymous GET request reached the identified ${definition.product} ${observation.purpose} on ${hostname}. ${impact} Authentication and default credentials were not tested.`,
    severity: exposure === 'data-api' || exposure === 'diagnostic' ? 'medium' as const : 'low' as const,
    confidence: 100,
    asset: hostname,
    assetKey: serviceKey,
    relatedAssetKeys: [],
    relationKey: '',
    evidence: [`GET ${observation.url} returned HTTP ${observation.status}.`, ...observation.matchedEvidence].slice(0, 6),
    remediation: `Confirm that public access to this ${definition.product} ${observation.purpose} is required. If not, remove the route or place it behind a trusted access layer. Keep vendor-supported authentication and updates enabled.`,
    sourceUrls: [definition.sourceUrl],
    cveIds: [],
    weaknessIds: [],
    frameworkRefs: frameworkReferences('CRA-I-2j')
  };
}
