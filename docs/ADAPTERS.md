# Product adapter catalog

Wellguard ships 30 versioned product adapters. The catalog favors technologies that are both commonly used and externally observable: web frameworks from the [2025 Stack Overflow Developer Survey](https://survey.stackoverflow.co/2025/technology) are combined with high-value administration, observability, identity, CMS, API, and web-server surfaces. It is an intentionally useful catalog, not a claim that these products form one universal popularity ranking.

| Family | Adapters |
| --- | --- |
| Identity and content | Keycloak, WordPress, Drupal, Joomla |
| Developer and management | GitLab, Jenkins, Portainer, File Browser, phpMyAdmin, Adminer |
| Observability and data | Grafana, Kibana, Prometheus, RabbitMQ Management, Elasticsearch, Apache Solr |
| Runtime and gateway | Apache Tomcat, Spring Boot Actuator, Traefik |
| Application frameworks | Next.js, Angular, Express, Django, Flask/Werkzeug, FastAPI, Laravel, Ruby on Rails |
| Web servers | nginx, Apache HTTP Server, Microsoft IIS |

Each manifest declares its product aliases, capabilities, methods, maximum request count, and official documentation source. Twenty-nine adapters use the declarative engine in `agent/adapters/declarative.ts`; Keycloak keeps bespoke logic because its public OIDC document can establish an evidence relationship to another advertised host or address.

The declarative engine accepts only one to three fixed anonymous GET probes per product. It retains status, selected safe headers, cookie names and attributes, page title, matching signature descriptions, and version captures. It does not retain response bodies. A route is reported as a public management or diagnostic surface only after a product-specific marker matches; HTTP status alone never identifies a product.

Adapters do not authenticate, submit forms, guess credentials, follow arbitrary discovered paths, invoke business APIs, upload files, or test exploits. A public login page is an exposure decision—not proof of weak authentication.

To add another adapter, add one `DeclarativeAdapterDefinition` with:

- a stable id and product aliases;
- an official vendor documentation URL;
- fixed GET paths and narrowly scoped response signatures;
- optional version captures;
- an exposure label only when the route has clear management, login, data-API, or diagnostic meaning.

The catalog tests enforce unique ids, GET-only methods, and a maximum four-request manifest ceiling.
