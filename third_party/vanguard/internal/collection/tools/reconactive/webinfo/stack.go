package webinfo

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var (
	reAssetURL    = regexp.MustCompile(`(?i)<(?:script|link)[^>]+(?:src|href)=["']([^"']+)["']`)
	reMetaTag     = regexp.MustCompile(`(?i)<meta\b[^>]*>`)
	reContentAttr = regexp.MustCompile(`(?i)\bcontent=["']([^"']*)["']`)
	reStripTags   = regexp.MustCompile(`(?is)<[^>]+>`)
)

// metaContent returns the content attribute of the first <meta> tag whose
// name/property attribute equals value (case-insensitive).
func metaContent(_, original, nameOrProp, value string) string {
	if original == "" {
		return ""
	}
	pattern := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(nameOrProp) + `\s*=\s*["']` + regexp.QuoteMeta(strings.ToLower(value)) + `["']`)
	for _, tag := range reMetaTag.FindAllString(original, -1) {
		if !pattern.MatchString(strings.ToLower(tag)) {
			continue
		}
		if match := reContentAttr.FindStringSubmatch(tag); len(match) > 1 {
			return cleanText(match[1])
		}
	}
	return ""
}

func stripTags(value string) string {
	return reStripTags.ReplaceAllString(value, " ")
}

func cleanText(value string) string {
	value = stripTags(value)
	value = html.UnescapeString(value)
	value = strings.Join(strings.Fields(value), " ")
	return strings.TrimSpace(value)
}

// DetectStack detects web stack signals from response headers and page HTML.
func DetectStack(headers http.Header, body []byte, domain string) *StackResult {
	source := string(body)
	lower := strings.ToLower(source)
	domain = normalizeDomainHost(domain)

	result := &StackResult{
		PoweredBy: strings.TrimSpace(headers.Get("X-Powered-By")),
		Server:    strings.TrimSpace(headers.Get("Server")),
	}
	result.CDN = detectCDN(headers)
	result.Hosting = detectHosting(headers, lower, domain)
	result.CMS = detectCMS(headers, lower, source)
	if isWordPress(lower, result.CMS) {
		result.Plugins = detectWordPressPlugins(lower)
	}
	result.JSLibs = detectJSLibraries(lower)
	result.CSSLibs = detectCSSLibraries(lower)
	result.ExternalSvc = detectExternalServices(source, domain)

	return result
}

func detectCDN(headers http.Header) string {
	switch {
	case headers.Get("Cf-Ray") != "" || strings.Contains(strings.ToLower(headers.Get("Server")), "cloudflare"):
		return "Cloudflare"
	case strings.Contains(strings.ToLower(headers.Get("X-Served-By")), "fastly") || strings.Contains(strings.ToLower(headers.Get("Via")), "fastly"):
		return "Fastly"
	case headers.Get("X-Amz-Cf-Id") != "" || headers.Get("X-Amz-Cf-Pop") != "":
		return "CloudFront"
	case headers.Get("X-Vercel-Id") != "":
		return "Vercel"
	case headers.Get("X-Nf-Request-Id") != "" || strings.Contains(strings.ToLower(headers.Get("Server")), "netlify"):
		return "Netlify"
	default:
		return ""
	}
}

func detectHosting(headers http.Header, lowerBody, domain string) string {
	switch {
	case headersContain(headers, "wpengine") || strings.Contains(lowerBody, "wpengine"):
		return "WP Engine"
	case headersContain(headers, "kinsta") || strings.Contains(lowerBody, "kinsta"):
		return "Kinsta"
	case headers.Get("X-Pantheon-Styx-Hostname") != "" || headersContain(headers, "pantheon") || strings.Contains(lowerBody, "pantheon"):
		return "Pantheon"
	case strings.HasSuffix(domain, ".github.io") || strings.Contains(strings.ToLower(headers.Get("Server")), "github.com"):
		return "GitHub Pages"
	case headers.Get("X-Vercel-Id") != "" || strings.Contains(lowerBody, "vercel.app"):
		return "Vercel"
	case headers.Get("X-Nf-Request-Id") != "" || strings.Contains(lowerBody, "netlify.app"):
		return "Netlify"
	case headers.Get("X-Render-Origin-Server") != "" || strings.Contains(lowerBody, "onrender.com"):
		return "Render"
	case headers.Get("Fly-Request-Id") != "" || strings.Contains(strings.ToLower(headers.Get("Server")), "fly.io") || strings.Contains(lowerBody, "fly.io"):
		return "Fly.io"
	default:
		return ""
	}
}

func detectCMS(headers http.Header, lowerBody, original string) string {
	generator := metaContent(lowerBody, original, "name", "generator")
	generatorLower := strings.ToLower(generator)

	switch {
	case strings.Contains(generatorLower, "wordpress") || containsAny(lowerBody, "/wp-content/", "/wp-includes/", "/wp-json/", "wp-embed.min.js"):
		if generator != "" && strings.Contains(generatorLower, "wordpress") {
			return generator
		}
		return "WordPress"
	case containsAny(lowerBody, "cdn.shopify.com", "shopify-section", "shopify-payment-button"):
		return "Shopify"
	case containsAny(lowerBody, "static.squarespace.com", "squarespace-cdn.com"):
		return "Squarespace"
	case containsAny(lowerBody, "wixstatic.com", "wix.com/website/templates"):
		return "Wix"
	case headers.Get("X-Drupal-Cache") != "" || containsAny(lowerBody, "drupal.settings", "/sites/default/files/", "/sites/all/"):
		return "Drupal"
	case strings.Contains(generatorLower, "hugo"):
		if generator != "" {
			return generator
		}
		return "Hugo"
	case containsAny(lowerBody, "webflow.com", "data-wf-page", "data-wf-site"):
		return "Webflow"
	default:
		return ""
	}
}

func isWordPress(lowerBody, cms string) bool {
	return strings.Contains(strings.ToLower(cms), "wordpress") || containsAny(lowerBody, "/wp-content/", "/wp-includes/", "/wp-json/")
}

func detectWordPressPlugins(lowerBody string) []string {
	plugins := map[string]string{
		"Elementor":                 "/wp-content/plugins/elementor/",
		"WooCommerce":               "/wp-content/plugins/woocommerce/",
		"Yoast SEO":                 "/wp-content/plugins/wordpress-seo/",
		"Contact Form 7":            "/wp-content/plugins/contact-form-7/",
		"Jetpack":                   "/wp-content/plugins/jetpack/",
		"WP Rocket":                 "/wp-content/plugins/wp-rocket/",
		"Akismet":                   "/wp-content/plugins/akismet/",
		"Wordfence":                 "/wp-content/plugins/wordfence/",
		"WPForms":                   "/wp-content/plugins/wpforms/",
		"Revolution Slider":         "/wp-content/plugins/revslider/",
		"Advanced Custom Fields":    "/wp-content/plugins/advanced-custom-fields/",
		"Mailchimp for WooCommerce": "/wp-content/plugins/mailchimp-for-woocommerce/",
		"LiteSpeed Cache":           "/wp-content/plugins/litespeed-cache/",
		"Smush":                     "/wp-content/plugins/wp-smushit/",
		"Rank Math":                 "/wp-content/plugins/seo-by-rank-math/",
	}

	out := make([]string, 0)
	for name, pattern := range plugins {
		if strings.Contains(lowerBody, pattern) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func detectJSLibraries(lowerBody string) []string {
	detectors := []struct {
		name     string
		patterns []string
	}{
		{name: "Alpine.js", patterns: []string{"alpinejs", "x-data="}},
		{name: "Angular", patterns: []string{"angular.min.js", "angular.js", "ng-version"}},
		{name: "Astro", patterns: []string{"/_astro/", "astro-island", "data-astro-cid"}},
		{name: "htmx", patterns: []string{"htmx.min.js", "hx-get=", "hx-post="}},
		{name: "jQuery", patterns: []string{"jquery.min.js", "jquery.js", "window.jquery"}},
		{name: "Next.js", patterns: []string{"/_next/", "__next_data__"}},
		{name: "Nuxt", patterns: []string{"/_nuxt/", "__nuxt__"}},
		{name: "React", patterns: []string{"react.production.min.js", "react-dom", "__react_devtools_global_hook__"}},
		{name: "Remix", patterns: []string{"__remixcontext", "__remixmanifest"}},
		{name: "Svelte", patterns: []string{"/_app/immutable/", "svelte"}},
		{name: "Vue", patterns: []string{"vue.js", "vue.min.js", "data-v-"}},
	}

	out := make([]string, 0)
	for _, detector := range detectors {
		if containsAny(lowerBody, detector.patterns...) {
			out = append(out, detector.name)
		}
	}
	sort.Strings(out)
	return out
}

func detectCSSLibraries(lowerBody string) []string {
	detectors := []struct {
		name     string
		patterns []string
	}{
		{name: "Bootstrap", patterns: []string{"bootstrap.min.css", "bootstrap.css"}},
		{name: "Bulma", patterns: []string{"bulma.min.css", "bulma.css"}},
		{name: "Foundation", patterns: []string{"foundation.min.css", "foundation.css"}},
		{name: "Tailwind", patterns: []string{"tailwindcss", "tailwind.min.css", "tailwind.css"}},
	}

	out := make([]string, 0)
	for _, detector := range detectors {
		if containsAny(lowerBody, detector.patterns...) {
			out = append(out, detector.name)
		}
	}
	sort.Strings(out)
	return out
}

func detectExternalServices(source, domain string) []ExternalService {
	seen := make(map[string]string)
	for _, match := range reAssetURL.FindAllStringSubmatch(source, -1) {
		rawURL := strings.TrimSpace(match[1])
		if rawURL == "" || strings.HasPrefix(rawURL, "data:") || strings.HasPrefix(rawURL, "mailto:") {
			continue
		}
		if strings.HasPrefix(rawURL, "//") {
			rawURL = "https:" + rawURL
		}

		parsed, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		host := normalizeDomainHost(parsed.Hostname())
		if host == "" {
			continue
		}
		if domain != "" && (host == domain || strings.HasSuffix(host, "."+domain)) {
			continue
		}

		kind := classifyExternalService(host)
		if current, ok := seen[host]; !ok || current == svcOther && kind != svcOther {
			seen[host] = kind
		}
	}

	out := make([]ExternalService, 0, len(seen))
	for host, kind := range seen {
		out = append(out, ExternalService{Domain: host, Type: kind})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Domain < out[j].Domain
	})
	return out
}

func classifyExternalService(host string) string {
	switch {
	case containsAny(host, "google-analytics.com", "analytics.google.com"):
		return "Analytics"
	case containsAny(host, "googletagmanager.com"):
		return "Tag Manager"
	case containsAny(host, "fonts.googleapis.com", "fonts.gstatic.com", "typekit.net"):
		return "Fonts"
	case containsAny(host, "doubleclick.net", "googleadservices.com"):
		return "Ads"
	case containsAny(host, "facebook.com", "facebook.net", "twitter.com", "linkedin.com"):
		return "Social"
	case containsAny(host, "youtube.com", "youtu.be", "vimeo.com"):
		return "Video"
	case containsAny(host, "stripe.com", "paypal.com"):
		return "Payment"
	case containsAny(host, "intercom.io", "zendesk.com", "crisp.chat"):
		return "Chat"
	case containsAny(host, "hubspot.com", "marketo.com"):
		return "Marketing"
	case containsAny(host, "cloudflare.com", "cloudfront.net", "jsdelivr.net", "unpkg.com", "cdnjs.com", "gstatic.com", "googleapis.com"):
		return "CDN"
	default:
		return svcOther
	}
}

// svcOther is the fallback external-service classification.
const svcOther = "Other"

func headersContain(headers http.Header, needle string) bool {
	needle = strings.ToLower(needle)
	for name, values := range headers {
		if strings.Contains(strings.ToLower(name), needle) {
			return true
		}
		for _, value := range values {
			if strings.Contains(strings.ToLower(value), needle) {
				return true
			}
		}
	}
	return false
}

func containsAny(source string, patterns ...string) bool {
	for _, pattern := range patterns {
		if strings.Contains(source, pattern) {
			return true
		}
	}
	return false
}

func normalizeDomainHost(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimPrefix(domain, "www.")
	return domain
}
