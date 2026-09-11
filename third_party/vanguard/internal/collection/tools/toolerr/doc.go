// Package toolerr defines error classifications shared by collection tools.
//
// ErrProviderUnavailable distinguishes a provider-wide authorization, plan, or
// quota failure from a single-target lookup failure. This lets orchestration
// stop calling that provider for the current scan without depending on any
// concrete client package. Tools wrap the sentinel only when the whole provider
// is unavailable.
package toolerr
