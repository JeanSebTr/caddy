// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddy

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

// ReplacementProvider describes a global placeholder namespace
// contributed by a plugin. Once registered, placeholders of the
// form {<Namespace>.<key>} are available in every Replacer made
// with NewReplacer, including those used while provisioning
// config (TLS, storage, global options, etc.), not only in
// HTTP routes.
//
// EXPERIMENTAL: Subject to change or removal.
type ReplacementProvider struct {
	// Namespace is the placeholder prefix handled by this
	// provider, without the trailing dot. For example,
	// "secrets" handles {secrets.*}. It must not be empty,
	// must not contain dots, braces or whitespace, and must
	// not collide with a built-in global namespace.
	Namespace string

	// Func is called with the key relative to the namespace:
	// for {secrets.api_token}, it receives "api_token". It
	// must be safe for concurrent use, as it may be called
	// from any goroutine at any time.
	Func ReplacerFunc

	// Sensitive marks values from this namespace as unsafe to
	// expose in contexts where the input may not be trusted,
	// such as templates. Replacers returned by WithoutFile
	// omit sensitive providers.
	Sensitive bool

	// App is the optional name of an app module backing this
	// provider. When that app is configured, it is provisioned
	// before the config's storage and other apps, so that its
	// placeholders can be used while provisioning them.
	App string
}

// RegisterReplacementProvider registers a global placeholder
// namespace. It is intended to be called from a plugin's init
// function, alongside RegisterModule. It panics if the provider
// is invalid or the namespace is already registered.
//
// Registered namespaces are consulted after all other providers
// of a Replacer, so they never shadow built-in or per-request
// placeholders (such as {http.*}).
//
// EXPERIMENTAL: Subject to change or removal.
func RegisterReplacementProvider(p ReplacementProvider) {
	if p.Namespace == "" {
		panic("replacement provider namespace missing")
	}
	if strings.ContainsAny(p.Namespace, ".{} \t\r\n") {
		panic(fmt.Sprintf("invalid replacement provider namespace '%s'", p.Namespace))
	}
	if _, ok := reservedReplacementNamespaces[p.Namespace]; ok {
		panic(fmt.Sprintf("replacement provider namespace '%s' is reserved", p.Namespace))
	}
	if p.Func == nil {
		panic("missing ReplacementProvider.Func")
	}

	registeredProvidersMu.Lock()
	defer registeredProvidersMu.Unlock()

	current := loadRegisteredProviders()
	for _, rp := range current {
		if rp.prefix == p.Namespace+"." {
			panic(fmt.Sprintf("replacement provider namespace already registered: %s", p.Namespace))
		}
	}

	// copy-on-write, so that NewReplacer never needs a lock
	updated := make([]registeredProvider, len(current), len(current)+1)
	copy(updated, current)
	updated = append(updated, registeredProvider{
		prefix:    p.Namespace + ".",
		fn:        p.Func,
		sensitive: p.Sensitive,
		app:       p.App,
	})
	registeredProviders.Store(&updated)
}

// registeredProvider is the internal form of a ReplacementProvider.
type registeredProvider struct {
	prefix    string
	fn        ReplacerFunc
	sensitive bool
	app       string
}

func (p registeredProvider) replace(key string) (any, bool) {
	if !strings.HasPrefix(key, p.prefix) {
		return nil, false
	}
	return p.fn(key[len(p.prefix):])
}

// provisionReplacementProviderApps provisions the configured
// apps backing registered replacement providers, so their
// placeholders are available to the rest of the config.
func provisionReplacementProviderApps(ctx Context, cfg *Config) error {
	for _, p := range loadRegisteredProviders() {
		if p.app == "" {
			continue
		}
		if _, ok := cfg.AppsRaw[p.app]; !ok {
			continue
		}
		if _, err := ctx.App(p.app); err != nil {
			return err
		}
	}
	return nil
}

func loadRegisteredProviders() []registeredProvider {
	if p := registeredProviders.Load(); p != nil {
		return *p
	}
	return nil
}

// reservedReplacementNamespaces are the namespaces handled by
// the global default providers of NewReplacer.
var reservedReplacementNamespaces = map[string]struct{}{
	"env":    {},
	"file":   {},
	"system": {},
	"time":   {},
}

var (
	registeredProviders   atomic.Pointer[[]registeredProvider]
	registeredProvidersMu sync.Mutex
)
