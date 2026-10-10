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
	"encoding/json"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/caddyserver/certmagic"
)

// isolateRegisteredProviders restores the global registry
// once the test is over, so tests don't leak into each other.
func isolateRegisteredProviders(t *testing.T) {
	t.Helper()
	prev := registeredProviders.Load()
	registeredProviders.Store(nil)
	t.Cleanup(func() { registeredProviders.Store(prev) })
}

func mapProvider(values map[string]string) ReplacerFunc {
	return func(key string) (any, bool) {
		v, ok := values[key]
		return v, ok
	}
}

func TestRegisterReplacementProvider(t *testing.T) {
	isolateRegisteredProviders(t)

	RegisterReplacementProvider(ReplacementProvider{
		Namespace: "secrets",
		Func:      mapProvider(map[string]string{"api_token": "s3cr3t"}),
	})

	repl := NewReplacer()

	for _, tc := range []struct {
		input  string
		expect string
	}{
		{input: "{secrets.api_token}", expect: "s3cr3t"},
		{input: "Bearer {secrets.api_token}", expect: "Bearer s3cr3t"},
		{input: "{secrets.unknown}", expect: "{secrets.unknown}"},
		// the namespace alone, or a namespace that merely shares the prefix, is not handled
		{input: "{secrets}", expect: "{secrets}"},
		{input: "{secretsx.api_token}", expect: "{secretsx.api_token}"},
	} {
		if actual := repl.ReplaceKnown(tc.input, ""); actual != tc.expect {
			t.Errorf("input '%s': expected '%s', got '%s'", tc.input, tc.expect, actual)
		}
	}

	if _, err := repl.ReplaceOrErr("{secrets.unknown}", true, true); err == nil {
		t.Error("expected an error for an unknown key in a registered namespace")
	}
}

func TestRegisteredProviderNotInEmptyReplacer(t *testing.T) {
	isolateRegisteredProviders(t)

	RegisterReplacementProvider(ReplacementProvider{
		Namespace: "secrets",
		Func:      mapProvider(map[string]string{"api_token": "s3cr3t"}),
	})

	if _, ok := NewEmptyReplacer().Get("secrets.api_token"); ok {
		t.Error("expected registered providers to be absent from an empty replacer")
	}
}

func TestRegisteredProviderDoesNotShadow(t *testing.T) {
	isolateRegisteredProviders(t)

	RegisterReplacementProvider(ReplacementProvider{
		Namespace: "custom",
		Func: func(key string) (any, bool) {
			return "from registry", true
		},
	})

	repl := NewReplacer()
	repl.Set("custom.static", "from static")
	repl.Map(func(key string) (any, bool) {
		if key == "custom.mapped" {
			return "from map", true
		}
		return nil, false
	})

	for key, expect := range map[string]string{
		"custom.static": "from static",
		"custom.mapped": "from map",
		"custom.other":  "from registry",
	} {
		if actual, _ := repl.GetString(key); actual != expect {
			t.Errorf("key '%s': expected '%s', got '%s'", key, expect, actual)
		}
	}
}

func TestRegisteredProviderWithoutFile(t *testing.T) {
	isolateRegisteredProviders(t)

	RegisterReplacementProvider(ReplacementProvider{
		Namespace: "secrets",
		Func:      mapProvider(map[string]string{"api_token": "s3cr3t"}),
		Sensitive: true,
	})
	RegisterReplacementProvider(ReplacementProvider{
		Namespace: "build",
		Func:      mapProvider(map[string]string{"version": "1.2.3"}),
	})

	repl := NewReplacer().WithoutFile()

	if _, ok := repl.Get("secrets.api_token"); ok {
		t.Error("expected sensitive provider to be omitted by WithoutFile")
	}
	if actual, _ := repl.GetString("build.version"); actual != "1.2.3" {
		t.Errorf("expected non-sensitive provider to be kept by WithoutFile, got '%s'", actual)
	}
}

func TestRegisterReplacementProviderPanics(t *testing.T) {
	isolateRegisteredProviders(t)

	noop := func(string) (any, bool) { return nil, false }
	RegisterReplacementProvider(ReplacementProvider{Namespace: "taken", Func: noop})

	for name, p := range map[string]ReplacementProvider{
		"empty namespace":    {Func: noop},
		"dotted namespace":   {Namespace: "a.b", Func: noop},
		"braced namespace":   {Namespace: "a}", Func: noop},
		"spaced namespace":   {Namespace: "a b", Func: noop},
		"reserved namespace": {Namespace: "env", Func: noop},
		"nil func":           {Namespace: "nofunc"},
		"duplicate":          {Namespace: "taken", Func: noop},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("expected a panic")
				}
			}()
			RegisterReplacementProvider(p)
		})
	}
}

func TestRegisterReplacementProviderConcurrent(t *testing.T) {
	isolateRegisteredProviders(t)

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			RegisterReplacementProvider(ReplacementProvider{
				Namespace: "ns" + string(rune('a'+i)),
				Func:      mapProvider(map[string]string{"k": "v"}),
			})
		}()
		go func() {
			defer wg.Done()
			NewReplacer().Get("nsa.k")
		}()
	}
	wg.Wait()

	if n := len(loadRegisteredProviders()); n != 20 {
		t.Errorf("expected 20 registered providers, got %d", n)
	}
	if actual, _ := NewReplacer().GetString("nst.k"); actual != "v" {
		t.Errorf("expected 'v', got '%s'", actual)
	}
}

// test modules for TestReplacementProviderAppProvisionedFirst
type (
	testProviderApp  struct{}
	testConsumerApp  struct{ seen string }
	testConsumerStor struct{ seen string }
)

var (
	testProviderValue  atomic.Pointer[string]
	testConsumersSeen  sync.Map // module ID -> value seen during Provision
	registerTestModule sync.Once
)

func (testProviderApp) CaddyModule() ModuleInfo {
	return ModuleInfo{ID: "replacer_test_provider", New: func() Module { return new(testProviderApp) }}
}

func (*testProviderApp) Provision(Context) error {
	v := "provided"
	testProviderValue.Store(&v)
	return nil
}
func (*testProviderApp) Start() error { return nil }
func (*testProviderApp) Stop() error  { return nil }

func (testConsumerApp) CaddyModule() ModuleInfo {
	return ModuleInfo{ID: "replacer_test_consumer", New: func() Module { return new(testConsumerApp) }}
}

func (*testConsumerApp) Provision(Context) error {
	testConsumersSeen.Store("app", NewReplacer().ReplaceAll("{replacertest.value}", ""))
	return nil
}
func (*testConsumerApp) Start() error { return nil }
func (*testConsumerApp) Stop() error  { return nil }

func (testConsumerStor) CaddyModule() ModuleInfo {
	return ModuleInfo{ID: "caddy.storage.replacer_test", New: func() Module { return new(testConsumerStor) }}
}

func (*testConsumerStor) Provision(Context) error {
	testConsumersSeen.Store("storage", NewReplacer().ReplaceAll("{replacertest.value}", ""))
	return nil
}

func (*testConsumerStor) CertMagicStorage() (certmagic.Storage, error) {
	return &certmagic.FileStorage{Path: os.TempDir()}, nil
}

func TestReplacementProviderAppProvisionedFirst(t *testing.T) {
	isolateRegisteredProviders(t)
	registerTestModule.Do(func() {
		RegisterModule(testProviderApp{})
		RegisterModule(testConsumerApp{})
		RegisterModule(testConsumerStor{})
	})

	RegisterReplacementProvider(ReplacementProvider{
		Namespace: "replacertest",
		App:       "replacer_test_provider",
		Func: func(key string) (any, bool) {
			if v := testProviderValue.Load(); v != nil && key == "value" {
				return *v, true
			}
			return nil, false
		},
	})

	// apps are provisioned in map order, which is random;
	// repeat so a wrong order would very likely show up
	for range 20 {
		testProviderValue.Store(nil)
		testConsumersSeen.Clear()

		cfg := &Config{
			StorageRaw: json.RawMessage(`{"module": "replacer_test"}`),
			AppsRaw: ModuleMap{
				"replacer_test_consumer": json.RawMessage(`{}`),
				"replacer_test_provider": json.RawMessage(`{}`),
			},
		}
		ctx, err := ProvisionContext(cfg)
		if err != nil {
			t.Fatalf("provisioning config: %v", err)
		}
		ctx.cfg.cancelFunc(nil)

		for _, consumer := range []string{"storage", "app"} {
			seen, _ := testConsumersSeen.Load(consumer)
			if seen != "provided" {
				t.Fatalf("expected %s to see the provider's value, got '%v'", consumer, seen)
			}
		}
	}
	certmagic.Default.Storage = DefaultStorage
}

func TestReplacementProviderAppNotConfigured(t *testing.T) {
	isolateRegisteredProviders(t)

	RegisterReplacementProvider(ReplacementProvider{
		Namespace: "unconfigured",
		App:       "not_a_registered_app",
		Func:      func(string) (any, bool) { return nil, false },
	})

	// an unconfigured provider app is neither loaded nor an error
	ctx, err := ProvisionContext(&Config{})
	if err != nil {
		t.Fatalf("provisioning config: %v", err)
	}
	ctx.cfg.cancelFunc(nil)
}
