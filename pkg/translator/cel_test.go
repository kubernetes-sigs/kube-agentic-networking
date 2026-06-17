/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package translator

import (
	"strings"
	"sync"
	"testing"
)

func TestGetCelEnv(t *testing.T) {
	env, err := GetCelEnv()
	if err != nil {
		t.Fatalf("GetCelEnv() returned error: %v", err)
	}
	if env == nil {
		t.Fatal("GetCelEnv() returned nil environment")
	}

	// Check if it returns the exact same instance on second call
	env2, err := GetCelEnv()
	if err != nil {
		t.Fatalf("GetCelEnv() second call returned error: %v", err)
	}
	if env != env2 {
		t.Error("GetCelEnv() did not return the same singleton instance")
	}
}

func TestCompileCelExpression(t *testing.T) {
	tests := []struct {
		name        string
		expression  string
		wantErr     bool
		errContains string
	}{
		{
			name:       "valid standard expression",
			expression: "request.path.startsWith('/verify_')",
			wantErr:    false,
		},
		{
			name:       "valid macro replacement",
			expression: "request.mcp.tool_name.startsWith('verify_')",
			wantErr:    false,
		},
		{
			name:       "valid complex expression with multiple macros and logical operators",
			expression: "request.mcp.tool_name == 'fetch_data' || request.path.startsWith('/read_')",
			wantErr:    false,
		},
		{
			name:        "invalid syntax error",
			expression:  "request.mcp.tool_name.startsWith(",
			wantErr:     true,
			errContains: "Syntax error",
		},
		{
			name:        "unsupported variable error",
			expression:  "request.unrecognized == 'bar'",
			wantErr:     true,
			errContains: "unsupported CEL variable: request.unrecognized",
		},
		{
			name:        "unsupported source variable error",
			expression:  "source.unknown == 'foo'",
			wantErr:     true,
			errContains: "undeclared reference",
		},
		{
			name:        "undeclared variable error",
			expression:  "unknown_variable.foo == 'bar'",
			wantErr:     true,
			errContains: "undeclared reference",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := CompileCelExpression(tt.expression)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CompileCelExpression() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && ast == nil {
				t.Error("CompileCelExpression() returned nil ast for valid expression")
			}
			if tt.wantErr && err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("CompileCelExpression() error %q does not contain expected substring %q", err.Error(), tt.errContains)
				}
			}
		})
	}
}

func TestCompileCelExpressionCachingAndConcurrency(t *testing.T) {
	expression := "request.mcp.tool_name.startsWith('safe_')"

	// Compile first time
	ast1, err := CompileCelExpression(expression)
	if err != nil {
		t.Fatalf("First compilation failed: %v", err)
	}

	// Compile second time - should be cached
	ast2, err := CompileCelExpression(expression)
	if err != nil {
		t.Fatalf("Second compilation failed: %v", err)
	}

	// In Go, pointers to the exact same underlying structure should be identical if we cache the *cel.Ast pointer
	if ast1 != ast2 {
		t.Error("CompileCelExpression() did not return cached AST pointer on duplicate call")
	}

	// Concurrency test to check for races
	var wg sync.WaitGroup
	concurrency := 10
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			_, err := CompileCelExpression(expression)
			if err != nil {
				t.Errorf("Concurrent compilation failed: %v", err)
			}
		}()
	}
	wg.Wait()
}
