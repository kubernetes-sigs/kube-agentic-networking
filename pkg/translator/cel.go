/*
Copyright 2025 The Kubernetes Authors.

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
	"regexp"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
)

var (
	celEnv           *cel.Env
	celEnvErr        error
	celEnvOnce       sync.Once
	mcpToolNameRegex = regexp.MustCompile(`\brequest\.mcp\.tool_name\b`)

	astCacheMutex sync.RWMutex
	astCache      = make(map[string]*cel.Ast)
)

// GetCelEnv returns the shared CEL environment.
func GetCelEnv() (*cel.Env, error) {
	celEnvOnce.Do(func() {
		celEnv, celEnvErr = cel.NewEnv(
			cel.Variable("request", cel.MapType(cel.StringType, cel.AnyType)),
			cel.Variable("metadata", cel.MapType(cel.StringType, cel.AnyType)),
			ext.Strings(),
		)
	})
	return celEnv, celEnvErr
}

// CompileCelExpression compiles a CEL expression after applying macro replacements.
// It uses an internal in-memory cache to avoid duplicate compilation overhead.
func CompileCelExpression(expression string) (*cel.Ast, error) {
	astCacheMutex.RLock()
	if ast, ok := astCache[expression]; ok {
		astCacheMutex.RUnlock()
		return ast, nil
	}
	astCacheMutex.RUnlock()

	env, err := GetCelEnv()
	if err != nil {
		return nil, err
	}
	replaced := mcpToolNameRegex.ReplaceAllString(expression, "metadata.filter_metadata['mcp_proxy'].params.name")
	ast, issues := env.Compile(replaced)
	if issues != nil && issues.Err() != nil {
		return nil, issues.Err()
	}

	astCacheMutex.Lock()
	astCache[expression] = ast
	astCacheMutex.Unlock()

	return ast, nil
}
