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
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
)

const (
	celVarRequestMCPToolName = "request.mcp.tool_name"
	celVarRequestPath        = "request.path"
	celVarRequestURLPath     = "request.url_path"
	celVarRequestMethod      = "request.method"
	celVarRequestHost        = "request.host"
	celVarRequestHeaders     = "request.headers"
	celVarRequestTime        = "request.time"
)

var (
	celEnv     *cel.Env
	celEnvErr  error
	celEnvOnce sync.Once

	astCacheMutex sync.RWMutex
	astCache      = make(map[string]*cel.Ast)

	// variableRegex matches any `request.*` identifier chains in a CEL expression.
	variableRegex = regexp.MustCompile(`\brequest\.[a-zA-Z0-9_.]+`)
)

func isValidVariable(match string) bool {
	switch {
	case strings.HasPrefix(match, celVarRequestMCPToolName):
		return true
	case strings.HasPrefix(match, celVarRequestPath):
		return true
	case strings.HasPrefix(match, celVarRequestURLPath):
		return true
	case strings.HasPrefix(match, celVarRequestMethod):
		return true
	case strings.HasPrefix(match, celVarRequestHost):
		return true
	case strings.HasPrefix(match, celVarRequestHeaders):
		return true
	case strings.HasPrefix(match, celVarRequestTime):
		return true
	default:
		return false
	}
}

// GetCelEnv returns the shared CEL environment.
func GetCelEnv() (*cel.Env, error) {
	celEnvOnce.Do(func() {
		// Define request/source loosely to natively support Envoy's selectExpr AST format.
		celEnv, celEnvErr = cel.NewEnv(
			cel.Variable("request", cel.MapType(cel.StringType, cel.AnyType)),
			cel.Variable("metadata", cel.MapType(cel.StringType, cel.AnyType)),
			ext.Strings(),
		)
	})
	return celEnv, celEnvErr
}

// CompileCelExpression validates and compiles a CEL expression after applying macro replacements.
// It uses an internal in-memory cache to avoid duplicate compilation overhead.
func CompileCelExpression(expression string) (*cel.Ast, error) {
	astCacheMutex.RLock()
	if ast, ok := astCache[expression]; ok {
		astCacheMutex.RUnlock()
		return ast, nil
	}
	astCacheMutex.RUnlock()

	// 1. Validate variables in the original expression to ensure they are on the allowlist
	matches := variableRegex.FindAllString(expression, -1)
	for _, match := range matches {
		if !isValidVariable(match) {
			return nil, fmt.Errorf("unsupported CEL variable: %s", match)
		}
	}

	// 2. Translate our custom variables to Envoy-native variables
	translatedExpr := strings.ReplaceAll(expression, celVarRequestMCPToolName, "metadata.filter_metadata['mcp_proxy'].params.name")

	// 3. Compile the translated expression exactly once
	env, err := GetCelEnv()
	if err != nil {
		return nil, err
	}
	ast, issues := env.Compile(translatedExpr)
	if issues != nil && issues.Err() != nil {
		return nil, issues.Err()
	}

	// 4. Cache the result
	astCacheMutex.Lock()
	astCache[expression] = ast
	astCacheMutex.Unlock()

	return ast, nil
}
