package analyzer

import (
	"go/ast"
	"go/token"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

var Analyzer = &analysis.Analyzer{
	Name:     "loglinter",
	Doc:      "checks log messages for specific formatting and security rules",
	Run:      run,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
}

var logMethods = map[string]bool{
	"Info": true, "Error": true, "Warn": true,
	"Debug": true, "Fatal": true, "Panic": true,
	"Print": true,
}

var sensitiveWords = []string{
	"password", "token", "secret", "api_key", "apikey", "credential",
}

func run(pass *analysis.Pass) (any, error) {
	inspect := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	nodeFilter := []ast.Node{
		(*ast.CallExpr)(nil),
	}

	inspect.Preorder(nodeFilter, func(node ast.Node) {
		call := node.(*ast.CallExpr)

		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !logMethods[sel.Sel.Name] || len(call.Args) == 0 {
			return
		}

		t := pass.TypesInfo.TypeOf(sel.X)
		if t == nil {
			return
		}
		typeName := t.String()

		if !strings.Contains(typeName, "slog") && !strings.Contains(typeName, "zap") {
			return
		}

		stringsToCheck := extractStrings(call.Args[0])
		if len(stringsToCheck) == 0 {
			return
		}

		fullText := strings.Join(stringsToCheck, "")

		for _, msg := range stringsToCheck {
			if len(msg) > 0 {
				firstRune, _ := utf8.DecodeRuneInString(msg)
				if unicode.IsLetter(firstRune) && !unicode.IsLower(firstRune) {
					pass.Reportf(call.Pos(), "log message must start with a lowercase letter")
				}
				break
			}
		}

		isEnglish := true

		for _, msg := range stringsToCheck {
			for _, r := range msg {
				if r > unicode.MaxASCII {
					isEnglish = false
				}

				if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r) {
					pass.Reportf(call.Pos(), "log message must not contain special characters or emojis (found '%c')", r)
					break
				}
			}
		}

		if !isEnglish {
			pass.Reportf(call.Pos(), "log message must be in English only")
		}

		lowerMsg := strings.ToLower(fullText)
		for _, word := range sensitiveWords {
			if strings.Contains(lowerMsg, word) {
				pass.Reportf(call.Pos(), "log message contains potentially sensitive data ('%s')", word)
				break
			}
		}
	})

	return nil, nil
}

func extractStrings(expr ast.Expr) []string {
	var result []string

	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			result = append(result, strings.Trim(e.Value, `"`))
		}
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			result = append(result, extractStrings(e.X)...)
			result = append(result, extractStrings(e.Y)...)
		}
	}

	return result
}
