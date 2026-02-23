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
	"Info":  true,
	"Error": true,
	"Warn":  true,
	"Debug": true,
	"Fatal": true,
	"Panic": true,
	"Print": true,
}

func run(pass *analysis.Pass) (interface{}, error) {
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

		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return
		}

		msg := strings.Trim(lit.Value, `"`)
		if len(msg) == 0 {
			return
		}

		firstRune, _ := utf8.DecodeRuneInString(msg)

		if unicode.IsLetter(firstRune) && !unicode.IsLower(firstRune) {
			pass.Reportf(lit.Pos(), "log message must start with a lowercase letter")
		}

		for _, r := range msg {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r) {
				pass.Reportf(lit.Pos(), "log message must not contain special characters or emojis (found '%c')", r)
				break
			}
		}
	})

	return nil, nil
}
