package analyzer

import (
	"go/ast"
	"go/token"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

var (
	cfg  Config
	once sync.Once
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

func run(pass *analysis.Pass) (any, error) {
	once.Do(func() {
		cfg = loadConfig()
	})

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

		fnObj := pass.TypesInfo.Uses[sel.Sel]
		if fnObj == nil {
			return
		}

		fnSignature := fnObj.String()
		if !strings.Contains(fnSignature, "slog") && !strings.Contains(fnSignature, "zap") {
			return
		}

		lits := extractBasicLits(call.Args[0])

		for i, lit := range lits {
			rawText := lit.Value
			if len(rawText) < 2 {
				continue
			}
			cleanText := rawText[1 : len(rawText)-1]

			var fixedBuilder strings.Builder
			hasSpecial := false
			isEnglish := true
			hasCapital := false

			for j, r := range cleanText {
				if r > unicode.MaxASCII {
					isEnglish = false
				}

				if i == 0 && j == 0 && unicode.IsLetter(r) && !unicode.IsLower(r) {
					hasCapital = true
					fixedBuilder.WriteRune(unicode.ToLower(r))
					continue
				}

				if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsSpace(r) {
					fixedBuilder.WriteRune(r)
				} else {
					hasSpecial = true
				}
			}

			if !isEnglish {
				pass.Reportf(lit.Pos(), "log message must be in English only")
			}

			var fixes []analysis.SuggestedFix
			if hasCapital || hasSpecial {
				newRawText := `"` + fixedBuilder.String() + `"`
				fixes = []analysis.SuggestedFix{
					{
						Message: "Format log message (lowercase and remove special chars)",
						TextEdits: []analysis.TextEdit{
							{
								Pos:     lit.Pos(),
								End:     lit.End(),
								NewText: []byte(newRawText),
							},
						},
					},
				}
			}

			if hasCapital {
				pass.Report(analysis.Diagnostic{
					Pos:            lit.Pos(),
					Message:        "log message must start with a lowercase letter",
					SuggestedFixes: fixes,
				})
				fixes = nil
			}

			if hasSpecial {
				pass.Report(analysis.Diagnostic{
					Pos:            lit.Pos(),
					Message:        "log message must not contain special characters or emojis",
					SuggestedFixes: fixes,
				})
			}
		}

		stringsToCheck := extractStrings(call.Args[0])
		fullText := strings.Join(stringsToCheck, "")

		hasDynamicData := len(call.Args) > 1
		if !hasDynamicData {
			if _, isBinary := call.Args[0].(*ast.BinaryExpr); isBinary {
				hasDynamicData = true
			}
		}

		if hasDynamicData {
			lowerMsg := strings.ToLower(fullText)
			for _, word := range cfg.SensitiveWords {
				if strings.Contains(lowerMsg, word) {
					pass.Reportf(call.Pos(), "log message contains potentially sensitive data ('%s')", word)
					break
				}
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

func extractBasicLits(expr ast.Expr) []*ast.BasicLit {
	var result []*ast.BasicLit
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			result = append(result, e)
		}
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			result = append(result, extractBasicLits(e.X)...)
			result = append(result, extractBasicLits(e.Y)...)
		}
	}
	return result
}
