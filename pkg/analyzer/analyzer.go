package analyzer

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

var (
	cfg              Config
	compiledPatterns []*regexp.Regexp
	once             sync.Once
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
		for _, p := range cfg.Patterns {
			if re, err := regexp.Compile(p); err == nil {
				compiledPatterns = append(compiledPatterns, re)
			}
		}
	})

	inspect := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	nodeFilter := []ast.Node{(*ast.CallExpr)(nil)}

	inspect.Preorder(nodeFilter, func(node ast.Node) {
		call := node.(*ast.CallExpr)
		if !isLoggerCall(pass, call) {
			return
		}

		checkFormattingRules(pass, call)
		checkSecurityRules(pass, call)
	})

	return nil, nil
}

func isLoggerCall(pass *analysis.Pass, call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !logMethods[sel.Sel.Name] || len(call.Args) == 0 {
		return false
	}

	fnObj := pass.TypesInfo.Uses[sel.Sel]
	if fnObj == nil {
		return false
	}

	pkg := fnObj.Pkg()
	if pkg == nil {
		return false
	}

	pkgPath := pkg.Path()
	return pkgPath == "log/slog" || pkgPath == "go.uber.org/zap"
}

func checkFormattingRules(pass *analysis.Pass, call *ast.CallExpr) {
	lits := extractBasicLits(call.Args[0])
	for i, lit := range lits {
		rawText := lit.Value
		if len(rawText) < 2 {
			continue
		}
		cleanText := rawText[1 : len(rawText)-1]

		var fixedBuilder strings.Builder
		hasSpecial, isEnglish, hasCapital := false, true, false

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

		reportFormattingIssues(pass, lit, hasCapital, hasSpecial, fixedBuilder.String())
	}
}

func reportFormattingIssues(pass *analysis.Pass, lit *ast.BasicLit, hasCapital, hasSpecial bool, fixedText string) {
	var fixes []analysis.SuggestedFix
	if hasCapital || hasSpecial {
		fixes = []analysis.SuggestedFix{{
			Message: "Format log message (lowercase and remove special chars)",
			TextEdits: []analysis.TextEdit{{
				Pos:     lit.Pos(),
				End:     lit.End(),
				NewText: []byte(`"` + fixedText + `"`),
			}},
		}}
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

func checkSecurityRules(pass *analysis.Pass, call *ast.CallExpr) {
	terms := extractAllTerms(call.Args[0])
	fullText := strings.Join(terms, " ")

	hasDynamicData := len(call.Args) > 1
	if !hasDynamicData {
		if _, isBinary := call.Args[0].(*ast.BinaryExpr); isBinary {
			hasDynamicData = true
		}
	}

	lowerMsg := strings.ToLower(fullText)

	if hasDynamicData {
		for _, word := range cfg.SensitiveWords {
			if strings.Contains(lowerMsg, word) {
				pass.Reportf(call.Pos(), "log message contains potentially sensitive data ('%s')", word)
				return
			}
		}
	}

	for _, re := range compiledPatterns {
		if re.MatchString(fullText) {
			pass.Reportf(call.Pos(), "log message matches sensitive data pattern: %s", re.String())
			return
		}
	}
}

func extractAllTerms(expr ast.Expr) []string {
	var result []string
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			result = append(result, strings.Trim(e.Value, `"`))
		}
	case *ast.Ident:
		result = append(result, e.Name)
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			result = append(result, extractAllTerms(e.X)...)
			result = append(result, extractAllTerms(e.Y)...)
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
