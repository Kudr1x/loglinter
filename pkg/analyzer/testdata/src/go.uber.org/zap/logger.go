// Package zap is a stub for testing purposes.
// This is NOT the real go.uber.org/zap package.
// It's used by analysistest framework which requires local copies of dependencies.
package zap

type Logger struct{}

func (l *Logger) Info(msg string, fields ...any)  {}
func (l *Logger) Error(msg string, fields ...any) {}
func (l *Logger) Debug(msg string, fields ...any) {}
func (l *Logger) Warn(msg string, fields ...any)  {}
