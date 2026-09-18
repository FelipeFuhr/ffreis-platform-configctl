package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger is the structured logging interface used throughout the application.
type Logger interface {
	Info(msg string, fields ...zap.Field)
	Warn(msg string, fields ...zap.Field)
	Error(msg string, fields ...zap.Field)
	Debug(msg string, fields ...zap.Field)
	With(fields ...zap.Field) Logger
}

type zapLogger struct {
	z *zap.Logger
}

// New constructs a Logger at the given level (debug, info, warn, error).
// Defaults to info on unrecognised values.
func New(level string) (Logger, error) {
	var lvl zapcore.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = zapcore.InfoLevel
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.EncoderConfig.TimeKey = "ts"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	z, err := cfg.Build(zap.WithCaller(false))
	if err != nil {
		return nil, err
	}
	return &zapLogger{z: z}, nil
}

func (l *zapLogger) Info(msg string, fields ...zap.Field)  { l.z.Info(msg, fields...) }
func (l *zapLogger) Warn(msg string, fields ...zap.Field)  { l.z.Warn(msg, fields...) }
func (l *zapLogger) Error(msg string, fields ...zap.Field) { l.z.Error(msg, fields...) }
func (l *zapLogger) Debug(msg string, fields ...zap.Field) { l.z.Debug(msg, fields...) }

func (l *zapLogger) With(fields ...zap.Field) Logger {
	return &zapLogger{z: l.z.With(fields...)}
}

// Masked returns a zap.Field whose value is always "***".
// Use this for any field that may contain secret material.
func Masked(key string) zap.Field {
	return zap.String(key, "***")
}
