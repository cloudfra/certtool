// Copyright 2022 Jeremy Edwards
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

// Package logging configures the process-wide slog logger. The application
// logs through log/slog only; zap is the backend and is confined to this
// package, so replacing it later means changing this file alone.
package logging

import (
	"log/slog"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
	"go.uber.org/zap/zapcore"
)

// Init installs a slog default logger that writes human-readable output to
// stderr through zap, and returns it.
func Init() *slog.Logger {
	logger := New(newCore(zapcore.Lock(os.Stderr)))
	slog.SetDefault(logger)
	return logger
}

// New returns a slog logger that forwards records to the given zap core.
func New(core zapcore.Core) *slog.Logger {
	return slog.New(zapslog.NewHandler(core))
}

// newCore builds a console-encoded, info-level zap core that writes to out.
func newCore(out zapcore.WriteSyncer) zapcore.Core {
	cfg := zap.NewProductionEncoderConfig()
	cfg.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.EncodeLevel = zapcore.CapitalLevelEncoder
	cfg.StacktraceKey = zapcore.OmitKey // stack traces are noise for CLI errors
	return zapcore.NewCore(zapcore.NewConsoleEncoder(cfg), out, zapcore.InfoLevel)
}
