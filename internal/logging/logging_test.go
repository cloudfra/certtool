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

package logging

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestNewRoutesSlogRecordsToZapCore(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	logger := New(core)

	logger.Info("generated certificate", "cn", "example.com", "count", 2)
	logger.Warn("careful")
	logger.Error("failed", "error", errors.New("boom"))
	logger.Debug("dropped below the info level")

	entries := logs.All()
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3: %v", len(entries), entries)
	}

	first := entries[0]
	if first.Level != zapcore.InfoLevel || first.Message != "generated certificate" {
		t.Errorf("first entry = %v %q, want info %q", first.Level, first.Message, "generated certificate")
	}
	fields := first.ContextMap()
	if fields["cn"] != "example.com" || fields["count"] != int64(2) {
		t.Errorf("first entry fields = %v, want cn=example.com count=2", fields)
	}

	if entries[1].Level != zapcore.WarnLevel {
		t.Errorf("second entry level = %v, want warn", entries[1].Level)
	}
	if entries[2].Level != zapcore.ErrorLevel || entries[2].ContextMap()["error"] != "boom" {
		t.Errorf("third entry = %v %v, want error with error=boom", entries[2].Level, entries[2].ContextMap())
	}
}

func TestNewCoreWritesConsoleOutput(t *testing.T) {
	var buf bytes.Buffer
	logger := New(newCore(zapcore.AddSync(&buf)))

	logger.Info("generated certificate", "cn", "example.com")
	logger.Debug("should not appear")
	logger.Error("failed", "error", errors.New("boom"))

	out := buf.String()
	if !strings.Contains(out, "INFO") || !strings.Contains(out, "generated certificate") || !strings.Contains(out, "example.com") {
		t.Errorf("output = %q, want INFO line with message and cn attr", out)
	}
	if strings.Contains(out, "runtime.main") {
		t.Errorf("output = %q, error records should not include stack traces", out)
	}
	if strings.Contains(out, "should not appear") {
		t.Errorf("output = %q, debug record should be filtered", out)
	}
}

func TestInitSetsDefaultLogger(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	if got := Init(); got != slog.Default() {
		t.Error("Init() should install the returned logger as the slog default")
	}
}
