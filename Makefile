# Copyright 2026 Cloudfra
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

REGISTRY = ghcr.io/cloudfra
PROTOS =
TEST_ASSETS =
ASSETS = $(PROTOS)
GO_PACKAGE = github.com/cloudfra/certtool
ALL_APPS = certtool

# Build only the platforms certtool is released for. Makefile_build.mk uses
# these instead of its defaults, which cover every Go platform.
LINUX_PLATFORMS = linux/amd64 linux/arm64
WINDOWS_PLATFORMS = windows/amd64 windows/arm64
DARWIN_PLATFORMS = darwin/arm64
ANDROID_PLATFORMS =
IOS_PLATFORMS =
DRAGONFLY_PLATFORMS =
FREEBSD_PLATFORMS =
NETBSD_PLATFORMS =
OPENBSD_PLATFORMS =
PLAN9_PLATFORMS =
SOLARIS_PLATFORMS =
JS_PLATFORMS =
WASIP1_PLATFORMS =
ILLUMOS_PLATFORMS =
AIX_PLATFORMS =

include Makefile_build.mk
