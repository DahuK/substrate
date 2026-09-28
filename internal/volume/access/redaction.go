// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package access

import "fmt"

// Value receivers protect both pointer and value formatting, including %#v.
// Explicit Secrets access and arbitrary debugger inspection are not redacted.
func (Credential) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("access.Credential[redacted]")) }
func (Lease) Format(s fmt.State, _ rune)      { _, _ = s.Write([]byte("access.Lease[redacted]")) }
func (Broker) Format(s fmt.State, _ rune)     { _, _ = s.Write([]byte("access.Broker[redacted]")) }

func (Credential) MarshalJSON() ([]byte, error) {
	return []byte(`"access.Credential[redacted]"`), nil
}

func (Lease) MarshalJSON() ([]byte, error) {
	return []byte(`"access.Lease[redacted]"`), nil
}
