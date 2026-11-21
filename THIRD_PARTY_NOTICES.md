# Third-party software in Russian Armor

Russian Armor's native interface and process protection integrate the network
engine and rule data from **Zastava / ai-antiban v2.3.0**:

- Source: https://github.com/kingbest1195/ai-antiban
- Revision: `cda7a4c14ca926a1e6951af62082a4cb89a18ae2`
- Copyright (c) 2026 Zastava Contributors
- License: MIT, reproduced in `NetworkEngine/LICENSE` and included in application bundles.

Adaptations include native authenticated IPC, a windowless lifecycle, explicit
configuration changes, isolated data ownership, native update ownership and a
SwiftUI interface. The upstream React interface is not included in the app.
Third-party Rust dependencies are fixed in `NetworkEngine/src-tauri/Cargo.lock`
and retain their respective package licenses.

## MIT License — network engine and upstream rule data

Copyright (c) 2026 Zastava Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
