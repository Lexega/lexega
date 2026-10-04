// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! `lexega` — format, analyze and review SQL before it runs.

fn main() {
    lexega_cli::run(
        std::env::args().collect(),
        &lexega_cli::recognition::Recognition,
    );
}
