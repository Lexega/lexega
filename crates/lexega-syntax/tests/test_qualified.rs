// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::{parse_select_from_tokens, tokenize};
fn main() {
    let src = "SELECT t1.id FROM t1";
    let tokens = tokenize(src).tokens;
    let select = parse_select_from_tokens(src, &tokens).expect("parse");
    println!("{:#?}", select.projection);
}
