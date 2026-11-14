// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The shapes the procedure `CALL` names are written in, each read whole as the name it is.

mod name_shapes;

use lexega_syntax::dialect;
use name_shapes::reads_whole;

#[test]
fn bigquery_call_procedure_name() {
    reads_whole(
        &dialect::bigquery(),
        &[
            "CALL «my-proj.s1.p_load»();",
            "CALL «my-proj.stage.p_load»();",
            "CALL «proj1.stage.p_load»();",
        ],
    );
}

#[test]
fn mysql_call_procedure_name() {
    reads_whole(&dialect::mysql(), &["CALL «stage.p_load»();"]);
}

#[test]
fn postgres_call_procedure_name() {
    reads_whole(&dialect::postgres(), &["CALL «d1.stage.p_load»();"]);
}

#[test]
fn snowflake_call_procedure_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "CALL «d1.stage.p_load»();",
            "CALL «IDENTIFIER('d1.s1.p_load')»();",
        ],
    );
}
