// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

#[test]
fn print_struct_sizes() {
    use lexega_syntax::ast::types::*;
    use lexega_syntax::AstExpr;
    use lexega_syntax::AstStmt;
    use std::mem::size_of;

    eprintln!("=== Struct Sizes (bytes) ===");
    eprintln!("AstExpr:            {}", size_of::<AstExpr>());
    eprintln!("AstStmt:            {}", size_of::<AstStmt>());
    eprintln!("AstTableRef:        {}", size_of::<AstTableRef>());
    eprintln!("AstJoin:            {}", size_of::<AstJoin>());
    eprintln!("AstPivotClause:     {}", size_of::<AstPivotClause>());
    eprintln!("AstPivotAggregate:  {}", size_of::<AstPivotAggregate>());
    eprintln!("AstPivotInValues:   {}", size_of::<AstPivotInValues>());
    eprintln!("AstUnpivotClause:   {}", size_of::<AstUnpivotClause>());
    eprintln!("AstSelectItem:      {}", size_of::<AstSelectItem>());
    eprintln!("AstOrderItem:       {}", size_of::<AstOrderItem>());
    eprintln!("ProjectionItem:     {}", size_of::<ProjectionItem>());
    eprintln!("FromItem:           {}", size_of::<FromItem>());
    eprintln!(
        "AstSelect:          {}",
        size_of::<lexega_syntax::AstSelect>()
    );
    eprintln!("AstSampleClause:    {}", size_of::<AstSampleClause>());
    eprintln!("AstChangesClause:   {}", size_of::<AstChangesClause>());
    eprintln!("AstTimeTravel:      {}", size_of::<AstTimeTravel>());
    eprintln!("AstTimeTravelClause:{}", size_of::<AstTimeTravelClause>());
    eprintln!("AstMatchRecognize:  {}", size_of::<AstMatchRecognize>());
    eprintln!("ConditionClause:    {}", size_of::<ConditionClause>());
    eprintln!("AstGroupBy:         {}", size_of::<AstGroupBy>());
    eprintln!("AstOrderBy:         {}", size_of::<AstOrderBy>());
    eprintln!("AstForUpdate:       {}", size_of::<AstForUpdate>());
    eprintln!("AstConnectBy:       {}", size_of::<AstConnectBy>());
    // StmtWithSemicolon not public, skip
}
