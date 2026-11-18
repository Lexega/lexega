// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Source code position range.
///
/// Represents a half-open range `[start, end)` of byte positions in the
/// original source text. Used throughout the AST to maintain source location
/// information for error reporting and code reconstruction.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "SourceSpan"))]
pub struct Span {
    pub start: u32,
    pub end: u32,
}

impl Span {
    /// Whether the two ranges share a byte. A zero-width span overlaps a
    /// range it falls strictly inside.
    pub fn overlaps(self, other: Span) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// SQL and Snowflake Scripting keywords.
///
/// Represents all reserved and non-reserved keywords recognized by the lexer.
/// Keywords are matched case-insensitively during lexing.
///
/// Includes:
/// - Core SQL keywords (SELECT, FROM, WHERE, etc.)
/// - DDL keywords (CREATE, TABLE, VIEW, etc.)
/// - Snowflake Scripting keywords (BEGIN, END, IF, LOOP, etc.)
/// - Window function keywords (OVER, PARTITION, ROWS, RANGE, etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Keyword {
    // Core SQL
    Select,
    From,
    Where,
    Group,
    By,
    Cube,
    Rollup,
    Grouping,
    Sets,
    Having,
    Order,
    Limit,
    Top,
    Exclude,
    Join,
    Inner,
    Left,
    Right,
    Full,
    Outer,
    Cross,
    Asof,
    Directed,
    Lateral,
    Natural,
    On,
    Union,
    All,
    Any,
    Some,
    Distinct,
    Unique,
    Insert,
    Into,
    Values,
    Update,
    Set,
    Delete,
    Merge,
    Truncate,
    As,
    With,
    Qualify,
    Like,
    Ilike,
    Rlike,
    Regexp,
    Escape,
    Table,
    Create,
    Alter,
    Drop,
    Or,
    Replace,
    Rename,
    Secure,
    Temp,
    Temporary,
    Transient,
    Local,
    Global,
    View,
    Procedure,
    Function,
    Returns,
    Language,
    Call,
    Copy,
    Grant,
    Grants,
    Revoke,
    Deny,
    Access,
    Policy,
    Tag,
    To,
    Of,
    Unset,
    Execute,
    Immediate,
    Sql,
    Identifier,
    Cast,
    Between,
    Case,
    Transaction,
    Start,
    Connect,
    Prior,
    Commit,
    Rollback,
    Work,
    Column,
    Constraint,
    Check,
    Trigger,

    // Scripting / control-flow
    Declare,
    Begin,
    Exception,
    Whenever,
    Return,
    For,
    While,
    Repeat,
    Until,
    Loop,
    Break,
    Continue,
    Try,
    Catch,
    Raise,
    Open,
    Close,
    Fetch,
    Cursor,
    Resultset,
    Offset,
    Next,
    Only,
    Await,
    Cancel,
    In,
    Out,
    Inout,
    Input,
    Output,
    Let,
    If,
    Not,
    And,
    Is,
    Then,
    Else,
    Elsif,
    When,
    Do,
    Exit,
    End,

    // Literal-keywords
    True,
    False,
    Null,

    // Built-in temporal functions (treated as keywords)
    CurrentDate,
    CurrentTime,
    CurrentTimestamp,
    CurrentUser,
    Localtime,
    Localtimestamp,

    // Set operations
    Intersect,
    Except,
    Minus,

    // Window / analytic
    Over,
    Partition,
    Rows,
    Range,
    Unbounded,
    Preceding,
    Following,
    Current,
    Row,

    // Pattern matching (MATCH_RECOGNIZE)
    MatchRecognize,
    Measures,
    One,
    Per,
    After,
    Skip,
    Past,
    Pattern,
    Define,
    Default,
    Omit,
    Empty,
    Matches,
    Unmatched,
    Running,
    Final,

    // Null handling
    Nulls,
    First,
    Last,

    // Date/Time
    Interval,

    // Procedure attributes / options
    Volatile,
    Immutable,
    Comment,
    Body,
    Owner,
    Caller,
    Restricted,
    Using,
    Exists,
    Show,
    Describe,
    Use,
    Stage,
    Url,
    Storage,
    StorageIntegration,
    Integration,
    Credentials,
    Encryption,
    Directory,
    Enable,
    Auto,
    Refresh,
    Notification,
    Format,
    File,
    FileFormat,
    Type,
    Compression,
    Master,
    Key,
    Kms,
    Id,
    Endpoint,

    // Table constraints
    Primary,
    Foreign,
    References,

    // Table clustering
    Cluster,

    // PostgreSQL-specific keywords
    Returning,
    Tablesample,
    System,
    Bernoulli,
    Repeatable,
    Concurrently,
    Conflict,
    Nothing,
    Vacuum,
    Analyze,
    Analyse, // British spelling
    Explain,
    Listen,
    Notify,
    Unlisten,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operator {
    // Arithmetic / concat
    Plus,
    Minus,
    Star,
    /// Spread (expansion) operator: **
    StarStar,
    Slash,
    Percent,
    PipePipe,
    /// Flow pipe operator: ->>
    Pipe,

    // Comparison
    Eq,
    EqEq,
    NotEq,
    AngleNotEq,
    Lt,
    Le,
    Gt,
    Ge,

    // Assignment / mapping
    ColonEq,
    EqGt,

    // Arrow operator for policies
    RightArrow,

    // Cast / namespace
    ColonColon,

    // Bitwise and dialect-specific operators
    /// Bitwise XOR: ^ (exponentiation where the dialect reads it so: `Power`)
    Caret,
    /// Exponentiation: ^ where the dialect reads it so (PostgreSQL)
    Power,
    /// Bitwise AND: &
    Amp,
    /// Compound bitwise AND assignment: &= (T-SQL)
    AmpEq,
    /// Bitwise OR: |
    Bar,
    /// Bitwise XOR: #
    Hash,
    /// JSON path extraction (object): #>
    HashGt,
    /// JSON path extraction (text): #>>
    HashGtGt,
    /// Bitwise NOT as a prefix, regex match as an infix operator: ~
    Tilde,
    /// Bitwise left shift: <<
    LtLt,
    /// Bitwise right shift: >>
    GtGt,
    /// Array contains: @>
    AtGt,
    /// Array contained by: <@
    LtAt,
    /// Array overlap: &&
    AmpAmp,
    /// Logical AND: && (MySQL)
    AmpAmpAnd,
    /// JSON extract path (text): ->>
    MinusGtGt,
    /// JSON extract path (object): ->
    MinusGt,
    /// JSON contains: @?
    AtQuestion,
    /// JSON exists: ??
    QuestionQuestion,
    /// JSON contains left: @
    At,
    /// Regex match case-sensitive: ~
    RegexMatch,
    /// Regex match case-insensitive: ~*
    RegexMatchI,
    /// Regex not match case-sensitive: !~
    RegexNotMatch,
    /// Regex not match case-insensitive: !~*
    RegexNotMatchI,
    /// Geometric distance operator: <->
    LtMinusGt,
    /// Null-safe equality: <=> (MySQL / Spark)
    LtEqGt,
    /// SQL pipe operator: |>
    PipeGt,
    /// Compound bitwise OR assignment: |= (T-SQL)
    PipeEq,
    /// Text-search or JSON path match: @@ (PostgreSQL)
    AtAt,
    /// Starts with: ^@ (PostgreSQL)
    CaretAt,
    /// Square root, as a prefix: |/ (PostgreSQL)
    BarSlash,
    /// Any of the keys exists: ?| (PostgreSQL)
    QuestionBar,
    /// All of the keys exist: ?& (PostgreSQL)
    QuestionAmp,
    /// Logical NOT as a prefix: ! (MySQL)
    Bang,
    /// Not less than: !< (T-SQL)
    BangLt,
    /// Not greater than: !> (T-SQL)
    BangGt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Punctuation {
    LParen,
    RParen,
    LBracket,
    RBracket,
    LCurly,
    RCurly,
    Comma,
    Semi,
    Dot,
    Colon,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiteralKind {
    String,
    /// A string fragment that ends before a Jinja delimiter (e.g., `'prefix` before `{{ expr }}`).
    /// Used when Jinja expressions are embedded inside SQL string literals.
    StringFragment,
    Number,
    /// `$<n>` where the dialect reads it as a column by position.
    Position,
    /// `$<n>` where the dialect reads it as a bind parameter.
    Parameter,
    /// `$<n>` or `$<n>.<m>` where the dialect reads it as a money literal.
    Money,
    Boolean,
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentifierKind {
    Unquoted,
    Quoted,
    /// T-SQL @variable or @@system_variable (e.g., @name, @@ROWCOUNT)
    AtVariable,
    /// T-SQL #temp_table or ##global_temp_table (e.g., #users, ##cache)
    TempTable,
    /// A dollar-quote delimiter: the `$$` or `$tag$` that opens or closes a
    /// dollar-quoted string, where the dialect's lexer reads them
    /// (PostgreSQL, Redshift), or the `$$` that opens or closes a string the
    /// dialect writes as words (Snowflake). The string's content between a
    /// pair is lexed as tokens.
    DollarQuoteDelimiter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    Keyword(Keyword),
    Identifier {
        kind: IdentifierKind,
        /// The operator the lexer's dialect also writes with this word
        /// (MySQL `a MOD b`). The token is a name wherever a name is read;
        /// only the expression parser, where it looks for an operator,
        /// reads this.
        word_operator: Option<crate::dialect::WordOperator>,
    },
    Literal(LiteralKind),
    Operator(Operator),
    Punctuation(Punctuation),
    LineComment,
    BlockComment,
    /// Jinja comment: {# ... #}
    JinjaComment,

    // Jinja delimiter tokens
    /// Jinja expression opening: {{
    JinjaExprOpen,
    /// Jinja expression closing: }}
    JinjaExprClose,
    /// Jinja statement opening: {%
    JinjaStmtOpen,
    /// Jinja statement closing: %}
    JinjaStmtClose,

    // Jinja-specific tokens (used when tokenizing inside Jinja delimiters)
    /// Jinja filter pipe: |
    JinjaPipe,
    /// Jinja tilde (string concat): ~
    JinjaTilde,
    /// Jinja double-star (power): **
    JinjaDoubleStar,
    /// Jinja double-slash (floor division): //
    JinjaDoubleSlash,
    /// Jinja double-equals (equality comparison): ==
    JinjaDoubleEq,
    /// Jinja `and` keyword (lowercase)
    JinjaAnd,
    /// Jinja `or` keyword (lowercase)
    JinjaOr,
    /// Jinja `not` keyword (lowercase)
    JinjaNot,
    /// Jinja `in` keyword (lowercase)
    JinjaIn,
    /// Jinja `is` keyword (lowercase)
    JinjaIs,
    /// Jinja `true` literal (lowercase)
    JinjaTrue,
    /// Jinja `false` literal (lowercase)
    JinjaFalse,
    /// Jinja `null` literal (lowercase)
    JinjaNull,

    // Jinja statement keywords (used in {% %} blocks)
    /// Jinja `if` keyword
    JinjaIf,
    /// Jinja `elif` keyword
    JinjaElif,
    /// Jinja `else` keyword
    JinjaElse,
    /// Jinja `endif` keyword
    JinjaEndIf,
    /// Jinja `for` keyword
    JinjaFor,
    /// Jinja `endfor` keyword
    JinjaEndFor,
    /// Jinja `set` keyword
    JinjaSet,
    /// Jinja `endset` keyword
    JinjaEndSet,
    /// Jinja `docs` keyword (dbt)
    JinjaDocs,
    /// Jinja `enddocs` keyword (dbt)
    JinjaEndDocs,
    /// Jinja `filter`, written as a `{% %}` tag's first word
    JinjaFilter,
    /// Jinja `endfilter`, written as a `{% %}` tag's first word
    JinjaEndFilter,
    /// Jinja `call`, written as a `{% %}` tag's first word
    JinjaCall,
    /// Jinja `endcall`, written as a `{% %}` tag's first word
    JinjaEndCall,

    /// Placeholder for bind parameters: ?
    Placeholder,
    Eof,
    Unknown,
}

impl TokenKind {
    /// Returns true if this token can be used as an identifier AFTER a dot.
    /// After a dot (e.g., `schema.ORDER`), Snowflake allows ANY keyword to be
    /// used as an identifier since the context makes it unambiguous.
    /// This is more permissive than `can_be_identifier()`.
    pub fn can_be_identifier_after_dot(&self) -> bool {
        match self {
            TokenKind::Identifier { .. } => true,
            TokenKind::Keyword(_) => true, // ALL keywords allowed after dot
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TriviaKind {
    Whitespace,
    Newline,
    LineComment,
    BlockComment,
    /// Jinja comment: {# ... #}
    JinjaComment,
    /// A marker of a MySQL executable comment: the opening `/*!`,
    /// `/*!50100` or MariaDB `/*M!…`, or its closing `*/`. The text between
    /// the markers is lexed as SQL, as the server runs it.
    MysqlVersionComment,
    /// A psql command that sends the query written before it, to the end
    /// of its line. The `;` of no width after it ends the statement.
    PsqlMetaCommand(PsqlMetaCommand),
    /// The client's `DELIMITER x` command, to the end of its line: `x`
    /// ends each statement until the next one, lexed as a `;` of its width.
    ClientDelimiter,
    /// The rows a `COPY … FROM STDIN` (or psql's `\copy … from stdin`)
    /// reads, written after it: from the line after its terminator to the
    /// end of the line `\.` that ends them, or of the source. Trailing
    /// trivia of the `;` that ends the statement; no token is read in it.
    CopyData,
}

/// A psql command that sends the query written before it
/// ([`TriviaKind::PsqlMetaCommand`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PsqlMetaCommand {
    /// `\g [arguments]`: runs the query, as `;` does.
    Go,
    /// `\gexec`: runs the query, then each value of each row it returns as
    /// a statement.
    Gexec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trivia {
    pub kind: TriviaKind,
    pub span: Span,
}

/// A token in the source code.
///
/// Tokens store only their span (position in source), not the text itself.
/// To get the text, use `token.lexeme(source)` with the original source string.
/// This design enables zero-copy parsing - tokens are coordinates, not copies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
    pub leading_trivia: Vec<Trivia>,
    pub trailing_trivia: Vec<Trivia>,
}

impl Token {
    /// Get the text of this token from the source string.
    #[inline]
    pub fn lexeme<'a>(&self, source: &'a str) -> &'a str {
        &source[self.span.start as usize..self.span.end as usize]
    }
}
