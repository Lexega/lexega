// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use phf::phf_map;

use crate::dialect::{
    CaretOperator, Dialect, DollarNumber, DoubleAmpersand, NumberLiteralGrammar, RadixPrefix,
    SnowflakeDialect,
};
use crate::error::ExpectInvariant;
use crate::lexer::token::{
    IdentifierKind, Keyword, LiteralKind, Operator, Punctuation, Span, Token, TokenKind, Trivia,
    TriviaKind,
};

/// Compile-time perfect hash map for SQL keyword lookup.
/// Keys are UPPERCASE for case-insensitive matching.
static KEYWORDS: phf::Map<&'static str, Keyword> = phf_map! {
    "SELECT" => Keyword::Select,
    "FROM" => Keyword::From,
    "WHERE" => Keyword::Where,
    "GROUP" => Keyword::Group,
    "BY" => Keyword::By,
    "CUBE" => Keyword::Cube,
    "ROLLUP" => Keyword::Rollup,
    "GROUPING" => Keyword::Grouping,
    "SETS" => Keyword::Sets,
    "HAVING" => Keyword::Having,
    "ORDER" => Keyword::Order,
    "LIMIT" => Keyword::Limit,
    "OFFSET" => Keyword::Offset,
    "TOP" => Keyword::Top,
    "EXCLUDE" => Keyword::Exclude,
    "JOIN" => Keyword::Join,
    "INNER" => Keyword::Inner,
    "LEFT" => Keyword::Left,
    "RIGHT" => Keyword::Right,
    "FULL" => Keyword::Full,
    "OUTER" => Keyword::Outer,
    "CROSS" => Keyword::Cross,
    "ASOF" => Keyword::Asof,
    "DIRECTED" => Keyword::Directed,
    "LATERAL" => Keyword::Lateral,
    "NATURAL" => Keyword::Natural,
    "ON" => Keyword::On,
    "UNION" => Keyword::Union,
    "ALL" => Keyword::All,
    "ANY" => Keyword::Any,
    "SOME" => Keyword::Some,
    "DISTINCT" => Keyword::Distinct,
    "UNIQUE" => Keyword::Unique,
    "INSERT" => Keyword::Insert,
    "INTO" => Keyword::Into,
    "VALUES" => Keyword::Values,
    "UPDATE" => Keyword::Update,
    "SET" => Keyword::Set,
    "DELETE" => Keyword::Delete,
    "MERGE" => Keyword::Merge,
    "TRUNCATE" => Keyword::Truncate,
    "AS" => Keyword::As,
    "WITH" => Keyword::With,
    "QUALIFY" => Keyword::Qualify,
    "LIKE" => Keyword::Like,
    "ILIKE" => Keyword::Ilike,
    "RLIKE" => Keyword::Rlike,
    "REGEXP" => Keyword::Regexp,
    "ESCAPE" => Keyword::Escape,
    "TABLE" => Keyword::Table,
    "CREATE" => Keyword::Create,
    "ALTER" => Keyword::Alter,
    "DROP" => Keyword::Drop,
    "OR" => Keyword::Or,
    "REPLACE" => Keyword::Replace,
    "RENAME" => Keyword::Rename,
    "SECURE" => Keyword::Secure,
    "TEMP" => Keyword::Temp,
    "TEMPORARY" => Keyword::Temporary,
    "TRANSIENT" => Keyword::Transient,
    "LOCAL" => Keyword::Local,
    "GLOBAL" => Keyword::Global,
    "VIEW" => Keyword::View,
    "PROCEDURE" => Keyword::Procedure,
    "FUNCTION" => Keyword::Function,
    "RETURNS" => Keyword::Returns,
    "LANGUAGE" => Keyword::Language,
    "CALL" => Keyword::Call,
    "COPY" => Keyword::Copy,
    "GRANT" => Keyword::Grant,
    "GRANTS" => Keyword::Grants,
    "REVOKE" => Keyword::Revoke,
    "DENY" => Keyword::Deny,
    "ACCESS" => Keyword::Access,
    "POLICY" => Keyword::Policy,
    "TAG" => Keyword::Tag,
    "TO" => Keyword::To,
    "OF" => Keyword::Of,
    "UNSET" => Keyword::Unset,
    "EXECUTE" => Keyword::Execute,
    "IMMEDIATE" => Keyword::Immediate,
    "SQL" => Keyword::Sql,
    "CAST" => Keyword::Cast,
    "BETWEEN" => Keyword::Between,
    "CASE" => Keyword::Case,
    "TRANSACTION" => Keyword::Transaction,
    "START" => Keyword::Start,
    "CONNECT" => Keyword::Connect,
    "PRIOR" => Keyword::Prior,
    "COMMIT" => Keyword::Commit,
    "ROLLBACK" => Keyword::Rollback,
    "WORK" => Keyword::Work,
    "COLUMN" => Keyword::Column,
    "CONSTRAINT" => Keyword::Constraint,
    "CHECK" => Keyword::Check,
    "TRIGGER" => Keyword::Trigger,
    "DECLARE" => Keyword::Declare,
    "BEGIN" => Keyword::Begin,
    "EXCEPTION" => Keyword::Exception,
    "WHENEVER" => Keyword::Whenever,
    "RETURN" => Keyword::Return,
    "RETURNING" => Keyword::Returning,
    "FOR" => Keyword::For,
    "WHILE" => Keyword::While,
    "REPEAT" => Keyword::Repeat,
    "UNTIL" => Keyword::Until,
    "LOOP" => Keyword::Loop,
    "BREAK" => Keyword::Break,
    "CONTINUE" => Keyword::Continue,
    "TRY" => Keyword::Try,
    "CATCH" => Keyword::Catch,
    "RAISE" => Keyword::Raise,
    "OPEN" => Keyword::Open,
    "CLOSE" => Keyword::Close,
    "FETCH" => Keyword::Fetch,
    "CURSOR" => Keyword::Cursor,
    "RESULTSET" => Keyword::Resultset,
    "NEXT" => Keyword::Next,
    "ONLY" => Keyword::Only,
    "AWAIT" => Keyword::Await,
    "CANCEL" => Keyword::Cancel,
    "IN" => Keyword::In,
    "OUT" => Keyword::Out,
    "INOUT" => Keyword::Inout,
    "INPUT" => Keyword::Input,
    "OUTPUT" => Keyword::Output,
    "LET" => Keyword::Let,
    "IF" => Keyword::If,
    "NOT" => Keyword::Not,
    "AND" => Keyword::And,
    "IS" => Keyword::Is,
    "THEN" => Keyword::Then,
    "ELSE" => Keyword::Else,
    "ELSEIF" => Keyword::Elsif,
    "ELSIF" => Keyword::Elsif,
    "WHEN" => Keyword::When,
    "DO" => Keyword::Do,
    "EXIT" => Keyword::Exit,
    "END" => Keyword::End,
    "TRUE" => Keyword::True,
    "FALSE" => Keyword::False,
    "NULL" => Keyword::Null,
    "CURRENT_DATE" => Keyword::CurrentDate,
    "CURRENT_TIME" => Keyword::CurrentTime,
    "CURRENT_TIMESTAMP" => Keyword::CurrentTimestamp,
    "CURRENT_USER" => Keyword::CurrentUser,
    "LOCALTIME" => Keyword::Localtime,
    "LOCALTIMESTAMP" => Keyword::Localtimestamp,
    "INTERSECT" => Keyword::Intersect,
    "EXCEPT" => Keyword::Except,
    "MINUS" => Keyword::Minus,
    "OVER" => Keyword::Over,
    "PARTITION" => Keyword::Partition,
    "ROWS" => Keyword::Rows,
    "RANGE" => Keyword::Range,
    "UNBOUNDED" => Keyword::Unbounded,
    "PRECEDING" => Keyword::Preceding,
    "FOLLOWING" => Keyword::Following,
    "CURRENT" => Keyword::Current,
    "ROW" => Keyword::Row,
    "MATCH_RECOGNIZE" => Keyword::MatchRecognize,
    "MEASURES" => Keyword::Measures,
    "ONE" => Keyword::One,
    "PER" => Keyword::Per,
    "AFTER" => Keyword::After,
    "SKIP" => Keyword::Skip,
    "PAST" => Keyword::Past,
    "PATTERN" => Keyword::Pattern,
    "DEFINE" => Keyword::Define,
    "DEFAULT" => Keyword::Default,
    "OMIT" => Keyword::Omit,
    "EMPTY" => Keyword::Empty,
    "MATCHES" => Keyword::Matches,
    "UNMATCHED" => Keyword::Unmatched,
    "RUNNING" => Keyword::Running,
    "FINAL" => Keyword::Final,
    "NULLS" => Keyword::Nulls,
    "FIRST" => Keyword::First,
    "LAST" => Keyword::Last,
    "INTERVAL" => Keyword::Interval,
    "VOLATILE" => Keyword::Volatile,
    "IMMUTABLE" => Keyword::Immutable,
    "COMMENT" => Keyword::Comment,
    "BODY" => Keyword::Body,
    "OWNER" => Keyword::Owner,
    "CALLER" => Keyword::Caller,
    "RESTRICTED" => Keyword::Restricted,
    "USING" => Keyword::Using,
    "EXISTS" => Keyword::Exists,
    "SHOW" => Keyword::Show,
    "DESCRIBE" => Keyword::Describe,
    "USE" => Keyword::Use,
    "STAGE" => Keyword::Stage,
    "URL" => Keyword::Url,
    "STORAGE_INTEGRATION" => Keyword::StorageIntegration,
    "STORAGE" => Keyword::Storage,
    "INTEGRATION" => Keyword::Integration,
    "CREDENTIALS" => Keyword::Credentials,
    "ENCRYPTION" => Keyword::Encryption,
    "DIRECTORY" => Keyword::Directory,
    "ENABLE" => Keyword::Enable,
    "AUTO" => Keyword::Auto,
    "REFRESH" => Keyword::Refresh,
    "NOTIFICATION" => Keyword::Notification,
    "FORMAT" => Keyword::Format,
    "FILE" => Keyword::File,
    "FILE_FORMAT" => Keyword::FileFormat,
    "TYPE" => Keyword::Type,
    "COMPRESSION" => Keyword::Compression,
    "MASTER" => Keyword::Master,
    "KEY" => Keyword::Key,
    "KMS" => Keyword::Kms,
    "ID" => Keyword::Id,
    "ENDPOINT" => Keyword::Endpoint,
    "PRIMARY" => Keyword::Primary,
    "FOREIGN" => Keyword::Foreign,
    "REFERENCES" => Keyword::References,
    "CLUSTER" => Keyword::Cluster,
};

/// Lexer mode for handling SQL vs. Jinja tokenization.
/// What a block comment's body read as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockComment {
    /// A comment, closed.
    Closed(TriviaKind),
    /// Ran to the end of the text with its `*/` unmatched.
    Unterminated,
    /// The opening marker of a MySQL executable comment; its content is SQL.
    Executable,
    /// Closed, but holding a `/*` in a dialect whose comments may or may not
    /// nest, so where it ends is not known.
    Unreadable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LexMode {
    /// Standard SQL tokenization.
    Sql,
    /// Inside Jinja expression delimiters: {{ }}
    JinjaExpr,
    /// Inside Jinja statement delimiters: {% %}
    JinjaStmt,
    /// Inside the body of a dollar-quoted region (`$tag$ ... $tag$`) under a
    /// dialect that supports dollar quoting. The opening delimiter has already
    /// been emitted; inner content is lexed as ordinary SQL tokens BOUNDED to
    /// the body region (`dollar_body_end`), and the matching close tag is
    /// emitted as a closing delimiter token. This converges PG/Redshift onto
    /// the canonical single-token-stream shape (the parser, not the lexer,
    /// decides body-vs-string-literal).
    DollarBody,
}

pub struct Lexer<'src> {
    source: &'src str,
    /// SQL dialect controlling keyword/operator behavior.
    dialect: &'src dyn Dialect,
    /// Current byte offset into `source`.
    pos: usize,
    /// Current lexing mode (None = SQL, Some = inside Jinja delimiters).
    mode: LexMode,
    /// Tracks if any {% %} tokens were encountered during lexing.
    /// Tracks if we're inside a SQL string that was interrupted by Jinja.
    /// When true, a `'` should be treated as closing/continuing the string, not starting a new one.
    in_interrupted_string: bool,
    /// Tracks nesting depth of braces { } and brackets [ ] in Jinja mode.
    /// Used to prevent `}}` from being treated as JinjaExprClose when one `}` belongs to a dict.
    jinja_brace_depth: i32,
    /// Whether a `}` of the current `{{ }}` expression closed nothing: the
    /// expression is not balanced, and its next `}}` closes it.
    jinja_expr_unbalanced: bool,
    /// Whether the next token of the current `{% %}` tag is its first: a
    /// block's word (`filter`, `call`) is a keyword there only.
    jinja_tag_first: bool,
    /// Stack of enclosing dollar-quoted bodies (innermost last). Each entry is
    /// `(body_end, close_tag_span)`: the byte offset where the body content ends
    /// and the matching close tag (`$tag$`) begins, plus that close tag's span
    /// (emitted as the closing delimiter when the body ends). Inner lexing is
    /// bounded to the innermost `body_end` (`is_eof`/`peek_*` treat it as a soft
    /// end) so no scanner — string, comment, nested dollar-quote — can consume
    /// past it. A stack, not a single slot, so a DIFFERENT-tag dollar quote
    /// nested inside a body (`$func$ … $sql$ … $sql$ … $func$`) lexes correctly
    /// and restores the enclosing bound on close. Empty outside dollar-body
    /// lexing (no effect on normal tokenization).
    dollar_bodies: Vec<(usize, Span)>,
    /// Span of a top-level block comment that ran to EOF without its closing
    /// `*/`. Set during trivia collection; the next SQL-token step emits it as
    /// an `Unknown` token (instead of swallowing the rest of the file as a
    /// comment) so the parser surfaces it as unparsed content.
    unterminated_comment: Option<Span>,
    /// Inside a MySQL executable comment, between its opening marker and
    /// its `*/`.
    executable_comment: bool,
    /// Where the dialect writes a `$$…$$` string as words: the offset of the
    /// `$$` that closes the string an opening `$$` began, which no word,
    /// quote or comment inside the string reads past.
    dollar_words_close: Option<usize>,
    /// Each dollar-quoted string read, in the order its opener is read.
    dollar_quotes: Vec<crate::lexer::DollarQuote>,
    /// The statement terminator the last client `DELIMITER` command set, its
    /// byte range in the source; `None` while it is `;`.
    client_delimiter: Option<(usize, usize)>,
    /// What the statement being read is so far, as a `COPY` whose rows
    /// follow its terminator ([`CopyRows`]).
    copy_rows: CopyRows,
    /// Whether a psql `\copy` command is being read: its line ends it.
    psql_copy_line: bool,
}

/// What the statement being read is so far, as a `COPY … FROM STDIN`, whose
/// rows follow its terminator ([`TriviaKind::CopyData`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CopyRows {
    /// No token of the statement is read.
    Start,
    /// A `COPY`, inside `depth` parentheses.
    Copy { depth: u32 },
    /// A `COPY` whose last token is a `FROM` outside parentheses.
    From,
    /// A `COPY … FROM STDIN`.
    Stdin,
    /// Another statement.
    Other,
}

/// What a token is to [`CopyRows`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CopyToken {
    /// A `;`, or the end of the source.
    End,
    Copy,
    From,
    Open,
    Close,
    /// `STDIN`, in any case.
    Stdin,
    Other,
}

impl<'src> Lexer<'src> {
    /// Create a new lexer with the default Snowflake dialect.
    pub fn new(source: &'src str) -> Self {
        Self::with_dialect(source, &SnowflakeDialect)
    }

    /// Create a new lexer with an explicit dialect.
    ///
    /// This allows parsing SQL from different dialects (PostgreSQL, MySQL, etc.)
    /// by providing dialect-specific keyword and operator handling.
    pub fn with_dialect(source: &'src str, dialect: &'src dyn Dialect) -> Self {
        Self::validate_dialect_flags(dialect);
        Self {
            source,
            dialect,
            pos: 0,
            mode: LexMode::Sql,
            in_interrupted_string: false,
            jinja_brace_depth: 0,
            jinja_expr_unbalanced: false,
            jinja_tag_first: false,
            dollar_bodies: Vec::new(),
            unterminated_comment: None,
            executable_comment: false,
            dollar_words_close: None,
            dollar_quotes: Vec::new(),
            client_delimiter: None,
            copy_rows: CopyRows::Start,
            psql_copy_line: false,
        }
    }

    /// Soft end of the lexable region: the dollar-body boundary when lexing a
    /// dollar-quoted body (so inner scanners stop at the close tag), else the
    /// real end of source. `None` body-end means no effect on normal lexing.
    #[inline]
    fn effective_end(&self) -> usize {
        match self.dollar_bodies.last() {
            Some((end, _)) => *end,
            None => self.source.len(),
        }
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.effective_end()
    }

    /// Mode to resume when a Jinja delimiter closes. If an enclosing
    /// dollar-quoted body is still active — i.e. the Jinja appeared inside
    /// `$tag$ … $tag$` (e.g. a dbt-templated PostgreSQL function body) — resume
    /// body lexing so the close tag is recognized; otherwise plain SQL. Without
    /// this, closing Jinja inside a dollar body drops the body context, the
    /// stack is never popped, and the bounded `is_eof` emits a premature EOF.
    #[inline]
    fn mode_after_jinja(&self) -> LexMode {
        match self.dollar_bodies.last() {
            Some((end, _)) if self.pos < *end => LexMode::DollarBody,
            _ => LexMode::Sql,
        }
    }

    /// Dialect-aware identifier continuation check.
    /// Includes the base set (alphanumeric + underscore + Unicode) plus any
    /// extra characters the dialect allows (e.g., `$` and `#` for Snowflake/MSSQL).
    #[inline]
    fn is_ident_continue(&self, ch: char) -> bool {
        is_identifier_continue(ch) || self.dialect.extra_identifier_chars().contains(&ch)
    }

    /// Validate dialect flag consistency. Called once during lexer construction.
    #[inline]
    fn validate_dialect_flags(dialect: &dyn crate::dialect::Dialect) {
        debug_assert!(
            !(dialect.hash_is_line_comment() && dialect.hash_is_identifier_prefix()),
            "Dialect '{}' sets both hash_is_line_comment() and hash_is_identifier_prefix(). \
             These are mutually exclusive — # cannot be both a comment and an identifier prefix.",
            dialect.name()
        );
    }

    /// Consume a block comment body after the opening `/*` has already been consumed.
    /// Handles:
    /// - Nested block comments (`/* ... /* ... */ ... */`) when the dialect supports them
    /// - MySQL executable comments (`/*! ... */`), whose opening marker alone
    ///   is consumed: the text after it is SQL
    /// - A dialect whose comments may or may not nest: a body holding `/*`
    ///   is unreadable
    fn consume_block_comment_body(&mut self) -> BlockComment {
        if self.dialect.supports_version_comments() {
            let marker = match (self.peek_char(), self.peek_next_char()) {
                (Some('!'), _) => Some(1),
                (Some('M'), Some('!')) => Some(2),
                _ => None,
            };
            if let Some(len) = marker {
                for _ in 0..len {
                    self.bump();
                }
                // The server version the content needs, which it is read
                // as meeting.
                while matches!(self.peek_char(), Some(c) if c.is_ascii_digit()) {
                    self.bump();
                }
                return BlockComment::Executable;
            }
        }

        let nesting = self.dialect.supports_nested_block_comments();
        let ambiguous = self.dialect.block_comment_nesting_unknown();
        let mut holds_opener = false;
        let start = self.current_pos();
        let mut depth: u32 = 1;
        while let Some(c) = self.peek_char() {
            // Inside a `$$` string written as words, the text ends at its
            // closer, which ends the comment's text too.
            if self.at_dollar_words_close(start) {
                return BlockComment::Closed(TriviaKind::BlockComment);
            }
            if c == '/' && (nesting || ambiguous) {
                self.bump();
                if let Some('*') = self.peek_char() {
                    self.bump();
                    if nesting {
                        depth += 1;
                    } else {
                        holds_opener = true;
                    }
                    continue;
                }
                continue;
            }
            if c == '*' {
                self.bump();
                if let Some('/') = self.peek_char() {
                    self.bump();
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                    continue;
                }
                continue;
            }
            self.bump();
        }

        match (depth == 0, holds_opener) {
            (false, _) => BlockComment::Unterminated,
            (true, true) => BlockComment::Unreadable,
            (true, false) => BlockComment::Closed(TriviaKind::BlockComment),
        }
    }

    /// At the `*/` that closes the executable comment being read: consume
    /// it and return its trivia.
    fn take_executable_close(&mut self) -> Option<Trivia> {
        if !(self.executable_comment
            && self.peek_char() == Some('*')
            && self.peek_next_char() == Some('/'))
        {
            return None;
        }
        let start = self.current_pos();
        self.bump();
        self.bump();
        self.executable_comment = false;
        Some(Trivia {
            kind: TriviaKind::MysqlVersionComment,
            span: Span {
                start,
                end: self.current_pos(),
            },
        })
    }

    fn peek_char(&self) -> Option<char> {
        if self.pos >= self.effective_end() {
            return None;
        }
        self.source[self.pos..self.effective_end()].chars().next()
    }

    fn peek_next_char(&self) -> Option<char> {
        if self.pos >= self.effective_end() {
            return None;
        }
        let mut iter = self.source[self.pos..self.effective_end()].chars();
        iter.next()?;
        iter.next()
    }

    /// Peek ahead n characters (0-indexed, so n=0 is current, n=1 is next, n=2 is two ahead, etc.)
    fn peek_ahead_n(&self, n: usize) -> Option<char> {
        if self.pos >= self.effective_end() {
            return None;
        }
        self.source[self.pos..self.effective_end()].chars().nth(n)
    }

    fn bump(&mut self) -> Option<char> {
        let ch = self.peek_char()?;
        self.pos += ch.len_utf8();
        Some(ch)
    }

    fn current_pos(&self) -> u32 {
        self.pos as u32
    }

    /// The width of the client delimiter written at the current position
    /// ([`TriviaKind::ClientDelimiter`]).
    fn client_delimiter_at(&self) -> Option<usize> {
        let (start, end) = self.client_delimiter?;
        self.source
            .get(self.pos..self.effective_end())?
            .starts_with(&self.source[start..end])
            .then_some(end - start)
    }

    /// Whether the client's `DELIMITER` command starts at the current
    /// position: the word first on its line, then a space or tab.
    fn client_delimiter_command_at(&self) -> bool {
        const WORD: &str = "DELIMITER";
        if !self.dialect.client_delimiter_command()
            || self.mode != LexMode::Sql
            || !self.dollar_bodies.is_empty()
        {
            return false;
        }
        let line_start = self.source[..self.pos].rfind('\n').map_or(0, |n| n + 1);
        let first_on_line = self.source[line_start..self.pos]
            .chars()
            .all(|c| c == ' ' || c == '\t');
        let rest = &self.source[self.pos..];
        first_on_line
            && rest
                .get(..WORD.len())
                .is_some_and(|word| word.eq_ignore_ascii_case(WORD))
            && rest[WORD.len()..].starts_with([' ', '\t'])
    }

    /// The client's `DELIMITER x` command at the current position, to the end
    /// of its line; `x`, its first word, is the terminator from here on.
    fn lex_client_delimiter_command(&mut self) -> Trivia {
        let start = self.pos;
        while let Some(c) = self.peek_char() {
            if c == '\n' || c == '\r' {
                break;
            }
            self.bump();
        }
        let end = self.pos;
        let after_word = start + "DELIMITER".len();
        let text = &self.source[after_word..end];
        let from = after_word + (text.len() - text.trim_start().len());
        let to = self.source[from..end]
            .find(char::is_whitespace)
            .map_or(end, |n| from + n);
        self.client_delimiter = (to > from && &self.source[from..to] != ";").then_some((from, to));
        Trivia {
            kind: TriviaKind::ClientDelimiter,
            span: Span {
                start: start as u32,
                end: end as u32,
            },
        }
    }

    /// The psql command that sends the query written at the `\\` at the
    /// current position: `\g` or `\gexec`, a whole word. `None` for any
    /// other command.
    fn psql_meta_command_at(&self) -> Option<crate::lexer::token::PsqlMetaCommand> {
        use crate::lexer::token::PsqlMetaCommand;
        let rest = self.source.get(self.pos + 1..self.effective_end())?;
        let word_end = rest
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(rest.len());
        match &rest[..word_end] {
            "g" => Some(PsqlMetaCommand::Go),
            "gexec" => Some(PsqlMetaCommand::Gexec),
            _ => None,
        }
    }

    /// Whether psql's `\copy` command starts at the current position: first
    /// on its line, a whole word.
    fn psql_copy_at(&self) -> bool {
        if self.mode != LexMode::Sql || !self.dollar_bodies.is_empty() {
            return false;
        }
        let line_start = self.source[..self.pos].rfind('\n').map_or(0, |n| n + 1);
        let first_on_line = self.source[line_start..self.pos]
            .chars()
            .all(|c| c == ' ' || c == '\t');
        let rest = &self.source[self.pos..];
        first_on_line
            && rest.starts_with(PSQL_COPY)
            && !rest[PSQL_COPY.len()..]
                .chars()
                .next()
                .is_some_and(|c| self.is_ident_continue(c))
    }

    /// Read `token`, a token of a statement at the top level, into what the
    /// statement is so far ([`CopyRows`]); at the `;` that ends a `COPY …
    /// FROM STDIN`, read the rows written after it, from the next line to
    /// the end of the line `\.` that ends them or of the source, as its
    /// trailing trivia ([`TriviaKind::CopyData`]).
    fn read_copy_rows(&mut self, token: &mut Token) {
        if !self.dollar_bodies.is_empty() {
            return;
        }
        let read = if matches!(
            token.kind,
            TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
        ) {
            CopyToken::End
        } else if matches!(token.kind, TokenKind::Keyword(Keyword::Copy)) {
            CopyToken::Copy
        } else if matches!(token.kind, TokenKind::Keyword(Keyword::From)) {
            CopyToken::From
        } else if matches!(token.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            CopyToken::Open
        } else if matches!(token.kind, TokenKind::Punctuation(Punctuation::RParen)) {
            CopyToken::Close
        } else if matches!(token.kind, TokenKind::Identifier { .. })
            && token.lexeme(self.source).eq_ignore_ascii_case("STDIN")
        {
            CopyToken::Stdin
        } else {
            CopyToken::Other
        };
        self.copy_rows = match (self.copy_rows, read) {
            (CopyRows::Stdin, CopyToken::End) => {
                if let Some(rows) = self.copy_data() {
                    token.trailing_trivia.extend(rows);
                }
                CopyRows::Start
            }
            (_, CopyToken::End) => CopyRows::Start,
            (CopyRows::Start, CopyToken::Copy) => CopyRows::Copy { depth: 0 },
            // psql's `\copy` runs a `COPY` wherever it is written.
            (_, CopyToken::Copy) if self.psql_copy_line => CopyRows::Copy { depth: 0 },
            (CopyRows::Start, _) => CopyRows::Other,
            (CopyRows::Copy { depth }, CopyToken::Open) => CopyRows::Copy { depth: depth + 1 },
            (CopyRows::Copy { depth }, CopyToken::Close) => CopyRows::Copy {
                depth: depth.saturating_sub(1),
            },
            (CopyRows::Copy { depth: 0 }, CopyToken::From) => CopyRows::From,
            (CopyRows::From, CopyToken::Stdin) => CopyRows::Stdin,
            (CopyRows::From, _) => CopyRows::Copy { depth: 0 },
            (state @ (CopyRows::Copy { .. } | CopyRows::Stdin | CopyRows::Other), _) => state,
        };
    }

    /// The rows a `COPY … FROM STDIN` reads, at the end of the line of its
    /// `;`: the line break, then the rows to the end of the line `\.`
    /// that ends them, or of the source. `None` where the line holds more
    /// than trivia after the `;`, or no line follows.
    fn copy_data(&mut self) -> Option<[Trivia; 2]> {
        let break_start = self.pos;
        let rest = self.source.get(break_start..)?;
        let width = if rest.starts_with("\r\n") {
            2
        } else if rest.starts_with(['\n', '\r']) {
            1
        } else {
            return None;
        };
        let start = break_start + width;
        if start >= self.source.len() {
            return None;
        }
        let mut end = self.source.len();
        let mut at = start;
        for line in self.source[start..].split_inclusive('\n') {
            let content = line.trim_end_matches(['\n', '\r']);
            if content.trim() == "\\." {
                end = at + content.len();
                break;
            }
            at += line.len();
        }
        self.pos = end;
        let span = |from: usize, to: usize| Span {
            start: from as u32,
            end: to as u32,
        };
        Some([
            Trivia {
                kind: TriviaKind::Newline,
                span: span(break_start, start),
            },
            Trivia {
                kind: TriviaKind::CopyData,
                span: span(start, end),
            },
        ])
    }

    /// The psql `command` at the current position, to the end of its line, as
    /// trivia of the `;` of no width after it, which ends the statement.
    fn lex_psql_meta_command(
        &mut self,
        mut leading_trivia: Vec<Trivia>,
        command: crate::lexer::token::PsqlMetaCommand,
    ) -> Token {
        let start = self.current_pos();
        while let Some(c) = self.peek_char() {
            if c == '\n' || c == '\r' {
                break;
            }
            self.bump();
        }
        let end = self.current_pos();
        leading_trivia.push(Trivia {
            kind: TriviaKind::PsqlMetaCommand(command),
            span: Span { start, end },
        });
        Token {
            kind: TokenKind::Punctuation(crate::lexer::Punctuation::Semi),
            span: Span { start: end, end },
            leading_trivia,
            trailing_trivia: Vec::new(),
        }
    }

    /// Collect leading trivia (whitespace, newlines, comments) starting at current position.
    fn collect_leading_trivia(&mut self) -> Vec<Trivia> {
        let mut trivia = Vec::new();

        loop {
            if self.is_eof() {
                break;
            }
            if let Some(close) = self.take_executable_close() {
                trivia.push(close);
                continue;
            }

            let start = self.current_pos();
            let ch = match self.peek_char() {
                Some(c) => c,
                None => break,
            };

            // The client's terminator is a token, not a comment's start.
            if self.client_delimiter_at().is_some() {
                break;
            }
            if matches!(ch, 'D' | 'd') && self.client_delimiter_command_at() {
                let command = self.lex_client_delimiter_command();
                trivia.push(command);
                continue;
            }

            // BOM (Byte Order Mark) - treat as whitespace trivia
            if ch == '\u{feff}' {
                self.bump();
                let end = self.current_pos();
                trivia.push(Trivia {
                    kind: TriviaKind::Whitespace,
                    span: Span { start, end },
                });
                continue;
            }

            // Whitespace (space/tab)
            if ch == ' ' || ch == '\t' {
                self.bump();
                while let Some(c2) = self.peek_char() {
                    if c2 == ' ' || c2 == '\t' {
                        self.bump();
                    } else {
                        break;
                    }
                }
                let end = self.current_pos();
                trivia.push(Trivia {
                    kind: TriviaKind::Whitespace,
                    span: Span { start, end },
                });
                continue;
            }

            // Newline
            if ch == '\n' {
                self.bump();
                let end = self.current_pos();
                trivia.push(Trivia {
                    kind: TriviaKind::Newline,
                    span: Span { start, end },
                });
                continue;
            }

            if ch == '\r' {
                self.bump();
                if let Some('\n') = self.peek_char() {
                    self.bump();
                }
                let end = self.current_pos();
                trivia.push(Trivia {
                    kind: TriviaKind::Newline,
                    span: Span { start, end },
                });
                continue;
            }

            // Line comment "-- ..."
            if ch == '-' {
                if let Some('-') = self.peek_next_char() {
                    // MySQL requires whitespace or a control character (a line
                    // end included) after '--' for it to be a comment. Without
                    // it, '--' is two minus operators (e.g., x--y = x - (-y)).
                    if self.dialect.requires_space_after_double_dash() {
                        let is_comment = self
                            .peek_ahead_n(2)
                            .is_none_or(|c| c.is_whitespace() || c.is_control());
                        if !is_comment {
                            break; // Not a comment — fall through to operator lexing
                        }
                    }
                    self.bump();
                    self.bump();
                    while let Some(c) = self.peek_char() {
                        if c == '\n' || c == '\r' || self.at_dollar_words_close(start) {
                            break;
                        }
                        self.bump();
                    }
                    let end = self.current_pos();
                    trivia.push(Trivia {
                        kind: TriviaKind::LineComment,
                        span: Span { start, end },
                    });
                    continue;
                }
            }

            // Block comment "/* ... */" or C-style line comment "// ..."
            if ch == '/' {
                // C-style line comment "// ..." (Snowflake supports this)
                // EXCEPTION: Inside Jinja expressions {{ }}, "//" is floor division operator, not comment
                if let (Some('/'), true) = (
                    self.peek_next_char(),
                    self.dialect.slash_slash_is_line_comment(),
                ) {
                    // Only treat as comment if:
                    // 1. We're in regular SQL (mode = Sql), OR
                    // 2. We're in Jinja statement mode {% %} (where SQL can appear)
                    // Do NOT treat as comment when in JinjaExpr mode {{ }} - that's floor division
                    let is_jinja_floor_div = self.mode == LexMode::JinjaExpr;

                    // A `//` immediately preceded by `:` or `/` is part of a
                    // `scheme://…` URI / path slash-run (e.g. unquoted
                    // `file:///tmp/…` / `s3://…` in PUT/GET), not a line
                    // comment. A real `//` comment is always preceded by
                    // whitespace or a non-slash token, so this never masks one.
                    let prev_byte = start
                        .checked_sub(1)
                        .and_then(|p| self.source.as_bytes().get(p as usize));
                    let is_uri_scheme = matches!(prev_byte, Some(&b':') | Some(&b'/'));

                    if !is_jinja_floor_div && !is_uri_scheme {
                        self.bump();
                        self.bump();
                        while let Some(c) = self.peek_char() {
                            if c == '\n' || c == '\r' || self.at_dollar_words_close(start) {
                                break;
                            }
                            self.bump();
                        }
                        let end = self.current_pos();
                        trivia.push(Trivia {
                            kind: TriviaKind::LineComment,
                            span: Span { start, end },
                        });
                        continue;
                    }
                    // In JinjaExpr mode, break out and let next_jinja_token handle it as operator
                    break;
                }
                // Block comment "/* ... */"
                // PostgreSQL supports nested block comments; other dialects do not.
                // MySQL version comments: /*!50100 ... */ contain executable SQL.
                if let Some('*') = self.peek_next_char() {
                    self.bump(); // consume /
                    self.bump(); // consume *

                    let body = self.consume_block_comment_body();

                    let end = self.current_pos();
                    let comment_kind = match body {
                        BlockComment::Closed(kind) => kind,
                        BlockComment::Executable => {
                            self.executable_comment = true;
                            TriviaKind::MysqlVersionComment
                        }
                        BlockComment::Unterminated | BlockComment::Unreadable
                            if self.mode == LexMode::Sql && self.dollar_bodies.is_empty() =>
                        {
                            // Ran to EOF with no closing `*/`, or cannot be read
                            // one way. Record the span; the next SQL-token step
                            // emits it as an Unknown token so the parser surfaces
                            // it as unparsed content instead of text vanishing
                            // into a comment.
                            self.unterminated_comment = Some(Span { start, end });
                            break;
                        }
                        BlockComment::Unterminated | BlockComment::Unreadable => {
                            TriviaKind::BlockComment
                        }
                    };
                    trivia.push(Trivia {
                        kind: comment_kind,
                        span: Span { start, end },
                    });
                    continue;
                }
            }

            // Jinja comment "{# ... #}" - treat as trivia like SQL comments
            if ch == '{' {
                if let Some('#') = self.peek_next_char() {
                    self.bump(); // {
                    self.bump(); // #
                                 // Consume until #}
                    while let Some(c) = self.peek_char() {
                        if c == '#' {
                            self.bump();
                            if let Some('}') = self.peek_char() {
                                self.bump();
                                break;
                            }
                        } else {
                            self.bump();
                        }
                    }
                    let end = self.current_pos();
                    trivia.push(Trivia {
                        kind: TriviaKind::JinjaComment,
                        span: Span { start, end },
                    });
                    continue;
                }
            }

            // Non-trivia
            break;
        }

        trivia
    }

    pub fn next_token(&mut self) -> Token {
        // Dispatch based on current lexing mode
        match self.mode {
            LexMode::Sql => {
                let mut token = self.next_sql_token();
                self.read_copy_rows(&mut token);
                token
            }
            LexMode::DollarBody => self.next_dollar_body_token(),
            LexMode::JinjaExpr | LexMode::JinjaStmt => self.next_jinja_token(),
        }
    }

    /// Lex one token inside a dollar-quoted body (`LexMode::DollarBody`). The
    /// opening delimiter has already been emitted; here we either emit the next
    /// ordinary SQL token (bounded to the body region so no scanner overruns the
    /// close tag) or, on reaching the body end, emit the closing delimiter and
    /// return to SQL mode.
    fn next_dollar_body_token(&mut self) -> Token {
        // Trivia up to (but not across) the close tag — `peek_*`/`is_eof` are
        // bounded by `dollar_body_end`, so this stops at the body boundary.
        let trivia = self.collect_leading_trivia();

        let at_close = match self.dollar_bodies.last() {
            Some((end, _)) => self.pos >= *end,
            None => true,
        };
        if at_close {
            // Pop the innermost body and emit its closing delimiter. Popping
            // FIRST means the close tag (and anything after) is consumed against
            // the ENCLOSING bound — a nested body returns to its parent body, an
            // outermost body returns to SQL mode.
            let close_span = self
                .dollar_bodies
                .pop()
                .map(|(_, close)| close)
                .unwrap_or(Span {
                    start: self.pos as u32,
                    end: self.pos as u32,
                });
            self.pos = close_span.end as usize;
            if self.dollar_bodies.is_empty() {
                self.mode = LexMode::Sql;
            }
            return Token {
                kind: TokenKind::Identifier {
                    kind: IdentifierKind::DollarQuoteDelimiter,
                    word_operator: None,
                },
                span: close_span,
                leading_trivia: trivia,
                trailing_trivia: Vec::new(),
            };
        }

        // One ordinary SQL token, bounded to the body region.
        self.lex_sql_token(trivia)
    }

    /// Continue tokenizing with pre-collected leading trivia.
    /// Used when a lexer decision (e.g., # as comment in MySQL) consumes content
    /// that should become trivia of the NEXT token.
    fn next_token_with_leading_trivia(&mut self, mut existing_trivia: Vec<Trivia>) -> Token {
        // Collect any additional trivia (whitespace/comments after the injected trivia)
        let more_trivia = self.collect_leading_trivia();
        existing_trivia.extend(more_trivia);

        if let Some(span) = self.unterminated_comment.take() {
            return Token {
                kind: TokenKind::Unknown,
                span,
                leading_trivia: existing_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        if self.is_eof() {
            return Token {
                kind: TokenKind::Eof,
                span: Span {
                    start: self.current_pos(),
                    end: self.current_pos(),
                },
                leading_trivia: existing_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        self.lex_sql_token(existing_trivia)
    }

    fn next_sql_token(&mut self) -> Token {
        // If we're in an interrupted string (after a Jinja block inside a string),
        // continue lexing the string content directly without collecting trivia
        // (whitespace inside strings is content, not trivia).
        // BUT: if we're at a Jinja delimiter, handle that first.
        if self.in_interrupted_string {
            // Check if we're at another Jinja block
            if let Some('{') = self.peek_char() {
                if let Some(next) = self.peek_next_char() {
                    if next == '#' {
                        // A comment inside the string is a token of it, not
                        // trivia; the string continues after it.
                        return self.lex_jinja_comment(Vec::new());
                    } else if next == '{' || next == '%' {
                        // Let normal dispatch handle the Jinja token
                        // (in_interrupted_string stays true so we continue after)
                    } else {
                        return self.lex_string_continuation(Vec::new());
                    }
                } else {
                    return self.lex_string_continuation(Vec::new());
                }
            } else {
                return self.lex_string_continuation(Vec::new());
            }
        }

        // A psql `\copy` command ends at its line's end: a `;` of no width.
        if self.psql_copy_line && matches!(self.peek_char(), None | Some('\n' | '\r')) {
            self.psql_copy_line = false;
            let at = self.current_pos();
            return Token {
                kind: TokenKind::Punctuation(Punctuation::Semi),
                span: Span { start: at, end: at },
                leading_trivia: Vec::new(),
                trailing_trivia: Vec::new(),
            };
        }

        let leading_trivia = self.collect_leading_trivia();

        if let Some(span) = self.unterminated_comment.take() {
            return Token {
                kind: TokenKind::Unknown,
                span,
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        if self.is_eof() {
            return Token {
                kind: TokenKind::Eof,
                span: Span {
                    start: self.current_pos(),
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        self.lex_sql_token(leading_trivia)
    }

    /// Core SQL token dispatch — separated from trivia collection so it can be
    /// reused by `next_token_with_leading_trivia` (e.g., after # comment in MySQL).
    fn lex_sql_token(&mut self, leading_trivia: Vec<Trivia>) -> Token {
        let start = self.current_pos();
        let ch = self
            .peek_char()
            .expect_invariant("Character should be available in lex_token");
        // The terminator a client `DELIMITER` command set: a `;` of its width.
        if let Some(width) = self.client_delimiter_at() {
            self.pos += width;
            return Token {
                kind: TokenKind::Punctuation(crate::lexer::Punctuation::Semi),
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }
        // psql's `\copy`, in any dialect: the `COPY` it runs, to its line's end.
        if ch == '\\' && self.psql_copy_at() {
            self.pos += PSQL_COPY.len();
            self.psql_copy_line = true;
            let mut token = Token {
                kind: TokenKind::Keyword(Keyword::Copy),
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
            token.trailing_trivia = self.collect_trailing_trivia();
            return token;
        }
        // A psql command that sends the query: kept as written, a `;` after.
        if ch == '\\' && self.mode == LexMode::Sql && self.dialect.psql_meta_commands() {
            if let Some(command) = self.psql_meta_command_at() {
                return self.lex_psql_meta_command(leading_trivia, command);
            }
        }

        let mut token = if ch == '{' {
            // Check for Jinja syntax: {{ }}, {% %}, {# #}
            if let Some(next_ch) = self.peek_next_char() {
                if next_ch == '{' {
                    self.lex_jinja_expression(leading_trivia)
                } else if next_ch == '%' {
                    self.lex_jinja_statement(leading_trivia)
                } else if next_ch == '#' {
                    self.lex_jinja_comment(leading_trivia)
                } else {
                    // Not Jinja, treat as symbol/operator
                    self.lex_symbol_or_operator(leading_trivia, start)
                }
            } else {
                // Not Jinja, treat as symbol/operator
                self.lex_symbol_or_operator(leading_trivia, start)
            }
        } else if ch == '"' {
            // Dialect-aware: double-quote is an identifier in Snowflake/PostgreSQL,
            // but a string literal in MySQL (when ANSI_QUOTES is off).
            if self.dialect.supports_double_quoted_strings() {
                // MySQL mode: "..." is a string literal
                self.lex_double_quoted_string(leading_trivia)
            } else {
                self.lex_quoted_identifier(leading_trivia)
            }
        } else if ch == '`' && self.dialect.identifier_quote_char() == '`' {
            // MySQL backtick-quoted identifier: `column_name`
            self.lex_backtick_identifier(leading_trivia)
        } else if ch == '['
            && self.mode == LexMode::Sql
            && self.dialect.supports_bracket_identifiers()
        {
            // MSSQL bracket-delimited identifier: [column_name]
            self.lex_bracket_identifier(leading_trivia)
        } else if is_identifier_start(ch) {
            self.lex_identifier_or_keyword(leading_trivia)
        } else if ch.is_ascii_digit() || ch == '.' {
            // Numbers and dot-prefixed decimals are handled in `lex_number`,
            // but a bare '.' (not followed by a digit) should be punctuation.
            if ch == '.' {
                // Look ahead: if next char is not a digit, treat as '.' punctuation.
                // The second dot of `..` (a range, an omitted schema) is never a
                // decimal point: `1..10` is `1`, `.`, `.`, `10`.
                let after_dot = self.source[..self.pos].ends_with('.');
                if let Some(next) = self.peek_next_char() {
                    if after_dot || !next.is_ascii_digit() {
                        // Consume '.' and return it as a Dot punctuation token.
                        let start = self.current_pos();
                        self.bump();
                        return Token {
                            kind: TokenKind::Punctuation(crate::lexer::token::Punctuation::Dot),
                            span: Span {
                                start,
                                end: self.current_pos(),
                            },
                            leading_trivia,
                            trailing_trivia: Vec::new(),
                        };
                    }
                } else {
                    // '.' at end of input – treat as punctuation as well.
                    let start = self.current_pos();
                    self.bump();
                    return Token {
                        kind: TokenKind::Punctuation(crate::lexer::token::Punctuation::Dot),
                        span: Span {
                            start,
                            end: self.current_pos(),
                        },
                        leading_trivia,
                        trailing_trivia: Vec::new(),
                    };
                }
            }
            self.lex_number(leading_trivia)
        } else if ch == '$' {
            self.lex_positional_or_identifier(leading_trivia)
        } else if ch == '\'' {
            self.lex_string(leading_trivia)
        } else {
            self.lex_symbol_or_operator(leading_trivia, start)
        };

        // Collect trailing trivia (up to newline) and attach to token.
        token.trailing_trivia = self.collect_trailing_trivia();
        token
    }

    fn next_jinja_token(&mut self) -> Token {
        let leading_trivia = self.collect_leading_trivia();
        let tag_first = std::mem::take(&mut self.jinja_tag_first);

        if self.is_eof() {
            return Token {
                kind: TokenKind::Eof,
                span: Span {
                    start: self.current_pos(),
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        let start = self.current_pos();
        let ch = self
            .peek_char()
            .expect_invariant("Character should be available in next_jinja_token");

        // Check for closing delimiters: }} or %}
        // BUT: only treat }} as JinjaExprClose if we're at brace depth 0
        if ch == '}' {
            if let Some(next_ch) = self.peek_next_char() {
                if next_ch == '}'
                    && self.mode == LexMode::JinjaExpr
                    && (self.jinja_brace_depth == 0 || self.jinja_expr_unbalanced)
                {
                    // Exit Jinja expression mode - we're closing the {{ }}
                    self.mode = self.mode_after_jinja();
                    self.bump(); // }
                    self.bump(); // }
                    return Token {
                        kind: TokenKind::JinjaExprClose,
                        span: Span {
                            start,
                            end: self.current_pos(),
                        },
                        leading_trivia,
                        trailing_trivia: Vec::new(),
                    };
                }
            }
            // Single } - treat as punctuation (for dict literals)
            // Decrement brace depth when closing a dict/set
            if self.mode != LexMode::Sql && self.jinja_brace_depth > 0 {
                self.jinja_brace_depth -= 1;
            } else if self.mode == LexMode::JinjaExpr {
                self.jinja_expr_unbalanced = true;
            }
            self.bump();
            return Token {
                kind: TokenKind::Punctuation(Punctuation::RCurly),
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        if ch == '%' {
            if let Some(next_ch) = self.peek_next_char() {
                if next_ch == '}' && self.mode == LexMode::JinjaStmt {
                    // Exit Jinja statement mode
                    self.mode = self.mode_after_jinja();
                    self.bump(); // %
                    self.bump(); // }
                    return Token {
                        kind: TokenKind::JinjaStmtClose,
                        span: Span {
                            start,
                            end: self.current_pos(),
                        },
                        leading_trivia,
                        trailing_trivia: Vec::new(),
                    };
                }
            }
            // Single % - treat as operator
            self.bump();
            return Token {
                kind: TokenKind::Operator(Operator::Percent),
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        // Jinja operators
        if ch == '|' {
            self.bump();
            return Token {
                kind: TokenKind::JinjaPipe,
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        if ch == '~' {
            self.bump();
            return Token {
                kind: TokenKind::JinjaTilde,
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        // Check for multi-character operators
        if ch == '*' {
            if let Some('*') = self.peek_next_char() {
                self.bump();
                self.bump();
                return Token {
                    kind: TokenKind::JinjaDoubleStar,
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                };
            }
            // Single * - arithmetic multiply
            self.bump();
            return Token {
                kind: TokenKind::Operator(Operator::Star),
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        if ch == '/' {
            if let Some('/') = self.peek_next_char() {
                self.bump();
                self.bump();
                return Token {
                    kind: TokenKind::JinjaDoubleSlash,
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                };
            }
            // Single / - arithmetic divide
            self.bump();
            return Token {
                kind: TokenKind::Operator(Operator::Slash),
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        if ch == '=' {
            if let Some('=') = self.peek_next_char() {
                self.bump();
                self.bump();
                return Token {
                    kind: TokenKind::JinjaDoubleEq,
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                };
            }
            // Single = - assignment (for set statements)
            self.bump();
            return Token {
                kind: TokenKind::Operator(Operator::Eq),
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        // Standard comparison operators (reuse SQL tokens)
        if ch == '!' {
            if let Some('=') = self.peek_next_char() {
                self.bump();
                self.bump();
                return Token {
                    kind: TokenKind::Operator(Operator::NotEq),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                };
            }
        }

        if ch == '<' {
            self.bump();
            if let Some('=') = self.peek_char() {
                self.bump();
                // <=> null-safe equality (MySQL / Spark)
                if let Some('>') = self.peek_char() {
                    self.bump();
                    return Token {
                        kind: TokenKind::Operator(Operator::LtEqGt),
                        span: Span {
                            start,
                            end: self.current_pos(),
                        },
                        leading_trivia,
                        trailing_trivia: Vec::new(),
                    };
                }
                return Token {
                    kind: TokenKind::Operator(Operator::Le),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                };
            }

            return Token {
                kind: TokenKind::Operator(Operator::Lt),
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        if ch == '>' {
            self.bump();
            if let Some('=') = self.peek_char() {
                self.bump();
                return Token {
                    kind: TokenKind::Operator(Operator::Ge),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                };
            }
            return Token {
                kind: TokenKind::Operator(Operator::Gt),
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        // Arithmetic operators
        if ch == '+' {
            self.bump();
            return Token {
                kind: TokenKind::Operator(Operator::Plus),
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        if ch == '-' {
            // Check for -> arrow operator first (used in ROW ACCESS POLICY)
            if let Some('>') = self.peek_next_char() {
                // Consume - and > to produce -> arrow operator
                self.bump();
                self.bump();
                return Token {
                    kind: TokenKind::Operator(Operator::RightArrow),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                };
            }
            // Check if this is whitespace-stripping syntax: -%} or -}}
            if let Some(next_ch) = self.peek_next_char() {
                if next_ch == '%' && self.mode == LexMode::JinjaStmt {
                    // This is -%} - consume it as JinjaStmtClose
                    if let Some(after_percent) = self.peek_ahead_n(2) {
                        if after_percent == '}' {
                            self.mode = self.mode_after_jinja();
                            self.bump(); // -
                            self.bump(); // %
                            self.bump(); // }
                            return Token {
                                kind: TokenKind::JinjaStmtClose,
                                span: Span {
                                    start,
                                    end: self.current_pos(),
                                },
                                leading_trivia,
                                trailing_trivia: Vec::new(),
                            };
                        }
                    }
                } else if next_ch == '}'
                    && self.mode == LexMode::JinjaExpr
                    && (self.jinja_brace_depth == 0 || self.jinja_expr_unbalanced)
                {
                    // This is -}} - check if the next char is also }
                    if let Some(after_brace) = self.peek_ahead_n(2) {
                        if after_brace == '}' {
                            self.mode = self.mode_after_jinja();
                            self.bump(); // -
                            self.bump(); // }
                            self.bump(); // }
                            return Token {
                                kind: TokenKind::JinjaExprClose,
                                span: Span {
                                    start,
                                    end: self.current_pos(),
                                },
                                leading_trivia,
                                trailing_trivia: Vec::new(),
                            };
                        }
                    }
                }
            }
            // Not a closing delimiter - treat as minus operator
            self.bump();
            return Token {
                kind: TokenKind::Operator(Operator::Minus),
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        // Punctuation
        if ch == '(' {
            self.bump();
            return Token {
                kind: TokenKind::Punctuation(Punctuation::LParen),
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        if ch == ')' {
            self.bump();
            return Token {
                kind: TokenKind::Punctuation(Punctuation::RParen),
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        if ch == '[' {
            // Track bracket depth in Jinja mode (for lists)
            if self.mode != LexMode::Sql {
                self.jinja_brace_depth += 1;
            }
            self.bump();
            return Token {
                kind: TokenKind::Punctuation(Punctuation::LBracket),
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        if ch == ']' {
            // Decrement bracket depth in Jinja mode
            if self.mode != LexMode::Sql && self.jinja_brace_depth > 0 {
                self.jinja_brace_depth -= 1;
            }
            self.bump();
            return Token {
                kind: TokenKind::Punctuation(Punctuation::RBracket),
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        if ch == ',' {
            self.bump();
            return Token {
                kind: TokenKind::Punctuation(Punctuation::Comma),
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        if ch == '.' {
            self.bump();
            return Token {
                kind: TokenKind::Punctuation(Punctuation::Dot),
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        if ch == ':' {
            self.bump();
            return Token {
                kind: TokenKind::Punctuation(Punctuation::Colon),
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        // Curly braces for dictionary literals: { }
        if ch == '{' {
            // Increment brace depth when opening a dict/set in Jinja mode
            if self.mode != LexMode::Sql {
                self.jinja_brace_depth += 1;
            }
            self.bump();
            return Token {
                kind: TokenKind::Punctuation(Punctuation::LCurly),
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        // Strings (single or double quoted in Jinja)
        if ch == '\'' || ch == '"' {
            return self.lex_jinja_string(leading_trivia, ch);
        }

        // Numbers
        if ch.is_ascii_digit() {
            return self.lex_jinja_number(leading_trivia);
        }

        // Identifiers and keywords (lowercase in Jinja)
        if is_identifier_start(ch) {
            return self.lex_jinja_identifier_or_keyword(leading_trivia, tag_first);
        }

        // Unknown/unsupported character
        self.bump();
        Token {
            kind: TokenKind::Unknown,
            span: Span {
                start,
                end: self.current_pos(),
            },
            leading_trivia,
            trailing_trivia: Vec::new(),
        }
    }

    /// A Jinja word: a keyword, or, as the first word of a `{% %}` tag
    /// (`tag_first`), a block's word too.
    fn lex_jinja_identifier_or_keyword(
        &mut self,
        leading_trivia: Vec<Trivia>,
        tag_first: bool,
    ) -> Token {
        let start = self.current_pos();
        self.bump();
        while let Some(c) = self.peek_char() {
            if is_identifier_continue(c) {
                self.bump();
            } else {
                break;
            }
        }
        let end = self.current_pos();
        let text = &self.source[start as usize..end as usize];

        // Jinja keywords are lowercase (unlike SQL which is case-insensitive)
        let kind = match text {
            "and" => TokenKind::JinjaAnd,
            "or" => TokenKind::JinjaOr,
            "not" => TokenKind::JinjaNot,
            "in" => TokenKind::JinjaIn,
            "is" => TokenKind::JinjaIs,
            "true" => TokenKind::JinjaTrue,
            "false" => TokenKind::JinjaFalse,
            "null" | "none" => TokenKind::JinjaNull,
            // Statement keywords (used in {% %} blocks)
            "if" => TokenKind::JinjaIf,
            "elif" => TokenKind::JinjaElif,
            "else" => TokenKind::JinjaElse,
            "endif" => TokenKind::JinjaEndIf,
            "for" => TokenKind::JinjaFor,
            "endfor" => TokenKind::JinjaEndFor,
            "set" => TokenKind::JinjaSet,
            "endset" => TokenKind::JinjaEndSet,
            "docs" => TokenKind::JinjaDocs,
            "enddocs" => TokenKind::JinjaEndDocs,
            "filter" if tag_first => TokenKind::JinjaFilter,
            "endfilter" if tag_first => TokenKind::JinjaEndFilter,
            "call" if tag_first => TokenKind::JinjaCall,
            "endcall" if tag_first => TokenKind::JinjaEndCall,
            _ => TokenKind::Identifier {
                kind: IdentifierKind::Unquoted,
                word_operator: None,
            },
        };

        Token {
            kind,
            span: Span { start, end },
            leading_trivia,
            trailing_trivia: Vec::new(),
        }
    }

    fn lex_jinja_string(&mut self, leading_trivia: Vec<Trivia>, quote_char: char) -> Token {
        let start = self.current_pos();
        self.bump(); // opening quote

        while let Some(c) = self.peek_char() {
            if c == quote_char {
                self.bump(); // closing quote
                break;
            } else if c == '\\' {
                // Escape sequence
                self.bump();
                if self.peek_char().is_some() {
                    self.bump();
                }
            } else {
                self.bump();
            }
        }

        let end = self.current_pos();

        Token {
            kind: TokenKind::Literal(LiteralKind::String),
            span: Span { start, end },
            leading_trivia,
            trailing_trivia: Vec::new(),
        }
    }

    fn lex_jinja_number(&mut self, leading_trivia: Vec<Trivia>) -> Token {
        let start = self.current_pos();

        // Integer part
        while let Some(c) = self.peek_char() {
            if c.is_ascii_digit() {
                self.bump();
            } else {
                break;
            }
        }

        // Check for decimal part
        if let Some('.') = self.peek_char() {
            if let Some(next) = self.peek_next_char() {
                if next.is_ascii_digit() {
                    self.bump(); // consume '.'
                    while let Some(c) = self.peek_char() {
                        if c.is_ascii_digit() {
                            self.bump();
                        } else {
                            break;
                        }
                    }
                }
            }
        }

        // Check for scientific notation (e or E)
        if let Some(c) = self.peek_char() {
            if c == 'e' || c == 'E' {
                self.bump();
                if let Some(sign) = self.peek_char() {
                    if sign == '+' || sign == '-' {
                        self.bump();
                    }
                }
                while let Some(c) = self.peek_char() {
                    if c.is_ascii_digit() {
                        self.bump();
                    } else {
                        break;
                    }
                }
            }
        }

        let end = self.current_pos();

        Token {
            kind: TokenKind::Literal(LiteralKind::Number),
            span: Span { start, end },
            leading_trivia,
            trailing_trivia: Vec::new(),
        }
    }

    fn lex_identifier_or_keyword(&mut self, leading_trivia: Vec<Trivia>) -> Token {
        let start = self.current_pos();
        self.bump();
        while let Some(c) = self.peek_char() {
            // Inside a `$$` string written as words, a word ends at its closer.
            if self.at_dollar_words_close(start) {
                break;
            }
            if self.is_ident_continue(c) {
                self.bump();
            } else {
                break;
            }
        }
        let end = self.current_pos();
        let text = &self.source[start as usize..end as usize];

        // Dialect-aware: PostgreSQL E'...' escape string literals.
        // If the identifier is just "E" or "e" and the next char is a single quote,
        // backtrack and lex as an escape string literal.
        if self.dialect.supports_escape_string_literals()
            && text.len() == 1
            && (text == "E" || text == "e")
            && self.peek_char() == Some('\'')
        {
            // Reset position to start and lex as escape string
            self.pos = start as usize;
            return self.lex_escape_string(leading_trivia);
        }

        // Dialect-aware: MSSQL national string literals N'...'.
        // If the identifier is just "N" or "n" and the next char is a single quote,
        // re-lex as a national string literal token.
        if self.dialect.supports_national_string_literals()
            && text.len() == 1
            && (text == "N" || text == "n")
            && self.peek_char() == Some('\'')
        {
            self.pos = start as usize;
            return self.lex_national_string(leading_trivia);
        }

        // O(1) keyword lookup using phf perfect hash map with stack-allocated
        // uppercase buffer (no heap allocation).
        let kind = match keyword_lookup(text) {
            Some(Keyword::True) => TokenKind::Literal(LiteralKind::Boolean),
            Some(Keyword::False) => TokenKind::Literal(LiteralKind::Boolean),
            Some(Keyword::Null) => TokenKind::Literal(LiteralKind::Null),
            Some(kw) => TokenKind::Keyword(kw),
            // Still a name, and marked where the dialect also writes an
            // operator with the word.
            None => TokenKind::Identifier {
                kind: IdentifierKind::Unquoted,
                word_operator: self.dialect.word_operator(text),
            },
        };

        Token {
            kind,
            span: Span { start, end },
            leading_trivia,
            trailing_trivia: Vec::new(),
        }
    }

    fn lex_quoted_identifier(&mut self, leading_trivia: Vec<Trivia>) -> Token {
        let start = self.current_pos();
        let mut stopped_at_close = false;
        // opening quote
        self.bump();

        while let Some(c) = self.peek_char() {
            // Inside a `$$` string written as words, the quote ends at its closer.
            if self.at_dollar_words_close(start) {
                stopped_at_close = true;
                break;
            }
            self.bump();
            if c == '"' {
                // doubled quote inside identifier
                if let Some('"') = self.peek_char() {
                    self.bump();
                    continue;
                }
                break;
            }
        }

        let end = self.current_pos();

        Token {
            kind: if stopped_at_close {
                // Part of the text of a `$$` string written as words.
                TokenKind::Literal(LiteralKind::StringFragment)
            } else {
                TokenKind::Identifier {
                    kind: IdentifierKind::Quoted,
                    word_operator: None,
                }
            },
            span: Span { start, end },
            leading_trivia,
            trailing_trivia: Vec::new(),
        }
    }

    /// Lex a double-quoted string literal: "text" (MySQL default mode).
    /// In MySQL (without ANSI_QUOTES), "..." is a string literal, not an identifier.
    fn lex_double_quoted_string(&mut self, leading_trivia: Vec<Trivia>) -> Token {
        let start = self.current_pos();
        self.bump(); // opening "

        while let Some(c) = self.peek_char() {
            self.bump();
            if c == '"' {
                // doubled quote escape ""
                if let Some('"') = self.peek_char() {
                    self.bump();
                    continue;
                }
                break;
            }
            if c == '\\' {
                // Backslash escape in MySQL strings
                if self.peek_char().is_some() {
                    self.bump();
                }
            }
        }

        let end = self.current_pos();

        Token {
            kind: TokenKind::Literal(LiteralKind::String),
            span: Span { start, end },
            leading_trivia,
            trailing_trivia: Vec::new(),
        }
    }

    /// Lex a backtick-quoted identifier: `column_name` (MySQL).
    fn lex_backtick_identifier(&mut self, leading_trivia: Vec<Trivia>) -> Token {
        let start = self.current_pos();
        self.bump(); // opening `

        while let Some(c) = self.peek_char() {
            self.bump();
            if c == '`' {
                // doubled backtick escape ``
                if let Some('`') = self.peek_char() {
                    self.bump();
                    continue;
                }
                break;
            }
        }

        let end = self.current_pos();

        Token {
            kind: TokenKind::Identifier {
                kind: IdentifierKind::Quoted,
                word_operator: None,
            },
            span: Span { start, end },
            leading_trivia,
            trailing_trivia: Vec::new(),
        }
    }

    /// Lex a bracket-delimited identifier: [column_name] (MSSQL/T-SQL).
    /// In T-SQL, `]]` inside brackets represents a literal `]` character.
    fn lex_bracket_identifier(&mut self, leading_trivia: Vec<Trivia>) -> Token {
        let start = self.current_pos();
        self.bump(); // opening [

        while let Some(c) = self.peek_char() {
            self.bump();
            if c == ']' {
                // doubled ]] escape: literal ] inside identifier
                if let Some(']') = self.peek_char() {
                    self.bump();
                    continue;
                }
                break;
            }
        }

        let end = self.current_pos();

        Token {
            kind: TokenKind::Identifier {
                kind: IdentifierKind::Quoted,
                word_operator: None,
            },
            span: Span { start, end },
            leading_trivia,
            trailing_trivia: Vec::new(),
        }
    }

    /// Lex a T-SQL `@variable` or `@@system_variable` identifier.
    /// Consumes the `@` or `@@` prefix plus the identifier body.
    fn lex_at_identifier(&mut self, leading_trivia: Vec<Trivia>) -> Token {
        let start = self.current_pos();
        self.bump(); // consume first @

        // Check for @@ (system variable)
        if let Some('@') = self.peek_char() {
            self.bump(); // consume second @
        }

        // Validate that at least one identifier-start character follows the prefix.
        // Bare `@` (no identifier body) is not a `@var` reference — it is the
        // standalone `@` operator. MySQL uses it as the user/host separator in
        // grantee literals (`'user'@'host'`). Emit `Operator::At` so the parser
        // can match on a typed kind rather than falling back to lexeme inspection.
        let has_body = self
            .peek_char()
            .is_some_and(|c| is_identifier_start(c) || c == '_');
        if !has_body {
            let end = self.current_pos();
            return Token {
                kind: TokenKind::Operator(Operator::At),
                span: Span { start, end },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        // Consume identifier body
        while let Some(c) = self.peek_char() {
            if self.is_ident_continue(c) {
                self.bump();
            } else {
                break;
            }
        }

        let end = self.current_pos();

        Token {
            kind: TokenKind::Identifier {
                kind: IdentifierKind::AtVariable,
                word_operator: None,
            },
            span: Span { start, end },
            leading_trivia,
            trailing_trivia: Vec::new(),
        }
    }

    /// Lex a T-SQL `#temp_table` or `##global_temp_table` identifier.
    /// Consumes the `#` or `##` prefix plus the identifier body.
    fn lex_hash_identifier(&mut self, leading_trivia: Vec<Trivia>) -> Token {
        let start = self.current_pos();
        self.bump(); // consume first #

        // Check for ## (global temp table)
        if let Some('#') = self.peek_char() {
            self.bump(); // consume second #
        }

        // Consume identifier body
        while let Some(c) = self.peek_char() {
            if self.is_ident_continue(c) {
                self.bump();
            } else {
                break;
            }
        }

        let end = self.current_pos();

        Token {
            kind: TokenKind::Identifier {
                kind: IdentifierKind::TempTable,
                word_operator: None,
            },
            span: Span { start, end },
            leading_trivia,
            trailing_trivia: Vec::new(),
        }
    }

    /// Lex a PostgreSQL E'...' escape string literal.
    /// The E prefix enables C-style escape sequences: \n, \t, \\, \', etc.
    fn lex_escape_string(&mut self, leading_trivia: Vec<Trivia>) -> Token {
        let start = self.current_pos();
        self.bump(); // consume E
        self.bump(); // consume opening '

        while let Some(c) = self.peek_char() {
            if c == '\\' {
                // Escape sequence - consume the backslash and the next character
                self.bump();
                if self.peek_char().is_some() {
                    self.bump();
                }
                continue;
            }
            self.bump();
            if c == '\'' {
                // doubled quote escape ''
                if let Some('\'') = self.peek_char() {
                    self.bump();
                    continue;
                }
                break;
            }
        }

        let end = self.current_pos();

        Token {
            kind: TokenKind::Literal(LiteralKind::String),
            span: Span { start, end },
            leading_trivia,
            trailing_trivia: Vec::new(),
        }
    }

    /// Lex an MSSQL national string literal: N'...'.
    /// Uses single-quote escaping rules (`''` for embedded quote).
    fn lex_national_string(&mut self, leading_trivia: Vec<Trivia>) -> Token {
        let start = self.current_pos();
        self.bump(); // consume N/n prefix
        self.bump(); // consume opening '

        while let Some(c) = self.peek_char() {
            self.bump();
            if c == '\'' {
                // doubled quote escape ''
                if let Some('\'') = self.peek_char() {
                    self.bump();
                    continue;
                }
                break;
            }
        }

        let end = self.current_pos();
        let text = &self.source[start as usize..end as usize];
        let is_complete = text.ends_with('\'');
        let kind = if is_complete {
            TokenKind::Literal(LiteralKind::String)
        } else {
            TokenKind::Literal(LiteralKind::StringFragment)
        };

        Token {
            kind,
            span: Span { start, end },
            leading_trivia,
            trailing_trivia: Vec::new(),
        }
    }

    /// Lex a PostgreSQL dollar-quoted string: $$body$$ or $tag$body$tag$.
    /// Called when we've already peeked and confirmed this is a dollar-quote pattern
    /// (not a positional parameter or identifier).
    fn lex_dollar_quoted_string(&mut self, leading_trivia: Vec<Trivia>) -> Token {
        let start = self.current_pos();

        // Consume the opening tag: $$ or $tag$
        self.bump(); // first $

        // Consume optional tag name between the dollars (the tag text is derived
        // from the opening-delimiter span below, so no separate copy is kept).
        while let Some(c) = self.peek_char() {
            if c == '$' {
                break;
            }
            if is_identifier_continue(c) {
                self.bump();
            } else {
                // Not a valid dollar-quote — fall back to identifier
                return self.finish_dollar_identifier(start, leading_trivia);
            }
        }

        // Consume the closing $ of the opening tag
        if self.peek_char() != Some('$') {
            return self.finish_dollar_identifier(start, leading_trivia);
        }
        self.bump(); // closing $ of opening tag

        let open_end = self.pos; // body content starts here
        let tag_lo = start as usize;
        let tag_len = open_end - tag_lo; // length of `$tag$` (open tag == close tag)

        // Opaque scan for the matching close tag. PostgreSQL dollar-quote
        // semantics: the close is the first literal `$tag$` after the opener,
        // regardless of any string/comment structure between. Scanning opaquely
        // here BOUNDS the body so the subsequent token-level inner lexing can
        // never overrun the close tag (e.g. a body apostrophe cannot swallow it).
        // The scan is itself bounded by `effective_end()`: at top level that is
        // the source end; inside an enclosing body it is the enclosing close, so
        // a nested opener can only pair with a close that lies WITHIN its parent.
        let scan_end = self.effective_end();
        let mut scan = open_end;
        let mut close_at: Option<usize> = None;
        while scan < scan_end {
            if self.source[scan..].starts_with(&self.source[tag_lo..open_end]) {
                close_at = Some(scan);
                break;
            }
            scan += self.source[scan..]
                .chars()
                .next()
                .map(|c| c.len_utf8())
                .unwrap_or(1);
        }

        match close_at {
            Some(cs) => {
                self.dollar_quotes.push(crate::lexer::DollarQuote {
                    span: Span {
                        start,
                        end: (cs + tag_len) as u32,
                    },
                    content: Span {
                        start: open_end as u32,
                        end: cs as u32,
                    },
                });
                // Push a bounded dollar-body. `pos` is already at `open_end`
                // (body start); inner lexing runs until `cs`, then the close tag
                // `[cs, cs + tag_len)` is emitted as the closing delimiter. The
                // push (vs. a single slot) preserves any enclosing body's bound
                // so a nested region returns to its parent body on close.
                self.dollar_bodies.push((
                    cs,
                    Span {
                        start: cs as u32,
                        end: (cs + tag_len) as u32,
                    },
                ));
                self.mode = LexMode::DollarBody;
                // Emit the opening delimiter token (exactly `$tag$`).
                Token {
                    kind: TokenKind::Identifier {
                        kind: IdentifierKind::DollarQuoteDelimiter,
                        word_operator: None,
                    },
                    span: Span {
                        start,
                        end: open_end as u32,
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            }
            None if self.dollar_bodies.is_empty() => {
                // Unclosed top-level dollar-quote — consume to EOF and emit one
                // Unknown token so the parser rejects it (→ OpaqueContent) rather
                // than accepting a literal that silently swallows the rest of the
                // file; no body entered.
                self.pos = self.source.len();
                let end = self.current_pos();
                Token {
                    kind: TokenKind::Unknown,
                    span: Span { start, end },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            }
            None => {
                // A nested opener with no matching close inside the enclosing
                // body is not a valid nested dollar quote. Degrade to an ordinary
                // identifier (bounded by the parent body) so the enclosing
                // boundary stays intact rather than overrunning past it.
                self.finish_dollar_identifier(start, leading_trivia)
            }
        }
    }

    /// Whether a scanner that started at `start` has reached the closing `$$`
    /// of the `$$…$$` string, written as words, that it started inside.
    fn at_dollar_words_close(&self, start: u32) -> bool {
        self.dollar_words_close
            .is_some_and(|close| close > start as usize && self.pos >= close)
    }

    /// Tracks the `$$…$$` string, written as words, that the `$$` at `start`
    /// opens or closes: the `$$` at the open string's closer closes it, any
    /// other opens one that runs to the next `$$`.
    fn note_dollar_quote(&mut self, start: usize) {
        if self.dollar_words_close == Some(start) {
            self.dollar_words_close = None;
            return;
        }
        self.dollar_words_close = self.source[start + 2..].find("$$").map(|at| start + 2 + at);
        // A string no `$$` closes runs to the end of the source.
        let close = self.dollar_words_close.unwrap_or(self.source.len());
        self.dollar_quotes.push(crate::lexer::DollarQuote {
            span: Span {
                start: start as u32,
                end: (close + 2).min(self.source.len()) as u32,
            },
            content: Span {
                start: (start + 2) as u32,
                end: close as u32,
            },
        });
    }

    /// Helper: finish lexing a dollar-prefixed token as an identifier (fallback).
    fn finish_dollar_identifier(&mut self, start: u32, leading_trivia: Vec<Trivia>) -> Token {
        while let Some(c) = self.peek_char() {
            if self.is_ident_continue(c) || c == '$' {
                self.bump();
            } else {
                break;
            }
        }
        let end = self.current_pos();
        Token {
            kind: TokenKind::Identifier {
                kind: IdentifierKind::Unquoted,
                word_operator: None,
            },
            span: Span { start, end },
            leading_trivia,
            trailing_trivia: Vec::new(),
        }
    }

    fn lex_number(&mut self, leading_trivia: Vec<Trivia>) -> Token {
        let start = self.current_pos();
        let grammar = self.dialect.number_literal_grammar();
        let separators = grammar.digit_separators;

        if !self.lex_radix_digits(grammar) {
            let mut integer = true;
            if let Some(c) = self.peek_char() {
                if c.is_ascii_digit() {
                    self.bump_digit_run(|d| d.is_ascii_digit(), separators);
                } else if c == '.' {
                    // Leading '.' case: .123
                    self.bump();
                    integer = false;
                }
            }

            // Optional fractional part for forms like 123.45 or 123.
            if let Some('.') = self.peek_char() {
                // Lookahead for ".." (range, not part of the number)
                let mut iter = self.source[self.pos..].chars();
                let first = iter.next();
                let second = iter.next();
                if matches!(first, Some('.')) && !matches!(second, Some('.')) {
                    // Single '.' as decimal point
                    self.bump();
                    integer = false;
                    self.bump_digit_run(|d| d.is_ascii_digit(), separators);
                }
            } else {
                // We started with '.', consume trailing digits for .123 or .0
                self.bump_digit_run(|d| d.is_ascii_digit(), separators);
            }

            // Optional exponent part: e[+/-]?digits
            if let Some(c) = self.peek_char() {
                if c == 'e' || c == 'E' {
                    // Look ahead to ensure this looks like an exponent (has digit after optional sign).
                    let mut iter = self.source[self.pos + c.len_utf8()..].chars();
                    let maybe_sign = iter.next();
                    let mut next_after_sign = maybe_sign;
                    if matches!(maybe_sign, Some('+') | Some('-')) {
                        next_after_sign = iter.next();
                    }
                    if matches!(next_after_sign, Some(d) if d.is_ascii_digit()) {
                        // Consume 'e' / 'E'
                        self.bump();
                        integer = false;
                        // Optional sign
                        if let Some(sign) = self.peek_char() {
                            if sign == '+' || sign == '-' {
                                self.bump();
                            }
                        }
                        // At least one digit (we know it's there from lookahead)
                        self.bump_digit_run(|d| d.is_ascii_digit(), separators);
                    }
                }
            }

            if grammar.type_suffixes {
                self.bump_type_suffix(integer);
            }
        }

        let end = self.current_pos();

        Token {
            kind: TokenKind::Literal(LiteralKind::Number),
            span: Span { start, end },
            leading_trivia,
            trailing_trivia: Vec::new(),
        }
    }

    /// Consumes `0x…`, `0b…` or `0o…` where `grammar` reads that prefix in
    /// the case written and a digit of its radix follows (an `_` before it
    /// where the grammar has digit separators). Returns whether it did.
    fn lex_radix_digits(&mut self, grammar: NumberLiteralGrammar) -> bool {
        let mut chars = self.source[self.pos..self.effective_end()].chars();
        if chars.next() != Some('0') {
            return false;
        }
        let Some(letter) = chars.next() else {
            return false;
        };
        let (prefix, is_digit): (RadixPrefix, fn(char) -> bool) = match letter.to_ascii_lowercase()
        {
            'x' => (grammar.hexadecimal, |d| d.is_ascii_hexdigit()),
            'b' => (grammar.binary, |d| matches!(d, '0' | '1')),
            'o' => (grammar.octal, |d| matches!(d, '0'..='7')),
            _ => return false,
        };
        let case_read = match prefix {
            RadixPrefix::Absent => false,
            RadixPrefix::LowerCase => letter.is_ascii_lowercase(),
            RadixPrefix::AnyCase => true,
        };
        let first = match chars.next() {
            Some('_') if grammar.digit_separators => chars.next(),
            other => other,
        };
        if !case_read || !first.is_some_and(is_digit) {
            return false;
        }
        self.bump();
        self.bump();
        if self.peek_char() == Some('_') {
            self.bump();
        }
        self.bump_digit_run(is_digit, grammar.digit_separators);
        true
    }

    /// Consumes the digits `is_digit` accepts from here, and, where
    /// `separators`, each `_` written between two of them.
    fn bump_digit_run(&mut self, is_digit: impl Fn(char) -> bool, separators: bool) {
        let mut after_digit = false;
        while let Some(c) = self.peek_char() {
            if is_digit(c) {
                self.bump();
                after_digit = true;
            } else if separators
                && c == '_'
                && after_digit
                && self.peek_next_char().is_some_and(&is_digit)
            {
                self.bump();
            } else {
                break;
            }
        }
    }

    /// Consumes a type suffix written against a number (`BD`, `D`, `F`, and on
    /// an `integer` also `L`, `S`, `Y`), in either case, when no name
    /// character follows it.
    fn bump_type_suffix(&mut self, integer: bool) {
        let rest = &self.source[self.pos..self.effective_end()];
        let len = if rest.get(..2).is_some_and(|s| s.eq_ignore_ascii_case("BD")) {
            2
        } else {
            match rest.chars().next().map(|c| c.to_ascii_uppercase()) {
                Some('D' | 'F') => 1,
                Some('L' | 'S' | 'Y') if integer => 1,
                Some(_) | None => 0,
            }
        };
        let ends_word = rest[len..]
            .chars()
            .next()
            .is_none_or(|c| !self.is_ident_continue(c));
        if len > 0 && ends_word {
            for _ in 0..len {
                self.bump();
            }
        }
    }

    fn lex_string(&mut self, leading_trivia: Vec<Trivia>) -> Token {
        let start = self.current_pos();
        let backslash_escapes = self.dialect.backslash_escapes_in_single_quoted_strings();
        // Inside a `$$` string written as words, the quote ends at its closer.
        let mut stopped_at_close = false;
        // opening quote
        self.bump();

        while let Some(c) = self.peek_char() {
            if self.at_dollar_words_close(start) {
                stopped_at_close = true;
                break;
            }
            // Jinja-first: Check for {{ before consuming the character.
            // If we see {{, stop the string here so the Jinja expression
            // is lexed as its own token.
            if c == '{' {
                if let Some(next) = self.peek_next_char() {
                    if next == '{' || next == '%' || next == '#' {
                        // Mark that we're in an interrupted string so the continuation
                        // after the Jinja block is handled correctly
                        self.in_interrupted_string = true;
                        // End the string fragment here (before the Jinja delimiter)
                        break;
                    }
                }
            }

            // Backslash escape: consume \ + next char as pair.
            // Snowflake and MySQL always interpret \ as escape in '...' strings.
            // PostgreSQL only does this in E'...' strings (handled by lex_escape_string).
            //
            // CRITICAL: We must check whether the next char exists before consuming.
            // If `\` is at EOF, we just consume it as a regular character and let
            // the string be unclosed. This prevents eating the closing quote as
            // an escaped character when it is actually the end of the string.
            if backslash_escapes && c == '\\' {
                if let Some(next) = self.peek_next_char() {
                    // \' (escaped quote) - consume both and continue
                    // \n, \t, \\, etc. - consume both and continue
                    self.bump(); // consume backslash
                    self.bump(); // consume escaped char
                    let _ = next; // used for readability
                    continue;
                }
                // Backslash at EOF with no char to escape — fall through
                // to the normal bump+close-quote logic below (string will be unclosed)
            }

            self.bump();
            if c == '\'' {
                // doubled quote inside string
                if let Some('\'') = self.peek_char() {
                    self.bump();
                    continue;
                }
                // String completed normally - clear interrupted state
                self.in_interrupted_string = false;
                break;
            }
        }

        let end = self.current_pos();
        let text = &self.source[start as usize..end as usize];

        // Determine the token kind based on whether the string is complete
        // A complete string ends with a closing quote (and is not a doubled quote escape)
        let is_complete = text.ends_with('\'') && !self.in_interrupted_string;
        let kind = if stopped_at_close {
            // Part of the text of a `$$` string written as words.
            TokenKind::Literal(LiteralKind::StringFragment)
        } else if is_complete {
            TokenKind::Literal(LiteralKind::String)
        } else if self.in_interrupted_string || !self.dollar_bodies.is_empty() {
            // Interrupted by a Jinja block (continuation follows), or bounded
            // inside a dollar-quoted body — a legitimate fragment.
            TokenKind::Literal(LiteralKind::StringFragment)
        } else {
            // Ran to EOF with no closing quote: an unterminated string literal.
            // Emit Unknown so the parser rejects it (→ OpaqueContent) rather than
            // accepting a literal that silently swallows the rest of the file.
            TokenKind::Unknown
        };

        Token {
            kind,
            span: Span { start, end },
            leading_trivia,
            trailing_trivia: Vec::new(),
        }
    }

    /// Lex the continuation of a string after a Jinja block.
    /// This handles the case: `'prefix{{ expr }}suffix'`
    /// After the Jinja expression, we see `suffix'` which needs to be lexed as a string fragment/end.
    fn lex_string_continuation(&mut self, leading_trivia: Vec<Trivia>) -> Token {
        let start = self.current_pos();

        while let Some(c) = self.peek_char() {
            // Check for another embedded Jinja block
            if c == '{' {
                if let Some(next) = self.peek_next_char() {
                    if next == '{' || next == '%' || next == '#' {
                        // Another Jinja block - keep in_interrupted_string = true
                        break;
                    }
                }
            }

            self.bump();
            if c == '\'' {
                // This could be the end of the string or a doubled quote escape
                if let Some('\'') = self.peek_char() {
                    // Doubled quote - escape, continue
                    self.bump();
                    continue;
                }
                // String completed - clear interrupted state
                self.in_interrupted_string = false;
                break;
            }
        }

        // If we hit EOF, clear the interrupted state to prevent infinite loop
        if self.is_eof() {
            self.in_interrupted_string = false;
        }

        let end = self.current_pos();
        let text = &self.source[start as usize..end as usize];

        // Handle empty fragment case (can happen at EOF or when immediately hitting Jinja)
        if text.is_empty() {
            // If we hit another Jinja block with no content between, just return empty fragment
            // The next call will handle the Jinja
            return Token {
                kind: TokenKind::Literal(LiteralKind::StringFragment),
                span: Span { start, end },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        Token {
            kind: TokenKind::Literal(LiteralKind::StringFragment),
            span: Span { start, end },
            leading_trivia,
            trailing_trivia: Vec::new(),
        }
    }

    /// Lex Jinja expression: {{ ... }}
    ///
    /// Optimization: Scans directly to first }} instead of tracking nested depth.
    /// Nested {{ }} doesn't exist in valid Jinja2 syntax, so this is safe and ~30% faster.
    fn lex_jinja_expression(&mut self, leading_trivia: Vec<Trivia>) -> Token {
        let start = self.current_pos();

        // Enter Jinja expression mode and reset brace depth
        self.mode = LexMode::JinjaExpr;
        self.jinja_brace_depth = 0;
        self.jinja_expr_unbalanced = false;

        // Consume opening delimiters: {{ or {{-
        self.bump(); // {
        self.bump(); // {

        // Check for optional whitespace-stripping dash: {{-
        if let Some('-') = self.peek_char() {
            self.bump(); // -
        }

        Token {
            kind: TokenKind::JinjaExprOpen,
            span: Span {
                start,
                end: self.current_pos(),
            },
            leading_trivia,
            trailing_trivia: Vec::new(),
        }
    }

    /// Lex Jinja statement: {% ... %}
    fn lex_jinja_statement(&mut self, leading_trivia: Vec<Trivia>) -> Token {
        let start = self.current_pos();

        // Enter Jinja statement mode and reset brace depth
        self.mode = LexMode::JinjaStmt;
        self.jinja_brace_depth = 0;
        self.jinja_tag_first = true;

        // Consume opening delimiters: {% or {%-
        self.bump(); // {
        self.bump(); // %

        // Check for optional whitespace-stripping dash: {%-
        if let Some('-') = self.peek_char() {
            self.bump(); // -
        }

        Token {
            kind: TokenKind::JinjaStmtOpen,
            span: Span {
                start,
                end: self.current_pos(),
            },
            leading_trivia,
            trailing_trivia: Vec::new(),
        }
    }

    /// Lex Jinja comment: {# ... #}
    fn lex_jinja_comment(&mut self, leading_trivia: Vec<Trivia>) -> Token {
        self.lex_jinja_token(leading_trivia, '#', '#', TokenKind::JinjaComment, false)
    }

    /// Unified Jinja token lexing method.
    ///
    /// Handles {{ }}, {% %}, and {# #} syntax with optional depth tracking.
    ///
    /// # Arguments
    /// * `leading_trivia` - Trivia collected before this token
    /// * `open_char` - Second character of opening delimiter ('{', '%', or '#')
    /// * `close_char` - First character of closing delimiter ('}', '%', or '#')
    /// * `kind` - Token kind to create
    /// * `track_depth` - Whether to track nesting depth (only needed for {% %} statements)
    fn lex_jinja_token(
        &mut self,
        leading_trivia: Vec<Trivia>,
        open_char: char,
        close_char: char,
        kind: TokenKind,
        track_depth: bool,
    ) -> Token {
        let start = self.current_pos();

        // Consume opening delimiters: { + open_char
        self.bump(); // {
        self.bump(); // open_char

        if track_depth {
            // Track nesting depth for {% %} statements (supports nested control flow)
            let mut depth = 1;
            while let Some(c) = self.peek_char() {
                if c == '{' {
                    self.bump();
                    if self.peek_char() == Some(open_char) {
                        self.bump();
                        depth += 1;
                    }
                } else if c == close_char {
                    self.bump();
                    if self.peek_char() == Some('}') {
                        self.bump();
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                } else {
                    self.bump();
                }
            }
        } else {
            // Fast path: scan directly to first closing delimiter (for {{ }} and {# #})
            // This is safe because nested delimiters don't exist in valid Jinja2 syntax
            while let Some(c) = self.peek_char() {
                if c == close_char {
                    self.bump();
                    if self.peek_char() == Some('}') {
                        self.bump();
                        break;
                    }
                } else {
                    self.bump();
                }
            }
        }

        let end = self.current_pos();

        Token {
            kind,
            span: Span { start, end },
            leading_trivia,
            trailing_trivia: Vec::new(),
        }
    }

    fn lex_positional_or_identifier(&mut self, leading_trivia: Vec<Trivia>) -> Token {
        let start = self.current_pos();
        // consume '$'
        let dollar_start = start;
        self.bump();

        // `$<n>`: a bind parameter, a column by position or a money literal,
        // as the dialect reads it
        let mut tmp_pos = self.pos;
        let mut had_digit = false;
        while tmp_pos < self.source.len() {
            let c = self.source[tmp_pos..]
                .chars()
                .next()
                .expect_invariant("Character should exist at valid position");
            if c.is_ascii_digit() {
                had_digit = true;
                tmp_pos += c.len_utf8();
            } else {
                break;
            }
        }

        if had_digit {
            // commit the digit consumption
            while self.pos < tmp_pos {
                self.bump();
            }
            let kind = match self.dialect.dollar_number() {
                DollarNumber::PositionalColumn => LiteralKind::Position,
                DollarNumber::Parameter => LiteralKind::Parameter,
                DollarNumber::Money => {
                    // The fraction is part of the literal: `$1.50`.
                    let fraction = self.peek_char() == Some('.')
                        && self.peek_next_char().is_some_and(|c| c.is_ascii_digit());
                    if fraction {
                        self.bump();
                        while self.peek_char().is_some_and(|c| c.is_ascii_digit()) {
                            self.bump();
                        }
                    }
                    LiteralKind::Money
                }
            };
            let span = Span {
                start: dollar_start,
                end: self.current_pos(),
            };
            return Token {
                kind: TokenKind::Literal(kind),
                span,
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        // Dialect-aware: PostgreSQL $$...$$ and $tag$...$tag$ dollar-quoted strings.
        // At this point we've consumed the first '$'. Check if this looks like a
        // dollar-quote opening: either another '$' (empty tag) or identifier chars
        // followed by '$'.
        // This fires inside a dollar body too: a DIFFERENT-tag dollar quote nested
        // in a body (e.g. dynamic SQL built from `$sql$…$sql$` fragments inside a
        // `$$…$$` routine body) is a real nested region. `next_dollar_body_token`
        // checks the enclosing close BEFORE this path runs, so any opener seen
        // here lies strictly within the parent body; `lex_dollar_quoted_string`
        // bounds the nested close-scan to the parent and degrades a closeless
        // opener to an identifier, so the enclosing boundary is never corrupted.
        if self.dialect.supports_dollar_quoted_strings() {
            if let Some(next) = self.peek_char() {
                if next == '$' || is_identifier_start(next) {
                    // Reset to the first '$' and let lex_dollar_quoted_string handle it
                    self.pos = start as usize;
                    return self.lex_dollar_quoted_string(leading_trivia);
                }
            }
        }

        // Where the dialect writes a `$$…$$` string as words, its opening and
        // closing `$$` are delimiters of their own.
        if self.dialect.dollar_strings_written_as_words() && self.peek_char() == Some('$') {
            self.bump();
            self.note_dollar_quote(start as usize);
            return Token {
                kind: TokenKind::Identifier {
                    kind: IdentifierKind::DollarQuoteDelimiter,
                    word_operator: None,
                },
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            };
        }

        // Otherwise, treat the whole thing as an identifier starting with '$'
        while let Some(c) = self.peek_char() {
            if self.at_dollar_words_close(start) {
                break;
            }
            if self.is_ident_continue(c) || c == '$' {
                self.bump();
            } else {
                break;
            }
        }
        let end = self.current_pos();

        Token {
            kind: TokenKind::Identifier {
                kind: IdentifierKind::Unquoted,
                word_operator: None,
            },
            span: Span { start, end },
            leading_trivia,
            trailing_trivia: Vec::new(),
        }
    }

    fn lex_symbol_or_operator(&mut self, leading_trivia: Vec<Trivia>, start: u32) -> Token {
        let ch = self
            .peek_char()
            .expect_invariant("Character should be available in lex_symbol_or_operator");

        // Multi-char operators first
        let token = if ch == ':' {
            if let Some('=') = self.peek_next_char() {
                self.bump();
                self.bump();
                Token {
                    kind: TokenKind::Operator(Operator::ColonEq),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            } else if let Some(':') = self.peek_next_char() {
                self.bump();
                self.bump();
                Token {
                    kind: TokenKind::Operator(Operator::ColonColon),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            } else {
                self.bump();
                Token {
                    kind: TokenKind::Punctuation(Punctuation::Colon),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            }
        } else if ch == '=' {
            if let Some('>') = self.peek_next_char() {
                self.bump();
                self.bump();
                Token {
                    kind: TokenKind::Operator(Operator::EqGt),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            } else if let Some('=') = self.peek_next_char() {
                self.bump();
                self.bump();
                Token {
                    kind: TokenKind::Operator(Operator::EqEq),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            } else {
                self.bump();
                Token {
                    kind: TokenKind::Operator(Operator::Eq),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            }
        } else if ch == '!' {
            if let Some('=') = self.peek_next_char() {
                self.bump();
                self.bump();
                Token {
                    kind: TokenKind::Operator(Operator::NotEq),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            } else if let Some('~') = self.peek_next_char() {
                // PostgreSQL regex not match: !~ or !~*
                self.bump(); // consume !
                self.bump(); // consume ~
                if let Some('*') = self.peek_char() {
                    self.bump(); // consume *
                    Token {
                        kind: TokenKind::Operator(Operator::RegexNotMatchI),
                        span: Span {
                            start,
                            end: self.current_pos(),
                        },
                        leading_trivia,
                        trailing_trivia: Vec::new(),
                    }
                } else {
                    Token {
                        kind: TokenKind::Operator(Operator::RegexNotMatch),
                        span: Span {
                            start,
                            end: self.current_pos(),
                        },
                        leading_trivia,
                        trailing_trivia: Vec::new(),
                    }
                }
            } else {
                // T-SQL's `!<` and `!>`; a bare `!` is MySQL's prefix NOT.
                self.bump();
                let op = match self.peek_char() {
                    Some('<') => {
                        self.bump();
                        Operator::BangLt
                    }
                    Some('>') => {
                        self.bump();
                        Operator::BangGt
                    }
                    _ => Operator::Bang,
                };
                Token {
                    kind: TokenKind::Operator(op),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            }
        } else if ch == '<' {
            if let Some('=') = self.peek_next_char() {
                // <=> null-safe equality (MySQL / Spark) vs plain <=
                let chars: Vec<char> = self.source[self.pos..].chars().take(3).collect();
                if chars.len() == 3 && chars[1] == '=' && chars[2] == '>' {
                    self.bump();
                    self.bump();
                    self.bump();
                    Token {
                        kind: TokenKind::Operator(Operator::LtEqGt),
                        span: Span {
                            start,
                            end: self.current_pos(),
                        },
                        leading_trivia,
                        trailing_trivia: Vec::new(),
                    }
                } else {
                    self.bump();
                    self.bump();
                    Token {
                        kind: TokenKind::Operator(Operator::Le),
                        span: Span {
                            start,
                            end: self.current_pos(),
                        },
                        leading_trivia,
                        trailing_trivia: Vec::new(),
                    }
                }
            } else if let Some('>') = self.peek_next_char() {
                self.bump();
                self.bump();
                Token {
                    kind: TokenKind::Operator(Operator::AngleNotEq),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            } else if let Some('<') = self.peek_next_char() {
                // PostgreSQL bitwise left shift: <<
                self.bump();
                self.bump();
                Token {
                    kind: TokenKind::Operator(Operator::LtLt),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            } else if let Some('@') = self.peek_next_char() {
                // PostgreSQL array contained by: <@
                self.bump();
                self.bump();
                Token {
                    kind: TokenKind::Operator(Operator::LtAt),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            } else {
                // Check for PostgreSQL geometric distance operator: <->
                // Need to peek ahead TWO characters: next is '-' and one after is '>'
                let chars: Vec<char> = self.source[self.pos..].chars().take(3).collect();
                if chars.len() == 3 && chars[0] == '<' && chars[1] == '-' && chars[2] == '>' {
                    self.bump(); // consume <
                    self.bump(); // consume -
                    self.bump(); // consume >
                    Token {
                        kind: TokenKind::Operator(Operator::LtMinusGt),
                        span: Span {
                            start,
                            end: self.current_pos(),
                        },
                        leading_trivia,
                        trailing_trivia: Vec::new(),
                    }
                } else {
                    self.bump();
                    Token {
                        kind: TokenKind::Operator(Operator::Lt),
                        span: Span {
                            start,
                            end: self.current_pos(),
                        },
                        leading_trivia,
                        trailing_trivia: Vec::new(),
                    }
                }
            }
        } else if ch == '>' {
            if let Some('=') = self.peek_next_char() {
                self.bump();
                self.bump();
                Token {
                    kind: TokenKind::Operator(Operator::Ge),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            } else if let Some('>') = self.peek_next_char() {
                // PostgreSQL bitwise right shift: >>
                self.bump();
                self.bump();
                Token {
                    kind: TokenKind::Operator(Operator::GtGt),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            } else {
                self.bump();
                Token {
                    kind: TokenKind::Operator(Operator::Gt),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            }
        } else if ch == '|' {
            if let Some('|') = self.peek_next_char() {
                self.bump();
                self.bump();
                Token {
                    kind: TokenKind::Operator(Operator::PipePipe),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            } else if let Some('>') = self.peek_next_char() {
                // SQL pipe operator |>
                self.bump();
                self.bump();
                Token {
                    kind: TokenKind::Operator(Operator::PipeGt),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            } else if let Some('=') = self.peek_next_char() {
                // Compound bitwise OR assignment: |= (T-SQL)
                self.bump();
                self.bump();
                Token {
                    kind: TokenKind::Operator(Operator::PipeEq),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            } else if self.dialect.supports_postgres_operator_symbols()
                && self.source[self.pos..].starts_with("|/")
                && !self.source[self.pos..].starts_with("|/*")
            {
                // Square root `|/`; a `/*` after `|` opens a comment.
                self.bump();
                self.bump();
                Token {
                    kind: TokenKind::Operator(Operator::BarSlash),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            } else {
                self.bump();
                Token {
                    kind: TokenKind::Operator(Operator::Bar),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            }
        } else if ch == '+' || ch == '-' || ch == '*' || ch == '/' || ch == '%' {
            // Handle simple arithmetic, spread (**) operators, and '-' when not part of pipe.
            if ch == '*' {
                if let Some('*') = self.peek_next_char() {
                    // Spread operator '**'
                    self.bump();
                    self.bump();
                    Token {
                        kind: TokenKind::Operator(Operator::StarStar),
                        span: Span {
                            start,
                            end: self.current_pos(),
                        },
                        leading_trivia,
                        trailing_trivia: Vec::new(),
                    }
                } else {
                    self.bump();
                    Token {
                        kind: TokenKind::Operator(Operator::Star),
                        span: Span {
                            start,
                            end: self.current_pos(),
                        },
                        leading_trivia,
                        trailing_trivia: Vec::new(),
                    }
                }
            } else if ch == '-' {
                // Check for arrow operator '->' or flow pipe operator '->>'
                if let Some('>') = self.peek_next_char() {
                    // Look ahead one more char after '>'
                    let mut iter = self.source[self.pos..].chars();
                    let _dash = iter.next();
                    let gt1 = iter.next();
                    let gt2 = iter.next();
                    if matches!(gt1, Some('>')) && matches!(gt2, Some('>')) {
                        // '->>': in dialects that use it for JSON text extraction
                        // (PostgreSQL / MySQL) it is the dedicated `MinusGtGt`
                        // operator; elsewhere it is the `Pipe` flow operator. The
                        // dialect decision lives here so the downstream
                        // pipe-chain/boundary handling (which keys on `Pipe`)
                        // stays untouched for JSON dialects.
                        self.bump();
                        self.bump();
                        self.bump();
                        let op = if self.dialect.supports_json_operators() {
                            Operator::MinusGtGt
                        } else {
                            Operator::Pipe
                        };
                        Token {
                            kind: TokenKind::Operator(op),
                            span: Span {
                                start,
                                end: self.current_pos(),
                            },
                            leading_trivia,
                            trailing_trivia: Vec::new(),
                        }
                    } else {
                        // Arrow '->': Consume '-' and '>'
                        self.bump();
                        self.bump();
                        Token {
                            kind: TokenKind::Operator(Operator::RightArrow),
                            span: Span {
                                start,
                                end: self.current_pos(),
                            },
                            leading_trivia,
                            trailing_trivia: Vec::new(),
                        }
                    }
                } else {
                    self.bump();
                    Token {
                        kind: TokenKind::Operator(Operator::Minus),
                        span: Span {
                            start,
                            end: self.current_pos(),
                        },
                        leading_trivia,
                        trailing_trivia: Vec::new(),
                    }
                }
            } else {
                self.bump();
                let op = match ch {
                    '+' => Operator::Plus,
                    '-' => Operator::Minus,
                    '/' => Operator::Slash,
                    '%' => Operator::Percent,
                    _ => Operator::Plus,
                };
                Token {
                    kind: TokenKind::Operator(op),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            }
        } else if ch == '@' {
            // Dispatch priority: @-identifiers (MSSQL) take precedence over @> operator (PG).
            // In MSSQL, `@>` should be `@` (start of identifier) + `>` (operator).
            if self.dialect.supports_at_sign_identifiers() {
                // T-SQL: @var (local variable) or @@var (system variable)
                self.lex_at_identifier(leading_trivia)
            } else if let Some('>') = self.peek_next_char() {
                // PostgreSQL array contains: @>
                self.bump();
                self.bump();
                Token {
                    kind: TokenKind::Operator(Operator::AtGt),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            } else if self.dialect.supports_postgres_operator_symbols() {
                // `@@` match, `@?` path exists, a bare `@` absolute value
                self.bump();
                let op = match self.peek_char() {
                    Some('@') => {
                        self.bump();
                        Operator::AtAt
                    }
                    Some('?') => {
                        self.bump();
                        Operator::AtQuestion
                    }
                    _ => Operator::At,
                };
                Token {
                    kind: TokenKind::Operator(op),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            } else if self.dialect.at_is_operator() {
                // Databricks: @ is a time travel separator (events@v123)
                self.bump();
                Token {
                    kind: TokenKind::Operator(Operator::At),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            } else {
                self.bump();
                Token {
                    kind: TokenKind::Unknown,
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            }
        } else if ch == '&' {
            // `&&`: array overlap, or the dialect's logical AND.
            if let Some('&') = self.peek_next_char() {
                self.bump();
                self.bump();
                let op = match self.dialect.double_ampersand() {
                    DoubleAmpersand::ArrayOverlap => Operator::AmpAmp,
                    DoubleAmpersand::LogicalAnd => Operator::AmpAmpAnd,
                };
                Token {
                    kind: TokenKind::Operator(op),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            } else {
                // `&=` is T-SQL's compound assignment, as `|=`.
                self.bump();
                let op = if let Some('=') = self.peek_char() {
                    self.bump();
                    Operator::AmpEq
                } else {
                    Operator::Amp
                };
                Token {
                    kind: TokenKind::Operator(op),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            }
        } else if ch == '^' {
            // Exponentiation or bitwise XOR, as the dialect reads it;
            // PostgreSQL's `^@` is starts-with.
            self.bump();
            let op = if self.dialect.supports_postgres_operator_symbols()
                && self.peek_char() == Some('@')
            {
                self.bump();
                Operator::CaretAt
            } else {
                match self.dialect.caret() {
                    CaretOperator::BitwiseXor => Operator::Caret,
                    CaretOperator::Exponent => Operator::Power,
                }
            };
            Token {
                kind: TokenKind::Operator(op),
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            }
        } else if ch == '#' {
            // Dialect-aware: MySQL treats # as a line comment delimiter.
            // Snowflake/PostgreSQL treat it as an operator (bitwise XOR / JSON path extraction).
            if self.dialect.hash_is_line_comment() {
                // MySQL: # starts a line comment (skip to end of line, emit as trivia)
                self.bump(); // consume #
                while let Some(c) = self.peek_char() {
                    if c == '\n' || c == '\r' {
                        break;
                    }
                    self.bump();
                }
                let end = self.current_pos();
                // Re-enter the main loop — this token is trivia, not a real token.
                // We need to emit it as leading trivia of the NEXT token.
                // Return an empty-span token that the caller can skip,
                // or better: add to leading_trivia and recurse.
                let mut combined_trivia = leading_trivia;
                combined_trivia.push(Trivia {
                    kind: TriviaKind::LineComment,
                    span: Span { start, end },
                });
                return self.next_token_with_leading_trivia(combined_trivia);
            } else if self.dialect.hash_is_identifier_prefix() {
                // T-SQL: # starts temp table name (#temp or ##global_temp)
                self.lex_hash_identifier(leading_trivia)
            } else if let Some('>') = self.peek_next_char() {
                // Check for #>> (JSON path text extraction)
                let chars: Vec<char> = self.source[self.pos..].chars().take(3).collect();
                if chars.len() >= 3 && chars[1] == '>' && chars[2] == '>' {
                    self.bump(); // #
                    self.bump(); // >
                    self.bump(); // >
                    Token {
                        kind: TokenKind::Operator(Operator::HashGtGt),
                        span: Span {
                            start,
                            end: self.current_pos(),
                        },
                        leading_trivia,
                        trailing_trivia: Vec::new(),
                    }
                } else {
                    // #> (JSON path object extraction)
                    self.bump();
                    self.bump();
                    Token {
                        kind: TokenKind::Operator(Operator::HashGt),
                        span: Span {
                            start,
                            end: self.current_pos(),
                        },
                        leading_trivia,
                        trailing_trivia: Vec::new(),
                    }
                }
            } else {
                self.bump();
                Token {
                    kind: TokenKind::Operator(Operator::Hash),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            }
        } else if ch == '~' {
            // PostgreSQL regex match: ~ or ~*
            self.bump();
            if let Some('*') = self.peek_char() {
                self.bump();
                Token {
                    kind: TokenKind::Operator(Operator::RegexMatchI),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            } else {
                Token {
                    kind: TokenKind::Operator(Operator::Tilde),
                    span: Span {
                        start,
                        end: self.current_pos(),
                    },
                    leading_trivia,
                    trailing_trivia: Vec::new(),
                }
            }
        } else if ch == '?'
            && self.dialect.supports_postgres_operator_symbols()
            && matches!(self.peek_next_char(), Some('|' | '&'))
        {
            // Any or all of the keys exist: `?|`, `?&`
            self.bump();
            let op = if self.peek_char() == Some('|') {
                Operator::QuestionBar
            } else {
                Operator::QuestionAmp
            };
            self.bump();
            Token {
                kind: TokenKind::Operator(op),
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            }
        } else {
            // Punctuation or unknown
            self.bump();
            let kind = match ch {
                '(' => TokenKind::Punctuation(Punctuation::LParen),
                ')' => TokenKind::Punctuation(Punctuation::RParen),
                '[' => TokenKind::Punctuation(Punctuation::LBracket),
                ']' => TokenKind::Punctuation(Punctuation::RBracket),
                '{' => TokenKind::Punctuation(Punctuation::LCurly),
                '}' => TokenKind::Punctuation(Punctuation::RCurly),
                ',' => TokenKind::Punctuation(Punctuation::Comma),
                ';' => TokenKind::Punctuation(Punctuation::Semi),
                '.' => TokenKind::Punctuation(Punctuation::Dot),
                ':' => TokenKind::Punctuation(Punctuation::Colon),
                '?' => TokenKind::Placeholder,
                _ => TokenKind::Unknown,
            };
            Token {
                kind,
                span: Span {
                    start,
                    end: self.current_pos(),
                },
                leading_trivia,
                trailing_trivia: Vec::new(),
            }
        };

        token
    }

    /// Collect trailing trivia for a token on the SAME LINE.
    ///
    /// This includes:
    /// 1. Whitespace (spaces/tabs)
    /// 2. Same-line block comments `/* ... */`
    /// 3. Same-line line comments `-- ...` (these end at newline)
    ///
    /// We STOP at newlines - anything after a newline becomes leading trivia of the next token.
    /// This preserves the semantic association: `col1, /* comment */` keeps the comment with col1.
    fn collect_trailing_trivia(&mut self) -> Vec<Trivia> {
        let mut trivia = Vec::new();
        loop {
            if self.is_eof() {
                break;
            }
            if let Some(close) = self.take_executable_close() {
                trivia.push(close);
                continue;
            }
            let start = self.current_pos();
            let ch = match self.peek_char() {
                Some(c) => c,
                None => break,
            };

            // Whitespace (space/tab) - collect on same line
            if ch == ' ' || ch == '\t' {
                self.bump();
                while let Some(c2) = self.peek_char() {
                    if c2 == ' ' || c2 == '\t' {
                        self.bump();
                    } else {
                        break;
                    }
                }
                let end = self.current_pos();
                trivia.push(Trivia {
                    kind: TriviaKind::Whitespace,
                    span: Span { start, end },
                });
                continue;
            }

            // Newline - STOP here, don't collect as trailing
            // Things after newline become leading trivia of the next token
            if ch == '\n' || ch == '\r' {
                break;
            }

            // Block comment `/* ... */` on same line - collect as trailing
            if ch == '/' {
                if let Some('*') = self.peek_next_char() {
                    self.bump(); // consume '/'
                    self.bump(); // consume '*'

                    let body = self.consume_block_comment_body();

                    let end = self.current_pos();
                    let trivia_kind = match body {
                        BlockComment::Closed(kind) => kind,
                        BlockComment::Executable => {
                            self.executable_comment = true;
                            TriviaKind::MysqlVersionComment
                        }
                        BlockComment::Unterminated | BlockComment::Unreadable
                            if self.mode == LexMode::Sql && self.dollar_bodies.is_empty() =>
                        {
                            // Hand it to the next SQL-token step as an Unknown
                            // token rather than letting text vanish as trailing
                            // trivia on the current token.
                            self.unterminated_comment = Some(Span { start, end });
                            break;
                        }
                        BlockComment::Unterminated | BlockComment::Unreadable => {
                            TriviaKind::BlockComment
                        }
                    };
                    trivia.push(Trivia {
                        kind: trivia_kind,
                        span: Span { start, end },
                    });
                    continue;
                }
            }

            // Line comment `-- ...` on same line - collect as trailing
            // The comment extends to end of line but the newline itself stays out
            if ch == '-' {
                if let Some('-') = self.peek_next_char() {
                    // MySQL requires whitespace or a control character (a line
                    // end included) after `--` for it to be a comment. `--y` is
                    // two minus operators followed by identifier in MySQL.
                    if self.dialect.requires_space_after_double_dash() {
                        let is_comment = self
                            .peek_ahead_n(2)
                            .is_none_or(|c| c.is_whitespace() || c.is_control());
                        if !is_comment {
                            break; // not a comment in MySQL — leave for operator lexing
                        }
                    }

                    self.bump(); // consume '-'
                    self.bump(); // consume '-'
                    while let Some(c) = self.peek_char() {
                        if c == '\n' || c == '\r' || self.at_dollar_words_close(start) {
                            break; // stop before newline
                        }
                        self.bump();
                    }
                    let end = self.current_pos();
                    trivia.push(Trivia {
                        kind: TriviaKind::LineComment,
                        span: Span { start, end },
                    });
                    // After line comment, stop collecting trailing trivia
                    // (the newline is NOT part of this token's trailing trivia)
                    break;
                }
            }

            // Non-trivia character - stop
            break;
        }
        trivia
    }

    pub fn lex_all(mut self) -> crate::lexer::LexResult {
        let mut tokens = Vec::new();
        loop {
            let tok = self.next_token();
            let is_eof = matches!(tok.kind, TokenKind::Eof);
            tokens.push(tok);
            if is_eof {
                break;
            }
        }
        crate::lexer::LexResult {
            tokens,
            dollar_quotes: self.dollar_quotes,
        }
    }
}

/// psql's command that runs a `COPY` from the client.
const PSQL_COPY: &str = "\\copy";

fn is_identifier_start(ch: char) -> bool {
    // Allow ASCII letters and underscore for the first character.
    // (Snowflake also supports broader Unicode identifier starts, which we can add later.)
    ch.is_ascii_alphabetic() || ch == '_'
}

pub(super) fn is_identifier_continue(ch: char) -> bool {
    // Base identifier continuation: alphanumeric, underscore, and Unicode.
    // Does NOT include $ or # — those are dialect-specific via extra_identifier_chars().
    // Use Lexer::is_ident_continue() for dialect-aware checks.
    ch.is_ascii_alphanumeric()
        || ch == '_'
        || (!ch.is_ascii() && (ch.is_alphabetic() || ch.is_numeric()))
}

/// Zero-allocation keyword lookup using phf perfect hash map.
///
/// Uses a stack buffer to uppercase the input for case-insensitive matching,
/// then looks up in the compile-time generated KEYWORDS map.
///
/// SQL keywords are short (max ~20 chars like "STORAGE_INTEGRATION").
/// If the input is longer than 32 bytes, it can't be a keyword.
#[inline]
fn keyword_lookup(s: &str) -> Option<Keyword> {
    const MAX_KEYWORD_LEN: usize = 32;

    // Fast path: if longer than any keyword, skip lookup
    if s.len() > MAX_KEYWORD_LEN {
        return None;
    }

    // Stack-allocated buffer for uppercase conversion (no heap allocation)
    let mut buf = [0u8; MAX_KEYWORD_LEN];
    for (i, b) in s.bytes().enumerate() {
        buf[i] = b.to_ascii_uppercase();
    }

    // Safe conversion: to_ascii_uppercase() only changes ASCII letters,
    // preserving UTF-8 validity of the input.
    let upper = std::str::from_utf8(&buf[..s.len()]).ok()?;

    // O(1) lookup in compile-time perfect hash map
    KEYWORDS.get(upper).copied()
}
