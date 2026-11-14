// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! What names a secret, and where a string literal's text is: the two
//! questions every reader that masks secrets out of quoted SQL asks.

use crate::lexer::token::Span;

/// Whether `name` (a column, a field, a key, a variable or an option, as
/// written or normalised) names a secret: a credential property
/// ([`crate::parser::core::is_credential_value_property`]), or a name
/// holding a password, a secret, a private key, a token, an access or API
/// key or a connection string. Matched on a lowercased `contains`, so
/// `sslpassword`, `secret_access_key`, `pem_private_key` and
/// `azure_sas_token` are covered; a name ending in `pwd` (`Pwd`, `newpwd`)
/// is one, and so is a name whose last word is `key` (`app.key`,
/// `encryption_key`, `signing-key`) but a key of a table's structure
/// (`partitionKey`, `sort_key`), an Azure storage or Service Bus key
/// (`AccountKey`, `SharedAccessKey`), a shared access signature
/// (`SharedAccessSignature`) or its `sig`. A name is one too where a word
/// of it, or two words of it written together, name a credential: `pw`,
/// `pin`, `otp_seed`, `auth_header`, `authentication_string`, `credentials`,
/// `salt`, `stored_hash`, `jwt`, `dsn`, `conn_string`, `db_url`,
/// `session_cookie`, `cvv`, `ssn`, `webhook_url`; not `pass` before `fail`.
/// A name's words are written apart by any character
/// that is not a letter or a digit, by a lower-case letter followed by an
/// upper-case one (`userPw`), by the last capital of a run of them before a
/// lower-case letter (`APIKey`), and between letters and digits (`api2Key`).
/// Over-masking is safe: masking only affects what is displayed, never what
/// is read.
pub fn is_secret_name(name: &str) -> bool {
    let k = name.to_ascii_lowercase();
    let words = name_words(name);
    // The last run of letters and digits, and the last word of it.
    let last_run = k
        .trim_end_matches(|c: char| !c.is_ascii_alphanumeric())
        .rsplit(|c: char| !c.is_ascii_alphanumeric())
        .next();
    let last_word = words.last().map(String::as_str);
    // A key that is a table's structure (`partitionKey`, `sort_key`) holds
    // no secret.
    let structural_key = last_word == Some("key")
        && words
            .len()
            .checked_sub(2)
            .and_then(|at| words.get(at))
            .is_some_and(|before| STRUCTURAL_KEYS.contains(&before.as_str()));
    // `pass` before `fail` is a result, not a password.
    let result = |at: usize| {
        words.get(at).is_some_and(|word| word == "pass")
            && words.get(at + 1).is_some_and(|next| next == "fail")
    };
    words
        .iter()
        .enumerate()
        .any(|(at, word)| credential_word(word) && !result(at))
        || words
            .iter()
            .any(|word| CREDENTIAL_COMPOUNDS.contains(&word.as_str()))
        || words
            .windows(2)
            .any(|pair| CREDENTIAL_COMPOUNDS.contains(&format!("{}{}", pair[0], pair[1]).as_str()))
        || crate::parser::core::is_credential_value_property(&k.to_ascii_uppercase())
        || [
            "password",
            "passwd",
            "passphrase",
            "secret",
            "private_key",
            "privatekey",
            "token",
            "access_key",
            "accesskey",
            "api_key",
            "apikey",
            "connection_string",
            "connectionstring",
        ]
        .iter()
        .any(|fragment| k.contains(fragment))
        || k.ends_with("pwd")
        || matches!(last_word, Some("sig"))
        || (matches!(last_word, Some("key")) && !structural_key)
        || matches!(
            last_run,
            Some("accountkey" | "sharedaccesskey" | "sharedaccesssignature" | "sig")
        )
        || (matches!(last_run, Some("key")) && !structural_key)
}

/// The words that, written before `key`, name a key of a table's
/// structure rather than a secret: a partition, sort, primary or foreign
/// key, and the like.
const STRUCTURAL_KEYS: &[&str] = &[
    "partition",
    "sort",
    "primary",
    "secondary",
    "foreign",
    "unique",
    "cluster",
    "clustering",
    "distribution",
    "dist",
    "shard",
    "sharding",
    "natural",
    "surrogate",
    "business",
    "composite",
    "lookup",
    "join",
    "row",
    "idempotency",
    "dedup",
    "dedupe",
    "group",
    "index",
    "routing",
    "bucket",
    "cache",
];

/// The words, lowercased, that name a credential as a whole word of a
/// name: a password's short forms, a PIN, a one-time-password or MFA
/// secret, a credential, an authentication value, what a password is
/// stored with (a salt, a pepper, a hash), a card's verification code and
/// a social security number.
const CREDENTIAL_WORDS: &[&str] = &[
    "pw", "pwd", "pass", "passcode", "passkey", "pin", "pincode", "otp", "totp", "hotp", "mfa",
    "seed", "salt", "pepper", "hash", "auth", "authn", "jwt", "dsn", "bearer", "pgpass", "cvv",
    "cvv2", "cvc", "cvc2", "ssn",
];

/// What names a credential written as one word or as two (`conn_string`,
/// `connStr`, `dburl`): a connection string or URL, a private, SSH or
/// encryption key, a session cookie, a recovery or backup code, a refresh
/// token, a security answer, a webhook URL (which carries its token), a
/// card number and a key's material.
const CREDENTIAL_COMPOUNDS: &[&str] = &[
    "connstr",
    "connstring",
    "dburl",
    "databaseurl",
    "jdbcurl",
    "privkey",
    "sshkey",
    "enckey",
    "sessioncookie",
    "recoverycode",
    "recoverycodes",
    "backupcode",
    "backupcodes",
    "refreshtok",
    "securityanswer",
    "oauthrefresh",
    "webhookurl",
    "cardnumber",
    "cardno",
    "keyblob",
    "keymaterial",
];

/// The words of `name`, lowercased: written apart by any character that is
/// not a letter or a digit, by a lower-case letter followed by an upper-case
/// one, by the last capital of a run of them before a lower-case letter, and
/// between letters and digits.
fn name_words(name: &str) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let chars: Vec<char> = name.chars().collect();
    for (at, &c) in chars.iter().enumerate() {
        if !c.is_ascii_alphanumeric() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
            continue;
        }
        let before = at.checked_sub(1).and_then(|at| chars.get(at)).copied();
        let after = chars.get(at + 1).copied();
        let starts = before.is_some_and(|before| {
            (before.is_ascii_lowercase() && c.is_ascii_uppercase())
                || (before.is_ascii_uppercase()
                    && c.is_ascii_uppercase()
                    && after.is_some_and(|after| after.is_ascii_lowercase()))
                || (before.is_ascii_digit() != c.is_ascii_digit() && before.is_ascii_alphanumeric())
        });
        if starts && !word.is_empty() {
            words.push(std::mem::take(&mut word));
        }
        word.push(c.to_ascii_lowercase());
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

/// Whether `word`, a lowercased word of a name written without separators
/// inside it, names a credential: one of [`CREDENTIAL_WORDS`], or a word
/// that starts as one names its kind (`otpseed`, `authheader`,
/// `authentication`, `authorization`, `credential`, `totpsecret`) or ends
/// in a seed or a hash (`otpseed`, `pwhash`). `author` and `authority`
/// name no credential.
fn credential_word(word: &str) -> bool {
    // A plural names a list of credentials (`pins`, `salts`).
    credential_singular(word) || word.strip_suffix('s').is_some_and(credential_singular)
}

/// [`credential_word`] for a word as written.
fn credential_singular(word: &str) -> bool {
    let authenticates =
        word.starts_with("auth") && (!word.starts_with("author") || word.starts_with("authoriz"));
    CREDENTIAL_WORDS.contains(&word)
        || authenticates
        || word.contains("credential")
        || ["otp", "totp", "hotp", "mfa", "passcode", "pincode"]
            .iter()
            .any(|kind| word.starts_with(kind))
        || ["seed", "hash"].iter().any(|kind| word.ends_with(kind))
}

/// The span between the delimiters of the string literal `source` writes
/// at `span`, read as `dialect` reads it, in each spelling: quoted (`'…'`,
/// `"…"`), with a prefix written against it (`N'…'`, `E'…'`, `r'…'`,
/// `U&'…'`, a MySQL charset introducer such as `_utf8mb4'…'`), after a
/// charset introducer and white space (`_utf8mb4 '…'`), or dollar-quoted
/// (`$$…$$`, `$tag$…$tag$`). `span` itself where it writes no such
/// literal.
pub fn string_literal_content(
    span: Span,
    source: &str,
    dialect: &dyn crate::dialect::Dialect,
) -> Span {
    let Some(text) = source.get(span.start as usize..span.end as usize) else {
        return span;
    };
    let inside = |offset: usize, text: &str| {
        crate::lexer::decode_string_literal(text, dialect).map(|decoded| Span {
            start: span.start + offset as u32 + decoded.content.start,
            end: span.start + offset as u32 + decoded.content.end,
        })
    };
    if let Some(content) = inside(0, text) {
        return content;
    }
    // A charset introducer, white space, then the literal it reads.
    let introducer = text
        .find(char::is_whitespace)
        .filter(|&end| crate::lexer::is_charset_introducer(&text[..end]));
    introducer
        .and_then(|end| {
            let start = text.len() - text[end..].trim_start().len();
            inside(start, &text[start..])
        })
        .unwrap_or(span)
}

/// The byte range in `text` of the password of each URL it writes with
/// user information (`scheme://user:password@host/…`). The user
/// information runs from `://` to the last `@` before the next white space
/// or the end of the text, so a password written with an unencoded `/`,
/// `?`, `#` or `@` is read whole; the password is what follows its first
/// `:`. User information with no `:` writes no password, and neither does
/// a URL whose text between `://` and that `:` holds a `/`, `?` or `#` (a
/// path, query or fragment holding `a:b@c`), nor one that reads as
/// `host:port` with an all-digit port, no `@` before the path, query or
/// fragment after it.
pub fn url_password_ranges(text: &str) -> Vec<std::ops::Range<usize>> {
    let mut ranges = Vec::new();
    let mut word_start = 0;
    for piece in text.split_inclusive(char::is_whitespace) {
        let word = piece.trim_end_matches(char::is_whitespace);
        let offset = word_start;
        word_start += piece.len();
        let Some(last_at) = word.rfind('@') else {
            continue;
        };
        let mut from = 0;
        while let Some(k) = word[from..last_at].find("://") {
            let start = from + k + 3;
            from = start;
            let scheme_written = word[..start - 3]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric());
            let Some(colon) = word[start..last_at]
                .find([':', '/', '?', '#'])
                .map(|k| start + k)
                .filter(|&k| scheme_written && word.as_bytes()[k] == b':')
            else {
                continue;
            };
            let authority_end = word[colon..]
                .find(['/', '?', '#'])
                .map_or(word.len(), |k| colon + k);
            let port = &word[colon + 1..authority_end];
            let host_and_port = !word[start..authority_end].contains('@')
                && !port.is_empty()
                && port.bytes().all(|b| b.is_ascii_digit());
            if !host_and_port {
                ranges.push(offset + colon + 1..offset + last_at);
                break;
            }
        }
    }
    ranges
}

/// One `key=value` entry of a connection string, as byte ranges of the
/// text it is read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionStringEntry {
    /// The key, white space around it left out.
    pub key: std::ops::Range<usize>,
    /// The value, inside the delimiters (`"…"`, `{…}`) that close around
    /// it; a value with no delimiter, or one that does not close, reads to
    /// the next `;`, trailing white space left out.
    pub value: std::ops::Range<usize>,
    /// All the text the value may be written in, from its first character
    /// past the spaces after `=`: its delimiters included, and to the end of
    /// the text where a delimiter does not close.
    pub written: std::ops::Range<usize>,
}

/// The `key=value` entries of the connection string `text`
/// (`Server=s;Uid=u;Pwd=…;`), in order. An entry ends at the `;` not
/// inside its value's delimiters: `"…"`, or `{…}` where `}}` is one `}`.
/// Text before a `;` that writes no `=` is no entry.
pub fn connection_string_entries(text: &str) -> Vec<ConnectionStringEntry> {
    let bytes = text.as_bytes();
    let mut entries = Vec::new();
    let mut entry = 0usize;
    while entry < bytes.len() {
        // The key runs to `=`, the value to the `;` not inside its quotes.
        let Some(eq) = text[entry..].find(['=', ';']).map(|k| entry + k) else {
            break;
        };
        if bytes[eq] == b';' {
            entry = eq + 1;
            continue;
        }
        let key_text = &text[entry..eq];
        let key_start = entry + (key_text.len() - key_text.trim_start().len());
        let key_end = key_start + key_text.trim().len();
        let mut value_start = eq + 1;
        while value_start < bytes.len() && bytes[value_start] == b' ' {
            value_start += 1;
        }
        let close = match bytes.get(value_start) {
            Some(b'"') => Some(
                text[value_start + 1..]
                    .find('"')
                    .map(|k| value_start + 1 + k),
            ),
            Some(b'{') => Some(braced_value_close(bytes, value_start + 1)),
            _ => None,
        };
        let to_semicolon = text[value_start..]
            .find(';')
            .map_or(bytes.len(), |k| value_start + k);
        let undelimited =
            value_start..value_start + text[value_start..to_semicolon].trim_end().len();
        let (value, written_end) = match close {
            Some(Some(close)) => (value_start + 1..close, close + 1),
            Some(None) => (undelimited, bytes.len()),
            None => (undelimited, to_semicolon),
        };
        entries.push(ConnectionStringEntry {
            key: key_start..key_end,
            value,
            written: value_start..written_end,
        });
        entry = written_end + 1;
    }
    entries
}

/// The byte range in `text`, read as a connection string, of all the text
/// each value is written in ([`ConnectionStringEntry::written`]) whose key
/// names a secret ([`is_secret_name`]).
pub(crate) fn connection_string_secret_values(text: &str) -> Vec<std::ops::Range<usize>> {
    secret_values_of(text, connection_string_entries(text))
}

/// [`connection_string_secret_values`] of `text` where it reads as a
/// connection string wherever it is written, and none otherwise. Each key
/// is a keyword (words of ASCII letters, digits, `_`, `.`, `-` or `:`, one
/// space between two), no value opens with `'` (a value that does is a SQL
/// string, and the text SQL: `PASSWORD = 'x'`), and a value written in
/// delimiters ends its part. A `;`-separated part that writes no entry (a
/// JDBC URL's `jdbc:sqlserver://h`, a stray word) is read past where every
/// key is one word; where a key is several, every part writes an entry or
/// only white space, which SQL text read as entries does not
/// (`BEGIN SET password = p; END`).
pub(crate) fn written_connection_string_secret_values(text: &str) -> Vec<std::ops::Range<usize>> {
    let entries = connection_string_entries(text);
    let is_word = |word: &str| {
        !word.is_empty()
            && word
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b':'))
    };
    let keys_are_keywords = entries
        .iter()
        .all(|entry| text[entry.key.clone()].split(' ').all(is_word));
    let a_value_is_sql_string = entries
        .iter()
        .any(|entry| text[entry.written.start..].starts_with('\''));
    if entries.is_empty() || !keys_are_keywords || a_value_is_sql_string {
        return Vec::new();
    }
    let one_word_keys = entries
        .iter()
        .all(|entry| !text[entry.key.clone()].contains(' '));
    // The text between two entries, before the first or after the last:
    // after an entry, its part ends at the next `;`.
    let reads = |between: &str, after_entry: bool| {
        let rest = between.trim_start();
        (!after_entry || rest.is_empty() || rest.starts_with(';'))
            && (one_word_keys || between.chars().all(|c| c == ';' || c.is_whitespace()))
    };
    let mut read_to = 0;
    for entry in &entries {
        if !reads(&text[read_to..entry.key.start], read_to > 0) {
            return Vec::new();
        }
        read_to = entry.written.end;
    }
    if !reads(&text[read_to..], true) {
        return Vec::new();
    }
    secret_values_of(text, entries)
}

/// The written ranges of `entries`, read from `text`, whose key names a
/// secret and whose value is written.
fn secret_values_of(
    text: &str,
    entries: Vec<ConnectionStringEntry>,
) -> Vec<std::ops::Range<usize>> {
    entries
        .into_iter()
        .filter(|entry| is_secret_name(&text[entry.key.clone()]) && !entry.written.is_empty())
        .map(|entry| entry.written)
        .collect()
}

/// What each place of T-SQL `OPENROWSET`'s `'data source';'user';'password'`
/// run holds, named as a connection string names it.
pub const LOGIN_RUN_KEYS: [&str; 3] = ["Data Source", "User ID", "Password"];

/// A string literal written directly among the arguments of a connection
/// call (`OPENROWSET (…)`, `OPENDATASOURCE (…)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionCallString {
    /// Its index in the tokens read.
    pub token: usize,
    /// Its place, from 0, in a run of strings separated by `;`
    /// (`'data source';'user';'password'`, named by [`LOGIN_RUN_KEYS`]);
    /// `None` for a string that is an argument alone.
    pub place_in_run: Option<usize>,
}

/// The string literals a connection call's argument tokens write outside
/// the parentheses nested in them, in order. `tokens` start after the
/// call's `(` and are read up to the `)` that closes it, or to their end;
/// they hold no comment.
pub fn connection_call_strings(tokens: &[crate::lexer::Token]) -> Vec<ConnectionCallString> {
    use crate::lexer::{LiteralKind, Punctuation, TokenKind};
    let mut depth = 0u32;
    let mut run = 0usize;
    let mut strings = Vec::new();
    for (i, token) in tokens.iter().enumerate() {
        let kind = &token.kind;
        if matches!(kind, TokenKind::Punctuation(Punctuation::LParen)) {
            depth += 1;
        } else if matches!(kind, TokenKind::Punctuation(Punctuation::RParen)) {
            if depth == 0 {
                break;
            }
            depth -= 1;
        } else if depth > 0 {
            continue;
        } else if matches!(kind, TokenKind::Punctuation(Punctuation::Comma)) {
            run = 0;
        } else if matches!(kind, TokenKind::Literal(LiteralKind::String)) {
            let in_run = run > 0
                || matches!(
                    tokens.get(i + 1).map(|t| &t.kind),
                    Some(TokenKind::Punctuation(Punctuation::Semi))
                );
            strings.push(ConnectionCallString {
                token: i,
                place_in_run: in_run.then_some(run),
            });
            run += usize::from(in_run);
        }
    }
    strings
}

/// The index of the `}` that closes a `{…}` value whose content starts at
/// `from`: the first `}` not doubled (`}}` is one `}`).
fn braced_value_close(bytes: &[u8], from: usize) -> Option<usize> {
    let mut k = from;
    while k < bytes.len() {
        if bytes[k] == b'}' {
            if bytes.get(k + 1) == Some(&b'}') {
                k += 2;
                continue;
            }
            return Some(k);
        }
        k += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passwords(text: &str) -> Vec<&str> {
        url_password_ranges(text)
            .into_iter()
            .map(|r| &text[r])
            .collect()
    }

    fn entries(text: &str) -> Vec<(&str, &str, &str)> {
        connection_string_entries(text)
            .into_iter()
            .map(|e| (&text[e.key], &text[e.value], &text[e.written]))
            .collect()
    }

    #[test]
    fn url_password_is_the_user_information_after_its_colon() {
        assert_eq!(passwords("s3://u:pw@b/p"), ["pw"]);
        assert_eq!(passwords("jdbc:mysql://u:p:w@h:3306/db"), ["p:w"]);
        assert_eq!(passwords("https://u:a@b@h/x"), ["a@b"]);
        assert_eq!(passwords("https://u:@h"), [""]);
        assert_eq!(passwords("see s3://u:a@b and gs://v:c@d/e"), ["a", "c"]);
        assert!(passwords("s3://u@b/p:x@y").is_empty());
        assert!(passwords("s3://b/a:b@c").is_empty());
        assert!(passwords("://u:p@h").is_empty());
    }

    #[test]
    fn url_password_may_hold_a_slash_a_question_mark_or_a_hash() {
        assert_eq!(
            passwords("s3://AKIAX:wJalr/K7MDENG@bucket/p/"),
            ["wJalr/K7MDENG"]
        );
        assert_eq!(passwords("s3://u:pre?Qw7@b/p/"), ["pre?Qw7"]);
        assert_eq!(passwords("s3://u:pre#Qw7@b/p/"), ["pre#Qw7"]);
        assert_eq!(passwords("gs://u:a/b?c#d@b/*.csv"), ["a/b?c#d"]);
        assert_eq!(passwords("s3://u:a/b@c and s3://v:d#e@f"), ["a/b", "d#e"]);
        // A path, query or fragment before the first `:` holds no password.
        assert!(passwords("https://h/p?x=a:b@c").is_empty());
        assert!(passwords("https://h?x=a:b@c").is_empty());
        assert!(passwords("https://h#a:b@c").is_empty());
        // A host and its port, then a path holding `@`, hold no password.
        assert!(passwords("jdbc:snowflake://h.example.com:443/?user=jane@corp.com").is_empty());
        assert!(passwords("https://h:8080/x#a@b").is_empty());
        assert_eq!(passwords("https://u:8080@h/p"), ["8080"]);
        assert_eq!(passwords("s3://u:/wJalr@b/p"), ["/wJalr"]);
    }

    #[test]
    fn connection_string_values_close_at_their_delimiters() {
        assert_eq!(
            entries("Server=s;UID=u;PWD=p;"),
            [("Server", "s", "s"), ("UID", "u", "u"), ("PWD", "p", "p")]
        );
        assert_eq!(entries(" Password = p "), [("Password", "p", "p ")]);
        assert_eq!(
            entries("PWD={a;b};x=1"),
            [("PWD", "a;b", "{a;b}"), ("x", "1", "1")]
        );
        assert_eq!(entries("PWD={a}}b};"), [("PWD", "a}}b", "{a}}b}")]);
        assert_eq!(entries("PWD=\"a;b\""), [("PWD", "a;b", "\"a;b\"")]);
        // A template is no delimited value: its braces never close.
        assert_eq!(
            entries("PWD={{ secrets.pw }};x=1"),
            [("PWD", "{{ secrets.pw }}", "{{ secrets.pw }};x=1")]
        );
        assert_eq!(entries("junk;PWD=p"), [("PWD", "p", "p")]);
    }

    fn written_secrets(text: &str) -> Vec<&str> {
        written_connection_string_secret_values(text)
            .into_iter()
            .map(|r| &text[r])
            .collect()
    }

    #[test]
    fn text_read_as_a_connection_string_is_entries_alone() {
        assert_eq!(written_secrets("Server=h;Password=p;"), ["p"]);
        assert_eq!(written_secrets("password=p"), ["p"]);
        assert_eq!(written_secrets(" Uid=u; Pwd = \"a;b\" ;"), ["\"a;b\""]);
        assert_eq!(written_secrets("Jet OLEDB:Database Password={p}"), ["{p}"]);
        assert!(written_secrets("Server=p;Uid=u").is_empty());
        // A part that is no entry, where every key is one word.
        assert_eq!(written_secrets("junk;PWD=p"), ["p"]);
        assert_eq!(
            written_secrets("jdbc:sqlserver://h:1;user=sa;password=p;"),
            ["p"]
        );
        assert_eq!(written_secrets("User=u;Password=p;Port=1;X;"), ["p"]);
        assert_eq!(written_secrets("Password=p'';DROP TABLE x;--"), ["p''"]);
        // Azure storage, Service Bus and shared access signature keys.
        assert_eq!(
            written_secrets("AccountName=a;AccountKey=k==;EndpointSuffix=s"),
            ["k=="]
        );
        // `SharedAccessKeyName` holds `accesskey`: its value is masked too.
        assert_eq!(
            written_secrets("SharedAccessKeyName=R;SharedAccessKey=k="),
            ["R", "k="]
        );
        assert_eq!(
            written_secrets("BlobEndpoint=https://a/;SharedAccessSignature=sv=1&sig=s"),
            ["sv=1&sig=s"]
        );
        // SQL text: a part that is no entry beside a key of several words,
        // a key that is no keyword, a value that is a SQL string.
        assert!(written_secrets("BEGIN SET password = p; END").is_empty());
        assert!(written_secrets("Data Source=h;Password=p;X").is_empty());
        assert!(written_secrets("SELECT 'password=p'").is_empty());
        assert!(written_secrets("PASSWORD = ''p''").is_empty());
        assert!(written_secrets("PASSWORD = 'p'").is_empty());
        assert!(written_secrets("Pwd=\"p\"x;Server=h").is_empty());
        assert!(written_secrets("").is_empty());
    }
}
