use std::collections::HashMap;
use std::io::{self, BufRead, Write as IoWrite};
use std::path::PathBuf;
use std::sync::OnceLock;

use quick_xml::events::{BytesStart, BytesText, Event};
use quick_xml::{Reader, Writer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

#[derive(Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

impl JsonRpcResponse {
    fn ok(id: Value, result: Value) -> Self {
        Self { jsonrpc: "2.0".into(), id: Some(id), result: Some(result), error: None }
    }
    fn err(id: Value, code: i64, message: String) -> Self {
        Self { jsonrpc: "2.0".into(), id: Some(id), result: None, error: Some(JsonRpcError { code, message }) }
    }
}

// ---------------------------------------------------------------------------
// MCP notifications
// ---------------------------------------------------------------------------

fn send_notification(level: &str, message: &str) {
    let notification = json!({
        "jsonrpc": "2.0",
        "method": "notifications/message",
        "params": { "level": level, "logger": "xml-mcp", "data": message }
    });
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let _ = serde_json::to_writer(&mut out, &notification);
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

fn tool_notification(name: &str, args: &Value) -> String {
    let file = args.get("xml_file")
        .or_else(|| args.get("json_file"))
        .and_then(|v| v.as_str());
    let expr = args.get("expression").and_then(|v| v.as_str());

    match name {
        "xpath_query" => {
            let mut msg = "Querying XML with XPath".to_string();
            if let Some(e) = expr { msg.push_str(&format!(": {e}")); }
            if let Some(f) = file { msg.push_str(&format!(" in {f}")); }
            msg
        }
        "xpath_set" => {
            let mut msg = "Setting values via XPath".to_string();
            if let Some(e) = expr { msg.push_str(&format!(": {e}")); }
            if let Some(f) = file { msg.push_str(&format!(" in {f}")); }
            msg
        }
        "xpath_delete" => {
            let mut msg = "Deleting nodes via XPath".to_string();
            if let Some(e) = expr { msg.push_str(&format!(": {e}")); }
            if let Some(f) = file { msg.push_str(&format!(" in {f}")); }
            msg
        }
        "xpath_add" => {
            let mut msg = "Adding nodes via XPath".to_string();
            if let Some(e) = expr { msg.push_str(&format!(": {e}")); }
            if let Some(f) = file { msg.push_str(&format!(" in {f}")); }
            msg
        }
        "xml_to_json" => {
            if let Some(f) = file { format!("Converting {f} to JSON") }
            else { "Converting XML to JSON".into() }
        }
        "json_to_xml" => {
            if let Some(f) = file { format!("Converting {f} to XML") }
            else { "Converting JSON to XML".into() }
        }
        "xml_format" => {
            let mode = args.get("mode").and_then(|v| v.as_str()).unwrap_or("pretty");
            if let Some(f) = file { format!("Formatting {f} ({mode})") }
            else { format!("Formatting XML ({mode})") }
        }
        "xml_validate" => {
            if let Some(f) = file { format!("Validating {f}") }
            else { "Validating XML".into() }
        }
        "xml_diff" => "Comparing XML documents".into(),
        "xml_tree" => {
            if let Some(f) = file { format!("Showing structure of {f}") }
            else { "Showing XML structure".into() }
        }
        "xml_transform" => {
            if let Some(f) = file { format!("Transforming {f} with XSLT") }
            else { "Transforming XML with XSLT".into() }
        }
        "schema_infer" => {
            let store = args.get("store_as").and_then(|v| v.as_str());
            let mut msg = "Inferring XML schema".to_string();
            if let Some(f) = file { msg.push_str(&format!(" from {f}")); }
            if let Some(s) = store { msg.push_str(&format!(" → '{s}'")); }
            msg
        }
        "schema_store" => {
            let sn = args.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            format!("Storing schema '{sn}'")
        }
        "schema_get" => {
            let sn = args.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            format!("Loading schema '{sn}'")
        }
        "schema_list" => "Listing schemas".into(),
        "schema_delete" => {
            let sn = args.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            format!("Deleting schema '{sn}'")
        }
        "xml_generate" => {
            let sn = args.get("schema_name").and_then(|v| v.as_str()).unwrap_or("?");
            format!("Generating XML from schema '{sn}'")
        }
        _ => format!("Running {name}"),
    }
}

// ---------------------------------------------------------------------------
// Schema storage — persists to ~/.config/xml-mcp/schemas/
// ---------------------------------------------------------------------------

static SCHEMA_DIR: OnceLock<PathBuf> = OnceLock::new();

fn schema_dir() -> &'static PathBuf {
    SCHEMA_DIR.get_or_init(|| {
        let dir = dirs_or_default().join("schemas");
        let _ = std::fs::create_dir_all(&dir);
        dir
    })
}

fn dirs_or_default() -> PathBuf {
    if let Some(config) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(config).join("xml-mcp")
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".config").join("xml-mcp")
    } else {
        PathBuf::from("/tmp/xml-mcp")
    }
}

fn validate_schema_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Schema name cannot be empty.".into());
    }
    if name.contains('/') || name.contains('\\') || name.contains("..") || name.contains('\0') {
        return Err(format!("Invalid schema name '{name}': must not contain path separators or '..'"));
    }
    Ok(())
}

fn schema_path(name: &str) -> Result<PathBuf, String> {
    validate_schema_name(name)?;
    Ok(schema_dir().join(format!("{name}.json")))
}

fn schema_save(name: &str, schema: &Value) -> Result<(), String> {
    let path = schema_path(name)?;
    let content = serde_json::to_string_pretty(schema).map_err(|e| format!("Failed to serialize: {e}"))?;
    std::fs::write(&path, content).map_err(|e| format!("Failed to write {}: {e}", path.display()))
}

fn schema_load(name: &str) -> Result<Value, String> {
    let path = schema_path(name)?;
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Schema '{name}' not found: {e}. Use schema_list to see available schemas."))?;
    serde_json::from_str(&content).map_err(|e| format!("Invalid schema JSON: {e}"))
}

fn schema_list_all() -> Result<Vec<String>, String> {
    let dir = schema_dir();
    let mut names = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|e| format!("Cannot read schema dir: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("Dir entry error: {e}"))?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            if let Some(stem) = path.file_stem() {
                names.push(stem.to_string_lossy().into_owned());
            }
        }
    }
    names.sort();
    Ok(names)
}

fn schema_delete_file(name: &str) -> Result<(), String> {
    let path = schema_path(name)?;
    std::fs::remove_file(&path).map_err(|e| format!("Failed to delete schema '{name}': {e}"))
}

fn schema_summary(schema: &Value) -> String {
    let element = schema.get("element").and_then(|v| v.as_str()).unwrap_or("?");
    let attrs = schema.get("attributes").and_then(|v| v.as_object()).map_or(0, |m| m.len());
    let children = schema.get("children").and_then(|v| v.as_array()).map_or(0, |a| a.len());
    let has_text = schema.get("has_text").and_then(|v| v.as_bool()).unwrap_or(false);

    let mut parts = vec![format!("<{element}>")];
    if attrs > 0 {
        parts.push(format!("{attrs} attr(s)"));
    }
    if children > 0 {
        parts.push(format!("{children} child(ren)"));
    }
    if has_text {
        parts.push("text".into());
    }
    parts.join(", ")
}

// ---------------------------------------------------------------------------
// XML tree representation
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct XmlElement {
    name: String,
    attributes: Vec<(String, String)>,
    children: Vec<XmlChild>,
}

#[derive(Clone, Debug)]
enum XmlChild {
    Element(XmlElement),
    Text(String),
    CData(String),
    Comment(String),
}

impl XmlElement {
    /// Returns text content, trimmed. Avoids intermediate allocations.
    fn text_content(&self) -> String {
        let mut s = String::new();
        for child in &self.children {
            match child {
                XmlChild::Text(t) | XmlChild::CData(t) => s.push_str(t),
                _ => {}
            }
        }
        // Trim in-place by finding bounds, then truncating
        let trimmed = s.trim();
        if trimmed.len() == s.len() {
            s
        } else {
            trimmed.to_string()
        }
    }

    /// Returns iterator over child elements (avoids Vec allocation)
    fn child_elements(&self) -> impl Iterator<Item = &XmlElement> {
        self.children.iter().filter_map(|c| match c {
            XmlChild::Element(el) => Some(el),
            _ => None,
        })
    }

    /// Returns count of child elements without allocating
    fn child_element_count(&self) -> usize {
        self.children.iter().filter(|c| matches!(c, XmlChild::Element(_))).count()
    }

    fn get_attribute(&self, name: &str) -> Option<&str> {
        self.attributes.iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

// ---------------------------------------------------------------------------
// XML parsing — quick-xml events → tree
// ---------------------------------------------------------------------------

fn parse_xml_tree(xml: &str) -> Result<XmlElement, String> {
    let mut reader = Reader::from_str(xml);

    let mut stack: Vec<XmlElement> = Vec::new();
    let mut root: Option<XmlElement> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let name = std::str::from_utf8(e.name().as_ref())
                    .map_err(|err| format!("Invalid element name: {err}"))?
                    .to_string();
                let attrs = read_attributes(e)?;
                stack.push(XmlElement { name, attributes: attrs, children: Vec::new() });
            }
            Ok(Event::End(_)) => {
                let completed = stack.pop().ok_or("Unexpected closing tag")?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(XmlChild::Element(completed));
                } else {
                    root = Some(completed);
                }
            }
            Ok(Event::Empty(ref e)) => {
                let name = std::str::from_utf8(e.name().as_ref())
                    .map_err(|err| format!("Invalid element name: {err}"))?
                    .to_string();
                let attrs = read_attributes(e)?;
                let elem = XmlElement { name, attributes: attrs, children: Vec::new() };
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(XmlChild::Element(elem));
                } else {
                    root = Some(elem);
                }
            }
            Ok(Event::Text(ref e)) => {
                let text = e.unescape().map_err(|err| format!("Text error: {err}"))?.to_string();
                if !text.chars().all(|c| c.is_whitespace()) {
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(XmlChild::Text(text));
                    }
                }
            }
            Ok(Event::CData(ref e)) => {
                let text = std::str::from_utf8(e.as_ref())
                    .map_err(|err| format!("CData error: {err}"))?
                    .to_string();
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(XmlChild::CData(text));
                }
            }
            Ok(Event::Comment(ref e)) => {
                let text = std::str::from_utf8(e.as_ref())
                    .map_err(|err| format!("Comment error: {err}"))?
                    .to_string();
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(XmlChild::Comment(text));
                }
            }
            Ok(Event::Eof) => {
                if !stack.is_empty() {
                    let unclosed: Vec<&str> = stack.iter().map(|el| el.name.as_str()).collect();
                    return Err(format!(
                        "XML parse error: unclosed element(s): <{}>",
                        unclosed.join(">, <")
                    ));
                }
                break;
            }
            Ok(_) => {} // Skip declarations, PIs
            Err(e) => return Err(format!("XML parse error at position {}: {e}", reader.error_position())),
        }
    }

    root.ok_or_else(|| "Empty XML document: no root element found".to_string())
}

fn read_attributes(e: &BytesStart) -> Result<Vec<(String, String)>, String> {
    let mut attrs = Vec::new();
    for attr in e.attributes() {
        let attr = attr.map_err(|err| format!("Attribute error: {err}"))?;
        let key = std::str::from_utf8(attr.key.as_ref())
            .map_err(|err| format!("Attribute key error: {err}"))?
            .to_string();
        let val = attr.unescape_value()
            .map_err(|err| format!("Attribute value error: {err}"))?
            .to_string();
        attrs.push((key, val));
    }
    Ok(attrs)
}

// ---------------------------------------------------------------------------
// XML serialization — tree → string
// ---------------------------------------------------------------------------

/// Escape XML text content - single pass, no intermediate allocations
fn escape_xml_text(s: &str) -> std::borrow::Cow<'_, str> {
    if s.bytes().any(|b| matches!(b, b'&' | b'<' | b'>')) {
        let mut out = String::with_capacity(s.len() + 8);
        for c in s.chars() {
            match c {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                _ => out.push(c),
            }
        }
        std::borrow::Cow::Owned(out)
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

/// Escape XML attribute value - single pass, no intermediate allocations
fn escape_xml_attr(s: &str) -> std::borrow::Cow<'_, str> {
    if s.bytes().any(|b| matches!(b, b'&' | b'<' | b'>' | b'"')) {
        let mut out = String::with_capacity(s.len() + 8);
        for c in s.chars() {
            match c {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '"' => out.push_str("&quot;"),
                _ => out.push(c),
            }
        }
        std::borrow::Cow::Owned(out)
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

fn write_element(element: &XmlElement, indent: usize, pretty: bool, out: &mut String) {
    // Write indent
    if pretty {
        for _ in 0..indent {
            out.push(' ');
        }
    }

    // Opening tag
    out.push('<');
    out.push_str(&element.name);
    for (k, v) in &element.attributes {
        out.push(' ');
        out.push_str(k);
        out.push_str("=\"");
        out.push_str(&escape_xml_attr(v));
        out.push('"');
    }

    if element.children.is_empty() {
        out.push_str("/>");
        if pretty { out.push('\n'); }
        return;
    }

    out.push('>');

    let has_element_children = element.children.iter().any(|c| matches!(c, XmlChild::Element(_)));

    if has_element_children && pretty {
        out.push('\n');
    }

    for child in &element.children {
        match child {
            XmlChild::Element(el) => write_element(el, indent + 2, pretty, out),
            XmlChild::Text(t) => out.push_str(&escape_xml_text(t)),
            XmlChild::CData(c) => {
                out.push_str("<![CDATA[");
                out.push_str(c);
                out.push_str("]]>");
            }
            XmlChild::Comment(c) => {
                if pretty {
                    for _ in 0..indent + 2 {
                        out.push(' ');
                    }
                }
                out.push_str("<!--");
                out.push_str(c);
                out.push_str("-->");
                if pretty { out.push('\n'); }
            }
        }
    }

    if has_element_children && pretty {
        for _ in 0..indent {
            out.push(' ');
        }
    }
    out.push_str("</");
    out.push_str(&element.name);
    out.push('>');
    if pretty { out.push('\n'); }
}

fn serialize_element(element: &XmlElement, pretty: bool) -> String {
    let mut out = String::new();
    write_element(element, 0, pretty, &mut out);
    out
}

// ---------------------------------------------------------------------------
// XPath — full XPath 1.0 implementation
// ---------------------------------------------------------------------------

// --- Tokens ---

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Name(String), Str(String), Num(f64),
    Slash, DSlash, Dot, DDot, At, Star, Pipe,
    LBrack, RBrack, LParen, RParen, Comma,
    Eq, Ne, Lt, Gt, Le, Ge, Plus, Minus,
    And, Or, Div, Mod, DColon,
}

fn is_name_start(c: char) -> bool { c.is_ascii_alphabetic() || c == '_' }
fn is_name_char(c: char) -> bool { c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') }

/// Tokenize XPath expression - works directly on &str to avoid Vec<char> allocation
fn tokenize_xpath(input: &str) -> Result<Vec<Tok>, String> {
    let bytes = input.as_bytes();
    let mut toks: Vec<Tok> = Vec::with_capacity(16); // Pre-allocate for typical expressions
    let mut i = 0;

    // Helper to get char at byte position (ASCII-safe for XPath syntax)
    let char_at = |pos: usize| -> Option<char> {
        bytes.get(pos).map(|&b| b as char)
    };

    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_whitespace() { i += 1; continue; }

        match c {
            '/' if char_at(i + 1) == Some('/') => { toks.push(Tok::DSlash); i += 2; }
            '/' => { toks.push(Tok::Slash); i += 1; }
            '.' if char_at(i + 1) == Some('.') => { toks.push(Tok::DDot); i += 2; }
            '.' if char_at(i + 1).is_some_and(|c| c.is_ascii_digit()) => {
                let s = i; i += 1;
                while i < bytes.len() && (bytes[i] as char).is_ascii_digit() { i += 1; }
                let n = &input[s..i];
                toks.push(Tok::Num(n.parse().map_err(|_| format!("Bad number: {n}"))?));
            }
            '.' => { toks.push(Tok::Dot); i += 1; }
            '@' => { toks.push(Tok::At); i += 1; }
            '*' => { toks.push(Tok::Star); i += 1; }
            '|' => { toks.push(Tok::Pipe); i += 1; }
            '[' => { toks.push(Tok::LBrack); i += 1; }
            ']' => { toks.push(Tok::RBrack); i += 1; }
            '(' => { toks.push(Tok::LParen); i += 1; }
            ')' => { toks.push(Tok::RParen); i += 1; }
            ',' => { toks.push(Tok::Comma); i += 1; }
            '+' => { toks.push(Tok::Plus); i += 1; }
            '-' => { toks.push(Tok::Minus); i += 1; }
            '=' => { toks.push(Tok::Eq); i += 1; }
            '!' if char_at(i + 1) == Some('=') => { toks.push(Tok::Ne); i += 2; }
            '<' if char_at(i + 1) == Some('=') => { toks.push(Tok::Le); i += 2; }
            '<' => { toks.push(Tok::Lt); i += 1; }
            '>' if char_at(i + 1) == Some('=') => { toks.push(Tok::Ge); i += 2; }
            '>' => { toks.push(Tok::Gt); i += 1; }
            q @ ('\'' | '"') => {
                i += 1;
                let s = i;
                while i < bytes.len() && bytes[i] as char != q { i += 1; }
                if i >= bytes.len() { return Err("Unterminated string".into()); }
                toks.push(Tok::Str(input[s..i].to_string()));
                i += 1;
            }
            c if c.is_ascii_digit() => {
                let s = i;
                while i < bytes.len() && matches!(bytes[i] as char, '0'..='9' | '.') { i += 1; }
                let n = &input[s..i];
                toks.push(Tok::Num(n.parse().map_err(|_| format!("Bad number: {n}"))?));
            }
            c if is_name_start(c) => {
                let s = i;
                while i < bytes.len() && is_name_char(bytes[i] as char) { i += 1; }
                if char_at(i) == Some(':') && char_at(i + 1) == Some(':') {
                    // axis::
                    toks.push(Tok::Name(input[s..i].to_string()));
                    toks.push(Tok::DColon);
                    i += 2;
                } else if char_at(i) == Some(':') && char_at(i + 1).is_some_and(|c| is_name_start(c) || c == '*') {
                    // namespace prefix
                    i += 1;
                    if bytes[i] as char == '*' { i += 1; }
                    else { while i < bytes.len() && is_name_char(bytes[i] as char) { i += 1; } }
                    toks.push(Tok::Name(input[s..i].to_string()));
                } else {
                    let name = &input[s..i];
                    let is_op = toks.last().is_some_and(|t| matches!(t,
                        Tok::RBrack | Tok::RParen | Tok::Str(_) | Tok::Num(_) |
                        Tok::Name(_) | Tok::Star | Tok::Dot | Tok::DDot
                    ));
                    if is_op {
                        match name {
                            "and" => toks.push(Tok::And),
                            "or" => toks.push(Tok::Or),
                            "div" => toks.push(Tok::Div),
                            "mod" => toks.push(Tok::Mod),
                            _ => toks.push(Tok::Name(name.to_string())),
                        }
                    } else {
                        toks.push(Tok::Name(name.to_string()));
                    }
                }
            }
            c => return Err(format!("Unexpected char '{c}' in XPath")),
        }
    }
    Ok(toks)
}

// --- AST ---

#[derive(Debug, Clone)]
enum Expr {
    Path(bool, Vec<Step>),          // (absolute, steps)
    Union(Box<Expr>, Box<Expr>),
    BinOp(Op, Box<Expr>, Box<Expr>),
    Neg(Box<Expr>),
    FnCall(String, Vec<Expr>),
    Lit(String),
    NumLit(f64),
}

#[derive(Debug, Clone)]
struct Step {
    axis: Axis,
    test: NodeTest,
    preds: Vec<Expr>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Axis {
    Child, Descendant, DescendantOrSelf, Parent, Ancestor, AncestorOrSelf,
    FollowingSibling, PrecedingSibling, Following, Preceding, Self_, Attribute,
}

#[derive(Debug, Clone)]
enum NodeTest { Name(String), Wildcard, Text, Node, Comment }

#[derive(Debug, Clone, Copy)]
enum Op { Eq, Ne, Lt, Gt, Le, Ge, Add, Sub, Mul, Div, Mod, And, Or }

// --- Parser ---

struct XParser { toks: Vec<Tok>, pos: usize }

impl XParser {
    fn new(toks: Vec<Tok>) -> Self { Self { toks, pos: 0 } }
    fn peek(&self) -> Option<&Tok> { self.toks.get(self.pos) }
    fn advance(&mut self) -> Option<Tok> {
        if self.pos < self.toks.len() { let t = self.toks[self.pos].clone(); self.pos += 1; Some(t) } else { None }
    }
    fn eat(&mut self, tok: &Tok) -> bool { if self.peek() == Some(tok) { self.advance(); true } else { false } }
    fn expect(&mut self, tok: &Tok) -> Result<(), String> {
        if self.eat(tok) { Ok(()) } else { Err(format!("Expected {tok:?}, got {:?}", self.peek())) }
    }
    fn parse(&mut self) -> Result<Expr, String> {
        let e = self.parse_or()?;
        if self.pos < self.toks.len() {
            return Err(format!("Unexpected token at end: {:?}", self.peek()));
        }
        Ok(e)
    }

    fn parse_or(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_and()?;
        while self.eat(&Tok::Or) { let right = self.parse_and()?; left = Expr::BinOp(Op::Or, Box::new(left), Box::new(right)); }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_equality()?;
        while self.eat(&Tok::And) { let right = self.parse_equality()?; left = Expr::BinOp(Op::And, Box::new(left), Box::new(right)); }
        Ok(left)
    }

    fn parse_equality(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_relational()?;
        loop {
            if self.eat(&Tok::Eq) { let r = self.parse_relational()?; left = Expr::BinOp(Op::Eq, Box::new(left), Box::new(r)); }
            else if self.eat(&Tok::Ne) { let r = self.parse_relational()?; left = Expr::BinOp(Op::Ne, Box::new(left), Box::new(r)); }
            else { break; }
        }
        Ok(left)
    }

    fn parse_relational(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_additive()?;
        loop {
            if self.eat(&Tok::Lt) { let r = self.parse_additive()?; left = Expr::BinOp(Op::Lt, Box::new(left), Box::new(r)); }
            else if self.eat(&Tok::Gt) { let r = self.parse_additive()?; left = Expr::BinOp(Op::Gt, Box::new(left), Box::new(r)); }
            else if self.eat(&Tok::Le) { let r = self.parse_additive()?; left = Expr::BinOp(Op::Le, Box::new(left), Box::new(r)); }
            else if self.eat(&Tok::Ge) { let r = self.parse_additive()?; left = Expr::BinOp(Op::Ge, Box::new(left), Box::new(r)); }
            else { break; }
        }
        Ok(left)
    }

    fn parse_additive(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_multiplicative()?;
        loop {
            if self.eat(&Tok::Plus) { let r = self.parse_multiplicative()?; left = Expr::BinOp(Op::Add, Box::new(left), Box::new(r)); }
            else if self.eat(&Tok::Minus) { let r = self.parse_multiplicative()?; left = Expr::BinOp(Op::Sub, Box::new(left), Box::new(r)); }
            else { break; }
        }
        Ok(left)
    }

    fn parse_multiplicative(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_unary()?;
        loop {
            // Tok::Star in operator position = multiply (tokenizer ensures disambiguation via context)
            let is_mul_star = self.peek() == Some(&Tok::Star) && {
                // Star is multiply only after expression-producing tokens
                self.pos > 0 && matches!(&self.toks[self.pos - 1],
                    Tok::RBrack | Tok::RParen | Tok::Str(_) | Tok::Num(_) |
                    Tok::Name(_) | Tok::Dot | Tok::DDot)
            };
            if is_mul_star { self.advance(); let r = self.parse_unary()?; left = Expr::BinOp(Op::Mul, Box::new(left), Box::new(r)); }
            else if self.eat(&Tok::Div) { let r = self.parse_unary()?; left = Expr::BinOp(Op::Div, Box::new(left), Box::new(r)); }
            else if self.eat(&Tok::Mod) { let r = self.parse_unary()?; left = Expr::BinOp(Op::Mod, Box::new(left), Box::new(r)); }
            else { break; }
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Expr, String> {
        if self.eat(&Tok::Minus) { Ok(Expr::Neg(Box::new(self.parse_unary()?))) }
        else { self.parse_union() }
    }

    fn parse_union(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_path()?;
        while self.eat(&Tok::Pipe) { let right = self.parse_path()?; left = Expr::Union(Box::new(left), Box::new(right)); }
        Ok(left)
    }

    fn parse_path(&mut self) -> Result<Expr, String> {
        match self.peek() {
            Some(Tok::Slash) | Some(Tok::DSlash) => self.parse_location_path(),
            Some(Tok::LParen) | Some(Tok::Str(_)) | Some(Tok::Num(_)) => {
                let primary = self.parse_primary()?;
                if self.peek() == Some(&Tok::Slash) || self.peek() == Some(&Tok::DSlash) {
                    // FilterExpr followed by path continuation — not commonly needed
                    // For now, return the primary
                    Ok(primary)
                } else {
                    Ok(primary)
                }
            }
            Some(Tok::Name(n)) => {
                // Check if this is a function call (Name followed by LParen)
                let is_fn = self.pos + 1 < self.toks.len() && self.toks[self.pos + 1] == Tok::LParen
                    && !matches!(n.as_str(), "text" | "node" | "comment" | "processing-instruction");
                if is_fn { self.parse_primary() }
                else { self.parse_location_path() }
            }
            Some(Tok::Dot) | Some(Tok::DDot) | Some(Tok::At) | Some(Tok::Star) => {
                self.parse_location_path()
            }
            None => Err("Unexpected end of expression".into()),
            other => Err(format!("Unexpected token: {other:?}")),
        }
    }

    fn parse_location_path(&mut self) -> Result<Expr, String> {
        let mut absolute = false;
        let mut steps = Vec::new();

        if self.eat(&Tok::DSlash) {
            absolute = true;
            steps.push(Step { axis: Axis::DescendantOrSelf, test: NodeTest::Node, preds: vec![] });
            steps.push(self.parse_step()?);
        } else if self.eat(&Tok::Slash) {
            absolute = true;
            if self.peek().is_some() && !matches!(self.peek(), Some(Tok::Pipe) | Some(Tok::RBrack) | Some(Tok::RParen) | Some(Tok::Comma)) {
                steps.push(self.parse_step()?);
            }
        } else {
            steps.push(self.parse_step()?);
        }

        loop {
            if self.eat(&Tok::DSlash) {
                steps.push(Step { axis: Axis::DescendantOrSelf, test: NodeTest::Node, preds: vec![] });
                steps.push(self.parse_step()?);
            } else if self.eat(&Tok::Slash) {
                steps.push(self.parse_step()?);
            } else {
                break;
            }
        }

        Ok(Expr::Path(absolute, steps))
    }

    fn parse_step(&mut self) -> Result<Step, String> {
        // Abbreviated steps
        if self.eat(&Tok::Dot) {
            return Ok(Step { axis: Axis::Self_, test: NodeTest::Node, preds: vec![] });
        }
        if self.eat(&Tok::DDot) {
            return Ok(Step { axis: Axis::Parent, test: NodeTest::Node, preds: vec![] });
        }

        // Axis
        let axis = if self.eat(&Tok::At) {
            Axis::Attribute
        } else if self.pos + 1 < self.toks.len() && self.toks[self.pos + 1] == Tok::DColon {
            let axis_name = match self.advance() {
                Some(Tok::Name(n)) => n,
                other => return Err(format!("Expected axis name, got {other:?}")),
            };
            self.expect(&Tok::DColon)?;
            match axis_name.as_str() {
                "child" => Axis::Child,
                "descendant" => Axis::Descendant,
                "descendant-or-self" => Axis::DescendantOrSelf,
                "parent" => Axis::Parent,
                "ancestor" => Axis::Ancestor,
                "ancestor-or-self" => Axis::AncestorOrSelf,
                "following-sibling" => Axis::FollowingSibling,
                "preceding-sibling" => Axis::PrecedingSibling,
                "following" => Axis::Following,
                "preceding" => Axis::Preceding,
                "self" => Axis::Self_,
                "attribute" => Axis::Attribute,
                _ => return Err(format!("Unknown axis: {axis_name}")),
            }
        } else {
            Axis::Child
        };

        // Node test
        let test = if self.eat(&Tok::Star) {
            NodeTest::Wildcard
        } else if let Some(Tok::Name(n)) = self.peek().cloned() {
            // Check for node type tests: text(), node(), comment()
            if matches!(n.as_str(), "text" | "node" | "comment" | "processing-instruction")
                && self.pos + 1 < self.toks.len() && self.toks[self.pos + 1] == Tok::LParen
            {
                self.advance(); // consume name
                self.expect(&Tok::LParen)?;
                self.expect(&Tok::RParen)?;
                match n.as_str() {
                    "text" => NodeTest::Text,
                    "node" => NodeTest::Node,
                    "comment" => NodeTest::Comment,
                    _ => NodeTest::Node,
                }
            } else {
                self.advance();
                NodeTest::Name(n)
            }
        } else {
            return Err(format!("Expected node test, got {:?}", self.peek()));
        };

        // Predicates
        let mut preds = Vec::new();
        while self.eat(&Tok::LBrack) {
            preds.push(self.parse_or()?);
            self.expect(&Tok::RBrack)?;
        }

        Ok(Step { axis, test, preds })
    }

    fn parse_primary(&mut self) -> Result<Expr, String> {
        match self.peek().cloned() {
            Some(Tok::LParen) => {
                self.advance();
                let e = self.parse_or()?;
                self.expect(&Tok::RParen)?;
                Ok(e)
            }
            Some(Tok::Str(s)) => { self.advance(); Ok(Expr::Lit(s)) }
            Some(Tok::Num(n)) => { self.advance(); Ok(Expr::NumLit(n)) }
            Some(Tok::Name(name)) if self.pos + 1 < self.toks.len() && self.toks[self.pos + 1] == Tok::LParen => {
                self.advance(); // consume name
                self.expect(&Tok::LParen)?;
                let mut args = Vec::new();
                if !self.eat(&Tok::RParen) {
                    args.push(self.parse_or()?);
                    while self.eat(&Tok::Comma) {
                        args.push(self.parse_or()?);
                    }
                    self.expect(&Tok::RParen)?;
                }
                Ok(Expr::FnCall(name, args))
            }
            _ => self.parse_location_path(),
        }
    }
}

fn parse_xpath_expr(input: &str) -> Result<Expr, String> {
    let toks = tokenize_xpath(input)?;
    if toks.is_empty() { return Err("Empty XPath expression".into()); }
    let mut parser = XParser::new(toks);
    parser.parse()
}

// --- Arena for node navigation ---

struct Arena<'a> {
    nodes: Vec<ANode<'a>>,
}

struct ANode<'a> {
    elem: &'a XmlElement,
    parent: Option<usize>,
    children: Vec<usize>,
}

impl<'a> Arena<'a> {
    fn build(root: &'a XmlElement) -> Self {
        let mut arena = Arena { nodes: Vec::new() };
        // Index 0: virtual document root (XPath's "/")
        arena.nodes.push(ANode { elem: root, parent: None, children: vec![] });
        // Index 1+: actual element tree
        let root_idx = arena.add_node(root, Some(0));
        arena.nodes[0].children.push(root_idx);
        arena
    }

    fn add_node(&mut self, elem: &'a XmlElement, parent: Option<usize>) -> usize {
        let idx = self.nodes.len();
        self.nodes.push(ANode { elem, parent, children: Vec::new() });
        for child in elem.child_elements() {
            let child_idx = self.add_node(child, Some(idx));
            self.nodes[idx].children.push(child_idx);
        }
        idx
    }

    fn string_value(&self, idx: usize) -> String {
        self.nodes[idx].elem.text_content()
    }

    /// Returns path from root element to node (for use with follow_path_mut).
    /// Stops at document root (index 0), so path is relative to root element.
    fn node_path(&self, idx: usize) -> Vec<usize> {
        let mut path = Vec::new();
        let mut cur = idx;
        while let Some(parent) = self.nodes[cur].parent {
            if parent == 0 { break; } // stop at document root
            let pos = self.nodes[parent].children.iter().position(|&c| c == cur).unwrap();
            path.push(pos);
            cur = parent;
        }
        path.reverse();
        path
    }
}

// --- XPath value types ---

#[derive(Debug, Clone)]
enum XNode {
    Elem(usize),            // arena index
    Attr(usize, String),    // (element arena index, attr name)
    Text(usize, usize),     // (element arena index, child index within element.children)
}

#[derive(Debug, Clone)]
enum XValue {
    Nodes(Vec<XNode>),
    Str(String),
    Num(f64),
    Bool(bool),
}

impl XValue {
    fn to_bool(&self) -> bool {
        match self {
            XValue::Bool(b) => *b,
            XValue::Num(n) => *n != 0.0 && !n.is_nan(),
            XValue::Str(s) => !s.is_empty(),
            XValue::Nodes(ns) => !ns.is_empty(),
        }
    }

    fn to_num(&self, arena: &Arena) -> f64 {
        match self {
            XValue::Num(n) => *n,
            XValue::Bool(b) => if *b { 1.0 } else { 0.0 },
            XValue::Str(s) => s.trim().parse().unwrap_or(f64::NAN),
            XValue::Nodes(ns) => {
                let s = xnode_string_value(ns.first(), arena);
                s.trim().parse().unwrap_or(f64::NAN)
            }
        }
    }

    fn to_str(&self, arena: &Arena) -> String {
        match self {
            XValue::Str(s) => s.clone(),
            XValue::Num(n) => {
                if *n == n.trunc() && n.is_finite() { format!("{}", *n as i64) }
                else { format!("{n}") }
            }
            XValue::Bool(b) => if *b { "true" } else { "false" }.into(),
            XValue::Nodes(ns) => xnode_string_value(ns.first(), arena),
        }
    }
}

fn xnode_string_value(node: Option<&XNode>, arena: &Arena) -> String {
    match node {
        Some(XNode::Elem(idx)) => arena.string_value(*idx),
        Some(XNode::Attr(idx, name)) => {
            arena.nodes[*idx].elem.get_attribute(name).unwrap_or("").to_string()
        }
        Some(XNode::Text(elem_idx, child_idx)) => {
            match arena.nodes[*elem_idx].elem.children.get(*child_idx) {
                Some(XmlChild::Text(t)) | Some(XmlChild::CData(t)) => t.clone(),
                _ => String::new(),
            }
        }
        None => String::new(),
    }
}

// --- Evaluator ---

struct EvalCtx<'a> {
    arena: &'a Arena<'a>,
    context_node: usize,
    context_position: usize,
    context_size: usize,
}

fn xpath_eval(arena: &Arena, root_idx: usize, expr: &Expr) -> Result<XValue, String> {
    let ctx = EvalCtx { arena, context_node: root_idx, context_position: 1, context_size: 1 };
    eval_expr(&ctx, expr)
}

fn eval_expr(ctx: &EvalCtx, expr: &Expr) -> Result<XValue, String> {
    match expr {
        Expr::Lit(s) => Ok(XValue::Str(s.clone())),
        Expr::NumLit(n) => Ok(XValue::Num(*n)),

        Expr::Path(absolute, steps) => {
            let start_nodes = if *absolute {
                // Find root
                let mut root = ctx.context_node;
                while let Some(p) = ctx.arena.nodes[root].parent { root = p; }
                vec![root]
            } else {
                vec![ctx.context_node]
            };
            eval_steps(ctx.arena, &start_nodes, steps)
        }

        Expr::Union(left, right) => {
            let l = eval_expr(ctx, left)?;
            let r = eval_expr(ctx, right)?;
            match (l, r) {
                (XValue::Nodes(mut a), XValue::Nodes(b)) => {
                    for n in b {
                        if !a.iter().any(|existing| xnode_eq(existing, &n)) {
                            a.push(n);
                        }
                    }
                    Ok(XValue::Nodes(a))
                }
                _ => Err("Union operator requires node sets".into()),
            }
        }

        Expr::BinOp(op, left, right) => {
            let lv = eval_expr(ctx, left)?;
            let rv = eval_expr(ctx, right)?;
            eval_binop(ctx.arena, *op, &lv, &rv)
        }

        Expr::Neg(inner) => {
            let v = eval_expr(ctx, inner)?;
            Ok(XValue::Num(-v.to_num(ctx.arena)))
        }

        Expr::FnCall(name, args) => eval_function(ctx, name, args),
    }
}

fn xnode_eq(a: &XNode, b: &XNode) -> bool {
    match (a, b) {
        (XNode::Elem(i), XNode::Elem(j)) => i == j,
        (XNode::Attr(i, n1), XNode::Attr(j, n2)) => i == j && n1 == n2,
        (XNode::Text(i1, c1), XNode::Text(i2, c2)) => i1 == i2 && c1 == c2,
        _ => false,
    }
}

fn eval_steps(arena: &Arena, start: &[usize], steps: &[Step]) -> Result<XValue, String> {
    let mut current: Vec<XNode> = start.iter().map(|&i| XNode::Elem(i)).collect();

    for step in steps {
        let mut next = Vec::new();

        for node in &current {
            let XNode::Elem(node_idx) = node else { continue };
            let candidates = collect_axis(arena, *node_idx, step.axis);

            // Filter by node test
            let mut matched: Vec<XNode> = Vec::new();
            for cand in &candidates {
                if matches_test(arena, cand, &step.test) {
                    matched.push(cand.clone());
                }
            }

            // Apply predicates
            for pred in &step.preds {
                let mut filtered = Vec::new();
                let size = matched.len();
                for (pos, m) in matched.into_iter().enumerate() {
                    let ctx_node = match &m {
                        XNode::Elem(i) => *i,
                        XNode::Attr(i, _) | XNode::Text(i, _) => *i,
                    };
                    let pred_ctx = EvalCtx {
                        arena, context_node: ctx_node,
                        context_position: pos + 1, context_size: size,
                    };
                    let pred_val = eval_expr(&pred_ctx, pred)?;
                    // Numeric predicate: position() = N
                    let keep = match &pred_val {
                        XValue::Num(n) => (pos + 1) as f64 == *n,
                        _ => pred_val.to_bool(),
                    };
                    if keep { filtered.push(m); }
                }
                matched = filtered;
            }

            for m in matched {
                if !next.iter().any(|existing| xnode_eq(existing, &m)) {
                    next.push(m);
                }
            }
        }

        current = next;
    }

    Ok(XValue::Nodes(current))
}

fn collect_axis(arena: &Arena, node_idx: usize, axis: Axis) -> Vec<XNode> {
    match axis {
        Axis::Child => {
            let mut result: Vec<XNode> = arena.nodes[node_idx].children.iter().map(|&i| XNode::Elem(i)).collect();
            // Also include text nodes from the element's children
            for (child_idx, child) in arena.nodes[node_idx].elem.children.iter().enumerate() {
                if matches!(child, XmlChild::Text(_) | XmlChild::CData(_)) {
                    result.push(XNode::Text(node_idx, child_idx));
                }
            }
            result
        }
        Axis::Descendant => {
            let mut result = Vec::new();
            for &child in &arena.nodes[node_idx].children {
                collect_descendants_arena(arena, child, &mut result);
            }
            result
        }
        Axis::DescendantOrSelf => {
            let mut result = vec![XNode::Elem(node_idx)];
            for &child in &arena.nodes[node_idx].children {
                collect_descendants_arena(arena, child, &mut result);
            }
            result
        }
        Axis::Self_ => vec![XNode::Elem(node_idx)],
        Axis::Parent => {
            if let Some(p) = arena.nodes[node_idx].parent {
                vec![XNode::Elem(p)]
            } else {
                vec![]
            }
        }
        Axis::Ancestor => {
            let mut result = Vec::new();
            let mut cur = arena.nodes[node_idx].parent;
            while let Some(p) = cur {
                result.push(XNode::Elem(p));
                cur = arena.nodes[p].parent;
            }
            result
        }
        Axis::AncestorOrSelf => {
            let mut result = vec![XNode::Elem(node_idx)];
            let mut cur = arena.nodes[node_idx].parent;
            while let Some(p) = cur {
                result.push(XNode::Elem(p));
                cur = arena.nodes[p].parent;
            }
            result
        }
        Axis::FollowingSibling => {
            if let Some(parent) = arena.nodes[node_idx].parent {
                let siblings = &arena.nodes[parent].children;
                let my_pos = siblings.iter().position(|&s| s == node_idx).unwrap_or(0);
                siblings[my_pos + 1..].iter().map(|&i| XNode::Elem(i)).collect()
            } else {
                vec![]
            }
        }
        Axis::PrecedingSibling => {
            if let Some(parent) = arena.nodes[node_idx].parent {
                let siblings = &arena.nodes[parent].children;
                let my_pos = siblings.iter().position(|&s| s == node_idx).unwrap_or(0);
                siblings[..my_pos].iter().rev().map(|&i| XNode::Elem(i)).collect()
            } else {
                vec![]
            }
        }
        Axis::Following => {
            let mut result = Vec::new();
            collect_following(arena, node_idx, &mut result);
            result
        }
        Axis::Preceding => {
            let mut result = Vec::new();
            collect_preceding(arena, node_idx, &mut result);
            result
        }
        Axis::Attribute => {
            arena.nodes[node_idx].elem.attributes.iter()
                .map(|(k, _)| XNode::Attr(node_idx, k.clone()))
                .collect()
        }
    }
}

fn collect_descendants_arena(arena: &Arena, idx: usize, result: &mut Vec<XNode>) {
    result.push(XNode::Elem(idx));
    for &child in &arena.nodes[idx].children {
        collect_descendants_arena(arena, child, result);
    }
}

fn collect_following(arena: &Arena, idx: usize, result: &mut Vec<XNode>) {
    if let Some(parent) = arena.nodes[idx].parent {
        let siblings = &arena.nodes[parent].children;
        let my_pos = siblings.iter().position(|&s| s == idx).unwrap_or(0);
        for &sib in &siblings[my_pos + 1..] {
            collect_descendants_arena(arena, sib, result);
        }
        collect_following(arena, parent, result);
    }
}

fn collect_preceding(arena: &Arena, idx: usize, result: &mut Vec<XNode>) {
    if let Some(parent) = arena.nodes[idx].parent {
        let siblings = &arena.nodes[parent].children;
        let my_pos = siblings.iter().position(|&s| s == idx).unwrap_or(0);
        for &sib in siblings[..my_pos].iter().rev() {
            collect_descendants_reverse(arena, sib, result);
        }
        collect_preceding(arena, parent, result);
    }
}

fn collect_descendants_reverse(arena: &Arena, idx: usize, result: &mut Vec<XNode>) {
    for &child in arena.nodes[idx].children.iter().rev() {
        collect_descendants_reverse(arena, child, result);
    }
    result.push(XNode::Elem(idx));
}

fn matches_test(arena: &Arena, node: &XNode, test: &NodeTest) -> bool {
    match (node, test) {
        // Document root (index 0) only matches node() test, not * or named elements
        (XNode::Elem(0), NodeTest::Node) => true,
        (XNode::Elem(0), _) => false,
        (XNode::Elem(idx), NodeTest::Name(name)) => arena.nodes[*idx].elem.name == *name,
        (XNode::Elem(_), NodeTest::Wildcard) => true,
        (XNode::Elem(_), NodeTest::Node) => true,
        (XNode::Elem(idx), NodeTest::Comment) => {
            arena.nodes[*idx].elem.children.iter().any(|c| matches!(c, XmlChild::Comment(_)))
        }
        (XNode::Attr(_, name), NodeTest::Name(test_name)) => name == test_name,
        (XNode::Attr(_, _), NodeTest::Wildcard) => true,
        (XNode::Attr(_, _), NodeTest::Node) => true,
        // Text nodes
        (XNode::Text(_, _), NodeTest::Text) => true,
        (XNode::Text(_, _), NodeTest::Node) => true,
        _ => false,
    }
}

fn eval_binop(arena: &Arena, op: Op, lv: &XValue, rv: &XValue) -> Result<XValue, String> {
    match op {
        Op::And => Ok(XValue::Bool(lv.to_bool() && rv.to_bool())),
        Op::Or => Ok(XValue::Bool(lv.to_bool() || rv.to_bool())),

        Op::Eq | Op::Ne => {
            let result = match (lv, rv) {
                (XValue::Nodes(ns), XValue::Str(s)) | (XValue::Str(s), XValue::Nodes(ns)) => {
                    ns.iter().any(|n| xnode_string_value(Some(n), arena) == *s)
                }
                (XValue::Nodes(ns), XValue::Num(n)) | (XValue::Num(n), XValue::Nodes(ns)) => {
                    ns.iter().any(|nd| {
                        let sv = xnode_string_value(Some(nd), arena);
                        sv.trim().parse::<f64>().is_ok_and(|v| v == *n)
                    })
                }
                (XValue::Nodes(ns), XValue::Bool(b)) | (XValue::Bool(b), XValue::Nodes(ns)) => {
                    !ns.is_empty() == *b
                }
                (XValue::Nodes(a), XValue::Nodes(b)) => {
                    a.iter().any(|an| {
                        let av = xnode_string_value(Some(an), arena);
                        b.iter().any(|bn| xnode_string_value(Some(bn), arena) == av)
                    })
                }
                (XValue::Bool(a), XValue::Bool(b)) => a == b,
                (XValue::Num(a), XValue::Num(b)) => a == b,
                (XValue::Str(a), XValue::Str(b)) => a == b,
                (XValue::Bool(b), _) | (_, XValue::Bool(b)) => {
                    let other = if matches!(lv, XValue::Bool(_)) { rv } else { lv };
                    other.to_bool() == *b
                }
                (XValue::Num(n), _) | (_, XValue::Num(n)) => {
                    let other = if matches!(lv, XValue::Num(_)) { rv } else { lv };
                    other.to_num(arena) == *n
                }
            };
            Ok(XValue::Bool(if matches!(op, Op::Ne) { !result } else { result }))
        }

        Op::Lt | Op::Gt | Op::Le | Op::Ge => {
            let (ln, rn) = match (lv, rv) {
                (XValue::Nodes(ns), _) => {
                    // Compare each node's numeric value
                    let any_match = ns.iter().any(|n| {
                        let nv = xnode_string_value(Some(n), arena).trim().parse::<f64>().unwrap_or(f64::NAN);
                        let rv_num = rv.to_num(arena);
                        cmp_nums(op, nv, rv_num)
                    });
                    return Ok(XValue::Bool(any_match));
                }
                (_, XValue::Nodes(ns)) => {
                    let any_match = ns.iter().any(|n| {
                        let nv = xnode_string_value(Some(n), arena).trim().parse::<f64>().unwrap_or(f64::NAN);
                        let lv_num = lv.to_num(arena);
                        cmp_nums(op, lv_num, nv)
                    });
                    return Ok(XValue::Bool(any_match));
                }
                _ => (lv.to_num(arena), rv.to_num(arena)),
            };
            Ok(XValue::Bool(cmp_nums(op, ln, rn)))
        }

        Op::Add => Ok(XValue::Num(lv.to_num(arena) + rv.to_num(arena))),
        Op::Sub => Ok(XValue::Num(lv.to_num(arena) - rv.to_num(arena))),
        Op::Mul => Ok(XValue::Num(lv.to_num(arena) * rv.to_num(arena))),
        Op::Div => Ok(XValue::Num(lv.to_num(arena) / rv.to_num(arena))),
        Op::Mod => Ok(XValue::Num(lv.to_num(arena) % rv.to_num(arena))),
    }
}

fn cmp_nums(op: Op, a: f64, b: f64) -> bool {
    match op {
        Op::Lt => a < b, Op::Gt => a > b, Op::Le => a <= b, Op::Ge => a >= b,
        _ => false,
    }
}

fn eval_function(ctx: &EvalCtx, name: &str, args: &[Expr]) -> Result<XValue, String> {
    match name {
        "true" => Ok(XValue::Bool(true)),
        "false" => Ok(XValue::Bool(false)),
        "not" => {
            ensure_args(name, args, 1)?;
            Ok(XValue::Bool(!eval_expr(ctx, &args[0])?.to_bool()))
        }
        "boolean" => {
            ensure_args(name, args, 1)?;
            Ok(XValue::Bool(eval_expr(ctx, &args[0])?.to_bool()))
        }
        "string" => {
            if args.is_empty() {
                Ok(XValue::Str(ctx.arena.string_value(ctx.context_node)))
            } else {
                ensure_args(name, args, 1)?;
                Ok(XValue::Str(eval_expr(ctx, &args[0])?.to_str(ctx.arena)))
            }
        }
        "number" => {
            if args.is_empty() {
                let s = ctx.arena.string_value(ctx.context_node);
                Ok(XValue::Num(s.trim().parse().unwrap_or(f64::NAN)))
            } else {
                ensure_args(name, args, 1)?;
                Ok(XValue::Num(eval_expr(ctx, &args[0])?.to_num(ctx.arena)))
            }
        }
        "count" => {
            ensure_args(name, args, 1)?;
            match eval_expr(ctx, &args[0])? {
                XValue::Nodes(ns) => Ok(XValue::Num(ns.len() as f64)),
                _ => Err("count() requires a node set".into()),
            }
        }
        "sum" => {
            ensure_args(name, args, 1)?;
            match eval_expr(ctx, &args[0])? {
                XValue::Nodes(ns) => {
                    let total: f64 = ns.iter().map(|n| {
                        xnode_string_value(Some(n), ctx.arena).trim().parse::<f64>().unwrap_or(0.0)
                    }).sum();
                    Ok(XValue::Num(total))
                }
                _ => Err("sum() requires a node set".into()),
            }
        }
        "last" => Ok(XValue::Num(ctx.context_size as f64)),
        "position" => Ok(XValue::Num(ctx.context_position as f64)),
        "name" | "local-name" => {
            if args.is_empty() {
                let elem_name = &ctx.arena.nodes[ctx.context_node].elem.name;
                let result = if name == "local-name" {
                    elem_name.split(':').last().unwrap_or(elem_name)
                } else {
                    elem_name
                };
                Ok(XValue::Str(result.to_string()))
            } else {
                ensure_args(name, args, 1)?;
                match eval_expr(ctx, &args[0])? {
                    XValue::Nodes(ns) => {
                        if let Some(XNode::Elem(idx)) = ns.first() {
                            let elem_name = &ctx.arena.nodes[*idx].elem.name;
                            let result = if name == "local-name" {
                                elem_name.split(':').last().unwrap_or(elem_name)
                            } else {
                                elem_name
                            };
                            Ok(XValue::Str(result.to_string()))
                        } else {
                            Ok(XValue::Str(String::new()))
                        }
                    }
                    _ => Err(format!("{name}() requires a node set")),
                }
            }
        }
        "contains" => {
            ensure_args(name, args, 2)?;
            let s = eval_expr(ctx, &args[0])?.to_str(ctx.arena);
            let sub = eval_expr(ctx, &args[1])?.to_str(ctx.arena);
            Ok(XValue::Bool(s.contains(&*sub)))
        }
        "starts-with" => {
            ensure_args(name, args, 2)?;
            let s = eval_expr(ctx, &args[0])?.to_str(ctx.arena);
            let prefix = eval_expr(ctx, &args[1])?.to_str(ctx.arena);
            Ok(XValue::Bool(s.starts_with(&*prefix)))
        }
        "ends-with" => {
            ensure_args(name, args, 2)?;
            let s = eval_expr(ctx, &args[0])?.to_str(ctx.arena);
            let suffix = eval_expr(ctx, &args[1])?.to_str(ctx.arena);
            Ok(XValue::Bool(s.ends_with(&*suffix)))
        }
        "string-length" => {
            let s = if args.is_empty() {
                ctx.arena.string_value(ctx.context_node)
            } else {
                ensure_args(name, args, 1)?;
                eval_expr(ctx, &args[0])?.to_str(ctx.arena)
            };
            Ok(XValue::Num(s.len() as f64))
        }
        "normalize-space" => {
            let s = if args.is_empty() {
                ctx.arena.string_value(ctx.context_node)
            } else {
                ensure_args(name, args, 1)?;
                eval_expr(ctx, &args[0])?.to_str(ctx.arena)
            };
            Ok(XValue::Str(s.split_whitespace().collect::<Vec<_>>().join(" ")))
        }
        "concat" => {
            if args.len() < 2 { return Err("concat() requires at least 2 arguments".into()); }
            let mut result = String::new();
            for arg in args {
                result.push_str(&eval_expr(ctx, arg)?.to_str(ctx.arena));
            }
            Ok(XValue::Str(result))
        }
        "substring" => {
            if args.len() < 2 || args.len() > 3 {
                return Err("substring() requires 2 or 3 arguments".into());
            }
            let s = eval_expr(ctx, &args[0])?.to_str(ctx.arena);
            let start = eval_expr(ctx, &args[1])?.to_num(ctx.arena).round() as i64 - 1;
            let start = start.max(0) as usize;
            if args.len() == 3 {
                let len = eval_expr(ctx, &args[2])?.to_num(ctx.arena).round() as usize;
                let end = (start + len).min(s.len());
                Ok(XValue::Str(s.get(start..end).unwrap_or("").to_string()))
            } else {
                Ok(XValue::Str(s.get(start..).unwrap_or("").to_string()))
            }
        }
        "substring-before" => {
            ensure_args(name, args, 2)?;
            let s = eval_expr(ctx, &args[0])?.to_str(ctx.arena);
            let needle = eval_expr(ctx, &args[1])?.to_str(ctx.arena);
            Ok(XValue::Str(s.find(&*needle).map_or(String::new(), |i| s[..i].to_string())))
        }
        "substring-after" => {
            ensure_args(name, args, 2)?;
            let s = eval_expr(ctx, &args[0])?.to_str(ctx.arena);
            let needle = eval_expr(ctx, &args[1])?.to_str(ctx.arena);
            Ok(XValue::Str(s.find(&*needle).map_or(String::new(), |i| s[i + needle.len()..].to_string())))
        }
        "translate" => {
            ensure_args(name, args, 3)?;
            let s = eval_expr(ctx, &args[0])?.to_str(ctx.arena);
            let from: Vec<char> = eval_expr(ctx, &args[1])?.to_str(ctx.arena).chars().collect();
            let to: Vec<char> = eval_expr(ctx, &args[2])?.to_str(ctx.arena).chars().collect();
            let result: String = s.chars().filter_map(|c| {
                if let Some(pos) = from.iter().position(|&f| f == c) {
                    to.get(pos).copied() // None = remove char
                } else {
                    Some(c)
                }
            }).collect();
            Ok(XValue::Str(result))
        }
        "ceiling" => {
            ensure_args(name, args, 1)?;
            Ok(XValue::Num(eval_expr(ctx, &args[0])?.to_num(ctx.arena).ceil()))
        }
        "floor" => {
            ensure_args(name, args, 1)?;
            Ok(XValue::Num(eval_expr(ctx, &args[0])?.to_num(ctx.arena).floor()))
        }
        "round" => {
            ensure_args(name, args, 1)?;
            Ok(XValue::Num(eval_expr(ctx, &args[0])?.to_num(ctx.arena).round()))
        }
        _ => Err(format!("Unknown function: {name}(). Supported: count, sum, last, position, name, local-name, contains, starts-with, ends-with, string-length, normalize-space, concat, substring, substring-before, substring-after, translate, not, boolean, string, number, true, false, ceiling, floor, round")),
    }
}

fn ensure_args(name: &str, args: &[Expr], expected: usize) -> Result<(), String> {
    if args.len() != expected {
        Err(format!("{name}() requires {expected} argument(s), got {}", args.len()))
    } else {
        Ok(())
    }
}

// --- Public API ---

// Result types for tool handlers
enum XPathMatch {
    Element(String),
    Value(String),
}

// ---------------------------------------------------------------------------
// Streaming XPath optimization for large files
// ---------------------------------------------------------------------------

/// Fast streaming count for patterns like count(//elem) or count(//elem[@attr])
/// Returns Some(count) if pattern can be optimized, None to fall back to DOM
fn try_streaming_count(xml: &str, expr_str: &str) -> Option<usize> {
    let expr = expr_str.trim();

    // Match count(//name) or count(//name[@attr]) patterns
    if !expr.starts_with("count(") || !expr.ends_with(')') {
        return None;
    }

    let inner = expr[6..expr.len()-1].trim();

    // Pattern: //name or //name[@attr='val'] or //name[@attr]
    if !inner.starts_with("//") {
        return None;
    }

    let path = &inner[2..];

    // Extract element name and optional attribute filter
    let (elem_name, attr_filter): (&str, Option<(&str, Option<&str>)>) =
        if let Some(bracket_pos) = path.find('[') {
            let name = &path[..bracket_pos];
            let predicate = &path[bracket_pos+1..path.len()-1]; // strip [ ]

            // Parse [@attr] or [@attr='value'] or [@attr="value"]
            if predicate.starts_with('@') {
                let attr_part = &predicate[1..];
                if let Some(eq_pos) = attr_part.find('=') {
                    let attr_name = &attr_part[..eq_pos];
                    let val = attr_part[eq_pos+1..].trim();
                    // Strip quotes
                    let val = if (val.starts_with('\'') && val.ends_with('\'')) ||
                                (val.starts_with('"') && val.ends_with('"')) {
                        Some(&val[1..val.len()-1])
                    } else {
                        return None; // Invalid syntax
                    };
                    (name, Some((attr_name, val)))
                } else {
                    (attr_part, Some((attr_part, None))) // [@attr] - just check existence
                }
            } else {
                return None; // Non-attribute predicate, fall back to DOM
            }
        } else {
            (path, None)
        };

    // Validate element name (simple names only)
    if elem_name.is_empty() || elem_name.contains('/') || elem_name.contains('[') {
        return None;
    }

    // Stream count using quick-xml
    let mut reader = Reader::from_str(xml);
    let mut count = 0;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let name_bytes = e.name();
                let tag = std::str::from_utf8(name_bytes.as_ref()).unwrap_or("");
                // Handle namespace prefixes: match "ns:elem" or just "elem"
                let local_name = tag.rsplit(':').next().unwrap_or(tag);

                if local_name == elem_name || elem_name == "*" {
                    // Check attribute filter if present
                    let matches = match attr_filter {
                        None => true,
                        Some((attr_name, None)) => {
                            // Just check attribute exists
                            e.attributes().flatten().any(|a| {
                                let key = std::str::from_utf8(a.key.as_ref()).unwrap_or("");
                                key == attr_name || key.ends_with(&format!(":{attr_name}"))
                            })
                        }
                        Some((attr_name, Some(attr_val))) => {
                            // Check attribute value matches
                            e.attributes().flatten().any(|a| {
                                let key = std::str::from_utf8(a.key.as_ref()).unwrap_or("");
                                let val = std::str::from_utf8(&a.value).unwrap_or("");
                                (key == attr_name || key.ends_with(&format!(":{attr_name}"))) && val == attr_val
                            })
                        }
                    };
                    if matches {
                        count += 1;
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return None, // Parse error, fall back to DOM
            _ => {}
        }
    }

    Some(count)
}

/// Fast streaming extraction for simple patterns like //elem/@attr
/// Returns Some(values) if optimizable, None to fall back to DOM
fn try_streaming_extract(xml: &str, expr_str: &str) -> Option<Vec<String>> {
    let expr = expr_str.trim();

    // Pattern: //name/@attr
    if !expr.starts_with("//") {
        return None;
    }

    let path = &expr[2..];

    // Must have exactly one /@attr at the end
    let parts: Vec<&str> = path.rsplitn(2, "/@").collect();
    if parts.len() != 2 {
        return None;
    }

    let attr_name = parts[0];
    let elem_name = parts[1];

    // Validate: simple element name, simple attribute name
    if elem_name.is_empty() || elem_name.contains('/') || elem_name.contains('[') ||
       attr_name.is_empty() || attr_name.contains('/') || attr_name.contains('[') {
        return None;
    }

    let mut reader = Reader::from_str(xml);
    let mut values = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let name_bytes = e.name();
                let tag = std::str::from_utf8(name_bytes.as_ref()).unwrap_or("");
                let local_name = tag.rsplit(':').next().unwrap_or(tag);

                if local_name == elem_name || elem_name == "*" {
                    for attr in e.attributes().flatten() {
                        let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                        let local_key = key.rsplit(':').next().unwrap_or(key);
                        if local_key == attr_name {
                            if let Ok(val) = std::str::from_utf8(&attr.value) {
                                values.push(val.to_string());
                            }
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return None,
            _ => {}
        }
    }

    Some(values)
}

fn xpath_query_tree(root: &XmlElement, expr_str: &str) -> Result<(Vec<XPathMatch>, XValue), String> {
    let expr = parse_xpath_expr(expr_str)?;
    let arena = Arena::build(root);
    let value = xpath_eval(&arena, 0, &expr)?;

    let matches = match &value {
        XValue::Nodes(nodes) => {
            nodes.iter().map(|n| match n {
                XNode::Elem(idx) => XPathMatch::Element(serialize_element(arena.nodes[*idx].elem, true)),
                XNode::Attr(idx, name) => {
                    XPathMatch::Value(arena.nodes[*idx].elem.get_attribute(name).unwrap_or("").to_string())
                }
                XNode::Text(elem_idx, child_idx) => {
                    match arena.nodes[*elem_idx].elem.children.get(*child_idx) {
                        Some(XmlChild::Text(t)) | Some(XmlChild::CData(t)) => XPathMatch::Value(t.clone()),
                        _ => XPathMatch::Value(String::new()),
                    }
                }
            }).collect()
        }
        XValue::Str(s) => vec![XPathMatch::Value(s.clone())],
        XValue::Num(n) => {
            let s = if *n == n.trunc() && n.is_finite() { format!("{}", *n as i64) } else { format!("{n}") };
            vec![XPathMatch::Value(s)]
        }
        XValue::Bool(b) => vec![XPathMatch::Value(b.to_string())],
    };

    Ok((matches, value))
}

// --- XPath set — modify tree using new engine ---

fn follow_path_mut<'a>(root: &'a mut XmlElement, path: &[usize]) -> &'a mut XmlElement {
    let mut current = root;
    for &child_idx in path {
        let mut elem_count = 0;
        let mut target = None;
        for (i, child) in current.children.iter().enumerate() {
            if matches!(child, XmlChild::Element(_)) {
                if elem_count == child_idx {
                    target = Some(i);
                    break;
                }
                elem_count += 1;
            }
        }
        let idx = target.expect("Invalid path index");
        let XmlChild::Element(ref mut el) = current.children[idx] else { panic!("Expected element") };
        current = el;
    }
    current
}

fn xpath_set_tree(root: &mut XmlElement, expr_str: &str, value: &str) -> Result<usize, String> {
    let expr = parse_xpath_expr(expr_str)?;
    // Build arena from immutable view
    let arena = Arena::build(root);
    let result = xpath_eval(&arena, 0, &expr)?;

    let XValue::Nodes(nodes) = result else {
        return Err("XPath expression did not select any nodes".into());
    };

    // Collect paths and attribute/text info before mutating
    // For text nodes, we store (path to parent, Some("@text:idx")) as a marker
    let targets: Vec<(Vec<usize>, Option<String>)> = nodes.iter().map(|n| {
        match n {
            XNode::Elem(idx) => (arena.node_path(*idx), None),
            XNode::Attr(idx, name) => (arena.node_path(*idx), Some(name.clone())),
            XNode::Text(elem_idx, child_idx) => (arena.node_path(*elem_idx), Some(format!("@text:{child_idx}"))),
        }
    }).collect();

    drop(arena);

    let mut count = 0;
    for (path, target_info) in &targets {
        let elem = follow_path_mut(root, path);
        if let Some(info) = target_info {
            if let Some(idx_str) = info.strip_prefix("@text:") {
                // Text node: replace specific text child
                if let Ok(child_idx) = idx_str.parse::<usize>() {
                    if child_idx < elem.children.len() {
                        elem.children[child_idx] = XmlChild::Text(value.to_string());
                    }
                }
            } else {
                // Attribute: set attribute value
                if let Some((_, v)) = elem.attributes.iter_mut().find(|(k, _)| k == info) {
                    *v = value.to_string();
                } else {
                    elem.attributes.push((info.clone(), value.to_string()));
                }
            }
        } else {
            // Element: set text content (replace all text children)
            elem.children.retain(|c| !matches!(c, XmlChild::Text(_) | XmlChild::CData(_)));
            elem.children.push(XmlChild::Text(value.to_string()));
        }
        count += 1;
    }
    Ok(count)
}

// --- XPath delete — remove matched nodes ---

fn xpath_delete_tree(root: &mut XmlElement, expr_str: &str) -> Result<usize, String> {
    let expr = parse_xpath_expr(expr_str)?;
    let arena = Arena::build(root);
    let result = xpath_eval(&arena, 0, &expr)?;

    let XValue::Nodes(nodes) = result else {
        return Err("XPath expression did not select any nodes".into());
    };

    // Collect paths and types
    enum DeleteTarget { Element(Vec<usize>), Attribute(Vec<usize>, String), Text(Vec<usize>, usize) }
    let targets: Vec<DeleteTarget> = nodes.iter().map(|n| match n {
        XNode::Elem(idx) => DeleteTarget::Element(arena.node_path(*idx)),
        XNode::Attr(idx, name) => DeleteTarget::Attribute(arena.node_path(*idx), name.clone()),
        XNode::Text(elem_idx, child_idx) => DeleteTarget::Text(arena.node_path(*elem_idx), *child_idx),
    }).collect();

    drop(arena);

    let mut count = 0;
    // Process in reverse to avoid index shifting
    for target in targets.iter().rev() {
        match target {
            DeleteTarget::Element(path) => {
                if path.is_empty() {
                    return Err("Cannot delete root element".into());
                }
                let parent_path = &path[..path.len() - 1];
                let child_pos = path[path.len() - 1];
                let parent = follow_path_mut(root, parent_path);
                // Find the actual index in children (counting only elements)
                let mut elem_count = 0;
                let mut remove_idx = None;
                for (i, child) in parent.children.iter().enumerate() {
                    if matches!(child, XmlChild::Element(_)) {
                        if elem_count == child_pos {
                            remove_idx = Some(i);
                            break;
                        }
                        elem_count += 1;
                    }
                }
                if let Some(idx) = remove_idx {
                    parent.children.remove(idx);
                    count += 1;
                }
            }
            DeleteTarget::Attribute(path, attr_name) => {
                let elem = follow_path_mut(root, path);
                let before = elem.attributes.len();
                elem.attributes.retain(|(k, _)| k != attr_name);
                if elem.attributes.len() < before { count += 1; }
            }
            DeleteTarget::Text(path, child_idx) => {
                let elem = follow_path_mut(root, path);
                if *child_idx < elem.children.len() {
                    elem.children.remove(*child_idx);
                    count += 1;
                }
            }
        }
    }
    Ok(count)
}

// --- XPath add — insert elements/attributes ---

fn xpath_add_tree(root: &mut XmlElement, expr_str: &str, xml_content: &str, position: &str) -> Result<usize, String> {
    let expr = parse_xpath_expr(expr_str)?;
    let arena = Arena::build(root);
    let result = xpath_eval(&arena, 0, &expr)?;

    let XValue::Nodes(nodes) = result else {
        return Err("XPath expression did not select any nodes".into());
    };

    let paths: Vec<Vec<usize>> = nodes.iter().filter_map(|n| {
        if let XNode::Elem(idx) = n { Some(arena.node_path(*idx)) } else { None }
    }).collect();

    drop(arena);

    // Check if content is an attribute (@attr=value)
    if xml_content.starts_with('@') {
        let content = &xml_content[1..]; // strip @
        let eq_pos = content.find('=')
            .ok_or_else(|| format!("Invalid attribute syntax: {xml_content}. Use @name=value"))?;
        let attr_name = content[..eq_pos].trim().to_string();
        let attr_value = content[eq_pos + 1..].trim().to_string();

        let mut count = 0;
        for path in &paths {
            let target = follow_path_mut(root, path);
            target.attributes.retain(|(k, _)| k != &attr_name);
            target.attributes.push((attr_name.clone(), attr_value.clone()));
            count += 1;
        }
        return Ok(count);
    }

    // Parse the content to add as element (once, before the loop)
    let new_element = parse_xml_tree(xml_content)?;

    let mut count = 0;
    for path in &paths {
        match position {
            "child" | "append" | "last-child" | "inside" => {
                let target = follow_path_mut(root, path);
                target.children.push(XmlChild::Element(new_element.clone()));
                count += 1;
            }
            "first-child" | "prepend" => {
                let target = follow_path_mut(root, path);
                target.children.insert(0, XmlChild::Element(new_element.clone()));
                count += 1;
            }
            "after" => {
                if path.is_empty() { return Err("Cannot insert after root element".into()); }
                let parent_path = &path[..path.len() - 1];
                let child_pos = path[path.len() - 1];
                let parent = follow_path_mut(root, parent_path);
                let mut elem_count = 0;
                let mut insert_idx = None;
                for (i, child) in parent.children.iter().enumerate() {
                    if matches!(child, XmlChild::Element(_)) {
                        if elem_count == child_pos {
                            insert_idx = Some(i + 1);
                            break;
                        }
                        elem_count += 1;
                    }
                }
                if let Some(idx) = insert_idx {
                    parent.children.insert(idx, XmlChild::Element(new_element.clone()));
                    count += 1;
                }
            }
            "before" => {
                if path.is_empty() { return Err("Cannot insert before root element".into()); }
                let parent_path = &path[..path.len() - 1];
                let child_pos = path[path.len() - 1];
                let parent = follow_path_mut(root, parent_path);
                let mut elem_count = 0;
                let mut insert_idx = None;
                for (i, child) in parent.children.iter().enumerate() {
                    if matches!(child, XmlChild::Element(_)) {
                        if elem_count == child_pos {
                            insert_idx = Some(i);
                            break;
                        }
                        elem_count += 1;
                    }
                }
                if let Some(idx) = insert_idx {
                    parent.children.insert(idx, XmlChild::Element(new_element.clone()));
                    count += 1;
                }
            }
            _ => return Err(format!("Unknown position: '{position}'. Use: inside, first-child, after, before")),
        }
    }
    Ok(count)
}

// ---------------------------------------------------------------------------
// XML → JSON conversion
// ---------------------------------------------------------------------------

fn element_to_json(element: &XmlElement) -> Value {
    let child_elements: Vec<_> = element.child_elements().collect();
    let text = element.text_content();
    let has_text = !text.is_empty();

    // Simple text-only element with no attributes and no child elements
    if element.attributes.is_empty() && child_elements.is_empty() {
        return if has_text { Value::String(text) } else { Value::Null };
    }

    let mut map = Map::new();

    // Attributes with @ prefix
    for (key, val) in &element.attributes {
        map.insert(format!("@{key}"), Value::String(val.clone()));
    }

    // Count children by name to detect arrays
    let mut name_counts: HashMap<&str, usize> = HashMap::new();
    for child in &child_elements {
        *name_counts.entry(&child.name).or_insert(0) += 1;
    }

    // Group children, preserving first-appearance order
    let mut groups: Vec<(&str, Vec<Value>)> = Vec::new();
    let mut seen: HashMap<&str, usize> = HashMap::new();
    for child in &child_elements {
        let child_json = element_to_json(child);
        if let Some(&idx) = seen.get(child.name.as_str()) {
            groups[idx].1.push(child_json);
        } else {
            seen.insert(&child.name, groups.len());
            groups.push((&child.name, vec![child_json]));
        }
    }

    for (name, values) in groups {
        if name_counts.get(name).copied().unwrap_or(0) > 1 {
            map.insert(name.to_string(), Value::Array(values));
        } else {
            map.insert(name.to_string(), values.into_iter().next().unwrap());
        }
    }

    // Text content
    if has_text {
        map.insert("#text".to_string(), Value::String(text));
    }

    Value::Object(map)
}

fn xml_to_json_string(xml: &str) -> Result<String, String> {
    let root = parse_xml_tree(xml)?;
    let mut wrapper = Map::new();
    wrapper.insert(root.name.clone(), element_to_json(&root));
    let json = Value::Object(wrapper);
    serde_json::to_string_pretty(&json).map_err(|e| format!("JSON serialization error: {e}"))
}

// ---------------------------------------------------------------------------
// JSON → XML conversion
// ---------------------------------------------------------------------------

fn json_to_element(name: &str, value: &Value) -> Result<XmlElement, String> {
    match value {
        Value::Object(map) => {
            let mut attrs = Vec::new();
            let mut children = Vec::new();

            for (k, v) in map {
                if let Some(attr_name) = k.strip_prefix('@') {
                    let attr_val = match v {
                        Value::String(s) => s.clone(),
                        _ => v.to_string(),
                    };
                    attrs.push((attr_name.to_string(), attr_val));
                } else if k == "#text" {
                    let text = match v {
                        Value::String(s) => s.clone(),
                        _ => v.to_string(),
                    };
                    children.push(XmlChild::Text(text));
                } else if let Value::Array(arr) = v {
                    for item in arr {
                        children.push(XmlChild::Element(json_to_element(k, item)?));
                    }
                } else {
                    children.push(XmlChild::Element(json_to_element(k, v)?));
                }
            }

            Ok(XmlElement { name: name.to_string(), attributes: attrs, children })
        }
        Value::String(s) => Ok(XmlElement {
            name: name.to_string(),
            attributes: Vec::new(),
            children: vec![XmlChild::Text(s.clone())],
        }),
        Value::Number(n) => Ok(XmlElement {
            name: name.to_string(),
            attributes: Vec::new(),
            children: vec![XmlChild::Text(n.to_string())],
        }),
        Value::Bool(b) => Ok(XmlElement {
            name: name.to_string(),
            attributes: Vec::new(),
            children: vec![XmlChild::Text(b.to_string())],
        }),
        Value::Null => Ok(XmlElement {
            name: name.to_string(),
            attributes: Vec::new(),
            children: Vec::new(),
        }),
        Value::Array(_) => Err(format!(
            "Cannot convert JSON array directly to XML element '{name}'. Wrap it in an object."
        )),
    }
}

fn json_to_xml_string(json_str: &str, root_element: Option<&str>) -> Result<String, String> {
    let data: Value = serde_json::from_str(json_str).map_err(|e| format!("Invalid JSON: {e}"))?;

    let element = match (&data, root_element) {
        (Value::Object(map), None) if map.len() == 1 => {
            let (name, value) = map.iter().next().unwrap();
            json_to_element(name, value)?
        }
        (_, Some(root)) => json_to_element(root, &data)?,
        _ => return Err("JSON must have a single root key, or provide 'root_element' parameter.".into()),
    };

    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    write_element(&element, 0, true, &mut xml);
    Ok(xml)
}

// ---------------------------------------------------------------------------
// XML formatting — event pipeline
// ---------------------------------------------------------------------------

fn format_xml_str(xml: &str, mode: &str) -> Result<String, String> {
    // Validate input is well-formed first
    let _ = parse_xml_tree(xml)?;

    let mut reader = Reader::from_str(xml);

    let mut output: Vec<u8> = Vec::new();

    match mode {
        "pretty" => {
            let mut writer = Writer::new_with_indent(std::io::Cursor::new(&mut output), b' ', 2);
            loop {
                match reader.read_event() {
                    Ok(Event::Eof) => break,
                    Ok(e) => writer.write_event(e).map_err(|err| format!("Write error: {err}"))?,
                    Err(e) => return Err(format!("XML parse error: {e}")),
                }
            }
        }
        "compact" => {
            let mut writer = Writer::new(std::io::Cursor::new(&mut output));
            loop {
                match reader.read_event() {
                    Ok(Event::Eof) => break,
                    Ok(Event::Text(ref e)) => {
                        let text = e.unescape().map_err(|err| format!("Text error: {err}"))?;
                        let trimmed = text.trim();
                        if !trimmed.is_empty() {
                            writer.write_event(Event::Text(BytesText::new(trimmed)))
                                .map_err(|err| format!("Write error: {err}"))?;
                        }
                    }
                    Ok(e) => writer.write_event(e).map_err(|err| format!("Write error: {err}"))?,
                    Err(e) => return Err(format!("XML parse error: {e}")),
                }
            }
        }
        "sorted" => {
            // Parse into tree, sort attributes, then serialize
            let mut root = parse_xml_tree(xml)?;
            sort_attributes_recursive(&mut root);
            let mut out = String::new();
            write_element(&root, 0, true, &mut out);
            return Ok(out);
        }
        _ => return Err(format!("Unknown mode '{mode}'. Use 'pretty', 'compact', or 'sorted'.")),
    };

    String::from_utf8(output).map_err(|e| format!("UTF-8 error: {e}"))
}

fn sort_attributes_recursive(elem: &mut XmlElement) {
    elem.attributes.sort_by(|a, b| a.0.cmp(&b.0));
    for child in &mut elem.children {
        if let XmlChild::Element(ref mut child_elem) = child {
            sort_attributes_recursive(child_elem);
        }
    }
}

// ---------------------------------------------------------------------------
// XML tree — display document structure
// ---------------------------------------------------------------------------

fn xml_tree(xml: &str, max_depth: Option<usize>) -> Result<String, String> {
    let root = parse_xml_tree(xml)?;
    let mut out = String::new();
    write_tree_node(&root, 0, max_depth, &mut out);
    Ok(out)
}

fn write_tree_node(elem: &XmlElement, depth: usize, max_depth: Option<usize>, out: &mut String) {
    if max_depth.is_some_and(|m| depth > m) {
        return;
    }

    let indent = "  ".repeat(depth);

    // Element name with attributes summary
    let mut line = format!("{indent}<{}>", elem.name);
    if !elem.attributes.is_empty() {
        let attrs: Vec<_> = elem.attributes.iter().map(|(k, _)| format!("@{k}")).collect();
        line.push_str(&format!(" [{}]", attrs.join(", ")));
    }

    // Check content types
    let has_text = !elem.text_content().is_empty();
    let has_cdata = elem.children.iter().any(|c| matches!(c, XmlChild::CData(_)));
    let has_comment = elem.children.iter().any(|c| matches!(c, XmlChild::Comment(_)));
    let child_count = elem.child_element_count();

    let mut content_parts: Vec<&str> = Vec::new();
    if has_text { content_parts.push("text"); }
    if has_cdata { content_parts.push("CDATA"); }
    if has_comment { content_parts.push("comment"); }
    if child_count == 0 && !content_parts.is_empty() {
        line.push_str(" : ");
        line.push_str(&content_parts.join(", "));
    }

    out.push_str(&line);
    out.push('\n');

    // Recurse into children
    for child in elem.child_elements() {
        write_tree_node(child, depth + 1, max_depth, out);
    }
}

// ---------------------------------------------------------------------------
// XML validation
// ---------------------------------------------------------------------------

fn validate_xml(xml: &str) -> Result<String, String> {
    match parse_xml_tree(xml) {
        Ok(root) => {
            let child_count = root.child_element_count();
            let attr_count = root.attributes.len();
            Ok(format!(
                "Valid XML. Root element: <{}> ({} attribute(s), {} child element(s))",
                root.name, attr_count, child_count
            ))
        }
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// XSLT transform — via xsltproc
// ---------------------------------------------------------------------------

fn xslt_transform(xml: &str, xslt: &str) -> Result<String, String> {
    use std::process::Command;

    // Check if xsltproc is available
    let xsltproc_check = Command::new("which")
        .arg("xsltproc")
        .output();
    if xsltproc_check.is_err() || !xsltproc_check.unwrap().status.success() {
        return Err("xsltproc not found. Install libxslt tools: apt install xsltproc (Debian/Ubuntu), brew install libxslt (macOS), or dnf install libxslt (Fedora)".into());
    }

    // Create temp files for XML and XSLT
    let tmp_dir = std::env::temp_dir();
    let xml_path = tmp_dir.join(format!("xml-mcp-{}.xml", std::process::id()));
    let xslt_path = tmp_dir.join(format!("xml-mcp-{}.xslt", std::process::id()));

    std::fs::write(&xml_path, xml).map_err(|e| format!("Failed to write temp XML: {e}"))?;
    std::fs::write(&xslt_path, xslt).map_err(|e| format!("Failed to write temp XSLT: {e}"))?;

    let result = Command::new("xsltproc")
        .arg(&xslt_path)
        .arg(&xml_path)
        .output();

    // Clean up temp files
    let _ = std::fs::remove_file(&xml_path);
    let _ = std::fs::remove_file(&xslt_path);

    match result {
        Ok(output) => {
            if output.status.success() {
                String::from_utf8(output.stdout)
                    .map_err(|e| format!("Invalid UTF-8 in output: {e}"))
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Err(format!("xsltproc failed: {stderr}"))
            }
        }
        Err(e) => Err(format!("Failed to run xsltproc: {e}")),
    }
}

// ---------------------------------------------------------------------------
// XML diff — structural comparison
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct XmlDiff {
    path: String,
    kind: DiffKind,
}

#[derive(Debug)]
enum DiffKind {
    Added(String),
    Removed(String),
    Changed { from: String, to: String },
}

impl std::fmt::Display for XmlDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            DiffKind::Added(val) => write!(f, "+ {} = {}", self.path, val),
            DiffKind::Removed(val) => write!(f, "- {} = {}", self.path, val),
            DiffKind::Changed { from, to } => write!(f, "~ {} : {} → {}", self.path, from, to),
        }
    }
}

fn diff_xml_trees(a: &XmlElement, b: &XmlElement, path: &str, diffs: &mut Vec<XmlDiff>) {
    let path_a = if path.is_empty() { format!("/{}", a.name) } else { path.to_string() };

    if a.name != b.name {
        diffs.push(XmlDiff {
            path: path_a.clone(),
            kind: DiffKind::Changed { from: format!("<{}>", a.name), to: format!("<{}>", b.name) },
        });
        return;
    }

    // Compare attributes
    let a_attrs: HashMap<&str, &str> = a.attributes.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let b_attrs: HashMap<&str, &str> = b.attributes.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

    for (k, v_a) in &a_attrs {
        match b_attrs.get(k) {
            Some(v_b) if v_a != v_b => diffs.push(XmlDiff {
                path: format!("{path_a}/@{k}"),
                kind: DiffKind::Changed { from: v_a.to_string(), to: v_b.to_string() },
            }),
            None => diffs.push(XmlDiff {
                path: format!("{path_a}/@{k}"),
                kind: DiffKind::Removed(v_a.to_string()),
            }),
            _ => {}
        }
    }
    for (k, v_b) in &b_attrs {
        if !a_attrs.contains_key(k) {
            diffs.push(XmlDiff {
                path: format!("{path_a}/@{k}"),
                kind: DiffKind::Added(v_b.to_string()),
            });
        }
    }

    // Compare text content
    let text_a = a.text_content();
    let text_b = b.text_content();
    if text_a != text_b {
        if text_a.is_empty() {
            diffs.push(XmlDiff {
                path: format!("{path_a}/text()"),
                kind: DiffKind::Added(text_b),
            });
        } else if text_b.is_empty() {
            diffs.push(XmlDiff {
                path: format!("{path_a}/text()"),
                kind: DiffKind::Removed(text_a),
            });
        } else {
            diffs.push(XmlDiff {
                path: format!("{path_a}/text()"),
                kind: DiffKind::Changed { from: text_a, to: text_b },
            });
        }
    }

    // Compare child elements by name groups
    let a_children: Vec<_> = a.child_elements().collect();
    let b_children: Vec<_> = b.child_elements().collect();

    // Group children by name, preserving order
    let mut a_groups: HashMap<&str, Vec<&XmlElement>> = HashMap::new();
    let mut b_groups: HashMap<&str, Vec<&XmlElement>> = HashMap::new();
    let mut all_names: Vec<&str> = Vec::new();

    for child in &a_children {
        if !a_groups.contains_key(child.name.as_str()) {
            all_names.push(&child.name);
        }
        a_groups.entry(&child.name).or_default().push(child);
    }
    for child in &b_children {
        if !a_groups.contains_key(child.name.as_str()) && !b_groups.contains_key(child.name.as_str()) {
            all_names.push(&child.name);
        }
        b_groups.entry(&child.name).or_default().push(child);
    }

    for name in &all_names {
        let a_list = a_groups.get(name).map(|v| v.as_slice()).unwrap_or(&[]);
        let b_list = b_groups.get(name).map(|v| v.as_slice()).unwrap_or(&[]);
        let max_len = a_list.len().max(b_list.len());

        for i in 0..max_len {
            let child_path = if max_len > 1 || a_list.len() > 1 || b_list.len() > 1 {
                format!("{path_a}/{name}[{}]", i + 1)
            } else {
                format!("{path_a}/{name}")
            };

            match (a_list.get(i), b_list.get(i)) {
                (Some(a_child), Some(b_child)) => {
                    diff_xml_trees(a_child, b_child, &child_path, diffs);
                }
                (Some(a_child), None) => {
                    diffs.push(XmlDiff {
                        path: child_path,
                        kind: DiffKind::Removed(serialize_element(a_child, false).chars().take(80).collect()),
                    });
                }
                (None, Some(b_child)) => {
                    diffs.push(XmlDiff {
                        path: child_path,
                        kind: DiffKind::Added(serialize_element(b_child, false).chars().take(80).collect()),
                    });
                }
                (None, None) => unreachable!(),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Schema inference
// ---------------------------------------------------------------------------

fn infer_xml_schema(element: &XmlElement) -> Value {
    let mut schema = Map::new();
    schema.insert("element".to_string(), json!(element.name));

    // Attributes
    if !element.attributes.is_empty() {
        let mut attrs = Map::new();
        for (key, val) in &element.attributes {
            attrs.insert(key.clone(), json!({ "type": "string", "example": val }));
        }
        schema.insert("attributes".to_string(), Value::Object(attrs));
    }

    // Children
    let child_elements: Vec<_> = element.child_elements().collect();
    if !child_elements.is_empty() {
        let mut groups: HashMap<String, Vec<Value>> = HashMap::new();
        let mut order: Vec<String> = Vec::new();
        for child in &child_elements {
            let child_schema = infer_xml_schema(child);
            if !groups.contains_key(&child.name) {
                order.push(child.name.clone());
            }
            groups.entry(child.name.clone()).or_default().push(child_schema);
        }

        let mut children = Vec::new();
        for name in &order {
            let schemas = groups.remove(name).unwrap();
            let mut merged = merge_xml_schemas(&schemas);
            if schemas.len() > 1 {
                if let Some(obj) = merged.as_object_mut() {
                    obj.insert("multiple".to_string(), json!(true));
                }
            }
            children.push(merged);
        }
        schema.insert("children".to_string(), Value::Array(children));
    }

    // Text
    let text = element.text_content();
    if !text.is_empty() {
        schema.insert("has_text".to_string(), json!(true));
        schema.insert("example_text".to_string(), json!(text));
    }

    Value::Object(schema)
}

fn merge_xml_schemas(schemas: &[Value]) -> Value {
    if schemas.is_empty() {
        return json!({});
    }
    if schemas.len() == 1 {
        return schemas[0].clone();
    }

    // Use first as base, merge attributes from all
    let mut base = schemas[0].clone();
    let base_obj = base.as_object_mut().unwrap();

    for schema in &schemas[1..] {
        // Merge attributes
        if let Some(attrs) = schema.get("attributes").and_then(|v| v.as_object()) {
            let base_attrs = base_obj
                .entry("attributes")
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .unwrap();
            for (k, v) in attrs {
                base_attrs.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
        // Merge children
        if let Some(children) = schema.get("children").and_then(|v| v.as_array()) {
            let base_children = base_obj
                .entry("children")
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .unwrap();
            for child in children {
                let child_name = child.get("element").and_then(|v| v.as_str()).unwrap_or("");
                let exists = base_children.iter().any(|bc| {
                    bc.get("element").and_then(|v| v.as_str()).unwrap_or("") == child_name
                });
                if !exists {
                    base_children.push(child.clone());
                }
            }
        }
    }

    base
}

// ---------------------------------------------------------------------------
// XML generation from schema
// ---------------------------------------------------------------------------

fn generate_mock_value(field_name: &str, example: &str, index: usize) -> String {
    let fl = field_name.to_lowercase();

    // Preserve URI/namespace values verbatim
    if example.starts_with("http://") || example.starts_with("https://") || example.starts_with("urn:") {
        return example.to_string();
    }
    if fl.starts_with("xmlns") || fl.contains("namespace") || fl.contains("schemalocation") {
        return example.to_string();
    }

    if fl.contains("email") {
        format!("{field_name}_{index}@example.com")
    } else if fl.contains("url") || fl.contains("href") || fl.contains("link") {
        format!("https://example.com/{field_name}/{index}")
    } else if fl == "id" || fl.ends_with("_id") || fl.ends_with("Id") {
        format!("{}", index + 1)
    } else if fl.contains("date") || fl.contains("time") || fl.contains("created") || fl.contains("updated") {
        format!("2024-01-{:02}T00:00:00Z", (index % 28) + 1)
    } else if fl.contains("ip") || fl.contains("address") {
        format!("10.0.{}.{}", index / 256, index % 256 + 1)
    } else if fl.contains("port") {
        format!("{}", 8080 + index)
    } else if fl.contains("version") {
        format!("{}.{}.0", index + 1, index)
    } else if !example.is_empty() && example != field_name {
        format!("{}_{}", example, index + 1)
    } else {
        format!("{}_{}", field_name, index + 1)
    }
}

fn generate_element_from_schema(schema: &Value, index: usize) -> Result<XmlElement, String> {
    let name = schema.get("element").and_then(|v| v.as_str())
        .ok_or("Schema missing 'element' field")?;

    let mut attributes = Vec::new();
    if let Some(attrs) = schema.get("attributes").and_then(|v| v.as_object()) {
        for (key, attr_schema) in attrs {
            let example = attr_schema.get("example").and_then(|v| v.as_str()).unwrap_or("");
            attributes.push((key.clone(), generate_mock_value(key, example, index)));
        }
    }

    let mut children = Vec::new();
    if let Some(child_schemas) = schema.get("children").and_then(|v| v.as_array()) {
        for child_schema in child_schemas {
            let multiple = child_schema.get("multiple").and_then(|v| v.as_bool()).unwrap_or(false);
            let count = if multiple { 3 } else { 1 };
            for i in 0..count {
                children.push(XmlChild::Element(generate_element_from_schema(child_schema, i)?));
            }
        }
    }

    if schema.get("has_text").and_then(|v| v.as_bool()).unwrap_or(false) {
        let example = schema.get("example_text").and_then(|v| v.as_str()).unwrap_or("");
        children.push(XmlChild::Text(generate_mock_value(name, example, index)));
    }

    Ok(XmlElement { name: name.to_string(), attributes, children })
}

fn xml_generate_from_schema(schema_name: &str) -> Result<String, String> {
    let schema = schema_load(schema_name)?;
    let element = generate_element_from_schema(&schema, 0)?;
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    write_element(&element, 0, true, &mut xml);
    Ok(xml)
}

// ---------------------------------------------------------------------------
// Tool definitions — computed once via OnceLock
// ---------------------------------------------------------------------------

static TOOL_DEFS: OnceLock<Value> = OnceLock::new();

fn tool_definitions() -> &'static Value {
    TOOL_DEFS.get_or_init(|| {
        json!({
            "tools": [
                // ═══════════════════════════════════════════════════════════════
                // XPATH QUERY & MODIFY — Primary XML manipulation tools
                // ═══════════════════════════════════════════════════════════════
                {
                    "name": "xpath_query",
                    "description": concat!(
                        "Extract data from XML using XPath 1.0 expressions.\n\n",
                        "INPUT: XML (inline or file) + XPath expression\n",
                        "OUTPUT: Matched values, elements, or count\n\n",
                        "COMMON PATTERNS:\n",
                        "  //elem/@attr      → Get attribute from all matching elements\n",
                        "  //elem/text()     → Get text content\n",
                        "  //elem[@id='x']   → Filter by attribute value\n",
                        "  count(//elem)     → Count elements (streaming, fast on large files)\n",
                        "  //parent/child    → Navigate hierarchy\n\n",
                        "AXES: child, descendant, parent, ancestor, following-sibling, preceding-sibling\n",
                        "FUNCTIONS: count, sum, contains, starts-with, substring, concat, not, position, last\n\n",
                        "USE FOR: Data extraction, element counting, attribute lookup, validation queries."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "xml_data": { "type": "string", "description": "Inline XML string" },
                            "xml_file": { "type": "string", "description": "Absolute path to XML file" },
                            "expression": { "type": "string", "description": "XPath expression. Examples: //book/@title, count(//item), //user[@active='true']" }
                        },
                        "required": ["expression"]
                    }
                },
                {
                    "name": "xpath_set",
                    "description": concat!(
                        "Modify values at XPath-matched locations.\n\n",
                        "INPUT: XML + XPath + new value\n",
                        "OUTPUT: Modified XML (inline or written to file)\n\n",
                        "MODIFIES:\n",
                        "  //elem/@attr      → Update attribute value\n",
                        "  //elem/text()     → Update element text content\n",
                        "  //elem            → Replace element's text\n\n",
                        "USE FOR: Bulk updates, config changes, attribute modifications."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "xml_data": { "type": "string", "description": "Inline XML string" },
                            "xml_file": { "type": "string", "description": "Absolute path to XML file" },
                            "expression": { "type": "string", "description": "XPath selecting nodes to modify" },
                            "value": { "type": "string", "description": "New value to set" },
                            "output_file": { "type": "string", "description": "Write result to file (omit to return inline)" }
                        },
                        "required": ["expression", "value"]
                    }
                },
                {
                    "name": "xpath_delete",
                    "description": concat!(
                        "Remove nodes matching XPath expression.\n\n",
                        "INPUT: XML + XPath\n",
                        "OUTPUT: XML with matched nodes removed\n\n",
                        "DELETES: Elements, attributes, text nodes\n\n",
                        "EXAMPLES:\n",
                        "  //comment()       → Remove all comments\n",
                        "  //temp            → Remove all <temp> elements\n",
                        "  //@debug          → Remove debug attributes\n\n",
                        "USE FOR: Cleanup, removing deprecated elements, stripping metadata."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "xml_data": { "type": "string", "description": "Inline XML string" },
                            "xml_file": { "type": "string", "description": "Absolute path to XML file" },
                            "expression": { "type": "string", "description": "XPath selecting nodes to delete" },
                            "output_file": { "type": "string", "description": "Write result to file (omit to return inline)" }
                        },
                        "required": ["expression"]
                    }
                },
                {
                    "name": "xpath_add",
                    "description": concat!(
                        "Insert elements or attributes at XPath-matched locations.\n\n",
                        "INPUT: XML + XPath + content + position\n",
                        "OUTPUT: XML with new content inserted\n\n",
                        "POSITIONS:\n",
                        "  inside (default)  → Append as last child\n",
                        "  before            → Insert before matched element\n",
                        "  after             → Insert after matched element\n\n",
                        "CONTENT FORMATS:\n",
                        "  <elem>text</elem> → Insert element\n",
                        "  @attr=value       → Add attribute to matched elements\n\n",
                        "USE FOR: Adding new elements, setting attributes, document augmentation."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "xml_data": { "type": "string", "description": "Inline XML string" },
                            "xml_file": { "type": "string", "description": "Absolute path to XML file" },
                            "expression": { "type": "string", "description": "XPath selecting target elements" },
                            "content": { "type": "string", "description": "Content to insert: '<elem>text</elem>' or '@attr=value'" },
                            "position": { "type": "string", "enum": ["inside", "before", "after"], "description": "Insert position (default: inside)" },
                            "output_file": { "type": "string", "description": "Write result to file (omit to return inline)" }
                        },
                        "required": ["expression", "content"]
                    }
                },

                // ═══════════════════════════════════════════════════════════════
                // FORMAT CONVERSION — XML ↔ JSON
                // ═══════════════════════════════════════════════════════════════
                {
                    "name": "xml_to_json",
                    "description": concat!(
                        "Convert XML to JSON with consistent mapping.\n\n",
                        "INPUT: XML (inline or file)\n",
                        "OUTPUT: JSON object\n\n",
                        "MAPPING RULES:\n",
                        "  <elem attr=\"v\">  → {\"elem\": {\"@attr\": \"v\", ...}}\n",
                        "  <elem>text</elem> → {\"elem\": \"text\"} or {\"elem\": {\"#text\": \"text\"}}\n",
                        "  repeated <elem>   → {\"elem\": [...]}\n\n",
                        "USE FOR: Processing XML with JSON tools, data interchange, API integration."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "xml_data": { "type": "string", "description": "Inline XML string" },
                            "xml_file": { "type": "string", "description": "Absolute path to XML file" }
                        }
                    }
                },
                {
                    "name": "json_to_xml",
                    "description": concat!(
                        "Convert JSON to XML with consistent mapping.\n\n",
                        "INPUT: JSON (inline or file)\n",
                        "OUTPUT: XML document\n\n",
                        "MAPPING RULES:\n",
                        "  {\"@attr\": \"v\"}   → attr=\"v\"\n",
                        "  {\"#text\": \"t\"}   → text content\n",
                        "  {\"elem\": [...]}   → repeated <elem> elements\n\n",
                        "USE FOR: Generating XML from structured data, roundtrip with xml_to_json."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "json_data": { "type": "string", "description": "Inline JSON string" },
                            "json_file": { "type": "string", "description": "Absolute path to JSON file" },
                            "root_element": { "type": "string", "description": "Root element name (required if JSON has multiple top-level keys)" },
                            "output_file": { "type": "string", "description": "Write result to file (omit to return inline)" }
                        }
                    }
                },

                // ═══════════════════════════════════════════════════════════════
                // ANALYSIS & VALIDATION
                // ═══════════════════════════════════════════════════════════════
                {
                    "name": "xml_validate",
                    "description": concat!(
                        "Check XML well-formedness (not schema validation).\n\n",
                        "INPUT: XML (inline or file)\n",
                        "OUTPUT: Parse status, root element info, or error details\n\n",
                        "USE FOR: Validating generated XML, checking file integrity, debugging parse errors."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "xml_data": { "type": "string", "description": "Inline XML string" },
                            "xml_file": { "type": "string", "description": "Absolute path to XML file" }
                        }
                    }
                },
                {
                    "name": "xml_tree",
                    "description": concat!(
                        "Display XML structure as an indented tree.\n\n",
                        "INPUT: XML (inline or file)\n",
                        "OUTPUT: Tree view showing elements, attributes, content types\n\n",
                        "FORMAT:\n",
                        "  <element> [@attr1, @attr2] : text\n",
                        "    <child> [@id]\n\n",
                        "USE FOR: Understanding document structure, exploring unfamiliar XML, documentation."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "xml_data": { "type": "string", "description": "Inline XML string" },
                            "xml_file": { "type": "string", "description": "Absolute path to XML file" },
                            "max_depth": { "type": "integer", "description": "Maximum tree depth to display (default: unlimited)" }
                        }
                    }
                },
                {
                    "name": "xml_diff",
                    "description": concat!(
                        "Compare two XML documents and report differences.\n\n",
                        "INPUT: Two XML documents (inline or files)\n",
                        "OUTPUT: List of differences with XPath locations\n\n",
                        "REPORTS:\n",
                        "  + /path/elem      → Element added\n",
                        "  - /path/elem      → Element removed\n",
                        "  ~ /path/@attr     → Value changed: old → new\n\n",
                        "USE FOR: Version comparison, change detection, config drift analysis."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "a_data": { "type": "string", "description": "First XML (inline)" },
                            "a_file": { "type": "string", "description": "First XML file path" },
                            "b_data": { "type": "string", "description": "Second XML (inline)" },
                            "b_file": { "type": "string", "description": "Second XML file path" }
                        }
                    }
                },
                {
                    "name": "xml_format",
                    "description": concat!(
                        "Reformat XML with different styles.\n\n",
                        "INPUT: XML (inline or file) + format mode\n",
                        "OUTPUT: Reformatted XML\n\n",
                        "MODES:\n",
                        "  pretty (default)  → Indented, human-readable\n",
                        "  compact           → Minified, no whitespace\n",
                        "  sorted            → Pretty + attributes alphabetized\n\n",
                        "USE FOR: Normalizing for comparison, minifying for transmission, beautifying."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "xml_data": { "type": "string", "description": "Inline XML string" },
                            "xml_file": { "type": "string", "description": "Absolute path to XML file" },
                            "mode": { "type": "string", "enum": ["pretty", "compact", "sorted"], "description": "Format mode (default: pretty)" },
                            "output_file": { "type": "string", "description": "Write result to file (omit to return inline)" }
                        }
                    }
                },

                // ═══════════════════════════════════════════════════════════════
                // TRANSFORMATION
                // ═══════════════════════════════════════════════════════════════
                {
                    "name": "xml_transform",
                    "description": concat!(
                        "Apply XSLT 1.0 stylesheet to transform XML.\n\n",
                        "INPUT: XML + XSLT stylesheet\n",
                        "OUTPUT: Transformed result (XML, HTML, text, etc.)\n\n",
                        "REQUIRES: xsltproc installed on system\n\n",
                        "USE FOR: Complex transformations, XML→HTML, report generation, format conversion."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "xml_data": { "type": "string", "description": "Inline XML string" },
                            "xml_file": { "type": "string", "description": "Absolute path to XML file" },
                            "xslt_data": { "type": "string", "description": "Inline XSLT stylesheet" },
                            "xslt_file": { "type": "string", "description": "Absolute path to XSLT file" },
                            "output_file": { "type": "string", "description": "Write result to file (omit to return inline)" }
                        }
                    }
                },

                // ═══════════════════════════════════════════════════════════════
                // SCHEMA — Infer, store, and use XML structure schemas
                // ═══════════════════════════════════════════════════════════════
                {
                    "name": "schema_infer",
                    "description": concat!(
                        "Analyze XML and infer its structure schema.\n\n",
                        "INPUT: XML (inline or file)\n",
                        "OUTPUT: JSON schema describing element hierarchy, attributes, types\n\n",
                        "CAPTURES: Element names, attribute names/types, child relationships, text content\n\n",
                        "USE FOR: Understanding structure, generating mock data, documentation.\n",
                        "SEE ALSO: schema_store (save), xml_generate (create from schema)"
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "xml_data": { "type": "string", "description": "Inline XML string" },
                            "xml_file": { "type": "string", "description": "Absolute path to XML file" },
                            "store_as": { "type": "string", "description": "Save inferred schema with this name" }
                        }
                    }
                },
                {
                    "name": "schema_store",
                    "description": "Save a schema by name to ~/.config/xml-mcp/schemas/ for later use.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "name": { "type": "string", "description": "Schema name (e.g., 'maven-pom', 'svg-icon')" },
                            "schema": { "type": "string", "description": "Schema as JSON string" },
                            "schema_file": { "type": "string", "description": "Path to schema JSON file" }
                        },
                        "required": ["name"]
                    }
                },
                {
                    "name": "schema_get",
                    "description": "Retrieve a stored schema by name.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "name": { "type": "string", "description": "Schema name" }
                        },
                        "required": ["name"]
                    }
                },
                {
                    "name": "schema_list",
                    "description": "List all stored schemas with element summaries.",
                    "inputSchema": { "type": "object", "properties": {} }
                },
                {
                    "name": "schema_delete",
                    "description": "Delete a stored schema by name.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "name": { "type": "string", "description": "Schema name to delete" }
                        },
                        "required": ["name"]
                    }
                },
                {
                    "name": "xml_generate",
                    "description": concat!(
                        "Generate sample XML from a stored schema.\n\n",
                        "INPUT: Schema name\n",
                        "OUTPUT: Valid XML with realistic mock data\n\n",
                        "GENERATES: Field-appropriate values (emails, IDs, dates, URLs based on field names)\n\n",
                        "USE FOR: Test data, prototyping, documentation examples.\n",
                        "SEE ALSO: schema_infer (create schema from sample XML)"
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "schema_name": { "type": "string", "description": "Stored schema name (use schema_list to see available)" },
                            "output_file": { "type": "string", "description": "Write result to file (omit to return inline)" }
                        },
                        "required": ["schema_name"]
                    }
                }
            ]
        })
    })
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn load_xml_str(args: &Value, data_key: &str, file_key: &str) -> Result<String, String> {
    if let Some(s) = args.get(data_key).and_then(|v| v.as_str()) {
        Ok(s.to_string())
    } else if let Some(path) = args.get(file_key).and_then(|v| v.as_str()) {
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read file: {e}"))
    } else {
        Err(format!("Provide '{data_key}' (inline string) or '{file_key}' (absolute file path)."))
    }
}

enum WriteResult {
    Inline(String),
    Written { path: String, bytes: usize, lines: usize },
}

fn maybe_write_file(content: String, output_file: Option<&str>) -> Result<WriteResult, String> {
    let Some(path) = output_file else {
        return Ok(WriteResult::Inline(content));
    };
    let bytes = content.len();
    let lines = content.lines().count();
    std::fs::write(path, &content).map_err(|e| format!("write failed:{path}:{e}"))?;
    Ok(WriteResult::Written { path: path.to_string(), bytes, lines })
}

fn write_result_to_value(result: WriteResult, _lang: &str) -> Value {
    match result {
        WriteResult::Inline(content) => text_result(&content),
        WriteResult::Written { path, bytes, lines, .. } => {
            text_result(&format!("written:{path}:{bytes}:{lines}"))
        }
    }
}

fn text_result(text: &str) -> Value {
    json!({ "content": [{ "type": "text", "text": text }] })
}

fn code_result(text: &str, _lang: &str) -> Value {
    // Return raw content without markdown fences for machine parsing
    json!({ "content": [{ "type": "text", "text": text }] })
}

fn annotated_result(header: &str, body: &str, _lang: &str) -> Value {
    // Compact format: header on first line, content follows
    let formatted = format!("{header}\n{body}");
    json!({ "content": [{ "type": "text", "text": formatted }] })
}

// ---------------------------------------------------------------------------
// MCP tool dispatch
// ---------------------------------------------------------------------------

fn handle_tool_call(params: &Value) -> Result<Value, String> {
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    send_notification("info", &tool_notification(name, &args));

    match name {
        // --- XPath ---
        "xpath_query" => {
            let xml = load_xml_str(&args, "xml_data", "xml_file")?;
            let expr = args.get("expression").and_then(|v| v.as_str())
                .ok_or("Missing 'expression'")?;

            // Try streaming optimizations first (much faster for large files)
            if let Some(count) = try_streaming_count(&xml, expr) {
                return Ok(text_result(&count.to_string()));
            }
            if let Some(values) = try_streaming_extract(&xml, expr) {
                if values.is_empty() {
                    return Ok(text_result("0 matches"));
                } else if values.len() == 1 {
                    return Ok(text_result(&values[0]));
                } else {
                    let mut out = format!("{}\n", values.len());
                    for v in &values {
                        out.push_str(v);
                        out.push('\n');
                    }
                    return Ok(text_result(out.trim_end()));
                }
            }

            // Fall back to full DOM-based XPath evaluation
            let root = parse_xml_tree(&xml)?;
            let (results, _xvalue) = xpath_query_tree(&root, expr)?;
            if results.is_empty() {
                Ok(text_result("0 matches"))
            } else if results.len() == 1 {
                // Single result: return value directly
                match &results[0] {
                    XPathMatch::Value(s) => Ok(text_result(s)),
                    XPathMatch::Element(s) => Ok(text_result(s)),
                }
            } else {
                // Multiple results: count header + newline-separated values
                let mut out = format!("{}\n", results.len());
                for r in &results {
                    match r {
                        XPathMatch::Value(s) | XPathMatch::Element(s) => {
                            out.push_str(s);
                            out.push('\n');
                        }
                    }
                }
                Ok(text_result(out.trim_end()))
            }
        }

        "xpath_set" => {
            let xml = load_xml_str(&args, "xml_data", "xml_file")?;
            let expr = args.get("expression").and_then(|v| v.as_str()).ok_or("Missing 'expression'")?;
            let new_value = args.get("value").and_then(|v| v.as_str()).ok_or("Missing 'value'")?;
            let output_file = args.get("output_file").and_then(|v| v.as_str());

            let mut root = parse_xml_tree(&xml)?;
            let count = xpath_set_tree(&mut root, expr, new_value)?;
            if count == 0 { return Err("0 matches".into()); }
            let mut xml_out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
            write_element(&root, 0, true, &mut xml_out);
            match maybe_write_file(xml_out, output_file)? {
                WriteResult::Inline(content) => Ok(text_result(&format!("set:{count}\n{content}"))),
                WriteResult::Written { path, bytes, lines, .. } => Ok(text_result(&format!("set:{count}:written:{path}:{bytes}:{lines}"))),
            }
        }

        "xpath_delete" => {
            let xml = load_xml_str(&args, "xml_data", "xml_file")?;
            let expr = args.get("expression").and_then(|v| v.as_str()).ok_or("Missing 'expression'")?;
            let output_file = args.get("output_file").and_then(|v| v.as_str());

            let mut root = parse_xml_tree(&xml)?;
            let count = xpath_delete_tree(&mut root, expr)?;
            if count == 0 { return Err("0 matches".into()); }
            let mut xml_out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
            write_element(&root, 0, true, &mut xml_out);
            match maybe_write_file(xml_out, output_file)? {
                WriteResult::Inline(content) => Ok(text_result(&format!("deleted:{count}\n{content}"))),
                WriteResult::Written { path, bytes, lines, .. } => Ok(text_result(&format!("deleted:{count}:written:{path}:{bytes}:{lines}"))),
            }
        }

        "xpath_add" => {
            let xml = load_xml_str(&args, "xml_data", "xml_file")?;
            let expr = args.get("expression").and_then(|v| v.as_str()).ok_or("Missing 'expression'")?;
            let content = args.get("content").and_then(|v| v.as_str()).ok_or("Missing 'content'")?;
            let position = args.get("position").and_then(|v| v.as_str()).unwrap_or("inside");
            let output_file = args.get("output_file").and_then(|v| v.as_str());

            let mut root = parse_xml_tree(&xml)?;
            let count = xpath_add_tree(&mut root, expr, content, position)?;
            if count == 0 { return Err("0 matches".into()); }
            let mut xml_out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
            write_element(&root, 0, true, &mut xml_out);
            match maybe_write_file(xml_out, output_file)? {
                WriteResult::Inline(xml_content) => Ok(text_result(&format!("added:{count}\n{xml_content}"))),
                WriteResult::Written { path, bytes, lines, .. } => Ok(text_result(&format!("added:{count}:written:{path}:{bytes}:{lines}"))),
            }
        }

        // --- Conversion ---
        "xml_to_json" => {
            let xml = load_xml_str(&args, "xml_data", "xml_file")?;
            xml_to_json_string(&xml).map(|s| code_result(&s, "json"))
        }

        "json_to_xml" => {
            let json_str = load_xml_str(&args, "json_data", "json_file")?;
            let root_element = args.get("root_element").and_then(|v| v.as_str());
            let output_file = args.get("output_file").and_then(|v| v.as_str());
            let xml = json_to_xml_string(&json_str, root_element)?;
            Ok(write_result_to_value(maybe_write_file(xml, output_file)?, "xml"))
        }

        // --- Format / Validate ---
        "xml_format" => {
            let xml = load_xml_str(&args, "xml_data", "xml_file")?;
            let mode = args.get("mode").and_then(|v| v.as_str()).unwrap_or("pretty");
            let output_file = args.get("output_file").and_then(|v| v.as_str());
            let formatted = format_xml_str(&xml, mode)?;
            Ok(write_result_to_value(maybe_write_file(formatted, output_file)?, "xml"))
        }

        "xml_validate" => {
            let xml = load_xml_str(&args, "xml_data", "xml_file")?;
            validate_xml(&xml).map(|s| text_result(&s))
        }

        // --- Diff ---
        "xml_diff" => {
            let xml_a = load_xml_str(&args, "a_data", "a_file")?;
            let xml_b = load_xml_str(&args, "b_data", "b_file")?;
            let root_a = parse_xml_tree(&xml_a)?;
            let root_b = parse_xml_tree(&xml_b)?;
            let mut diffs = Vec::new();
            diff_xml_trees(&root_a, &root_b, "", &mut diffs);
            if diffs.is_empty() {
                Ok(text_result("Documents are identical."))
            } else {
                let mut out = format!("{} difference(s):\n\n", diffs.len());
                for d in &diffs {
                    out.push_str(&format!("{d}\n"));
                }
                Ok(text_result(out.trim_end()))
            }
        }

        "xml_tree" => {
            let xml = load_xml_str(&args, "xml_data", "xml_file")?;
            let max_depth = args.get("max_depth").and_then(|v| v.as_u64()).map(|n| n as usize);
            xml_tree(&xml, max_depth).map(|s| text_result(&s))
        }

        "xml_transform" => {
            let xml = load_xml_str(&args, "xml_data", "xml_file")?;
            let xslt = load_xml_str(&args, "xslt_data", "xslt_file")?;
            let output_file = args.get("output_file").and_then(|v| v.as_str());
            let result = xslt_transform(&xml, &xslt)?;
            Ok(write_result_to_value(maybe_write_file(result, output_file)?, "xml"))
        }

        // --- Schema ---
        "schema_infer" => {
            let xml = load_xml_str(&args, "xml_data", "xml_file")?;
            let root = parse_xml_tree(&xml)?;
            let schema = infer_xml_schema(&root);
            let pretty = serde_json::to_string_pretty(&schema).unwrap_or_default();
            if let Some(store_name) = args.get("store_as").and_then(|v| v.as_str()) {
                schema_save(store_name, &schema)?;
                Ok(annotated_result(
                    &format!("Schema inferred and stored as `{store_name}`"),
                    &pretty,
                    "json",
                ))
            } else {
                Ok(code_result(&pretty, "json"))
            }
        }

        "schema_store" => {
            let name = args.get("name").and_then(|v| v.as_str())
                .ok_or("Missing 'name'")?;
            let schema = if let Some(schema_str) = args.get("schema").and_then(|v| v.as_str()) {
                serde_json::from_str::<Value>(schema_str)
                    .map_err(|e| format!("Invalid schema JSON: {e}"))?
            } else if let Some(schema_path) = args.get("schema_file").and_then(|v| v.as_str()) {
                let content = std::fs::read_to_string(schema_path)
                    .map_err(|e| format!("Failed to read {schema_path}: {e}"))?;
                serde_json::from_str::<Value>(&content)
                    .map_err(|e| format!("Invalid schema JSON in file: {e}"))?
            } else {
                return Err("Provide 'schema' (inline JSON) or 'schema_file' (path to JSON file).".into());
            };
            schema_save(name, &schema)?;
            let pretty = serde_json::to_string_pretty(&schema).unwrap_or_default();
            Ok(annotated_result(&format!("Schema `{name}` stored"), &pretty, "json"))
        }

        "schema_get" => {
            let sn = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
            schema_load(sn)
                .map(|s| code_result(&serde_json::to_string_pretty(&s).unwrap_or_default(), "json"))
        }

        "schema_list" => {
            let names = schema_list_all()?;
            if names.is_empty() {
                return Ok(text_result("No schemas stored yet."));
            }
            let mut out = format!("{} stored schema(s):\n\n", names.len());
            for name in &names {
                if let Ok(schema) = schema_load(name) {
                    let summary = schema_summary(&schema);
                    out.push_str(&format!("- **{name}**: {summary}\n"));
                } else {
                    out.push_str(&format!("- **{name}**: _(unreadable)_\n"));
                }
            }
            Ok(text_result(out.trim_end()))
        }

        "schema_delete" => {
            let sn = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
            schema_delete_file(sn).map(|()| text_result(&format!("Schema `{sn}` deleted.")))
        }

        "xml_generate" => {
            let schema_name = args.get("schema_name").and_then(|v| v.as_str())
                .ok_or("Missing required parameter 'schema_name'. Use schema_list to see available schemas.")?;
            let output_file = args.get("output_file").and_then(|v| v.as_str());
            let xml = xml_generate_from_schema(schema_name)?;
            Ok(write_result_to_value(maybe_write_file(xml, output_file)?, "xml"))
        }

        _ => Err(format!(
            "Unknown tool: {name}. Available tools: xpath_query, xpath_set, xpath_delete, xpath_add, xml_to_json, json_to_xml, xml_format, xml_validate, xml_diff, xml_tree, xml_transform, schema_infer, schema_store, schema_get, schema_list, schema_delete, xml_generate"
        )),
    }
}

// ---------------------------------------------------------------------------
// MCP protocol handler
// ---------------------------------------------------------------------------

fn handle_request(req: &JsonRpcRequest) -> Option<JsonRpcResponse> {
    let id = req.id.as_ref()?.clone();

    let resp = match req.method.as_str() {
        "initialize" => JsonRpcResponse::ok(
            id,
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {}, "logging": {} },
                "serverInfo": { "name": "xml-mcp", "version": env!("CARGO_PKG_VERSION") },
                "instructions": concat!(
                    "# xml-mcp: XML Processing Server\n\n",
                    "## Quick Reference\n\n",
                    "**QUERYING (Read Operations)**\n",
                    "- `xpath_query`: Extract data with XPath → //elem/@attr, count(//elem), //elem[@id='x']\n",
                    "- `xml_tree`: Visualize structure → Fast overview of unfamiliar XML\n",
                    "- `xml_validate`: Check well-formedness → Parse status or error details\n\n",
                    "**MODIFYING (Write Operations)**\n",
                    "- `xpath_set`: Update values → //elem/@attr, //elem/text()\n",
                    "- `xpath_add`: Insert elements/attrs → position: inside|before|after\n",
                    "- `xpath_delete`: Remove nodes → //comment(), //@debug, //temp\n\n",
                    "**CONVERSION**\n",
                    "- `xml_to_json`: XML→JSON (attrs become @attr, text becomes #text)\n",
                    "- `json_to_xml`: JSON→XML (roundtrip compatible)\n",
                    "- `xml_transform`: XSLT 1.0 transformation (requires xsltproc)\n\n",
                    "**COMPARISON**\n",
                    "- `xml_diff`: Compare two documents → Shows +added/-removed/~changed with paths\n",
                    "- `xml_format`: Normalize → pretty|compact|sorted modes\n\n",
                    "**SCHEMA**\n",
                    "- `schema_infer`: Learn structure from sample XML (use store_as to save)\n",
                    "- `xml_generate`: Create mock XML from stored schema\n\n",
                    "## XPath Quick Reference\n",
                    "- `//elem` → All elements named 'elem'\n",
                    "- `//elem/@attr` → Attribute values\n",
                    "- `//elem[@id='x']` → Filter by attribute\n",
                    "- `//parent/child` → Direct children\n",
                    "- `count(//elem)` → Count (streaming, fast on large files)\n\n",
                    "## Tips\n",
                    "- count() and //elem/@attr queries use streaming (fast on large files)\n",
                    "- Complex XPath builds full DOM (slower on 10MB+ files)\n",
                    "- Schemas persist to ~/.config/xml-mcp/schemas/"
                )
            }),
        ),
        "tools/list" => JsonRpcResponse::ok(id, tool_definitions().clone()),
        "tools/call" => {
            let params = req.params.clone().unwrap_or(json!({}));
            match handle_tool_call(&params) {
                Ok(content) => JsonRpcResponse::ok(id, content),
                Err(e) => JsonRpcResponse::ok(
                    id,
                    json!({ "content": [{ "type": "text", "text": e }], "isError": true }),
                ),
            }
        }
        "ping" => JsonRpcResponse::ok(id, json!({})),
        _ => JsonRpcResponse::err(id, -32601, format!("Method not found: {}", req.method)),
    };

    Some(resp)
}

// ---------------------------------------------------------------------------
// Main — stdio transport
// ---------------------------------------------------------------------------

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("xml-mcp: failed to parse request: {e}");
                continue;
            }
        };

        if let Some(response) = handle_request(&request) {
            let mut out = stdout.lock();
            let _ = serde_json::to_writer(&mut out, &response);
            let _ = out.write_all(b"\n");
            let _ = out.flush();
        }
    }
}
