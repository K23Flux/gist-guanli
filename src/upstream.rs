//! Restricted Gist imports and bounded, shared raw-file caching.
//! This module never includes upstream URLs, identifiers, or bodies in errors.

use bytes::Bytes;
use futures_util::StreamExt;
use percent_encoding::percent_decode_str;
use reqwest::{header, Client, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::{Duration, Instant},
};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use url::Url;

const MAX_BODY: usize = 2 * 1024 * 1024;
const MAX_CACHE: usize = 4 * 1024 * 1024;
const MAX_ENTRIES: usize = 128;
const MAX_FLIGHTS: usize = 128;
const MAX_FILES: usize = 512;
const MAX_URL: usize = 8192;
const TIMEOUT: Duration = Duration::from_secs(15);

type Key = (i64, i64);

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct GistRef {
    pub owner: String,
    pub gist_id: String,
    pub filename: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ImportResult {
    pub gist_id: String,
    pub owner: String,
    pub files: Vec<String>,
    pub selected: Option<String>,
    pub pinned: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamError {
    InvalidInput,
    NotFound,
    Unavailable,
    TooLarge,
    Busy,
    InvalidResponse,
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid gist input",
            Self::NotFound => "upstream file not found",
            Self::Unavailable => "upstream unavailable",
            Self::TooLarge => "upstream size limit exceeded",
            Self::Busy => "upstream capacity exhausted",
            Self::InvalidResponse => "invalid upstream response",
        })
    }
}

impl std::error::Error for UpstreamError {}

#[derive(Clone)]
pub struct Upstream {
    inner: Arc<Inner>,
}

struct Inner {
    client: Client,
    permits: Semaphore,
    max_bytes: usize,
    cache_bytes: usize,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    entries: HashMap<Key, Entry>,
    bytes: usize,
    flights: HashMap<Key, Weak<Flight>>,
}

struct Flight {
    result: AsyncMutex<Option<(GistRef, Result<Bytes, UpstreamError>)>>,
}

#[derive(Clone)]
struct Entry {
    source: GistRef,
    body: Bytes,
    etag: Option<header::HeaderValue>,
    modified: Option<header::HeaderValue>,
    checked: Instant,
    touched: Instant,
}

impl State {
    fn cached(&mut self, key: Key, source: &GistRef) -> Option<Entry> {
        let entry = self.entries.get_mut(&key)?;
        if &entry.source != source {
            return None;
        }
        entry.touched = Instant::now();
        Some(entry.clone())
    }

    fn remove(&mut self, key: Key) {
        if let Some(entry) = self.entries.remove(&key) {
            self.bytes -= entry.body.len();
        }
    }

    fn insert(&mut self, key: Key, entry: Entry, budget: usize) {
        self.remove(key);
        if budget == 0 || entry.body.len() > budget {
            return;
        }
        while self.entries.len() >= MAX_ENTRIES || self.bytes > budget - entry.body.len() {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, value)| value.touched)
                .map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                self.remove(oldest);
            } else {
                break;
            }
        }
        self.bytes += entry.body.len();
        self.entries.insert(key, entry);
    }

    fn flight(&mut self, key: Key) -> Result<Arc<Flight>, UpstreamError> {
        if let Some(flight) = self.flights.get(&key).and_then(Weak::upgrade) {
            return Ok(flight);
        }
        // No strong references here: completed results cannot grow outside the cache.
        self.flights.retain(|_, flight| flight.strong_count() != 0);
        if self.flights.len() >= MAX_FLIGHTS {
            return Err(UpstreamError::Busy);
        }
        let flight = Arc::new(Flight {
            result: AsyncMutex::new(None),
        });
        self.flights.insert(key, Arc::downgrade(&flight));
        Ok(flight)
    }

    fn insert_if_current(
        &mut self,
        key: Key,
        flight: &Arc<Flight>,
        entry: Entry,
        budget: usize,
    ) -> bool {
        if !self.current_flight(key, flight) {
            return false;
        }
        self.insert(key, entry, budget);
        true
    }

    fn current_flight(&self, key: Key, flight: &Arc<Flight>) -> bool {
        self.flights
            .get(&key)
            .and_then(Weak::upgrade)
            .is_some_and(|current| Arc::ptr_eq(&current, flight))
    }
}

impl Upstream {
    pub fn new(
        max_bytes: usize,
        cache_bytes: usize,
        concurrency: usize,
    ) -> Result<Self, anyhow::Error> {
        if max_bytes == 0 || concurrency == 0 {
            return Err(anyhow::anyhow!("invalid upstream limits"));
        }
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .timeout(TIMEOUT)
            .connect_timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(2)
            .user_agent("gist-gateway/1")
            .build()
            .map_err(|_| anyhow::anyhow!("upstream client initialization failed"))?;
        Ok(Self {
            inner: Arc::new(Inner {
                client,
                permits: Semaphore::new(concurrency.min(2)),
                max_bytes: max_bytes.min(MAX_BODY),
                cache_bytes: cache_bytes.min(MAX_CACHE),
                state: Mutex::new(State::default()),
            }),
        })
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub async fn inspect(&self, input: &str) -> Result<ImportResult, UpstreamError> {
        let (url, pinned) = validate_input_url(input)?;
        let source = parse_source(&url)?;
        // Explicit raw URLs already identify the file. Never fetch API metadata
        // on this path, including imports of a revision-pinned raw URL.
        if let Some(filename) = source.filename {
            return Ok(ImportResult {
                gist_id: source.gist_id.to_ascii_lowercase(),
                owner: source.owner,
                files: vec![filename.clone()],
                selected: Some(filename),
                pinned,
            });
        }
        tokio::time::timeout(TIMEOUT, self.inspect_inner(source, pinned))
            .await
            .map_err(|_| UpstreamError::Unavailable)?
    }

    async fn inspect_inner(
        &self,
        source: ParsedSource,
        pinned: bool,
    ) -> Result<ImportResult, UpstreamError> {
        let _permit = self
            .inner
            .permits
            .acquire()
            .await
            .map_err(|_| UpstreamError::Busy)?;
        // The API host and endpoint are constructed here, never supplied by callers.
        let api = Url::parse(&format!("https://api.github.com/gists/{}", source.gist_id))
            .map_err(|_| UpstreamError::InvalidInput)?;
        let response = self
            .inner
            .client
            .get(api)
            .header(header::ACCEPT, "application/vnd.github+json")
            .send()
            .await
            .map_err(|_| UpstreamError::Unavailable)?;
        require_success(response.status())?; // Metadata redirects are never followed.
        let body = read_limited(response, self.inner.max_bytes).await?;
        import_metadata(&body, source, pinned)
    }

    pub async fn get(
        &self,
        source_id: i64,
        version: i64,
        source: &GistRef,
        ttl_secs: u64,
    ) -> Result<Bytes, UpstreamError> {
        validate_ref(source)?;
        tokio::time::timeout(
            TIMEOUT,
            self.get_inner((source_id, version), source, ttl_secs),
        )
        .await
        .map_err(|_| UpstreamError::Unavailable)?
    }

    async fn get_inner(
        &self,
        key: Key,
        source: &GistRef,
        ttl_secs: u64,
    ) -> Result<Bytes, UpstreamError> {
        let flight = {
            let mut state = self.state();
            if let Some(entry) = state.cached(key, source) {
                if entry.checked.elapsed() < Duration::from_secs(ttl_secs) {
                    return Ok(entry.body);
                }
            }
            state.flight(key)?
        };
        let mut result = flight.result.lock().await;
        // Waiters share the first refresh, including TTL=0 and uncacheable bodies.
        if let Some((previous_source, previous_result)) = result.as_ref() {
            if previous_source == source {
                return previous_result.clone();
            }
        }
        let previous = self.state().cached(key, source);
        let fetched = self.fetch(source, previous.as_ref()).await;
        let output = match fetched {
            Ok(entry) => {
                let body = entry.body.clone();
                let mut state = self.state();
                // Invalidation detaches this flight; it cannot repopulate the cache.
                state.insert_if_current(key, &flight, entry, self.inner.cache_bytes);
                Ok(body)
            }
            Err(error) => Err(error),
        };
        *result = Some((source.clone(), output.clone()));
        output
    }

    async fn fetch(
        &self,
        source: &GistRef,
        previous: Option<&Entry>,
    ) -> Result<Entry, UpstreamError> {
        let _permit = self
            .inner
            .permits
            .acquire()
            .await
            .map_err(|_| UpstreamError::Busy)?;
        let mut url = canonical_url(source)?;
        for redirects in 0..=3 {
            let request = conditional_request(self.inner.client.get(url.clone()), previous);
            let response = request
                .send()
                .await
                .map_err(|_| UpstreamError::Unavailable)?;
            if response.status() == StatusCode::NOT_MODIFIED {
                return revalidated(previous, response.headers());
            }
            if response.status().is_redirection() {
                if redirects == 3 {
                    return Err(UpstreamError::InvalidResponse);
                }
                let location = response
                    .headers()
                    .get(header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or(UpstreamError::InvalidResponse)?;
                url = redirect_url(&url, location, source)?;
                continue;
            }
            require_success(response.status())?;
            let etag = validator(response.headers(), header::ETAG);
            let modified = validator(response.headers(), header::LAST_MODIFIED);
            let body = read_limited(response, self.inner.max_bytes).await?;
            let now = Instant::now();
            return Ok(Entry {
                source: source.clone(),
                body,
                etag,
                modified,
                checked: now,
                touched: now,
            });
        }
        Err(UpstreamError::InvalidResponse)
    }

    pub async fn invalidate(&self, id: i64) {
        let mut state = self.state();
        state.entries.retain(|key, _| key.0 != id);
        state.bytes = state.entries.values().map(|entry| entry.body.len()).sum();
        state.flights.retain(|key, _| key.0 != id);
    }

    #[cfg(test)]
    pub(crate) async fn seed_for_test(&self, id: i64, version: i64, source: GistRef, body: Bytes) {
        let now = Instant::now();
        self.state().insert(
            (id, version),
            Entry {
                source,
                body,
                etag: None,
                modified: None,
                checked: now,
                touched: now,
            },
            self.inner.cache_bytes,
        );
    }

    pub async fn usage(&self) -> (usize, usize) {
        let state = self.state();
        (state.bytes, state.entries.len())
    }
}

fn import_metadata(
    body: &[u8],
    source: ParsedSource,
    pinned: bool,
) -> Result<ImportResult, UpstreamError> {
    let metadata: Metadata =
        serde_json::from_slice(body).map_err(|_| UpstreamError::InvalidResponse)?;
    if !metadata.id.eq_ignore_ascii_case(&source.gist_id)
        || !metadata.owner.login.eq_ignore_ascii_case(&source.owner)
        || !valid_owner(&metadata.owner.login)
        || metadata.files.is_empty()
        || metadata.files.len() > MAX_FILES
    {
        return Err(UpstreamError::InvalidResponse);
    }
    let mut files: Vec<String> = metadata.files.into_keys().collect();
    if files.iter().any(|name| !valid_filename(name)) {
        return Err(UpstreamError::InvalidResponse);
    }
    files.sort();
    let selected = match source.filename {
        Some(name) => {
            if !files.contains(&name) {
                return Err(UpstreamError::NotFound);
            }
            Some(name)
        }
        None if files.len() == 1 => Some(files[0].clone()),
        None => None,
    };
    Ok(ImportResult {
        gist_id: source.gist_id.to_ascii_lowercase(),
        owner: metadata.owner.login,
        files,
        selected,
        pinned,
    })
}

#[derive(Deserialize)]
struct Metadata {
    id: String,
    owner: MetadataOwner,
    // Ignore API file objects, especially their optional content and raw_url fields.
    files: HashMap<String, serde::de::IgnoredAny>,
}

#[derive(Deserialize)]
struct MetadataOwner {
    login: String,
}

struct ParsedSource {
    owner: String,
    gist_id: String,
    filename: Option<String>,
    pinned: bool,
}

/// Accept a Gist page or an explicit raw file. The boolean reports a raw revision.
/// Page fragments are discarded. Queries and explicit ports are always rejected.
pub fn validate_input_url(input: &str) -> Result<(Url, bool), UpstreamError> {
    if input.len() > MAX_URL
        || input.is_empty()
        || input.chars().any(|c| c.is_control() || c.is_whitespace())
        || input.contains('\\')
    {
        return Err(UpstreamError::InvalidInput);
    }
    // URL parsers normalize dot segments and erase an explicit default port.
    // Check the original authority and path first so neither can bypass policy.
    let (_, rest) = input.split_once("://").ok_or(UpstreamError::InvalidInput)?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() || authority.contains(['@', ':', '%']) {
        return Err(UpstreamError::InvalidInput);
    }
    let original_path = rest[authority_end..].split(['?', '#']).next().unwrap_or("");
    for segment in original_path.split('/').skip(1) {
        if !segment.is_empty() {
            decode_segment(segment)?;
        }
    }
    let mut url = Url::parse(input).map_err(|_| UpstreamError::InvalidInput)?;
    if url.scheme() != "https"
        || url.query().is_some()
        || !url.username().is_empty()
        || url.port().is_some()
    {
        return Err(UpstreamError::InvalidInput);
    }
    match url.host_str() {
        Some("gist.github.com") => url.set_fragment(None),
        Some("gist.githubusercontent.com") if url.fragment().is_none() => {}
        _ => return Err(UpstreamError::InvalidInput),
    }
    let source = parse_source(&url)?;
    Ok((url, source.pinned))
}

fn parse_source(url: &Url) -> Result<ParsedSource, UpstreamError> {
    let segments: Vec<_> = url
        .path_segments()
        .ok_or(UpstreamError::InvalidInput)?
        .map(decode_segment)
        .collect::<Result<_, _>>()?;
    let page = url.host_str() == Some("gist.github.com");
    let parts = if page && segments.last().is_some_and(String::is_empty) {
        &segments[..segments.len() - 1]
    } else {
        &segments[..]
    };
    if parts.len() < 2 || !valid_owner(&parts[0]) || !valid_hex(&parts[1], 5) {
        return Err(UpstreamError::InvalidInput);
    }
    let (filename, pinned) = if page {
        if parts.len() != 2 {
            return Err(UpstreamError::InvalidInput);
        }
        (None, false)
    } else {
        if !matches!(parts.len(), 4 | 5) || parts[2] != "raw" {
            return Err(UpstreamError::InvalidInput);
        }
        let pinned = parts.len() == 5;
        if pinned && !valid_hex(&parts[3], 7) {
            return Err(UpstreamError::InvalidInput);
        }
        let name = &parts[parts.len() - 1];
        if !valid_filename(name) {
            return Err(UpstreamError::InvalidInput);
        }
        (Some(name.clone()), pinned)
    };
    Ok(ParsedSource {
        owner: parts[0].clone(),
        gist_id: parts[1].clone(),
        filename,
        pinned,
    })
}

fn decode_segment(segment: &str) -> Result<String, UpstreamError> {
    let bytes = segment.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'%'
            && (index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit())
        {
            return Err(UpstreamError::InvalidInput);
        }
    }
    let decoded = percent_decode_str(segment)
        .decode_utf8()
        .map_err(|_| UpstreamError::InvalidInput)?;
    if decoded == "."
        || decoded == ".."
        || decoded
            .chars()
            .any(|c| c == '/' || c == '\\' || c.is_control())
    {
        return Err(UpstreamError::InvalidInput);
    }
    Ok(decoded.into_owned())
}

fn valid_owner(owner: &str) -> bool {
    !owner.is_empty()
        && owner.len() <= 39
        && owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !owner.starts_with('-')
        && !owner.ends_with('-')
}

fn valid_hex(value: &str, minimum: usize) -> bool {
    (minimum..=64).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn valid_filename(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 1024
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|c| c == '/' || c == '\\' || c.is_control())
}

fn validate_ref(source: &GistRef) -> Result<(), UpstreamError> {
    if !valid_owner(&source.owner)
        || !valid_hex(&source.gist_id, 5)
        || !valid_filename(&source.filename)
    {
        return Err(UpstreamError::InvalidInput);
    }
    Ok(())
}

fn canonical_url(source: &GistRef) -> Result<Url, UpstreamError> {
    validate_ref(source)?;
    let mut url = Url::parse("https://gist.githubusercontent.com/")
        .map_err(|_| UpstreamError::InvalidInput)?;
    url.path_segments_mut()
        .map_err(|_| UpstreamError::InvalidInput)?
        .clear()
        .push(&source.owner)
        .push(&source.gist_id)
        .push("raw")
        .push(&source.filename);
    Ok(url)
}

fn redirect_url(base: &Url, location: &str, source: &GistRef) -> Result<Url, UpstreamError> {
    // Check the unnormalized path as well as the final absolute URL.
    if location.len() > MAX_URL
        || location.contains('\\')
        || location
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(UpstreamError::InvalidResponse);
    }
    let path = location.split(['?', '#']).next().unwrap_or("");
    for segment in path.split('/') {
        if !segment.is_empty() {
            decode_segment(segment).map_err(|_| UpstreamError::InvalidResponse)?;
        }
    }
    // Explicit authorities must pass validation before join erases default ports.
    if location.contains("://") {
        validate_input_url(location).map_err(|_| UpstreamError::InvalidResponse)?;
    } else if location.starts_with("//") {
        validate_input_url(&format!("https:{location}"))
            .map_err(|_| UpstreamError::InvalidResponse)?;
    }
    let joined = base
        .join(location)
        .map_err(|_| UpstreamError::InvalidResponse)?;
    let (url, _) =
        validate_input_url(joined.as_str()).map_err(|_| UpstreamError::InvalidResponse)?;
    let parsed = parse_source(&url).map_err(|_| UpstreamError::InvalidResponse)?;
    if url.host_str() != Some("gist.githubusercontent.com")
        || !parsed.owner.eq_ignore_ascii_case(&source.owner)
        || !parsed.gist_id.eq_ignore_ascii_case(&source.gist_id)
        || parsed.filename.as_deref() != Some(source.filename.as_str())
    {
        return Err(UpstreamError::InvalidResponse);
    }
    Ok(url)
}

fn conditional_request(
    mut request: reqwest::RequestBuilder,
    previous: Option<&Entry>,
) -> reqwest::RequestBuilder {
    if let Some(previous) = previous {
        if let Some(etag) = &previous.etag {
            request = request.header(header::IF_NONE_MATCH, etag.clone());
        }
        if let Some(modified) = &previous.modified {
            request = request.header(header::IF_MODIFIED_SINCE, modified.clone());
        }
    }
    request
}

fn revalidated(
    previous: Option<&Entry>,
    headers: &header::HeaderMap,
) -> Result<Entry, UpstreamError> {
    let mut entry = previous.cloned().ok_or(UpstreamError::InvalidResponse)?;
    entry.checked = Instant::now();
    entry.touched = entry.checked;
    // A 304 may update validators without replacing the shared body.
    if let Some(etag) = validator(headers, header::ETAG) {
        entry.etag = Some(etag);
    }
    if let Some(modified) = validator(headers, header::LAST_MODIFIED) {
        entry.modified = Some(modified);
    }
    Ok(entry)
}

fn validator(headers: &header::HeaderMap, name: header::HeaderName) -> Option<header::HeaderValue> {
    headers
        .get(name)
        .filter(|value| value.as_bytes().len() <= 1024)
        .cloned()
}

fn require_success(status: StatusCode) -> Result<(), UpstreamError> {
    match status {
        StatusCode::OK => Ok(()),
        StatusCode::NOT_FOUND => Err(UpstreamError::NotFound),
        _ => Err(UpstreamError::Unavailable),
    }
}

fn append_limited(body: &mut Vec<u8>, chunk: &[u8], maximum: usize) -> Result<(), UpstreamError> {
    if chunk.len() > maximum.saturating_sub(body.len()) {
        return Err(UpstreamError::TooLarge);
    }
    // reserve_exact avoids geometric capacity growth above the body limit.
    body.try_reserve_exact(chunk.len())
        .map_err(|_| UpstreamError::TooLarge)?;
    body.extend_from_slice(chunk);
    Ok(())
}

async fn read_limited(response: Response, maximum: usize) -> Result<Bytes, UpstreamError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(UpstreamError::TooLarge);
    }
    // reqwest's gzip/brotli stream is decoded before these length checks.
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| UpstreamError::Unavailable)?;
        append_limited(&mut body, &chunk, maximum)?;
    }
    Ok(Bytes::from(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> GistRef {
        GistRef {
            owner: "example-user".into(),
            gist_id: "0123456789abcdef0123456789abcdef".into(),
            filename: "config file.yaml".into(),
        }
    }

    fn entry(body: &'static [u8]) -> Entry {
        let now = Instant::now();
        Entry {
            source: source(),
            body: Bytes::from_static(body),
            etag: None,
            modified: None,
            checked: now,
            touched: now,
        }
    }

    #[test]
    fn accepts_page_and_discards_fragment() {
        let (url, pinned) =
            validate_input_url("https://gist.github.com/example-user/0123456789abcdef#file-config")
                .unwrap();
        assert!(url.fragment().is_none());
        assert!(!pinned);
        assert!(
            validate_input_url("https://gist.github.com/example-user/0123456789abcdef/").is_ok()
        );
    }

    #[test]
    fn raw_revision_is_detected_but_canonical_fetch_is_latest() {
        let input = "https://gist.githubusercontent.com/example-user/0123456789abcdef0123456789abcdef/raw/abcdef0123456789/config%20file.yaml";
        let (url, pinned) = validate_input_url(input).unwrap();
        assert!(pinned);
        let parsed = parse_source(&url).unwrap();
        assert_eq!(parsed.filename.as_deref(), Some("config file.yaml"));
        let canonical = canonical_url(&source()).unwrap();
        assert!(!canonical.path().contains("abcdef0123456789/"));
        assert!(canonical.path().ends_with("/raw/config%20file.yaml"));
        assert!(!validate_input_url(canonical.as_str()).unwrap().1);
    }

    #[test]
    fn rejects_authority_query_and_normalization_bypasses() {
        for input in [
            "http://gist.github.com/user/0123456789abcdef",
            "https://gist.github.com.evil.test/user/0123456789abcdef",
            "https://gist.github.com:443/user/0123456789abcdef",
            "https://user@gist.github.com/user/0123456789abcdef",
            "https://gist.github.com/user/0123456789abcdef?",
            "https://api.github.com/gists/0123456789abcdef",
            "https://gist.github.com/user/x/../0123456789abcdef",
            "https://gist.github.com/user/%2e%2e/0123456789abcdef",
            "https://gist.githubusercontent.com/user/0123456789abcdef/raw/a%2fb",
            "https://gist.githubusercontent.com/user/0123456789abcdef/raw/%2E%2e",
            "https://gist.githubusercontent.com/user/0123456789abcdef/raw/a%5cb",
            "https://gist.githubusercontent.com/user/0123456789abcdef/raw/a%00b",
            "https://gist.githubusercontent.com/user/0123456789abcdef/raw/a%0Ab",
            "https://gist.githubusercontent.com/user/0123456789abcdef/raw/a%zz",
            "https://gist.githubusercontent.com/user/0123456789abcdef/raw/a%FF",
            "https://gist.githubusercontent.com/user/0123456789abcdef/raw/a#fragment",
            "https://gist.github.com/-user/0123456789abcdef",
            "https://gist.github.com/user/not-a-gist",
        ] {
            assert!(validate_input_url(input).is_err(), "accepted forbidden URL");
        }
    }

    #[test]
    fn filenames_roundtrip_without_double_decoding() {
        for name in ["文件.yaml", "literal%2f.txt", "a?b#c", "a b", "..yaml"] {
            let mut source = source();
            source.filename = name.into();
            let url = canonical_url(&source).unwrap();
            let (validated, _) = validate_input_url(url.as_str()).unwrap();
            assert_eq!(
                parse_source(&validated).unwrap().filename.as_deref(),
                Some(name)
            );
        }
    }

    #[test]
    fn redirects_remain_same_source_on_raw_host() {
        let source = source();
        let base = canonical_url(&source).unwrap();
        assert!(redirect_url(&base, "/example-user/0123456789abcdef0123456789abcdef/raw/abcdef0123456789/config%20file.yaml", &source).is_ok());
        for location in [
            "https://evil.test/file",
            "https://gist.githubusercontent.com:443/a",
            "https://gist.github.com/example-user/0123456789abcdef0123456789abcdef",
            "//gist.githubusercontent.com:443/a",
            "../config%20file.yaml",
            "/example-user/0123456789abcdef0123456789abcdef/raw/other.yaml",
            "?token=secret",
            "#fragment",
        ] {
            assert!(redirect_url(&base, location, &source).is_err());
        }
    }

    #[test]
    fn decompressed_body_limit_is_exact_and_binary_safe() {
        let mut body = Vec::new();
        append_limited(&mut body, &[0, 255], 4).unwrap();
        append_limited(&mut body, &[128, 1], 4).unwrap();
        assert_eq!(body, [0, 255, 128, 1]);
        assert_eq!(
            append_limited(&mut body, &[2], 4),
            Err(UpstreamError::TooLarge)
        );
        assert_eq!(body.len(), 4);
        append_limited(&mut body, &[], 4).unwrap();
    }

    #[test]
    fn cache_capacity_eviction_and_shared_bytes() {
        let mut state = State::default();
        let first = entry(b"abcd");
        let pointer = first.body.as_ptr();
        state.insert((1, 1), first, 8);
        let shared = state.cached((1, 1), &source()).unwrap();
        assert_eq!(shared.body.as_ptr(), pointer);
        state.insert((2, 1), entry(b"efgh"), 8);
        assert_eq!((state.bytes, state.entries.len()), (8, 2));
        state.entries.get_mut(&(1, 1)).unwrap().touched = Instant::now() - Duration::from_secs(2);
        state.insert((3, 1), entry(b"ijklm"), 8);
        assert_eq!((state.bytes, state.entries.len()), (5, 1));
        assert!(state.entries.contains_key(&(3, 1)));
        assert_eq!(shared.body.as_ref(), b"abcd");
        state.insert((3, 1), entry(b"too large"), 8);
        assert_eq!((state.bytes, state.entries.len()), (0, 0));
        state.insert((4, 1), entry(b""), 0);
        assert!(state.entries.is_empty());
    }

    #[test]
    fn empty_bodies_cannot_bypass_entry_limit() {
        let mut state = State::default();
        for id in 0..MAX_ENTRIES as i64 + 10 {
            state.insert((id, 1), entry(b""), 1);
        }
        assert_eq!(state.entries.len(), MAX_ENTRIES);
        assert_eq!(state.bytes, 0);
    }

    #[test]
    fn versions_and_references_are_isolated() {
        let mut state = State::default();
        state.insert((1, 1), entry(b"old"), 32);
        state.insert((1, 2), entry(b"new"), 32);
        assert_eq!(
            state.cached((1, 1), &source()).unwrap().body.as_ref(),
            b"old"
        );
        assert_eq!(
            state.cached((1, 2), &source()).unwrap().body.as_ref(),
            b"new"
        );
        let mut other = source();
        other.filename = "other.yaml".into();
        assert!(state.cached((1, 2), &other).is_none());
    }

    #[test]
    fn flights_coalesce_are_bounded_and_invalidation_detaches() {
        let mut state = State::default();
        let first = state.flight((1, 1)).unwrap();
        let waiter = state.flight((1, 1)).unwrap();
        assert!(Arc::ptr_eq(&first, &waiter));
        {
            let mut result = first.result.try_lock().unwrap();
            *result = Some((source(), Ok(Bytes::from_static(b"shared"))));
            assert!(waiter.result.try_lock().is_err());
        }
        let result = waiter.result.try_lock().unwrap();
        assert_eq!(
            result.as_ref().unwrap().1.as_ref().unwrap().as_ref(),
            b"shared"
        );
        drop(result);
        state.flights.remove(&(1, 1));
        assert!(!state.current_flight((1, 1), &first));
        let next = state.flight((1, 1)).unwrap();
        assert!(!Arc::ptr_eq(&first, &next));
        let held: Vec<_> = (2..=MAX_FLIGHTS as i64)
            .map(|id| state.flight((id, 1)).unwrap())
            .collect();
        assert!(matches!(state.flight((999, 1)), Err(UpstreamError::Busy)));
        drop(held);
        assert!(state.flight((999, 1)).is_ok());
        assert!(state.flights.len() <= MAX_FLIGHTS);
    }

    #[tokio::test]
    async fn seeded_cache_preserves_crlf_and_invalidation_removes_all_versions() {
        let upstream = Upstream::new(1024, 4096, 2).unwrap();
        let body = Bytes::from_static(b"one\r\ntwo\r\n\x00\xff");
        upstream.seed_for_test(7, 1, source(), body.clone()).await;
        upstream.seed_for_test(7, 2, source(), body.clone()).await;
        upstream
            .seed_for_test(8, 1, source(), Bytes::from_static(b"other"))
            .await;
        let returned = upstream.get(7, 2, &source(), 60).await.unwrap();
        assert_eq!(returned.as_ref(), body.as_ref());
        assert_eq!(returned.as_ptr(), body.as_ptr());
        upstream.invalidate(7).await;
        assert_eq!(upstream.usage().await, (5, 1));
        assert!(upstream.state().cached((7, 1), &source()).is_none());
        assert!(upstream.state().cached((7, 2), &source()).is_none());
    }

    #[tokio::test]
    async fn concurrent_get_waiters_share_one_completed_flight_even_at_zero_ttl() {
        let upstream = Upstream::new(1024, 0, 2).unwrap();
        // Reserve the flight before polling both gets. No network endpoint or
        // alternate URL is introduced, and permits stay held as a network guard.
        let _permits = upstream.inner.permits.acquire_many(2).await.unwrap();
        let flight = upstream.state().flight((7, 1)).unwrap();
        let mut result = flight.result.lock().await;
        let reference = source();
        let first = upstream.get(7, 1, &reference, 0);
        let second = upstream.get(7, 1, &reference, 0);
        tokio::pin!(first, second);
        assert!(futures_util::poll!(&mut first).is_pending());
        assert!(futures_util::poll!(&mut second).is_pending());
        let body = Bytes::from_static(b"shared\r\n");
        *result = Some((reference.clone(), Ok(body.clone())));
        drop(result);
        let (first, second) = tokio::join!(first, second);
        let first = first.unwrap();
        let second = second.unwrap();
        assert_eq!(first.as_ptr(), body.as_ptr());
        assert_eq!(second.as_ptr(), body.as_ptr());
        assert_eq!(upstream.usage().await, (0, 0));
    }

    #[tokio::test]
    async fn invalidated_flight_cannot_commit_after_new_flight_starts() {
        let upstream = Upstream::new(1024, 4096, 2).unwrap();
        let old = upstream.state().flight((7, 1)).unwrap();
        upstream
            .seed_for_test(7, 1, source(), Bytes::from_static(b"old"))
            .await;
        upstream.invalidate(7).await;
        let next = upstream.state().flight((7, 1)).unwrap();
        let mut state = upstream.state();
        assert!(!state.insert_if_current((7, 1), &old, entry(b"stale"), 4096));
        assert_eq!(state.bytes, 0);
        assert!(state.insert_if_current((7, 1), &next, entry(b"current"), 4096));
        assert_eq!(
            state.cached((7, 1), &source()).unwrap().body.as_ref(),
            b"current"
        );
        assert!(!state.insert_if_current((7, 1), &old, entry(b"stale"), 4096));
        assert_eq!(
            state.cached((7, 1), &source()).unwrap().body.as_ref(),
            b"current"
        );
    }

    #[test]
    fn conditional_headers_and_304_reuse_body_without_copying() {
        let client = Client::builder().no_proxy().build().unwrap();
        let mut previous = entry(b"bytes\r\n\xff");
        previous.checked = Instant::now() - Duration::from_secs(60);
        previous.etag = Some(header::HeaderValue::from_static("\"first\""));
        previous.modified = Some(header::HeaderValue::from_static(
            "Wed, 01 Jan 2025 00:00:00 GMT",
        ));
        let request = conditional_request(
            client.get(canonical_url(&source()).unwrap()),
            Some(&previous),
        )
        .build()
        .unwrap();
        assert_eq!(
            request.headers().get(header::IF_NONE_MATCH),
            previous.etag.as_ref()
        );
        assert_eq!(
            request.headers().get(header::IF_MODIFIED_SINCE),
            previous.modified.as_ref()
        );
        let mut headers = header::HeaderMap::new();
        headers.insert(header::ETAG, header::HeaderValue::from_static("\"second\""));
        let updated = revalidated(Some(&previous), &headers).unwrap();
        assert_eq!(updated.body.as_ptr(), previous.body.as_ptr());
        assert_eq!(updated.body, previous.body);
        assert!(updated.checked > previous.checked);
        assert_eq!(updated.etag, headers.get(header::ETAG).cloned());
        assert_eq!(updated.modified, previous.modified);
        assert!(matches!(
            revalidated(None, &headers),
            Err(UpstreamError::InvalidResponse)
        ));
    }

    #[test]
    fn metadata_checks_owner_and_selects_only_unambiguous_files() {
        let url = validate_input_url("https://gist.github.com/example-user/0123456789abcdef")
            .unwrap()
            .0;
        let multiple = br#"{"id":"0123456789abcdef","owner":{"login":"Example-User"},"files":{"z.yaml":{"content":"ignored"},"a.yaml":{"raw_url":"https://evil.test/ignored"}}}"#;
        let imported = import_metadata(multiple, parse_source(&url).unwrap(), false).unwrap();
        assert_eq!(imported.files, vec!["a.yaml", "z.yaml"]);
        assert!(imported.selected.is_none());
        let single =
            br#"{"id":"0123456789abcdef","owner":{"login":"example-user"},"files":{"a.yaml":{}}}"#;
        assert_eq!(
            import_metadata(single, parse_source(&url).unwrap(), false)
                .unwrap()
                .selected
                .as_deref(),
            Some("a.yaml")
        );
        for invalid in [
            br#"{"id":"0123456789abcdef","owner":{"login":"other-user"},"files":{"a.yaml":{}}}"#.as_slice(),
            br#"{"id":"abcdef0123456789","owner":{"login":"example-user"},"files":{"a.yaml":{}}}"#.as_slice(),
            br#"{"id":"0123456789abcdef","owner":{"login":"example-user"},"files":{"../a.yaml":{}}}"#.as_slice(),
            br#"{"id":"0123456789abcdef","owner":{"login":"example-user"},"files":{}}"#.as_slice(),
        ] {
            assert!(matches!(import_metadata(invalid, parse_source(&url).unwrap(), false), Err(UpstreamError::InvalidResponse)));
        }
    }

    #[test]
    fn errors_are_fixed_categories() {
        for error in [
            UpstreamError::InvalidInput,
            UpstreamError::NotFound,
            UpstreamError::Unavailable,
            UpstreamError::TooLarge,
            UpstreamError::Busy,
            UpstreamError::InvalidResponse,
        ] {
            assert!(!error.to_string().contains("https:"));
            assert!(std::error::Error::source(&error).is_none());
        }
    }
}
