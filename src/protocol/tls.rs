//! Lightweight TLS ClientHello parser for extracting SNI.
//!
//! This module intentionally performs bounded, best-effort parsing over a
//! single TCP payload. It does not perform TCP reassembly.

use super::ParseError;

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE_HEADER_LEN: usize = 4;

const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS_EXTENSION_SERVER_NAME: u16 = 0x0000;

const MAX_TLS_RECORD_LEN: usize = 16 * 1024 + 2048;
const MAX_EXTENSIONS_LEN: usize = 16 * 1024;
const MAX_EXTENSION_ENTRIES: usize = 64;
const MAX_SERVER_NAME_LIST_ENTRIES: usize = 16;
const MAX_SNI_LEN: usize = 255;

/// Extracted TLS ClientHello metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientHelloInfo {
    pub sni: String,
    pub legacy_version: u16,
}

/// Parse a TCP payload as TLS and extract the ClientHello SNI hostname.
///
/// This is intentionally a single-payload parser: it does not perform TCP
/// stream reassembly, so split ClientHello messages will not decode.
///
/// Returns `None` when the payload is not a TLS ClientHello, is truncated, or
/// does not contain a valid SNI host_name entry.
#[inline]
pub fn parse_client_hello_sni(payload: &[u8]) -> Option<TlsClientHelloInfo> {
    // Fast prefilter for the common case (non-TLS TCP payloads) to avoid
    // allocating error strings in the deeper parser.
    if payload.len() < TLS_RECORD_HEADER_LEN {
        return None;
    }
    if payload[0] != TLS_CONTENT_TYPE_HANDSHAKE {
        return None;
    }
    if payload[1] != 0x03 || !(0x01..=0x04).contains(&payload[2]) {
        return None;
    }

    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if record_len == 0 || record_len > MAX_TLS_RECORD_LEN {
        return None;
    }
    if payload.len() < TLS_RECORD_HEADER_LEN + record_len {
        return None;
    }

    parse_client_hello_sni_inner(payload).ok()
}

fn parse_client_hello_sni_inner(payload: &[u8]) -> Result<TlsClientHelloInfo, ParseError> {
    ensure_len(payload, 0, TLS_RECORD_HEADER_LEN, "tls record header")?;

    if payload[0] != TLS_CONTENT_TYPE_HANDSHAKE {
        return Err(ParseError::InvalidHeader(
            "tls record is not a handshake".to_string(),
        ));
    }

    let record_version = read_u16(payload, 1);
    if !(0x0301..=0x0304).contains(&record_version) {
        return Err(ParseError::InvalidHeader(format!(
            "unsupported tls record version: 0x{:04x}",
            record_version
        )));
    }

    let record_len = read_u16(payload, 3) as usize;
    if record_len == 0 || record_len > MAX_TLS_RECORD_LEN {
        return Err(ParseError::InvalidHeader(format!(
            "tls record length out of bounds: {}",
            record_len
        )));
    }
    ensure_len(
        payload,
        TLS_RECORD_HEADER_LEN,
        record_len,
        "tls record body",
    )?;
    let record_end = TLS_RECORD_HEADER_LEN
        .checked_add(record_len)
        .ok_or_else(|| ParseError::InvalidHeader("tls record length overflow".to_string()))?;

    ensure_len(
        payload,
        TLS_RECORD_HEADER_LEN,
        TLS_HANDSHAKE_HEADER_LEN,
        "tls handshake header",
    )?;
    let handshake_type = payload[TLS_RECORD_HEADER_LEN];
    if handshake_type != TLS_HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(ParseError::InvalidHeader(
            "tls handshake is not clienthello".to_string(),
        ));
    }

    let handshake_len = read_u24(payload, TLS_RECORD_HEADER_LEN + 1);
    let handshake_start = TLS_RECORD_HEADER_LEN + TLS_HANDSHAKE_HEADER_LEN;
    let handshake_end = handshake_start
        .checked_add(handshake_len)
        .ok_or_else(|| ParseError::InvalidHeader("tls handshake length overflow".to_string()))?;
    if handshake_end > record_end {
        return Err(ParseError::TooShort {
            expected: handshake_end,
            actual: record_end,
        });
    }

    parse_client_hello_body(&payload[handshake_start..handshake_end])
}

fn parse_client_hello_body(body: &[u8]) -> Result<TlsClientHelloInfo, ParseError> {
    let mut offset = 0usize;

    ensure_len(body, offset, 34, "tls clienthello fixed fields")?;
    let legacy_version = read_u16(body, offset);
    offset += 2; // legacy_version
    offset += 32; // random

    // session_id
    ensure_len(body, offset, 1, "tls session_id length")?;
    let session_id_len = body[offset] as usize;
    if session_id_len > 32 {
        return Err(ParseError::InvalidHeader(format!(
            "tls session_id too long: {}",
            session_id_len
        )));
    }
    offset += 1;
    ensure_len(body, offset, session_id_len, "tls session_id")?;
    offset += session_id_len;

    // cipher_suites
    ensure_len(body, offset, 2, "tls cipher_suites length")?;
    let cipher_suites_len = read_u16(body, offset) as usize;
    if cipher_suites_len == 0 || cipher_suites_len % 2 != 0 {
        return Err(ParseError::InvalidHeader(format!(
            "tls cipher_suites length invalid: {}",
            cipher_suites_len
        )));
    }
    offset += 2;
    ensure_len(body, offset, cipher_suites_len, "tls cipher_suites")?;
    offset += cipher_suites_len;

    // compression_methods
    ensure_len(body, offset, 1, "tls compression_methods length")?;
    let compression_methods_len = body[offset] as usize;
    if compression_methods_len == 0 {
        return Err(ParseError::InvalidHeader(
            "tls compression_methods length is zero".to_string(),
        ));
    }
    offset += 1;
    ensure_len(
        body,
        offset,
        compression_methods_len,
        "tls compression_methods",
    )?;
    offset += compression_methods_len;

    // extensions
    ensure_len(body, offset, 2, "tls extensions length")?;
    let extensions_len = read_u16(body, offset) as usize;
    if extensions_len > MAX_EXTENSIONS_LEN {
        return Err(ParseError::InvalidHeader(format!(
            "tls extensions length out of bounds: {}",
            extensions_len
        )));
    }
    offset += 2;
    ensure_len(body, offset, extensions_len, "tls extensions data")?;
    let extensions_end = offset
        .checked_add(extensions_len)
        .ok_or_else(|| ParseError::InvalidHeader("tls extensions length overflow".to_string()))?;

    parse_extensions(&body[offset..extensions_end], legacy_version)
}

fn parse_extensions(data: &[u8], legacy_version: u16) -> Result<TlsClientHelloInfo, ParseError> {
    let mut offset = 0usize;
    let mut scanned = 0usize;

    while offset < data.len() {
        scanned += 1;
        if scanned > MAX_EXTENSION_ENTRIES {
            return Err(ParseError::InvalidHeader(
                "tls extension count exceeded bound".to_string(),
            ));
        }

        ensure_len(data, offset, 4, "tls extension header")?;
        let ext_type = read_u16(data, offset);
        let ext_len = read_u16(data, offset + 2) as usize;
        offset += 4;
        ensure_len(data, offset, ext_len, "tls extension body")?;

        if ext_type == TLS_EXTENSION_SERVER_NAME {
            let sni = parse_server_name_extension(&data[offset..offset + ext_len])?;
            return Ok(TlsClientHelloInfo {
                sni,
                legacy_version,
            });
        }

        offset += ext_len;
    }

    Err(ParseError::InvalidHeader(
        "tls clienthello missing server_name extension".to_string(),
    ))
}

fn parse_server_name_extension(data: &[u8]) -> Result<String, ParseError> {
    ensure_len(data, 0, 2, "tls server_name list length")?;
    let list_len = read_u16(data, 0) as usize;
    if list_len == 0 {
        return Err(ParseError::InvalidHeader(
            "tls server_name list is empty".to_string(),
        ));
    }

    ensure_len(data, 2, list_len, "tls server_name list")?;
    let list_end = 2usize
        .checked_add(list_len)
        .ok_or_else(|| ParseError::InvalidHeader("tls server_name list overflow".to_string()))?;
    if list_end != data.len() {
        return Err(ParseError::InvalidHeader(
            "tls server_name list length mismatch".to_string(),
        ));
    }

    let mut offset = 2usize;
    let mut entries = 0usize;

    while offset < list_end {
        entries += 1;
        if entries > MAX_SERVER_NAME_LIST_ENTRIES {
            return Err(ParseError::InvalidHeader(
                "tls server_name entry count exceeded bound".to_string(),
            ));
        }

        ensure_len(data, offset, 3, "tls server_name entry header")?;
        let name_type = data[offset];
        let name_len = read_u16(data, offset + 1) as usize;
        offset += 3;
        ensure_len(data, offset, name_len, "tls server_name entry value")?;

        let host = &data[offset..offset + name_len];
        offset += name_len;

        if name_type == 0 {
            return parse_host_name(host);
        }
    }

    Err(ParseError::InvalidHeader(
        "tls server_name has no host_name entry".to_string(),
    ))
}

fn parse_host_name(host: &[u8]) -> Result<String, ParseError> {
    if host.is_empty() || host.len() > MAX_SNI_LEN {
        return Err(ParseError::InvalidHeader(format!(
            "tls sni length invalid: {}",
            host.len()
        )));
    }

    let sni = std::str::from_utf8(host)
        .map_err(|_| ParseError::InvalidHeader("tls sni is not utf-8".to_string()))?;
    if !is_valid_hostname(sni) {
        return Err(ParseError::InvalidHeader(
            "tls sni contains invalid hostname characters".to_string(),
        ));
    }
    Ok(sni.to_string())
}

fn is_valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        return false;
    }

    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
    }

    true
}

#[inline]
fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

#[inline]
fn read_u24(data: &[u8], offset: usize) -> usize {
    ((data[offset] as usize) << 16) | ((data[offset + 1] as usize) << 8) | data[offset + 2] as usize
}

fn ensure_len(data: &[u8], offset: usize, needed: usize, context: &str) -> Result<(), ParseError> {
    let expected = offset
        .checked_add(needed)
        .ok_or_else(|| ParseError::InvalidHeader(format!("{} offset overflow", context)))?;
    if data.len() < expected {
        return Err(ParseError::TooShort {
            expected,
            actual: data.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_extension(ext_type: u16, ext_data: &[u8]) -> Vec<u8> {
        let mut ext = Vec::with_capacity(4 + ext_data.len());
        ext.extend_from_slice(&ext_type.to_be_bytes());
        ext.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        ext.extend_from_slice(ext_data);
        ext
    }

    fn build_server_name_extension(host: &str) -> Vec<u8> {
        let host_bytes = host.as_bytes();
        let mut ext_data = Vec::with_capacity(2 + 1 + 2 + host_bytes.len());
        let name_list_len = 1 + 2 + host_bytes.len();
        ext_data.extend_from_slice(&(name_list_len as u16).to_be_bytes());
        ext_data.push(0x00); // host_name
        ext_data.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        ext_data.extend_from_slice(host_bytes);
        build_extension(TLS_EXTENSION_SERVER_NAME, &ext_data)
    }

    fn build_client_hello_with_options(
        record_version: u16,
        legacy_version: u16,
        cipher_suites_len: usize,
        extensions: &[Vec<u8>],
    ) -> Vec<u8> {
        assert!(cipher_suites_len >= 2);
        assert_eq!(cipher_suites_len % 2, 0);
        assert!(cipher_suites_len <= u16::MAX as usize);

        let mut body = Vec::new();

        // ClientHello
        body.extend_from_slice(&legacy_version.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session_id len
        body.extend_from_slice(&(cipher_suites_len as u16).to_be_bytes());
        for _ in 0..(cipher_suites_len / 2) {
            body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        }
        body.push(0x01); // compression_methods len
        body.push(0x00); // null compression

        let total_extensions_len: usize = extensions.iter().map(Vec::len).sum();
        assert!(total_extensions_len <= u16::MAX as usize);
        body.extend_from_slice(&(total_extensions_len as u16).to_be_bytes());
        for ext in extensions {
            body.extend_from_slice(ext);
        }

        let mut handshake = Vec::new();
        handshake.push(TLS_HANDSHAKE_TYPE_CLIENT_HELLO);
        let handshake_len = body.len() as u32;
        handshake.push(((handshake_len >> 16) & 0xff) as u8);
        handshake.push(((handshake_len >> 8) & 0xff) as u8);
        handshake.push((handshake_len & 0xff) as u8);
        handshake.extend_from_slice(&body);

        assert!(handshake.len() <= u16::MAX as usize);
        let mut record = Vec::new();
        record.push(TLS_CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&record_version.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn build_client_hello(server_name: Option<&str>) -> Vec<u8> {
        let mut extensions: Vec<Vec<u8>> = Vec::new();
        if let Some(host) = server_name {
            extensions.push(build_server_name_extension(host));
        }

        // supported_versions ext (realistic, optional for parser)
        extensions.push(build_extension(0x002b, &[0x02, 0x03, 0x04]));

        build_client_hello_with_options(0x0303, 0x0303, 2, &extensions)
    }

    #[test]
    fn parse_valid_clienthello_sni() {
        let pkt = build_client_hello(Some("example.com"));
        let info = parse_client_hello_sni(&pkt).expect("should parse tls sni");
        assert_eq!(info.sni, "example.com");
        assert_eq!(info.legacy_version, 0x0303);
    }

    #[test]
    fn clienthello_without_sni_returns_none() {
        let pkt = build_client_hello(None);
        assert!(parse_client_hello_sni(&pkt).is_none());
    }

    fn find_server_name_list_len_offset(pkt: &[u8]) -> usize {
        // Locate the server_name extension's list length field without relying on
        // hard-coded byte offsets. This assumes `pkt` was built by `build_client_hello`.
        let record_len = u16::from_be_bytes([pkt[3], pkt[4]]) as usize;
        let record_end = TLS_RECORD_HEADER_LEN + record_len;
        assert!(record_end <= pkt.len());

        let handshake_type = pkt[TLS_RECORD_HEADER_LEN];
        assert_eq!(handshake_type, TLS_HANDSHAKE_TYPE_CLIENT_HELLO);
        let handshake_len = read_u24(pkt, TLS_RECORD_HEADER_LEN + 1);
        let handshake_start = TLS_RECORD_HEADER_LEN + TLS_HANDSHAKE_HEADER_LEN;
        let handshake_end = handshake_start + handshake_len;
        assert!(handshake_end <= record_end);

        // Walk the ClientHello body to the extensions block.
        let mut offset = handshake_start;
        offset += 2; // legacy_version
        offset += 32; // random
        let session_id_len = pkt[offset] as usize;
        offset += 1 + session_id_len;
        let cipher_suites_len = u16::from_be_bytes([pkt[offset], pkt[offset + 1]]) as usize;
        offset += 2 + cipher_suites_len;
        let compression_methods_len = pkt[offset] as usize;
        offset += 1 + compression_methods_len;
        let extensions_len = u16::from_be_bytes([pkt[offset], pkt[offset + 1]]) as usize;
        offset += 2;
        let extensions_end = offset + extensions_len;
        assert!(extensions_end <= handshake_end);

        // Scan extensions for server_name.
        let mut ext_off = offset;
        while ext_off + 4 <= extensions_end {
            let ext_type = u16::from_be_bytes([pkt[ext_off], pkt[ext_off + 1]]);
            let ext_len = u16::from_be_bytes([pkt[ext_off + 2], pkt[ext_off + 3]]) as usize;
            ext_off += 4;
            if ext_type == TLS_EXTENSION_SERVER_NAME {
                return ext_off;
            }
            ext_off += ext_len;
        }

        panic!("server_name extension not found");
    }

    #[test]
    fn reject_truncated_or_malformed_lengths() {
        let mut truncated = build_client_hello(Some("example.com"));
        truncated.truncate(truncated.len() - 3);
        assert!(parse_client_hello_sni(&truncated).is_none());

        let mut malformed = build_client_hello(Some("example.com"));
        // Corrupt server_name list length to exceed extension body.
        let list_len_off = find_server_name_list_len_offset(&malformed);
        malformed[list_len_off] = 0xff;
        malformed[list_len_off + 1] = 0xff;
        assert!(parse_client_hello_sni(&malformed).is_none());
    }

    #[test]
    fn reject_invalid_hostname() {
        let pkt = build_client_hello(Some("bad host"));
        assert!(parse_client_hello_sni(&pkt).is_none());
    }

    #[test]
    fn reject_hostname_with_underscore() {
        let pkt = build_client_hello(Some("api_test.example.com"));
        assert!(parse_client_hello_sni(&pkt).is_none());
    }

    #[test]
    fn parse_large_clienthello_sni() {
        let sni_ext = build_server_name_extension("example.com");
        let supported_versions_ext = build_extension(0x002b, &[0x02, 0x03, 0x04]);
        let used = sni_ext.len() + supported_versions_ext.len();
        let padding_len = MAX_EXTENSIONS_LEN - used - 4; // account for one extra extension header
        let padding_ext = build_extension(0xfffe, &vec![0xaa; padding_len]);

        let extensions = vec![sni_ext, supported_versions_ext, padding_ext];
        let pkt = build_client_hello_with_options(0x0303, 0x0303, 1024, &extensions);
        let info = parse_client_hello_sni(&pkt).expect("large ClientHello should parse");
        assert_eq!(info.sni, "example.com");
        assert_eq!(info.legacy_version, 0x0303);
    }

    #[test]
    fn parse_supported_record_version_combinations() {
        let combinations = [(0x0301, 0x0303), (0x0303, 0x0303), (0x0304, 0x0301)];
        for (record_version, legacy_version) in combinations {
            let extensions = vec![
                build_server_name_extension("example.com"),
                build_extension(0x002b, &[0x02, 0x03, 0x04]),
            ];
            let pkt =
                build_client_hello_with_options(record_version, legacy_version, 2, &extensions);
            let info = parse_client_hello_sni(&pkt).expect("supported version combo should parse");
            assert_eq!(info.sni, "example.com");
            assert_eq!(info.legacy_version, legacy_version);
        }
    }

    #[test]
    fn parse_sni_with_malformed_extension_after_sni() {
        let mut malformed_tail = Vec::new();
        malformed_tail.extend_from_slice(&0x1234u16.to_be_bytes());
        malformed_tail.extend_from_slice(&10u16.to_be_bytes()); // claims 10 bytes
        malformed_tail.extend_from_slice(&[0u8; 2]); // actually only 2 bytes

        let extensions = vec![build_server_name_extension("example.com"), malformed_tail];
        let pkt = build_client_hello_with_options(0x0303, 0x0303, 2, &extensions);
        let info = parse_client_hello_sni(&pkt).expect("should extract SNI before malformed tail");
        assert_eq!(info.sni, "example.com");
    }
}
