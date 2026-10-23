//! Probe: confirm hand-built element-segment encodings parse and classify
//! as expected with wasmparser 0.121.2.

use sorob_inspect::wasm::{inspect, ElementKind, ElementSegmentMode};

fn leb(mut n: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut v = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            v |= 0x80;
        }
        out.push(v);
        if n == 0 {
            break;
        }
    }
    out
}

fn header() -> Vec<u8> {
    vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]
}

fn type_section(n: usize) -> Vec<u8> {
    let mut payload = vec![n as u8];
    for _ in 0..n {
        payload.extend_from_slice(&[0x60, 0x00, 0x00]);
    }
    let mut b = vec![0x01, payload.len() as u8];
    b.extend_from_slice(&payload);
    b
}

fn import_section(names: &[&str]) -> Vec<u8> {
    let mut payload = vec![names.len() as u8];
    for name in names {
        payload.push(0x03);
        payload.extend_from_slice(b"env");
        payload.push(name.len() as u8);
        payload.extend_from_slice(name.as_bytes());
        payload.extend_from_slice(&[0x00, 0x00]);
    }
    let mut b = vec![0x02, payload.len() as u8];
    b.extend_from_slice(&payload);
    b
}

fn function_section(n: usize) -> Vec<u8> {
    let mut payload = vec![n as u8];
    payload.extend(std::iter::repeat_n(0u8, n));
    let mut b = vec![0x03, payload.len() as u8];
    b.extend_from_slice(&payload);
    b
}

fn code_section(n: usize) -> Vec<u8> {
    let mut payload = vec![n as u8];
    for _ in 0..n {
        payload.extend_from_slice(&[0x02, 0x00, 0x0b]);
    }
    let mut b = vec![0x0a, payload.len() as u8];
    b.extend_from_slice(&payload);
    b
}

fn table_section() -> Vec<u8> {
    // Table section (id 4): 1 table, funcref (0x70), flag 0x00, min 4.
    vec![0x04, 0x04, 0x01, 0x70, 0x00, 0x04]
}

fn element_section(bodies: &[Vec<u8>]) -> Vec<u8> {
    let mut content = Vec::new();
    content.extend_from_slice(&leb(bodies.len() as u32));
    for b in bodies {
        content.extend_from_slice(b);
    }
    let mut s = vec![0x09];
    s.extend_from_slice(&leb(content.len() as u32));
    s.extend_from_slice(&content);
    s
}

/// Active, table 0 (implicit), i32.const offset, function indices.
fn active_funcs(off: i32, idxs: &[u32]) -> Vec<u8> {
    let mut v = vec![0x00, 0x41];
    v.extend_from_slice(&leb(off as u32));
    v.push(0x0b);
    v.extend_from_slice(&leb(idxs.len() as u32));
    for i in idxs {
        v.extend_from_slice(&leb(*i));
    }
    v
}

/// Passive, function indices (flags 0x01). The parser requires the
/// external-kind byte `0x00` (func) after the flags.
fn passive_funcs(idxs: &[u32]) -> Vec<u8> {
    let mut v = vec![0x01, 0x00];
    v.extend_from_slice(&leb(idxs.len() as u32));
    for i in idxs {
        v.extend_from_slice(&leb(*i));
    }
    v
}

/// Declared, function indices (flags 0x03). The parser requires the
/// external-kind byte `0x00` (func) after the flags.
fn declared_funcs(idxs: &[u32]) -> Vec<u8> {
    let mut v = vec![0x03, 0x00];
    v.extend_from_slice(&leb(idxs.len() as u32));
    for i in idxs {
        v.extend_from_slice(&leb(*i));
    }
    v
}

/// Active, table 0 (explicit), offset, expression items. Flags `0x06`
/// selects the expression form with an explicit table index: bit 0 = 0
/// (active), bit 1 = 1 (explicit table index), bit 2 = 1 (expressions).
fn active_exprs(table: u32, off: i32, exprs: &[Vec<u8>]) -> Vec<u8> {
    let mut v = vec![0x06]; // flags 0b110: active, explicit table, expressions
    v.extend_from_slice(&leb(table));
    v.push(0x41);
    v.extend_from_slice(&leb(off as u32));
    v.push(0x0b);
    v.push(0x70); // elemtype funcref
    v.extend_from_slice(&leb(exprs.len() as u32));
    for e in exprs {
        v.extend_from_slice(e);
    }
    v
}

fn ref_func(idx: u32) -> Vec<u8> {
    let mut v = vec![0xd2];
    v.extend_from_slice(&leb(idx));
    v.push(0x0b);
    v
}

fn ref_null(hty: u8) -> Vec<u8> {
    vec![0xd0, hty, 0x0b]
}

#[test]
fn probe_active_funcs() {
    let mut b = header();
    b.extend_from_slice(&type_section(1));
    b.extend_from_slice(&function_section(2));
    b.extend_from_slice(&code_section(2));
    b.extend_from_slice(&table_section());
    b.extend_from_slice(&element_section(&[active_funcs(16, &[0, 1])]));
    let r = inspect(&b, false).unwrap();
    let s = r.structure.as_ref().unwrap();
    println!("active_funcs: {:#?}", s.element_segment_details);
    assert_eq!(s.element_segments, 1);
    assert_eq!(s.element_segment_details.len(), 1);
    let seg = &s.element_segment_details[0];
    assert_eq!(seg.mode, ElementSegmentMode::Active);
    assert_eq!(seg.table_index, Some(0));
    assert_eq!(seg.kind, ElementKind::Functions);
    assert_eq!(seg.element_count, 2);
}

#[test]
fn probe_passive_declared() {
    let mut b = header();
    b.extend_from_slice(&type_section(1));
    b.extend_from_slice(&function_section(1));
    b.extend_from_slice(&code_section(1));
    b.extend_from_slice(&element_section(&[
        passive_funcs(&[0]),
        declared_funcs(&[0]),
    ]));
    let r = inspect(&b, false).unwrap();
    let s = r.structure.as_ref().unwrap();
    println!("passive_declared: {:#?}", s.element_segment_details);
    assert_eq!(
        s.element_segment_details[0].mode,
        ElementSegmentMode::Passive
    );
    assert_eq!(
        s.element_segment_details[1].mode,
        ElementSegmentMode::Declared
    );
}

#[test]
fn probe_exprs() {
    let mut b = header();
    b.extend_from_slice(&type_section(1));
    b.extend_from_slice(&function_section(2));
    b.extend_from_slice(&code_section(2));
    b.extend_from_slice(&table_section());
    b.extend_from_slice(&element_section(&[active_exprs(
        0,
        0,
        &[ref_func(0), ref_func(1), ref_null(0x70)],
    )]));
    let r = inspect(&b, false).unwrap();
    let s = r.structure.as_ref().unwrap();
    println!("exprs: {:#?}", s.element_segment_details);
    assert_eq!(
        s.element_segment_details[0].kind,
        ElementKind::Expressions {
            element_type: "funcref".into()
        }
    );
}

#[test]
fn probe_import_resolution() {
    // 2 imports (idx 0,1) + 1 defined (idx 2). Segment lists [0,1,2,99].
    let mut b = header();
    b.extend_from_slice(&type_section(1));
    b.extend_from_slice(&import_section(&["a", "b"]));
    b.extend_from_slice(&function_section(1));
    b.extend_from_slice(&code_section(1));
    b.extend_from_slice(&table_section());
    b.extend_from_slice(&element_section(&[active_funcs(0, &[0, 1, 2, 99])]));
    let r = inspect(&b, false).unwrap();
    let s = r.structure.as_ref().unwrap();
    println!("import_resolution: {:#?}", s.element_segment_details);
}
