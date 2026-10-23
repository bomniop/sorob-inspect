//! Element-section encoding regression tests.
//!
//! Each test builds a minimal module whose element section uses one binary
//! flag encoding and asserts the parser's decoded mode / kind / count /
//! resolution through the public `inspect` API. Encodings 0x00 and 0x06 are
//! also exercised functionally by `probe_elements.rs`; this file pins the
//! full flag matrix so an encoding regression is caught even when no
//! functional scenario covers a given flag byte.
//!
//! Reference: the WebAssembly spec's element-section encodings:
//!   0x00 active, table 0 (implicit), offset expr, function indices
//!   0x04 active, table 0 (implicit), offset expr, expression items
//!   0x05 passive, reference type, expression items
//!   0x06 active, table index, offset expr, reference type, expression items
//!   0x07 declared, reference type, expression items

use sorob_inspect::wasm::{
    inspect, ElementExpr, ElementItem, ElementKind, ElementRefResolution, ElementSegmentMode,
};

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
    // magic + version.
    vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]
}

fn type_section(n: usize) -> Vec<u8> {
    // n function types, each `() -> ()` (0x60, 0 params, 0 results).
    let mut payload = vec![n as u8];
    for _ in 0..n {
        payload.extend_from_slice(&[0x60, 0x00, 0x00]);
    }
    let mut b = vec![0x01, payload.len() as u8];
    b.extend_from_slice(&payload);
    b
}

fn function_section(n: usize) -> Vec<u8> {
    // n functions, each referencing type index 0.
    let mut payload = vec![n as u8];
    payload.extend(std::iter::repeat_n(0u8, n));
    let mut b = vec![0x03, payload.len() as u8];
    b.extend_from_slice(&payload);
    b
}

fn code_section(n: usize) -> Vec<u8> {
    // n empty bodies (0 locals, just `end`).
    let mut payload = vec![n as u8];
    for _ in 0..n {
        payload.extend_from_slice(&[0x02, 0x00, 0x0b]);
    }
    let mut b = vec![0x0a, payload.len() as u8];
    b.extend_from_slice(&payload);
    b
}

fn table_section() -> Vec<u8> {
    // 1 funcref table, min 4.
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

/// Build a module carrying the given element-section segment bodies, including
/// the supporting type/function/code/table sections an element section refers to.
fn module_with_elements(bodies: &[Vec<u8>]) -> Vec<u8> {
    let mut b = header();
    b.extend_from_slice(&type_section(1));
    b.extend_from_slice(&function_section(2));
    b.extend_from_slice(&code_section(2));
    b.extend_from_slice(&table_section());
    b.extend_from_slice(&element_section(bodies));
    b
}

/// Inspect `bodies` and return the report so callers can read the first
/// decoded element segment. Asserts there is exactly one segment per body.
fn first_segment(bodies: &[Vec<u8>]) -> sorob_inspect::wasm::WasmReport {
    let b = module_with_elements(bodies);
    let report = inspect(&b, false).expect("module parses cleanly");
    let st = report
        .structure
        .as_ref()
        .expect("element section implies a structure");
    assert_eq!(st.element_segments, bodies.len());
    assert_eq!(st.element_segment_details.len(), bodies.len());
    report
}

fn i32_const_expr(v: u32) -> Vec<u8> {
    let mut e = vec![0x41]; // i32.const
    e.extend_from_slice(&leb(v));
    e.push(0x0b); // end
    e
}

fn ref_func(idx: u32) -> Vec<u8> {
    let mut e = vec![0xd2]; // ref.func
    e.extend_from_slice(&leb(idx));
    e.push(0x0b); // end
    e
}

fn ref_null_func() -> Vec<u8> {
    // funcref = heap type 0x70, then end.
    vec![0xd0, 0x70, 0x0b]
}

#[test]
fn variant_f00_active_funcs_implicit_table() {
    // flags 0x00: active, table 0 (implicit), i32 offset, function indices.
    let body = {
        let mut v = vec![0x00];
        v.extend_from_slice(&i32_const_expr(0)); // offset = i32.const 0
        v.extend_from_slice(&leb(2)); // 2 function indices
        v.extend_from_slice(&leb(0)); // func idx 0
        v.extend_from_slice(&leb(1)); // func idx 1
        v
    };
    let report = first_segment(&[body]);
    let seg = &report.structure.as_ref().unwrap().element_segment_details[0];
    assert_eq!(seg.mode, ElementSegmentMode::Active);
    assert_eq!(
        seg.table_index,
        Some(0),
        "implicit table 0 is normalised to 0"
    );
    assert_eq!(seg.kind, ElementKind::Functions);
    assert_eq!(seg.element_count, 2);
    match &seg.items[0] {
        ElementItem::FuncIndex(f) => {
            assert_eq!(f.raw_index, 0);
            assert_eq!(
                f.resolution,
                ElementRefResolution::Defined {
                    declared_index: 0,
                    signature: "() -> ()".to_string(),
                }
            );
        }
        other => panic!("expected FuncIndex item, got {other:?}"),
    }
}

#[test]
fn variant_f04_active_exprs_implicit_table() {
    // flags 0x04: active, table 0 (implicit), i32 offset, expression items.
    let body = {
        let mut v = vec![0x04];
        v.extend_from_slice(&i32_const_expr(0)); // offset
        v.extend_from_slice(&leb(1)); // 1 element
        v.extend_from_slice(&ref_func(0)); // ref.func 0
        v
    };
    let report = first_segment(&[body]);
    let seg = &report.structure.as_ref().unwrap().element_segment_details[0];
    assert_eq!(seg.mode, ElementSegmentMode::Active);
    assert_eq!(
        seg.table_index,
        Some(0),
        "implicit table 0 is normalised to 0"
    );
    assert_eq!(
        seg.kind,
        ElementKind::Expressions {
            element_type: "funcref".into()
        }
    );
    assert_eq!(seg.element_count, 1);
    match &seg.items[0] {
        ElementItem::Expr(e) => match &e.expr {
            ElementExpr::RefFunc {
                raw_index,
                resolution,
            } => {
                assert_eq!(*raw_index, 0);
                assert_eq!(
                    *resolution,
                    ElementRefResolution::Defined {
                        declared_index: 0,
                        signature: "() -> ()".into(),
                    }
                );
            }
            other => panic!("expected ref.func, got {other:?}"),
        },
        other => panic!("expected Expr item, got {other:?}"),
    }
}

#[test]
fn variant_f05_passive_exprs() {
    // flags 0x05: passive, reference type, expression items.
    let body = {
        let mut v = vec![0x05, 0x70]; // 0x70 = funcref
        v.extend_from_slice(&leb(1));
        v.extend_from_slice(&ref_null_func());
        v
    };
    let report = first_segment(&[body]);
    let seg = &report.structure.as_ref().unwrap().element_segment_details[0];
    assert_eq!(seg.mode, ElementSegmentMode::Passive);
    assert_eq!(seg.table_index, None, "passive segments have no table");
    assert_eq!(
        seg.kind,
        ElementKind::Expressions {
            element_type: "funcref".into()
        }
    );
    assert_eq!(seg.element_count, 1);
    match &seg.items[0] {
        ElementItem::Expr(e) => match &e.expr {
            ElementExpr::RefNull { heap_type } => {
                // `heap_type` is the abstract HeapType (Debug-formatted), which
                // wasmparser renders as "Func" for the 0x70 function heap type.
                // It is distinct from the segment-level `element_type` ("funcref",
                // a RefType) — both are opaque Debug strings.
                assert_eq!(*heap_type, "Func");
            }
            other => panic!("expected ref.null, got {other:?}"),
        },
        other => panic!("expected Expr item, got {other:?}"),
    }
}

#[test]
fn variant_f06_active_exprs_explicit_table() {
    // flags 0x06: active, explicit table index, i32 offset, reference type,
    // expression items.
    let body = {
        let mut v = vec![0x06, 0x00]; // table index 0
        v.extend_from_slice(&i32_const_expr(0)); // offset
        v.push(0x70); // funcref element type
        v.extend_from_slice(&leb(1));
        v.extend_from_slice(&ref_func(1)); // ref.func 1 -> Defined{declared_index:1}
        v
    };
    let report = first_segment(&[body]);
    let seg = &report.structure.as_ref().unwrap().element_segment_details[0];
    assert_eq!(seg.mode, ElementSegmentMode::Active);
    assert_eq!(seg.table_index, Some(0), "explicit table 0");
    assert_eq!(
        seg.kind,
        ElementKind::Expressions {
            element_type: "funcref".into()
        }
    );
    assert_eq!(seg.element_count, 1);
    match &seg.items[0] {
        ElementItem::Expr(e) => match &e.expr {
            ElementExpr::RefFunc {
                raw_index,
                resolution,
            } => {
                assert_eq!(*raw_index, 1);
                assert_eq!(
                    *resolution,
                    ElementRefResolution::Defined {
                        declared_index: 1,
                        signature: "() -> ()".into(),
                    }
                );
            }
            other => panic!("expected ref.func, got {other:?}"),
        },
        other => panic!("expected Expr item, got {other:?}"),
    }
}

#[test]
fn variant_f07_declared_exprs() {
    // flags 0x07: declared, reference type, expression items.
    let body = {
        let mut v = vec![0x07, 0x70];
        v.extend_from_slice(&leb(1));
        v.extend_from_slice(&ref_func(0));
        v
    };
    let report = first_segment(&[body]);
    let seg = &report.structure.as_ref().unwrap().element_segment_details[0];
    assert_eq!(seg.mode, ElementSegmentMode::Declared);
    assert_eq!(seg.table_index, None, "declared segments have no table");
    assert_eq!(
        seg.kind,
        ElementKind::Expressions {
            element_type: "funcref".into()
        }
    );
    assert_eq!(seg.element_count, 1);
    match &seg.items[0] {
        ElementItem::Expr(e) => match &e.expr {
            ElementExpr::RefFunc {
                raw_index,
                resolution,
            } => {
                assert_eq!(*raw_index, 0);
                assert!(matches!(*resolution, ElementRefResolution::Defined { .. }));
            }
            other => panic!("expected ref.func, got {other:?}"),
        },
        other => panic!("expected Expr item, got {other:?}"),
    }
}
