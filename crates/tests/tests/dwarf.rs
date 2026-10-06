//! DWARF addresses inside code that walrus removes must not be written as
//! `-1`: in DWARF 4 `.debug_loc`/`.debug_ranges` with 4-byte addresses, a
//! `begin` of `-1` is the base address selection marker, which desyncs every
//! reader of the rest of the section.

use gimli::write::{
    Address, AttributeValue, DwarfUnit, EndianVec, Expression, LineProgram, Location, LocationList,
    Range, RangeList, Sections,
};
use gimli::{
    constants, read, Encoding, EndianSlice, Format, LittleEndian, RawLocListEntry, SectionId,
};
use wasmparser::{Parser, Payload};

const WAT: &str = r#"
(module
  (func $live (export "live") (result i32) i32.const 1 i32.const 2 i32.add)
  (func $dead (result i32) i32.const 3 i32.const 4 i32.add))
"#;

/// Code-section-relative address ranges of each function body, in order.
fn function_ranges(wasm: &[u8]) -> Vec<(u64, u64)> {
    let mut code_start = 0;
    let mut ranges = Vec::new();
    for payload in Parser::new(0).parse_all(wasm) {
        match payload.unwrap() {
            Payload::CodeSectionStart { range, .. } => code_start = range.start,
            Payload::CodeSectionEntry(body) => {
                let range = body.range();
                ranges.push((
                    (range.start - code_start) as u64,
                    (range.end - code_start) as u64,
                ));
            }
            _ => {}
        }
    }
    ranges
}

fn debug_sections(wasm: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for payload in Parser::new(0).parse_all(wasm) {
        if let Payload::CustomSection(s) = payload.unwrap() {
            if s.name().starts_with(".debug_") {
                out.push((s.name().to_string(), s.data().to_vec()));
            }
        }
    }
    out
}

fn build_dwarf(live: (u64, u64), dead: (u64, u64)) -> Sections<EndianVec<LittleEndian>> {
    let encoding = Encoding {
        format: Format::Dwarf32,
        version: 4,
        address_size: 4,
    };
    let mut dwarf = DwarfUnit::new(encoding);
    dwarf.unit.line_program = LineProgram::none();
    let root = dwarf.unit.root();
    dwarf.unit.get_mut(root).set(
        constants::DW_AT_low_pc,
        AttributeValue::Address(Address::Constant(0)),
    );

    let mut variable = |name: &str, (begin, end): (u64, u64)| {
        let list = dwarf
            .unit
            .locations
            .add(LocationList(vec![Location::StartEnd {
                begin: Address::Constant(begin),
                end: Address::Constant(end),
                data: Expression::new(),
            }]));
        let var = dwarf.unit.add(root, constants::DW_TAG_variable);
        let var = dwarf.unit.get_mut(var);
        var.set(constants::DW_AT_name, AttributeValue::String(name.into()));
        var.set(
            constants::DW_AT_location,
            AttributeValue::LocationListRef(list),
        );
    };
    // Straddles removed code: begin lands in `dead`, end in `live`.
    variable("straddle", (dead.0 + 1, live.1));
    // Entirely inside live code, after the tombstoned entry in section order.
    variable("live", (live.0 + 1, live.1));

    for (name, (begin, end)) in [("live_code", live), ("dead_code", dead)] {
        let entry = dwarf.unit.add(root, constants::DW_TAG_subprogram);
        let entry = dwarf.unit.get_mut(entry);
        entry.set(constants::DW_AT_name, AttributeValue::String(name.into()));
        entry.set(
            constants::DW_AT_low_pc,
            AttributeValue::Address(Address::Constant(begin + 1)),
        );
        entry.set(
            constants::DW_AT_high_pc,
            AttributeValue::Data4((end - begin - 1) as u32),
        );
    }

    let mut sections = Sections::new(EndianVec::new(LittleEndian));
    dwarf.write(&mut sections).unwrap();
    sections
}

#[test]
fn removed_code_tombstone_is_not_base_address_marker() {
    let mut wasm = wat::parse_str(WAT).unwrap();
    let ranges = function_ranges(&wasm);
    assert_eq!(ranges.len(), 2);
    let (live, dead) = (ranges[0], ranges[1]);

    let sections = build_dwarf(live, dead);
    append_sections(&mut wasm, &sections);

    let mut config = walrus::ModuleConfig::new();
    config.generate_dwarf(true);
    let mut module = config.parse(&wasm).unwrap();
    // Removes `$dead`, so its addresses no longer map anywhere.
    walrus::passes::gc::run(&mut module);
    let output = module.emit_wasm();

    let out_sections = debug_sections(&output);
    let dwarf = read_dwarf(&out_sections);

    let mut lists = 0;
    let mut units = dwarf.units();
    while let Some(header) = units.next().unwrap() {
        let unit = dwarf.unit(header).unwrap();
        let mut entries = unit.entries();
        while let Some((_, entry)) = entries.next_dfs().unwrap() {
            let offset = match entry.attr_value(constants::DW_AT_location).unwrap() {
                Some(read::AttributeValue::LocationListsRef(offset)) => offset,
                _ => continue,
            };
            lists += 1;
            // The whole list (and everything after it in the section) must
            // parse, and nothing may have turned into a base address entry.
            let mut raw = dwarf.raw_locations(&unit, offset).unwrap();
            let mut n = 0;
            while let Some(entry) = raw.next().unwrap() {
                assert!(
                    !matches!(entry, RawLocListEntry::BaseAddress { .. }),
                    "tombstone written as base address selection: {entry:?}"
                );
                n += 1;
            }
            assert_eq!(n, 1);
        }
    }
    assert_eq!(lists, 2);
}

fn append_sections(wasm: &mut Vec<u8>, sections: &Sections<EndianVec<LittleEndian>>) {
    sections
        .for_each(|id: SectionId, data| -> Result<(), ()> {
            if !data.slice().is_empty() {
                let section = wasm_encoder::CustomSection {
                    name: id.name().into(),
                    data: data.slice().into(),
                };
                wasm.push(wasm_encoder::SectionId::Custom as u8);
                wasm_encoder::Encode::encode(&section, wasm);
            }
            Ok(())
        })
        .unwrap();
}

fn read_dwarf(sections: &[(String, Vec<u8>)]) -> read::Dwarf<EndianSlice<'_, LittleEndian>> {
    let load = |id: SectionId| -> Result<EndianSlice<'_, LittleEndian>, ()> {
        let data = sections
            .iter()
            .find(|(name, _)| name == id.name())
            .map(|(_, data)| data.as_slice())
            .unwrap_or(&[]);
        Ok(EndianSlice::new(data, LittleEndian))
    };
    read::Dwarf::load(load).unwrap()
}

#[test]
fn removed_subprograms_have_empty_ranges() {
    let mut wasm = wat::parse_str(WAT).unwrap();
    let functions = function_ranges(&wasm);
    append_sections(&mut wasm, &build_dwarf(functions[0], functions[1]));
    let mut module = walrus::ModuleConfig::new()
        .generate_dwarf(true)
        .parse(&wasm)
        .unwrap();
    walrus::passes::gc::run(&mut module);
    let output = module.emit_wasm();
    let sections = debug_sections(&output);
    let dwarf = read_dwarf(&sections);
    let unit = dwarf.unit(dwarf.units().next().unwrap().unwrap()).unwrap();
    let mut entries = unit.entries();
    let mut tombstones = 0;
    while let Some((_, entry)) = entries.next_dfs().unwrap() {
        if entry.attr_value(constants::DW_AT_low_pc).unwrap()
            == Some(read::AttributeValue::Addr(0xffff_fffe))
        {
            let high = entry.attr(constants::DW_AT_high_pc).unwrap().unwrap();
            assert_eq!(high.raw_value(), read::AttributeValue::Data4(0));
            tombstones += 1;
        }
    }
    assert_eq!(tombstones, 1);
    let live = function_ranges(&output)[0];
    assert_eq!(
        read_ranges(&output)["live_code"],
        vec![(live.0 + 1, live.1)]
    );
}

#[derive(Clone, Copy, Debug)]
enum Base {
    Zero,
    Unit,
    Explicit,
}

fn range_fixture(wasm: &mut Vec<u8>, version: u16, basis: Base) {
    let functions = function_ranges(wasm);
    let first = (functions[0].0 + 1, functions[0].1);
    let last = (functions[2].0 + 1, functions[2].1);
    let mut dwarf = DwarfUnit::new(Encoding {
        format: Format::Dwarf32,
        version,
        address_size: 4,
    });
    let root = dwarf.unit.root();
    let unit_base = if matches!(basis, Base::Unit) {
        first.0
    } else {
        0
    };
    dwarf.unit.get_mut(root).set(
        constants::DW_AT_low_pc,
        AttributeValue::Address(Address::Constant(unit_base)),
    );
    for (name, (begin, end)) in [
        ("first", first),
        ("last", last),
        ("dead", (functions[1].0 + 1, functions[1].1)),
        ("spanning", (first.0, last.1)),
    ] {
        let ranges = match basis {
            Base::Zero => vec![Range::StartEnd {
                begin: Address::Constant(begin),
                end: Address::Constant(end),
            }],
            Base::Unit => vec![Range::OffsetPair {
                begin: begin - unit_base,
                end: end - unit_base,
            }],
            Base::Explicit => vec![
                Range::BaseAddress {
                    address: Address::Constant(begin),
                },
                Range::OffsetPair {
                    begin: 0,
                    end: end - begin,
                },
            ],
        };
        let list = dwarf.unit.ranges.add(RangeList(ranges));
        let entry = dwarf.unit.add(root, constants::DW_TAG_subprogram);
        dwarf
            .unit
            .get_mut(entry)
            .set(constants::DW_AT_name, AttributeValue::String(name.into()));
        dwarf
            .unit
            .get_mut(entry)
            .set(constants::DW_AT_ranges, AttributeValue::RangeListRef(list));
    }
    let mut sections = Sections::new(EndianVec::new(LittleEndian));
    dwarf.write(&mut sections).unwrap();
    append_sections(wasm, &sections);
}

fn read_ranges(wasm: &[u8]) -> std::collections::BTreeMap<String, Vec<(u64, u64)>> {
    let sections = debug_sections(wasm);
    let dwarf = read_dwarf(&sections);
    let header = dwarf.units().next().unwrap().unwrap();
    let unit = dwarf.unit(header).unwrap();
    let mut entries = unit.entries();
    let mut result = std::collections::BTreeMap::new();
    while let Some((_, entry)) = entries.next_dfs().unwrap() {
        let Some(name) = entry.attr_value(constants::DW_AT_name).unwrap() else {
            continue;
        };
        let name = dwarf.attr_string(&unit, name).unwrap();
        let name = String::from_utf8(name.slice().to_vec()).unwrap();
        let mut ranges = dwarf.die_ranges(&unit, entry).unwrap();
        let mut values = Vec::new();
        while let Some(range) = ranges.next().unwrap() {
            values.push((range.begin, range.end));
        }
        result.insert(name, values);
    }
    result
}

const RANGES: &str = r#"
(module
  (func (export "first") (result i32) i32.const 1)
  (func (result i32) i32.const 99)
  (func (export "last") (result i32)
    i32.const 2 i32.const 3 i32.add i32.const 4 i32.add))
"#;

#[test]
fn ranges_resolve_bases_before_reordering_and_gc() {
    for version in [4, 5] {
        for basis in [Base::Zero, Base::Unit, Base::Explicit] {
            let mut wasm = wat::parse_str(RANGES).unwrap();
            range_fixture(&mut wasm, version, basis);
            let mut module = walrus::ModuleConfig::new()
                .generate_dwarf(true)
                .parse(&wasm)
                .unwrap();
            walrus::passes::gc::run(&mut module);
            let output = module.emit_wasm();
            let functions = function_ranges(&output);
            // Walrus emits the largest function first: source order reverses.
            assert_eq!(functions.len(), 2);
            let last = (functions[0].0 + 1, functions[0].1);
            let first = (functions[1].0 + 1, functions[1].1);
            let ranges = read_ranges(&output);
            assert_eq!(ranges["first"], vec![first], "{version} {basis:?}");
            assert_eq!(ranges["last"], vec![last], "{version} {basis:?}");
            assert!(ranges["dead"].is_empty(), "{version} {basis:?}");
            // Spanning intervals include the later function's size/locals
            // prefix, but never invent a reversed or out-of-code range.
            let spans = &ranges["spanning"];
            for &(begin, end) in spans {
                assert!(
                    begin < end && end <= first.1,
                    "{version} {basis:?}: {spans:?}"
                );
            }
            for (begin, end) in [first, last] {
                assert!(spans.iter().any(|&(a, b)| a <= begin && end <= b));
            }
        }
    }
}

#[test]
fn range_origin_uses_actual_function_count_width() {
    for count in [3, 128, 16_384] {
        let mut wat = RANGES.trim_end().strip_suffix(')').unwrap().to_owned();
        for _ in 3..count {
            wat.push_str("(func)");
        }
        wat.push(')');
        let mut wasm = wat::parse_str(&wat).unwrap();
        range_fixture(&mut wasm, 4, Base::Explicit);
        let mut module = walrus::ModuleConfig::new()
            .generate_dwarf(true)
            .parse(&wasm)
            .unwrap();
        // Keep all functions so the encoded count crosses 1/2/3-byte widths.
        let output = module.emit_wasm();
        let functions = function_ranges(&output);
        assert_eq!(functions.len(), count);
        let last = (functions[0].0 + 1, functions[0].1);
        assert_eq!(read_ranges(&output)["last"], vec![last], "count={count}");
    }
}
