//! Relocate resolved intervals, never base-relative encoded offsets.

use gimli::{read, write, Range, Reader};

use super::units::DebuggingInformationCursor;

pub(super) fn convert<R: Reader<Offset = usize>>(
    source: &read::Dwarf<R>,
    from_unit: &read::Unit<R>,
    unit: &mut write::Unit,
    relocate: &dyn Fn(Range) -> Vec<Range>,
) -> gimli::Result<()> {
    // Replace the generic conversion's lists, rather than leaving malformed,
    // unreferenced lists in the emitted debug section.
    let mut lists = write::RangeListTable::default();
    let mut from_entries = from_unit.entries();
    let mut entries = DebuggingInformationCursor::new(unit);
    while let Some((_, from_entry)) = from_entries.next_dfs()? {
        let entry = entries.next_dfs().expect("matching converted DIE");
        let mut attrs = from_entry.attrs();
        while let Some(attr) = attrs.next()? {
            let Some(mut ranges) = source.attr_ranges(from_unit, attr.value())? else {
                continue;
            };
            let mut mapped = Vec::new();
            while let Some(range) = ranges.next()? {
                mapped.extend(relocate(range));
            }
            let list = lists.add(encode(mapped));
            entry.set(attr.name(), write::AttributeValue::RangeListRef(list));
        }
    }
    unit.ranges = lists;
    Ok(())
}

fn encode(mut ranges: Vec<Range>) -> write::RangeList {
    ranges.sort_unstable_by_key(|range| (range.begin, range.end));
    let mut merged: Vec<Range> = Vec::new();
    for range in ranges {
        if let Some(last) = merged.last_mut() {
            if range.begin <= last.end {
                last.end = last.end.max(range.end);
                continue;
            }
        }
        merged.push(range);
    }
    // In DWARF 4 even a StartEnd pair is interpreted relative to the CU's
    // low_pc unless a base-selection entry overrides it. Make the absolute
    // representation explicit without changing the CU or location lists.
    let mut encoded = Vec::new();
    if !merged.is_empty() {
        encoded.push(write::Range::BaseAddress {
            address: write::Address::Constant(0),
        });
    }
    encoded.extend(merged.into_iter().map(|range| write::Range::StartEnd {
        begin: write::Address::Constant(range.begin),
        end: write::Address::Constant(range.end),
    }));
    write::RangeList(encoded)
}
