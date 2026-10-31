use crate::error::{EwfError, Result};
use crate::sections::adler32;
use crate::types::{AcquisitionError, EwfMetadata};
use safe_read::le_u32;

/// Parse the tab-delimited text from an EWF `header` section into metadata fields.
///
/// Format (version 1, ASCII):
/// ```text
/// 1\r\n
/// main\r\n
/// c\tn\ta\te\tt\tav\tov\tm\tu\tp\r\n
/// val\tval\tval\t...\r\n
/// ```
///
/// Field codes: `c=case_number`, `n=evidence_number`, a=description,
/// e=examiner, t=notes, `av=acquiry_software`, `ov=os_version`,
/// `m=acquiry_date`, `u=system_date`, p=password (ignored).
pub(crate) fn parse_header_text(text: &str, meta: &mut EwfMetadata) {
    // Normalize line endings and split into lines
    let text = text.replace("\r\n", "\n");
    let lines: Vec<&str> = text.split('\n').collect();

    // Need at least 4 lines: version, "main", field names, field values
    if lines.len() < 4 {
        return;
    }

    let names: Vec<&str> = lines[2].split('\t').collect();
    let values: Vec<&str> = lines[3].split('\t').collect();

    for (i, &name) in names.iter().enumerate() {
        let val = values.get(i).copied().unwrap_or("");
        if val.is_empty() {
            continue;
        }
        let field = match name {
            "c" => &mut meta.case_number,
            "n" => &mut meta.evidence_number,
            "a" => &mut meta.description,
            "e" => &mut meta.examiner,
            "t" => &mut meta.notes,
            "av" => &mut meta.acquiry_software,
            "ov" => &mut meta.os_version,
            "m" => &mut meta.acquiry_date,
            "u" => &mut meta.system_date,
            _ => continue,
        };
        *field = Some(val.to_string());
    }
}

/// Parse EWF `error2` section data into acquisition error entries.
///
/// Layout (little-endian, after the 76-byte section descriptor), as libewf
/// reads it (`libewf_error2_section.c`, `ewf_error_header_v1_t`) and as its
/// format documentation states it:
/// - a 520-byte header: `u32` `number_of_entries`, 512 bytes unused, then the
///   Adler-32 of the 516 bytes before it
/// - for each entry: `u32` `first_sector` + `u32` `number_of_sectors`
/// - the Adler-32 of the entries
///
/// Fails, as libewf does, when either checksum disagrees or the entries the
/// header counts do not fit: the image then records read errors that cannot be
/// named, and an empty list would claim a clean acquisition.
pub fn parse_error2_data(data: &[u8]) -> Result<Vec<AcquisitionError>> {
    const HEADER: usize = 520;
    let damaged = |what: &str| EwfError::Parse(format!("error2 section: {what}"));
    let header = data
        .get(..HEADER)
        .ok_or_else(|| damaged("shorter than its 520-byte header"))?;
    if le_u32(header, 516) != adler32(&header[..516]) {
        return Err(damaged("header checksum does not match"));
    }
    let count = le_u32(header, 0) as usize;
    if count == 0 {
        return Ok(Vec::new());
    }
    let entries = count
        .checked_mul(8)
        .and_then(|size| data.get(HEADER..HEADER.checked_add(size)?))
        .ok_or_else(|| damaged("its entries run past the section"))?;
    let footer = HEADER + entries.len();
    let stored = data
        .get(footer..footer + 4)
        .ok_or_else(|| damaged("its entries checksum is missing"))?;
    if le_u32(stored, 0) != adler32(entries) {
        return Err(damaged("entries checksum does not match"));
    }
    Ok(entries
        .chunks_exact(8)
        .map(|entry| AcquisitionError {
            first_sector: le_u32(entry, 0),
            sector_count: le_u32(entry, 4),
        })
        .collect())
}

/// An `error2` section's data in libewf's layout, for tests: `entries` are
/// `(first_sector, sector_count)` pairs.
#[cfg(test)]
pub(crate) fn error2_bytes(entries: &[(u32, u32)]) -> Vec<u8> {
    let mut data = Vec::with_capacity(524 + entries.len() * 8);
    data.extend_from_slice(&u32::try_from(entries.len()).unwrap().to_le_bytes());
    data.resize(516, 0);
    data.extend_from_slice(&adler32(&data).to_le_bytes());
    let mut body = Vec::new();
    for (first, count) in entries {
        body.extend_from_slice(&first.to_le_bytes());
        body.extend_from_slice(&count.to_le_bytes());
    }
    data.extend_from_slice(&body);
    data.extend_from_slice(&adler32(&body).to_le_bytes());
    data
}
