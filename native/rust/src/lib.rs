//! Bounded binary metadata scan behind Fangida's stable C ABI.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

const ABI_MAJOR: u32 = 1;
const ABI_MINOR: u32 = 0;
const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const MIN_STRING_LENGTH: usize = 4;
const MAX_STRINGS: usize = 32;
const MAX_STRING_LENGTH: usize = 128;

#[repr(C)]
pub struct FangidaBuffer {
    pub data: *mut u8,
    pub length: u64,
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub enum FangidaStatus {
    Ok = 0,
    Invalid = 1,
    Failed = 2,
}

#[no_mangle]
pub extern "C" fn fangida_abi_version() -> u32 {
    (ABI_MAJOR << 16) | ABI_MINOR
}

fn analyze_json(data: &[u8]) -> String {
    let mut histogram = [0_u64; 256];
    for &byte in data {
        histogram[usize::from(byte)] += 1;
    }

    let mut json = String::from("{\"schema_version\":1,\"size\":");
    json.push_str(&data.len().to_string());
    json.push_str(",\"histogram\":[");
    for (i, count) in histogram.iter().enumerate() {
        if i != 0 {
            json.push(',');
        }
        json.push_str(&count.to_string());
    }
    json.push_str("],\"strings\":[");

    let mut found = 0;
    let mut truncated = false;
    let mut i = 0;
    while i < data.len() {
        if !data[i].is_ascii_graphic() && data[i] != b' ' {
            i += 1;
            continue;
        }
        let start = i;
        while i < data.len() && (data[i].is_ascii_graphic() || data[i] == b' ') {
            i += 1;
        }
        let run = &data[start..i];
        if run.len() < MIN_STRING_LENGTH {
            continue;
        }
        if found >= MAX_STRINGS {
            truncated = true;
            continue;
        }
        if found != 0 {
            json.push(',');
        }
        found += 1;
        json.push_str("{\"offset\":");
        json.push_str(&start.to_string());
        json.push_str(",\"text\":\"");
        for &byte in run.iter().take(MAX_STRING_LENGTH) {
            if byte == b'\\' || byte == b'"' {
                json.push('\\');
            }
            json.push(char::from(byte));
        }
        json.push_str("\"}");
        if run.len() > MAX_STRING_LENGTH {
            truncated = true;
        }
    }
    if truncated {
        json.push_str("],\"strings_truncated\":true}");
    } else {
        json.push_str("],\"strings_truncated\":false}");
    }
    json
}

/// # Safety
/// `out` must point to writable memory, and `data` must point to `length`
/// readable bytes when `length` is nonzero. The two regions must not overlap.
#[no_mangle]
pub unsafe extern "C" fn fangida_analyze(
    data: *const u8,
    length: u64,
    out: *mut FangidaBuffer,
) -> FangidaStatus {
    if out.is_null() {
        return FangidaStatus::Invalid;
    }
    // SAFETY: This follows the caller's writable out-pointer contract.
    let out = unsafe { &mut *out };
    out.data = ptr::null_mut();
    out.length = 0;
    if length > MAX_INPUT_BYTES || (data.is_null() && length != 0) {
        return FangidaStatus::Invalid;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let input: &[u8] = if length == 0 {
            &[]
        } else {
            // SAFETY: The caller guarantees the input range; the cap also
            // ensures that `length` fits in usize on supported targets.
            unsafe { std::slice::from_raw_parts(data, length as usize) }
        };
        let result = analyze_json(input).into_bytes().into_boxed_slice();
        let result_length = result.len() as u64;
        let result_data = Box::into_raw(result) as *mut u8;
        (result_data, result_length)
    }));
    match result {
        Ok((result_data, result_length)) => {
            out.data = result_data;
            out.length = result_length;
            FangidaStatus::Ok
        }
        Err(_) => FangidaStatus::Failed,
    }
}

/// # Safety
/// `buffer` must be null or point to a writable buffer returned by this same
/// library. Its contents must not have been changed by the caller.
#[no_mangle]
pub unsafe extern "C" fn fangida_release(buffer: *mut FangidaBuffer) {
    if buffer.is_null() {
        return;
    }
    // SAFETY: The caller guarantees a writable buffer from this library.
    let buffer = unsafe { &mut *buffer };
    if !buffer.data.is_null() {
        let bytes = ptr::slice_from_raw_parts_mut(buffer.data, buffer.length as usize);
        // SAFETY: analyze() allocates this pointer as Box<[u8]> with precisely
        // this length, and the pointer is released only once.
        unsafe { drop(Box::from_raw(bytes)) };
    }
    buffer.data = ptr::null_mut();
    buffer.length = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_buffer() -> FangidaBuffer {
        FangidaBuffer {
            data: ptr::null_mut(),
            length: 0,
        }
    }

    #[test]
    fn abi_and_bounded_scan() {
        assert_eq!(fangida_abi_version(), 0x10000);
        let data = b"XXXX\0a\"\\b";
        let mut out = empty_buffer();
        assert_eq!(
            unsafe { fangida_analyze(data.as_ptr(), data.len() as u64, &mut out) },
            FangidaStatus::Ok
        );
        let json = unsafe {
            std::str::from_utf8(std::slice::from_raw_parts(out.data, out.length as usize)).unwrap()
        };
        assert!(json.contains("\"size\":9"));
        assert!(json.contains("\"offset\":0,\"text\":\"XXXX\""));
        assert!(json.contains("\"offset\":5,\"text\":\"a\\\"\\\\b\""));
        assert!(json.contains("\"strings_truncated\":false"));
        unsafe { fangida_release(&mut out) };
        unsafe { fangida_release(&mut out) };
        assert!(out.data.is_null());
        assert_eq!(out.length, 0);
    }

    #[test]
    fn empty_invalid_and_truncation() {
        let mut out = empty_buffer();
        assert_eq!(
            unsafe { fangida_analyze(ptr::null(), 0, &mut out) },
            FangidaStatus::Ok
        );
        unsafe { fangida_release(&mut out) };
        assert_eq!(
            unsafe { fangida_analyze(ptr::null(), 1, &mut out) },
            FangidaStatus::Invalid
        );
        let data = [b'A'; MAX_STRING_LENGTH + 1];
        assert_eq!(
            unsafe { fangida_analyze(data.as_ptr(), data.len() as u64, &mut out) },
            FangidaStatus::Ok
        );
        let json = unsafe {
            std::str::from_utf8(std::slice::from_raw_parts(out.data, out.length as usize)).unwrap()
        };
        assert!(json.contains("\"strings_truncated\":true"));
        unsafe { fangida_release(&mut out) };
        assert_eq!(
            unsafe { fangida_analyze(data.as_ptr(), MAX_INPUT_BYTES + 1, &mut out) },
            FangidaStatus::Invalid
        );
        assert_eq!(
            unsafe { fangida_analyze(data.as_ptr(), 1, ptr::null_mut()) },
            FangidaStatus::Invalid
        );
    }
}
