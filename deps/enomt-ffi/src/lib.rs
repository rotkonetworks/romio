//! FFI bindings for ENOMT (Nearly Optimal Merkle Trie)
//! Provides C-compatible interface for Julia integration
//! Uses Blake2b-256 for JAM conformance

use blake2::{digest::typenum::U32, Blake2b, Digest};
use nomt::hasher::{BinaryHash, BinaryHasher};

/// Blake2b-256 type alias
type Blake2b256 = Blake2b<U32>;
use nomt::{KeyReadWrite, Nomt, Options, SessionParams};
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;
use std::sync::Mutex;

/// Blake2b-256 binary hasher for NOMT
pub struct Blake2bBinaryHasher;

impl BinaryHash for Blake2bBinaryHasher {
    fn hash(value: &[u8]) -> [u8; 32] {
        let mut hasher = Blake2b256::new();
        hasher.update(value);
        hasher.finalize().into()
    }

    fn hash2_32_concat(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        Self::hash2_concat(left, right)
    }

    fn hash2_concat(left: &[u8], right: &[u8]) -> [u8; 32] {
        let mut hasher = Blake2b256::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }

    fn hash3_concat(a: &[u8], b: &[u8], c: &[u8]) -> [u8; 32] {
        let mut hasher = Blake2b256::new();
        hasher.update(a);
        hasher.update(b);
        hasher.update(c);
        hasher.finalize().into()
    }
}

/// Blake2b hasher type for NOMT
pub type Blake2bHasher = BinaryHasher<Blake2bBinaryHasher>;

/// Opaque handle to NOMT database
pub struct NomtHandle {
    nomt: Nomt<Blake2bHasher>,
    overlay: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

/// Global handle storage (single instance for simplicity)
static NOMT_INSTANCE: Mutex<Option<NomtHandle>> = Mutex::new(None);

/// Initialize NOMT database at the given path
/// Returns 0 on success, non-zero on error
#[no_mangle]
pub extern "C" fn enomt_init(path: *const c_char) -> i32 {
    let path_str = unsafe {
        if path.is_null() {
            return -1;
        }
        match CStr::from_ptr(path).to_str() {
            Ok(s) => s,
            Err(_) => return -2,
        }
    };

    let mut opts = Options::new();
    opts.path(path_str);
    opts.commit_concurrency(1);

    match Nomt::<Blake2bHasher>::open(opts) {
        Ok(nomt) => {
            let handle = NomtHandle {
                nomt,
                overlay: BTreeMap::new(),
            };
            let mut instance = NOMT_INSTANCE.lock().unwrap();
            *instance = Some(handle);
            0
        }
        Err(_) => -3,
    }
}

/// Close NOMT database
#[no_mangle]
pub extern "C" fn enomt_close() {
    let mut instance = NOMT_INSTANCE.lock().unwrap();
    *instance = None;
}

/// Get current root hash
/// root_out must be a 32-byte buffer
/// Returns 0 on success
#[no_mangle]
pub extern "C" fn enomt_root(root_out: *mut u8) -> i32 {
    if root_out.is_null() {
        return -1;
    }

    let instance = NOMT_INSTANCE.lock().unwrap();
    match instance.as_ref() {
        Some(handle) => {
            let root = handle.nomt.root();
            let root_bytes = root.into_inner();
            unsafe {
                ptr::copy_nonoverlapping(root_bytes.as_ptr(), root_out, 32);
            }
            0
        }
        None => -2,
    }
}

/// Read value for a key
/// key must be 32 bytes
/// value_out is the output buffer
/// value_len is input: buffer size, output: actual value length
/// Returns 0 on success, 1 if key not found, negative on error
#[no_mangle]
pub extern "C" fn enomt_read(
    key: *const u8,
    value_out: *mut u8,
    value_len: *mut usize,
) -> i32 {
    if key.is_null() || value_len.is_null() {
        return -1;
    }

    let key_slice = unsafe { std::slice::from_raw_parts(key, 32) };
    let key_vec = key_slice.to_vec();

    let instance = NOMT_INSTANCE.lock().unwrap();
    match instance.as_ref() {
        Some(handle) => {
            // Check overlay first
            if let Some(val_opt) = handle.overlay.get(&key_vec) {
                match val_opt {
                    Some(val) => {
                        let out_len = unsafe { *value_len };
                        let copy_len = val.len().min(out_len);
                        if !value_out.is_null() && copy_len > 0 {
                            unsafe {
                                ptr::copy_nonoverlapping(val.as_ptr(), value_out, copy_len);
                            }
                        }
                        unsafe { *value_len = val.len() };
                        return 0;
                    }
                    None => {
                        unsafe { *value_len = 0 };
                        return 1; // Key deleted
                    }
                }
            }

            // Fall back to database read
            let session = handle.nomt.begin_session(SessionParams::default());
            match session.read(key_vec) {
                Ok(Some(val)) => {
                    let out_len = unsafe { *value_len };
                    let copy_len = val.len().min(out_len);
                    if !value_out.is_null() && copy_len > 0 {
                        unsafe {
                            ptr::copy_nonoverlapping(val.as_ptr(), value_out, copy_len);
                        }
                    }
                    unsafe { *value_len = val.len() };
                    0
                }
                Ok(None) => {
                    unsafe { *value_len = 0 };
                    1 // Not found
                }
                Err(_) => -3,
            }
        }
        None => -2,
    }
}

/// Write a key-value pair to the overlay (not committed yet)
/// key must be 32 bytes
/// value can be any length, or null to delete
/// Returns 0 on success
#[no_mangle]
pub extern "C" fn enomt_write(
    key: *const u8,
    value: *const u8,
    value_len: usize,
) -> i32 {
    if key.is_null() {
        return -1;
    }

    let key_slice = unsafe { std::slice::from_raw_parts(key, 32) };
    let key_vec = key_slice.to_vec();

    let value_opt = if value.is_null() || value_len == 0 {
        None
    } else {
        let val_slice = unsafe { std::slice::from_raw_parts(value, value_len) };
        Some(val_slice.to_vec())
    };

    let mut instance = NOMT_INSTANCE.lock().unwrap();
    match instance.as_mut() {
        Some(handle) => {
            handle.overlay.insert(key_vec, value_opt);
            0
        }
        None => -2,
    }
}

/// Commit all pending writes and compute new root
/// new_root_out must be 32 bytes
/// Returns 0 on success
#[no_mangle]
pub extern "C" fn enomt_commit(new_root_out: *mut u8) -> i32 {
    let mut instance = NOMT_INSTANCE.lock().unwrap();
    match instance.as_mut() {
        Some(handle) => {
            if handle.overlay.is_empty() {
                // Nothing to commit
                let root = handle.nomt.root();
                if !new_root_out.is_null() {
                    let root_bytes = root.into_inner();
                    unsafe {
                        ptr::copy_nonoverlapping(root_bytes.as_ptr(), new_root_out, 32);
                    }
                }
                return 0;
            }

            // Build actual_access from overlay
            let session = handle.nomt.begin_session(SessionParams::default());

            // Warm up all keys
            for key in handle.overlay.keys() {
                session.warm_up(key.clone());
            }

            // Build access list
            let mut actual_access: Vec<(Vec<u8>, KeyReadWrite)> = handle
                .overlay
                .iter()
                .map(|(k, v)| (k.clone(), KeyReadWrite::Write(v.clone())))
                .collect();
            actual_access.sort_by(|(k1, _), (k2, _)| k1.cmp(k2));

            // Commit
            match session.finish(actual_access) {
                Ok(mut finished) => {
                    let root = finished.root();
                    let root_bytes = root.into_inner();
                    if let Err(_) = finished.commit(&handle.nomt) {
                        return -4;
                    }

                    // Clear overlay
                    handle.overlay.clear();

                    if !new_root_out.is_null() {
                        unsafe {
                            ptr::copy_nonoverlapping(root_bytes.as_ptr(), new_root_out, 32);
                        }
                    }
                    0
                }
                Err(_) => -3,
            }
        }
        None => -2,
    }
}

/// Clear the in-memory overlay without committing
#[no_mangle]
pub extern "C" fn enomt_rollback() -> i32 {
    let mut instance = NOMT_INSTANCE.lock().unwrap();
    match instance.as_mut() {
        Some(handle) => {
            handle.overlay.clear();
            0
        }
        None => -2,
    }
}

/// Get number of pending writes in overlay
#[no_mangle]
pub extern "C" fn enomt_pending_count() -> i64 {
    let instance = NOMT_INSTANCE.lock().unwrap();
    match instance.as_ref() {
        Some(handle) => handle.overlay.len() as i64,
        None => -1,
    }
}
