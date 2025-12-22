//! FFI bindings for ParityDB
//! Handle-based API for multiple database instances
//! Provides C-compatible interface for Julia integration

use parity_db::{Db, Options, ColumnOptions};
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::Path;
use std::ptr;

/// Error codes
pub const PDB_OK: i32 = 0;
pub const PDB_NOT_FOUND: i32 = 1;
pub const PDB_ERR_NULL_PTR: i32 = -1;
pub const PDB_ERR_INVALID_STR: i32 = -2;
pub const PDB_ERR_OPEN_FAILED: i32 = -3;
pub const PDB_ERR_WRITE_FAILED: i32 = -4;
pub const PDB_ERR_READ_FAILED: i32 = -5;
pub const PDB_ERR_INVALID_HANDLE: i32 = -6;
pub const PDB_ERR_INVALID_COLUMN: i32 = -7;

/// Number of columns for JAM state
/// 0: Service state
/// 1: Authorizations
/// 2: Recent blocks
/// 3: Validator keys
/// 4: Statistics
pub const PDB_NUM_COLUMNS: u8 = 5;

/// Database handle with write overlay per column
pub struct PdbHandle {
    db: Db,
    /// Per-column overlay: column -> key -> Some(value) for insert, None for delete
    overlays: Vec<BTreeMap<Vec<u8>, Option<Vec<u8>>>>,
}

/// Opaque handle type for FFI
pub type PdbHandlePtr = *mut PdbHandle;

/// Open ParityDB at the given path
/// Returns handle on success, null on error
/// Error code written to error_out if not null
#[no_mangle]
pub extern "C" fn pdb_open(
    path: *const c_char,
    error_out: *mut i32,
) -> PdbHandlePtr {
    let set_error = |code: i32| {
        if !error_out.is_null() {
            unsafe { *error_out = code; }
        }
    };

    let path_str = unsafe {
        if path.is_null() {
            set_error(PDB_ERR_NULL_PTR);
            return ptr::null_mut();
        }
        match CStr::from_ptr(path).to_str() {
            Ok(s) => s,
            Err(_) => {
                set_error(PDB_ERR_INVALID_STR);
                return ptr::null_mut();
            }
        }
    };

    // Configure ParityDB with multiple columns
    let mut options = Options::with_columns(Path::new(path_str), PDB_NUM_COLUMNS);

    // Configure each column
    let col_opts = ColumnOptions {
        ref_counted: false,
        preimage: false,
        compression: parity_db::CompressionType::Lz4,
        ..Default::default()
    };
    options.columns = vec![col_opts; PDB_NUM_COLUMNS as usize];

    match Db::open_or_create(&options) {
        Ok(db) => {
            let handle = Box::new(PdbHandle {
                db,
                overlays: (0..PDB_NUM_COLUMNS).map(|_| BTreeMap::new()).collect(),
            });
            set_error(PDB_OK);
            Box::into_raw(handle)
        }
        Err(e) => {
            eprintln!("ParityDB open error: {:?}", e);
            set_error(PDB_ERR_OPEN_FAILED);
            ptr::null_mut()
        }
    }
}

/// Close ParityDB and free handle
#[no_mangle]
pub extern "C" fn pdb_close(handle: PdbHandlePtr) -> i32 {
    if handle.is_null() {
        return PDB_ERR_INVALID_HANDLE;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
    PDB_OK
}

/// Check if handle is valid
#[no_mangle]
pub extern "C" fn pdb_is_valid(handle: PdbHandlePtr) -> i32 {
    if handle.is_null() { 0 } else { 1 }
}

/// Get value size for a key (to pre-allocate buffer)
/// Returns size on success, -1 if not found, negative error code on failure
#[no_mangle]
pub extern "C" fn pdb_get_size(
    handle: PdbHandlePtr,
    column: u8,
    key_ptr: *const u8,
    key_len: usize,
) -> i64 {
    if handle.is_null() {
        return PDB_ERR_INVALID_HANDLE as i64;
    }
    if key_ptr.is_null() {
        return PDB_ERR_NULL_PTR as i64;
    }
    if column >= PDB_NUM_COLUMNS {
        return PDB_ERR_INVALID_COLUMN as i64;
    }

    let h = unsafe { &*handle };
    let key = unsafe { std::slice::from_raw_parts(key_ptr, key_len) };
    let col = column as usize;

    // Check overlay first
    if let Some(val_opt) = h.overlays[col].get(key) {
        return match val_opt {
            Some(val) => val.len() as i64,
            None => -1, // Deleted
        };
    }

    // Read from database
    match h.db.get(column, key) {
        Ok(Some(val)) => val.len() as i64,
        Ok(None) => -1,
        Err(_) => PDB_ERR_READ_FAILED as i64,
    }
}

/// Read value for a key
/// value_len: in: buffer size, out: actual value length
/// Returns 0 on success, 1 if not found, negative on error
#[no_mangle]
pub extern "C" fn pdb_get(
    handle: PdbHandlePtr,
    column: u8,
    key_ptr: *const u8,
    key_len: usize,
    value_out: *mut u8,
    value_len: *mut usize,
) -> i32 {
    if handle.is_null() {
        return PDB_ERR_INVALID_HANDLE;
    }
    if key_ptr.is_null() || value_len.is_null() {
        return PDB_ERR_NULL_PTR;
    }
    if column >= PDB_NUM_COLUMNS {
        return PDB_ERR_INVALID_COLUMN;
    }

    let h = unsafe { &*handle };
    let key = unsafe { std::slice::from_raw_parts(key_ptr, key_len) };
    let col = column as usize;

    // Check overlay first
    if let Some(val_opt) = h.overlays[col].get(key) {
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
                return PDB_OK;
            }
            None => {
                unsafe { *value_len = 0 };
                return PDB_NOT_FOUND;
            }
        }
    }

    // Read from database
    match h.db.get(column, key) {
        Ok(Some(val)) => {
            let out_len = unsafe { *value_len };
            let copy_len = val.len().min(out_len);
            if !value_out.is_null() && copy_len > 0 {
                unsafe {
                    ptr::copy_nonoverlapping(val.as_ptr(), value_out, copy_len);
                }
            }
            unsafe { *value_len = val.len() };
            PDB_OK
        }
        Ok(None) => {
            unsafe { *value_len = 0 };
            PDB_NOT_FOUND
        }
        Err(e) => {
            eprintln!("ParityDB read error: {:?}", e);
            PDB_ERR_READ_FAILED
        }
    }
}

/// Write a key-value pair to overlay (not committed yet)
/// value_ptr can be null to delete the key
#[no_mangle]
pub extern "C" fn pdb_put(
    handle: PdbHandlePtr,
    column: u8,
    key_ptr: *const u8,
    key_len: usize,
    value_ptr: *const u8,
    value_len: usize,
) -> i32 {
    if handle.is_null() {
        return PDB_ERR_INVALID_HANDLE;
    }
    if key_ptr.is_null() {
        return PDB_ERR_NULL_PTR;
    }
    if column >= PDB_NUM_COLUMNS {
        return PDB_ERR_INVALID_COLUMN;
    }

    let h = unsafe { &mut *handle };
    let key = unsafe { std::slice::from_raw_parts(key_ptr, key_len) }.to_vec();
    let col = column as usize;

    let value_opt = if value_ptr.is_null() {
        None // Delete
    } else {
        let val = unsafe { std::slice::from_raw_parts(value_ptr, value_len) }.to_vec();
        Some(val)
    };

    h.overlays[col].insert(key, value_opt);
    PDB_OK
}

/// Commit all pending writes across all columns
#[no_mangle]
pub extern "C" fn pdb_commit(handle: PdbHandlePtr) -> i32 {
    if handle.is_null() {
        return PDB_ERR_INVALID_HANDLE;
    }

    let h = unsafe { &mut *handle };

    // Collect all writes from all overlays
    let mut tx: Vec<(u8, Vec<u8>, Option<Vec<u8>>)> = Vec::new();
    for (col, overlay) in h.overlays.iter().enumerate() {
        for (key, value) in overlay.iter() {
            tx.push((col as u8, key.clone(), value.clone()));
        }
    }

    if tx.is_empty() {
        return PDB_OK;
    }

    match h.db.commit(tx) {
        Ok(()) => {
            // Clear all overlays
            for overlay in h.overlays.iter_mut() {
                overlay.clear();
            }
            PDB_OK
        }
        Err(e) => {
            eprintln!("ParityDB commit error: {:?}", e);
            PDB_ERR_WRITE_FAILED
        }
    }
}

/// Rollback pending writes for all columns
#[no_mangle]
pub extern "C" fn pdb_rollback(handle: PdbHandlePtr) -> i32 {
    if handle.is_null() {
        return PDB_ERR_INVALID_HANDLE;
    }

    let h = unsafe { &mut *handle };
    for overlay in h.overlays.iter_mut() {
        overlay.clear();
    }
    PDB_OK
}

/// Get number of pending writes for a column (-1 for all columns)
#[no_mangle]
pub extern "C" fn pdb_pending_count(handle: PdbHandlePtr, column: i8) -> i64 {
    if handle.is_null() {
        return PDB_ERR_INVALID_HANDLE as i64;
    }

    let h = unsafe { &*handle };

    if column < 0 {
        // All columns
        h.overlays.iter().map(|o| o.len() as i64).sum()
    } else if (column as u8) < PDB_NUM_COLUMNS {
        h.overlays[column as usize].len() as i64
    } else {
        PDB_ERR_INVALID_COLUMN as i64
    }
}

/// Iterate over all keys in a column (database + overlay)
/// callback: function(key_ptr, key_len, value_ptr, value_len) -> bool (1 to continue)
/// Returns number of entries iterated, negative on error
#[no_mangle]
pub extern "C" fn pdb_iterate(
    handle: PdbHandlePtr,
    column: u8,
    callback: extern "C" fn(*const u8, usize, *const u8, usize) -> i32,
) -> i64 {
    if handle.is_null() {
        return PDB_ERR_INVALID_HANDLE as i64;
    }
    if column >= PDB_NUM_COLUMNS {
        return PDB_ERR_INVALID_COLUMN as i64;
    }

    let h = unsafe { &*handle };
    let col = column as usize;
    let mut count: i64 = 0;

    // Iterate database entries
    let mut iter = match h.db.iter(column) {
        Ok(iter) => iter,
        Err(_) => return PDB_ERR_READ_FAILED as i64,
    };

    loop {
        match iter.next() {
            Ok(Some((key, value))) => {
                // Skip if key is in overlay (overlay takes precedence)
                if h.overlays[col].contains_key(&key) {
                    continue;
                }

                let cont = callback(
                    key.as_ptr(),
                    key.len(),
                    value.as_ptr(),
                    value.len(),
                );
                count += 1;
                if cont == 0 {
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => return PDB_ERR_READ_FAILED as i64,
        }
    }

    // Iterate overlay entries
    for (key, value_opt) in h.overlays[col].iter() {
        if let Some(value) = value_opt {
            let cont = callback(
                key.as_ptr(),
                key.len(),
                value.as_ptr(),
                value.len(),
            );
            count += 1;
            if cont == 0 {
                break;
            }
        }
    }

    count
}

/// Iterate over all keys in a column without values (for enumeration)
/// callback: function(key_ptr, key_len) -> bool (1 to continue)
#[no_mangle]
pub extern "C" fn pdb_iterate_keys(
    handle: PdbHandlePtr,
    column: u8,
    callback: extern "C" fn(*const u8, usize) -> i32,
) -> i64 {
    if handle.is_null() {
        return PDB_ERR_INVALID_HANDLE as i64;
    }
    if column >= PDB_NUM_COLUMNS {
        return PDB_ERR_INVALID_COLUMN as i64;
    }

    let h = unsafe { &*handle };
    let col = column as usize;
    let mut count: i64 = 0;

    let mut iter = match h.db.iter(column) {
        Ok(iter) => iter,
        Err(_) => return PDB_ERR_READ_FAILED as i64,
    };

    loop {
        match iter.next() {
            Ok(Some((key, _))) => {
                if h.overlays[col].contains_key(&key) {
                    continue;
                }
                let cont = callback(key.as_ptr(), key.len());
                count += 1;
                if cont == 0 {
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => return PDB_ERR_READ_FAILED as i64,
        }
    }

    for (key, value_opt) in h.overlays[col].iter() {
        if value_opt.is_some() {
            let cont = callback(key.as_ptr(), key.len());
            count += 1;
            if cont == 0 {
                break;
            }
        }
    }

    count
}

/// Get total entry count for a column (committed + overlay)
/// Returns count or negative error code
#[no_mangle]
pub extern "C" fn pdb_count(handle: PdbHandlePtr, column: u8) -> i64 {
    if handle.is_null() {
        return PDB_ERR_INVALID_HANDLE as i64;
    }
    if column >= PDB_NUM_COLUMNS {
        return PDB_ERR_INVALID_COLUMN as i64;
    }

    let h = unsafe { &*handle };
    let col = column as usize;

    // Count via iteration (ParityDB doesn't have a count method)
    let mut count: i64 = 0;

    let mut iter = match h.db.iter(column) {
        Ok(iter) => iter,
        Err(_) => return PDB_ERR_READ_FAILED as i64,
    };

    loop {
        match iter.next() {
            Ok(Some((key, _))) => {
                // Skip if deleted in overlay
                if let Some(None) = h.overlays[col].get(&key) {
                    continue;
                }
                // Skip if replaced in overlay (counted there)
                if h.overlays[col].contains_key(&key) {
                    continue;
                }
                count += 1;
            }
            Ok(None) => break,
            Err(_) => return PDB_ERR_READ_FAILED as i64,
        }
    }

    // Add overlay entries (only new/modified)
    for (_, value_opt) in h.overlays[col].iter() {
        if value_opt.is_some() {
            count += 1;
        }
    }

    count
}

// Backward compatibility: global instance for simple use cases
use std::sync::Mutex;

struct GlobalHandle(Option<Box<PdbHandle>>);
unsafe impl Send for GlobalHandle {}

static GLOBAL_HANDLE: Mutex<GlobalHandle> = Mutex::new(GlobalHandle(None));

#[no_mangle]
pub extern "C" fn pdb_init(path: *const c_char) -> i32 {
    let mut error: i32 = 0;
    let handle = pdb_open(path, &mut error);
    if handle.is_null() {
        return error;
    }
    let mut global = GLOBAL_HANDLE.lock().unwrap();
    global.0 = Some(unsafe { Box::from_raw(handle) });
    PDB_OK
}

#[no_mangle]
pub extern "C" fn pdb_global_close() {
    let mut global = GLOBAL_HANDLE.lock().unwrap();
    global.0 = None;
}

#[no_mangle]
pub extern "C" fn pdb_is_open() -> i32 {
    let global = GLOBAL_HANDLE.lock().unwrap();
    if global.0.is_some() { 1 } else { 0 }
}

/// Get global handle pointer for legacy API
fn get_global_handle() -> PdbHandlePtr {
    let global = GLOBAL_HANDLE.lock().unwrap();
    match global.0.as_ref() {
        Some(h) => h.as_ref() as *const PdbHandle as *mut PdbHandle,
        None => ptr::null_mut(),
    }
}

/// Legacy get - uses column 0
#[no_mangle]
pub extern "C" fn pdb_legacy_get(
    key_ptr: *const u8,
    key_len: usize,
    value_out: *mut u8,
    value_len: *mut usize,
) -> i32 {
    pdb_get(get_global_handle(), 0, key_ptr, key_len, value_out, value_len)
}

/// Legacy put - uses column 0
#[no_mangle]
pub extern "C" fn pdb_legacy_put(
    key_ptr: *const u8,
    key_len: usize,
    value_ptr: *const u8,
    value_len: usize,
) -> i32 {
    pdb_put(get_global_handle(), 0, key_ptr, key_len, value_ptr, value_len)
}

/// Legacy commit
#[no_mangle]
pub extern "C" fn pdb_legacy_commit() -> i32 {
    pdb_commit(get_global_handle())
}

/// Legacy rollback
#[no_mangle]
pub extern "C" fn pdb_legacy_rollback() -> i32 {
    pdb_rollback(get_global_handle())
}

/// Legacy pending count
#[no_mangle]
pub extern "C" fn pdb_legacy_pending_count() -> i64 {
    pdb_pending_count(get_global_handle(), -1)
}
