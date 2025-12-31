//! WASM bindings for BLC client

use wasm_bindgen::prelude::*;
use base64::Engine;
use crate::blc;
use crate::jam::{self, CorevmExecEnv, WorkItem};
use crate::work_package::{self, BlcWorkPackageBuilder};

/// Parse BLC from hex string
#[wasm_bindgen]
pub fn parse_blc_hex(hex: &str) -> Result<String, String> {
    let hex_str = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {}", e))?;
    let term = blc::parse_blc(&bytes)?;
    Ok(format!("{}", term))
}

/// Parse BLC from lambda notation
#[wasm_bindgen]
pub fn parse_blc_lambda(text: &str) -> Result<String, String> {
    let term = blc::parse_blc_text(text)?;
    Ok(format!("{}", term))
}

/// Encode a term to BLC hex
#[wasm_bindgen]
pub fn encode_to_hex(text: &str) -> Result<String, String> {
    let term = blc::parse_blc_text(text)?;
    let bytes = blc::encode_blc(&term);
    Ok(hex::encode(bytes))
}

/// Get identity combinator in hex
#[wasm_bindgen]
pub fn identity_hex() -> String {
    hex::encode(blc::encode_blc(&blc::prelude::identity()))
}

/// Get church true in hex
#[wasm_bindgen]
pub fn church_true_hex() -> String {
    hex::encode(blc::encode_blc(&blc::prelude::church_true()))
}

/// Get church false in hex
#[wasm_bindgen]
pub fn church_false_hex() -> String {
    hex::encode(blc::encode_blc(&blc::prelude::church_false()))
}

/// Get S combinator in hex
#[wasm_bindgen]
pub fn s_combinator_hex() -> String {
    hex::encode(blc::encode_blc(&blc::prelude::s_combinator()))
}

/// Build a work item payload for BLC-CoreVM
#[wasm_bindgen]
pub fn build_blc_payload(service_id: u32, code_hash_hex: &str, blc_program_hex: &str) -> Result<String, String> {
    let code_hash_bytes = hex::decode(code_hash_hex)
        .map_err(|e| format!("invalid code hash hex: {}", e))?;

    if code_hash_bytes.len() != 32 {
        return Err("code hash must be 32 bytes".to_string());
    }

    let mut code_hash = [0u8; 32];
    code_hash.copy_from_slice(&code_hash_bytes);

    let payload = CorevmExecEnv::new(service_id, code_hash)
        .arg(blc_program_hex)
        .encode();

    Ok(hex::encode(payload))
}

/// Encode JAM compact integer
#[wasm_bindgen]
pub fn encode_compact(value: u64) -> String {
    hex::encode(jam::encode_jam_compact(value))
}

/// Decode JAM compact integer from hex
#[wasm_bindgen]
pub fn decode_compact(hex_data: &str) -> Result<u64, String> {
    let bytes = hex::decode(hex_data).map_err(|e| format!("invalid hex: {}", e))?;
    let (value, _) = jam::decode_jam_compact(&bytes)?;
    Ok(value)
}

/// BLC client for WebSocket RPC
#[wasm_bindgen]
pub struct BlcClient {
    service_id: u32,
    code_hash: [u8; 32],
    rpc_url: String,
    next_id: u64,
}

#[wasm_bindgen]
impl BlcClient {
    /// Create a new BLC client
    #[wasm_bindgen(constructor)]
    pub fn new(rpc_url: &str, service_id: u32, code_hash_hex: &str) -> Result<BlcClient, String> {
        let code_hash_bytes = hex::decode(code_hash_hex)
            .map_err(|e| format!("invalid code hash hex: {}", e))?;

        if code_hash_bytes.len() != 32 {
            return Err("code hash must be 32 bytes".to_string());
        }

        let mut code_hash = [0u8; 32];
        code_hash.copy_from_slice(&code_hash_bytes);

        Ok(BlcClient {
            service_id,
            code_hash,
            rpc_url: rpc_url.to_string(),
            next_id: 1,
        })
    }

    /// Get service ID
    #[wasm_bindgen(getter)]
    pub fn service_id(&self) -> u32 {
        self.service_id
    }

    /// Get RPC URL
    #[wasm_bindgen(getter)]
    pub fn rpc_url(&self) -> String {
        self.rpc_url.clone()
    }

    /// Build work item JSON for a BLC program
    pub fn build_work_item_json(&mut self, blc_program_hex: &str, gas: u64) -> String {
        let payload = CorevmExecEnv::new(self.service_id, self.code_hash)
            .arg(blc_program_hex)
            .encode();

        let work_item = WorkItem {
            service_id: self.service_id,
            payload,
            refine_gas: gas,
            accumulate_gas: gas,
        };

        let id = self.next_id;
        self.next_id += 1;

        // Build JSON-RPC request
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "jam_submitWorkItem",
            "params": {
                "service_id": work_item.service_id,
                "payload": hex::encode(&work_item.payload),
                "refine_gas": work_item.refine_gas,
                "accumulate_gas": work_item.accumulate_gas
            }
        }).to_string()
    }

    /// Parse and encode a BLC term, returning hex
    pub fn encode_blc(&self, text: &str) -> Result<String, String> {
        let term = blc::parse_blc_text(text)?;
        Ok(hex::encode(blc::encode_blc(&term)))
    }
}

/// Log to browser console
#[wasm_bindgen]
pub fn console_log(msg: &str) {
    web_sys::console::log_1(&msg.into());
}

/// Blake2b-256 hash of data
#[wasm_bindgen]
pub fn blake2b_hash(data: &[u8]) -> Vec<u8> {
    work_package::blake2b_256(data).to_vec()
}

/// Blake2b-256 hash of hex data, returns hex
#[wasm_bindgen]
pub fn blake2b_hash_hex(hex_data: &str) -> Result<String, String> {
    let data = hex::decode(hex_data.strip_prefix("0x").unwrap_or(hex_data))
        .map_err(|e| format!("invalid hex: {}", e))?;
    Ok(hex::encode(work_package::blake2b_256(&data)))
}

/// Build a work package for BLC execution
/// Returns base64-encoded work package bytes
#[wasm_bindgen]
pub fn build_work_package(
    service_id: u32,
    code_hash_hex: &str,
    blc_payload_hex: &str,
    gas: u64,
) -> Result<String, String> {
    let code_hash_bytes = hex::decode(code_hash_hex.strip_prefix("0x").unwrap_or(code_hash_hex))
        .map_err(|e| format!("invalid code hash hex: {}", e))?;

    if code_hash_bytes.len() != 32 {
        return Err("code hash must be 32 bytes".to_string());
    }

    let mut code_hash = [0u8; 32];
    code_hash.copy_from_slice(&code_hash_bytes);

    let payload = hex::decode(blc_payload_hex.strip_prefix("0x").unwrap_or(blc_payload_hex))
        .map_err(|e| format!("invalid payload hex: {}", e))?;

    let builder = BlcWorkPackageBuilder::new(service_id, code_hash).gas(gas);
    let pkg = builder.build(&payload);
    let encoded = pkg.encode();

    Ok(base64::engine::general_purpose::STANDARD.encode(&encoded))
}

/// Build a work package and return both the package (base64) and its hash (hex)
#[wasm_bindgen]
pub fn build_work_package_with_hash(
    service_id: u32,
    code_hash_hex: &str,
    blc_payload_hex: &str,
    gas: u64,
) -> Result<JsValue, String> {
    let code_hash_bytes = hex::decode(code_hash_hex.strip_prefix("0x").unwrap_or(code_hash_hex))
        .map_err(|e| format!("invalid code hash hex: {}", e))?;

    if code_hash_bytes.len() != 32 {
        return Err("code hash must be 32 bytes".to_string());
    }

    let mut code_hash = [0u8; 32];
    code_hash.copy_from_slice(&code_hash_bytes);

    let payload = hex::decode(blc_payload_hex.strip_prefix("0x").unwrap_or(blc_payload_hex))
        .map_err(|e| format!("invalid payload hex: {}", e))?;

    let builder = BlcWorkPackageBuilder::new(service_id, code_hash).gas(gas);
    let pkg = builder.build(&payload);
    let encoded = pkg.encode();
    let hash = pkg.hash();

    let result = serde_json::json!({
        "package": base64::engine::general_purpose::STANDARD.encode(&encoded),
        "hash": hex::encode(hash)
    });

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| format!("serialization error: {}", e))
}

/// Build a complete submitWorkPackage RPC request
/// Returns JSON string ready to send over WebSocket
#[wasm_bindgen]
pub fn build_submit_work_package_rpc(
    request_id: u64,
    core_index: u32,
    service_id: u32,
    code_hash_hex: &str,
    blc_payload_hex: &str,
    gas: u64,
) -> Result<String, String> {
    let code_hash_bytes = hex::decode(code_hash_hex.strip_prefix("0x").unwrap_or(code_hash_hex))
        .map_err(|e| format!("invalid code hash hex: {}", e))?;

    if code_hash_bytes.len() != 32 {
        return Err("code hash must be 32 bytes".to_string());
    }

    let mut code_hash = [0u8; 32];
    code_hash.copy_from_slice(&code_hash_bytes);

    let payload = hex::decode(blc_payload_hex.strip_prefix("0x").unwrap_or(blc_payload_hex))
        .map_err(|e| format!("invalid payload hex: {}", e))?;

    let builder = BlcWorkPackageBuilder::new(service_id, code_hash).gas(gas);
    let pkg = builder.build(&payload);
    let encoded = pkg.encode();
    let pkg_b64 = base64::engine::general_purpose::STANDARD.encode(&encoded);

    // Also include the payload as extrinsic (some testnets expect this)
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&payload);

    let rpc = serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "submitWorkPackage",
        "params": [core_index, pkg_b64, [payload_b64]]
    });

    Ok(rpc.to_string())
}
