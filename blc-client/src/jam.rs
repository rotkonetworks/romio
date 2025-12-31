//! JAM RPC client and encoding utilities

use serde::{Deserialize, Serialize};

/// JAM compact integer encoding (same as SCALE compact)
pub fn encode_jam_compact(value: u64) -> Vec<u8> {
    if value < 64 {
        vec![(value as u8) << 2]
    } else if value < 16384 {
        let v = (value as u16) << 2 | 0x01;
        v.to_le_bytes().to_vec()
    } else if value < 1073741824 {
        let v = (value as u32) << 2 | 0x02;
        v.to_le_bytes().to_vec()
    } else {
        let mut buf = vec![0x03];
        buf.extend_from_slice(&value.to_le_bytes());
        buf
    }
}

/// Decode JAM compact integer
pub fn decode_jam_compact(data: &[u8]) -> Result<(u64, usize), String> {
    if data.is_empty() {
        return Err("empty input".to_string());
    }

    let mode = data[0] & 0x03;
    match mode {
        0 => Ok(((data[0] >> 2) as u64, 1)),
        1 => {
            if data.len() < 2 {
                return Err("not enough bytes for 2-byte compact".to_string());
            }
            let v = u16::from_le_bytes([data[0], data[1]]);
            Ok(((v >> 2) as u64, 2))
        }
        2 => {
            if data.len() < 4 {
                return Err("not enough bytes for 4-byte compact".to_string());
            }
            let v = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            Ok(((v >> 2) as u64, 4))
        }
        3 => {
            if data.len() < 9 {
                return Err("not enough bytes for 8-byte compact".to_string());
            }
            let v = u64::from_le_bytes([
                data[1], data[2], data[3], data[4],
                data[5], data[6], data[7], data[8]
            ]);
            Ok((v, 9))
        }
        _ => unreachable!(),
    }
}

/// Work item for JAM service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkItem {
    pub service_id: u32,
    pub payload: Vec<u8>,
    pub refine_gas: u64,
    pub accumulate_gas: u64,
}

/// CoreVM ExecEnv payload
#[derive(Debug, Clone)]
pub struct CorevmExecEnv {
    pub program_service_id: u32,
    pub program_hash: [u8; 32],
    pub root_dir: Option<([u8; 32], u32)>,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

impl CorevmExecEnv {
    /// Create a simple exec env with just program reference
    pub fn new(service_id: u32, code_hash: [u8; 32]) -> Self {
        Self {
            program_service_id: service_id,
            program_hash: code_hash,
            root_dir: None,
            args: Vec::new(),
            env: Vec::new(),
        }
    }

    /// Add command line argument
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Add environment variable
    pub fn env_var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // program: BlockRef (service_id: u32 LE + hash: [u8; 32])
        buf.extend_from_slice(&self.program_service_id.to_le_bytes());
        buf.extend_from_slice(&self.program_hash);

        // root_dir: Option<BlockRef>
        match &self.root_dir {
            None => buf.push(0x00),
            Some((hash, svc)) => {
                buf.push(0x01);
                buf.extend_from_slice(&svc.to_le_bytes());
                buf.extend_from_slice(hash);
            }
        }

        // args: Vec<String>
        buf.extend_from_slice(&encode_jam_compact(self.args.len() as u64));
        for arg in &self.args {
            let arg_bytes = arg.as_bytes();
            buf.extend_from_slice(&encode_jam_compact(arg_bytes.len() as u64));
            buf.extend_from_slice(arg_bytes);
        }

        // env: Vec<(String, String)>
        buf.extend_from_slice(&encode_jam_compact(self.env.len() as u64));
        for (key, value) in &self.env {
            let key_bytes = key.as_bytes();
            let value_bytes = value.as_bytes();
            buf.extend_from_slice(&encode_jam_compact(key_bytes.len() as u64));
            buf.extend_from_slice(key_bytes);
            buf.extend_from_slice(&encode_jam_compact(value_bytes.len() as u64));
            buf.extend_from_slice(value_bytes);
        }

        buf
    }
}

/// JSON-RPC request
#[derive(Debug, Serialize)]
pub struct RpcRequest<T> {
    pub jsonrpc: &'static str,
    pub id: u64,
    pub method: String,
    pub params: T,
}

impl<T> RpcRequest<T> {
    pub fn new(id: u64, method: impl Into<String>, params: T) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            method: method.into(),
            params,
        }
    }
}

/// JSON-RPC response
#[derive(Debug, Deserialize)]
pub struct RpcResponse<T> {
    pub jsonrpc: String,
    pub id: u64,
    #[serde(default)]
    pub result: Option<T>,
    #[serde(default)]
    pub error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

/// JAM client (platform-agnostic trait)
pub trait JamClient {
    type Error: std::fmt::Debug;

    /// Submit a work item
    fn submit_work_item(&mut self, item: WorkItem) -> Result<String, Self::Error>;

    /// Query service info
    fn get_service(&self, service_id: u32) -> Result<Option<ServiceInfo>, Self::Error>;

    /// Get storage value
    fn get_storage(&self, service_id: u32, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;
}

/// Service info from chain
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceInfo {
    pub code_hash: String,
    pub balance: u64,
}

/// BLC-specific work item builder
pub struct BlcWorkItem {
    pub service_id: u32,
    pub blc_program: Vec<u8>,
    pub gas: u64,
}

impl BlcWorkItem {
    pub fn new(service_id: u32, blc_program: Vec<u8>) -> Self {
        Self {
            service_id,
            blc_program,
            gas: 1_000_000_000,
        }
    }

    pub fn with_gas(mut self, gas: u64) -> Self {
        self.gas = gas;
        self
    }

    /// Build CoreVM ExecEnv payload with BLC program as argument
    pub fn build_payload(&self) -> Vec<u8> {
        // for BLC-CoreVM, we pass the program hex as first argument
        let hex_program = hex::encode(&self.blc_program);

        // we need the code hash - for now use zeros, would need to query
        let code_hash = [0u8; 32];

        CorevmExecEnv::new(self.service_id, code_hash)
            .arg(hex_program)
            .encode()
    }

    /// Convert to generic work item
    pub fn to_work_item(&self) -> WorkItem {
        WorkItem {
            service_id: self.service_id,
            payload: self.build_payload(),
            refine_gas: self.gas,
            accumulate_gas: self.gas,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jam_compact_small() {
        assert_eq!(encode_jam_compact(0), vec![0x00]);
        assert_eq!(encode_jam_compact(1), vec![0x04]);
        assert_eq!(encode_jam_compact(63), vec![0xFC]);
    }

    #[test]
    fn test_jam_compact_medium() {
        assert_eq!(encode_jam_compact(64), vec![0x01, 0x01]);
        assert_eq!(encode_jam_compact(16383), vec![0xFD, 0xFF]);
    }

    #[test]
    fn test_decode_jam_compact() {
        let (v, len) = decode_jam_compact(&[0x04]).unwrap();
        assert_eq!(v, 1);
        assert_eq!(len, 1);

        let (v, len) = decode_jam_compact(&[0x01, 0x01]).unwrap();
        assert_eq!(v, 64);
        assert_eq!(len, 2);
    }

    #[test]
    fn test_execenv_encode() {
        let env = CorevmExecEnv::new(1, [0xAB; 32])
            .arg("test");
        let encoded = env.encode();

        // service_id (4) + hash (32) + none (1) + args len (1) + arg len (1) + "test" (4) + env len (1)
        assert_eq!(encoded.len(), 4 + 32 + 1 + 1 + 1 + 4 + 1);
    }
}
