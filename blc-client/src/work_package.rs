//! JAM Work Package encoding for BLC service execution
//!
//! This module implements the JAM work package structure needed to
//! submit BLC programs for execution on the testnet.

use blake2::{Blake2b, Digest};
use blake2::digest::consts::U32;

/// Type alias for Blake2b with 256-bit output
type Blake2b256 = Blake2b<U32>;

/// Blake2b-256 hash
pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Encode a natural number in JAM compact format (same as SCALE compact)
pub fn encode_natural(value: u64) -> Vec<u8> {
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

/// Work context for a work package
#[derive(Clone, Debug)]
pub struct WorkContext {
    pub anchor: [u8; 32],
    pub state_root: [u8; 32],
    pub accumulation_root: [u8; 32],
    pub lookup_anchor: [u8; 32],
    pub lookup_slot: u32,
    pub prerequisites: Vec<[u8; 32]>,
}

impl WorkContext {
    /// Create a minimal context for testnet
    pub fn minimal() -> Self {
        Self {
            anchor: [0u8; 32],
            state_root: [0u8; 32],
            accumulation_root: [0u8; 32],
            lookup_anchor: [0u8; 32],
            lookup_slot: 0,
            prerequisites: Vec::new(),
        }
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.anchor);
        buf.extend_from_slice(&self.state_root);
        buf.extend_from_slice(&self.accumulation_root);
        buf.extend_from_slice(&self.lookup_anchor);
        buf.extend_from_slice(&self.lookup_slot.to_le_bytes());
        buf.extend_from_slice(&encode_natural(self.prerequisites.len() as u64));
        for hash in &self.prerequisites {
            buf.extend_from_slice(hash);
        }
        buf
    }
}

/// A single work item in a work package
#[derive(Clone, Debug)]
pub struct WorkItem {
    pub service: u32,
    pub code_hash: [u8; 32],
    pub payload: Vec<u8>,
    pub gas_refine: u64,
    pub gas_accumulate: u64,
    pub export_count: u16,
    pub imports: Vec<([u8; 32], u32)>,
    pub extrinsics: Vec<([u8; 32], u32)>,
}

impl WorkItem {
    /// Create a new work item for BLC execution
    pub fn new_blc(service_id: u32, code_hash: [u8; 32], blc_payload: Vec<u8>, gas: u64) -> Self {
        Self {
            service: service_id,
            code_hash,
            payload: blc_payload,
            gas_refine: gas,
            gas_accumulate: gas,
            export_count: 0,
            imports: Vec::new(),
            extrinsics: Vec::new(),
        }
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Fixed fields
        buf.extend_from_slice(&self.service.to_le_bytes());
        buf.extend_from_slice(&self.code_hash);
        buf.extend_from_slice(&self.gas_refine.to_le_bytes());
        buf.extend_from_slice(&self.gas_accumulate.to_le_bytes());
        buf.extend_from_slice(&self.export_count.to_le_bytes());

        // Payload with length prefix
        buf.extend_from_slice(&encode_natural(self.payload.len() as u64));
        buf.extend_from_slice(&self.payload);

        // Imports with length prefix
        buf.extend_from_slice(&encode_natural(self.imports.len() as u64));
        for (hash, len) in &self.imports {
            buf.extend_from_slice(hash);
            buf.extend_from_slice(&len.to_le_bytes());
        }

        // Extrinsics with length prefix
        buf.extend_from_slice(&encode_natural(self.extrinsics.len() as u64));
        for (hash, len) in &self.extrinsics {
            buf.extend_from_slice(hash);
            buf.extend_from_slice(&len.to_le_bytes());
        }

        buf
    }
}

/// A complete work package
#[derive(Clone, Debug)]
pub struct WorkPackage {
    pub authorization_token: Vec<u8>,
    pub auth_service: u32,
    pub auth_code_hash: [u8; 32],
    pub auth_config: Vec<u8>,
    pub context: WorkContext,
    pub items: Vec<WorkItem>,
}

impl WorkPackage {
    /// Create a minimal work package for testnet (Bootstrap auth)
    pub fn new_minimal(items: Vec<WorkItem>) -> Self {
        Self {
            authorization_token: Vec::new(),
            auth_service: 0,  // Bootstrap service
            auth_code_hash: [0u8; 32],
            auth_config: Vec::new(),
            context: WorkContext::minimal(),
            items,
        }
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Auth fields
        buf.extend_from_slice(&self.auth_service.to_le_bytes());
        buf.extend_from_slice(&self.auth_code_hash);

        // Context
        buf.extend_from_slice(&self.context.encode());

        // Authorization token with length prefix
        buf.extend_from_slice(&encode_natural(self.authorization_token.len() as u64));
        buf.extend_from_slice(&self.authorization_token);

        // Auth config with length prefix
        buf.extend_from_slice(&encode_natural(self.auth_config.len() as u64));
        buf.extend_from_slice(&self.auth_config);

        // Items with length prefix
        buf.extend_from_slice(&encode_natural(self.items.len() as u64));
        for item in &self.items {
            let item_bytes = item.encode();
            buf.extend_from_slice(&item_bytes);
        }

        buf
    }

    /// Get the hash of this work package
    pub fn hash(&self) -> [u8; 32] {
        blake2b_256(&self.encode())
    }
}

/// Builder for BLC work packages
pub struct BlcWorkPackageBuilder {
    service_id: u32,
    code_hash: [u8; 32],
    gas: u64,
}

impl BlcWorkPackageBuilder {
    /// Create a new builder
    pub fn new(service_id: u32, code_hash: [u8; 32]) -> Self {
        Self {
            service_id,
            code_hash,
            gas: 1_000_000_000,
        }
    }

    /// Set gas limit
    pub fn gas(mut self, gas: u64) -> Self {
        self.gas = gas;
        self
    }

    /// Build a work package for a BLC program
    pub fn build(&self, blc_program: &[u8]) -> WorkPackage {
        let item = WorkItem::new_blc(
            self.service_id,
            self.code_hash,
            blc_program.to_vec(),
            self.gas,
        );
        WorkPackage::new_minimal(vec![item])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_natural_small() {
        assert_eq!(encode_natural(0), vec![0x00]);
        assert_eq!(encode_natural(1), vec![0x04]);
        assert_eq!(encode_natural(63), vec![0xFC]);
    }

    #[test]
    fn test_encode_natural_medium() {
        assert_eq!(encode_natural(64), vec![0x01, 0x01]);
    }

    #[test]
    fn test_work_package_encode() {
        let builder = BlcWorkPackageBuilder::new(1, [0xAB; 32]);
        let pkg = builder.build(&[0x20]); // identity combinator
        let encoded = pkg.encode();

        // Should have some reasonable size
        assert!(encoded.len() > 100);

        // Hash should be 32 bytes
        let hash = pkg.hash();
        assert_eq!(hash.len(), 32);
    }
}
