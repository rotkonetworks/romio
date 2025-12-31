//! BLC (Binary Lambda Calculus) client for JAM CoreVM services
//!
//! This crate provides:
//! - BLC term parsing and encoding
//! - JAM RPC client for submitting work items
//! - Work package construction for service execution
//! - WASM bindings for web usage

pub mod blc;
pub mod jam;
pub mod work_package;

#[cfg(feature = "wasm")]
pub mod wasm;

pub use blc::{Term, parse_blc, encode_blc, parse_blc_text};
pub use jam::{JamClient, WorkItem, encode_jam_compact};
pub use work_package::{WorkPackage, BlcWorkPackageBuilder, blake2b_256};
