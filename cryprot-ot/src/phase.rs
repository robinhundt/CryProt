//! Phase identifiers used for [`cryprot_net::metrics`].

pub const BASE_OT: &str = "base-ot";
pub const OT_EXTENSION: &str = "ot-extension";
pub const PPRF_EXPANSION: &str = cryprot_pprf::COMMUNICATION_PHASE;
pub const SILENT_CORRELATED_EXTENSION: &str = "silent-correlated-extension";
pub const SILENT_RANDOM_EXTENSION: &str = "silent-random-extension";
pub const NOISY_VOLE: &str = "noisy-vole";
pub const MALICIOUS_CHECK: &str = "malicious-check";
