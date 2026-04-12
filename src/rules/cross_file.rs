//! Cross-file taint analysis infrastructure.
//!
//! Provides [`FunctionTaintSummary`] — a compact description of how a function
//! propagates taint from its parameters to sinks and return values. Summaries
//! are generated in pass 1 of the scanner (one per exported function) and
//! consumed in pass 2 by the per-file taint engines.
//!
//! The summary extraction reuses the existing single-file taint engine: each
//! parameter is treated as a synthetic taint source, and any findings or
//! return-taint that result are recorded in the summary.

use std::collections::HashMap;
use std::path::PathBuf;

/// Summary of a function's taint behavior for cross-file analysis.
/// Generated in pass 1, consumed in pass 2.
#[derive(Debug, Clone)]
pub struct FunctionTaintSummary {
    /// Function name as exported.
    pub name: String,
    /// Which parameter indices, when tainted, cause the return value to be tainted.
    pub params_to_return: Vec<usize>,
    /// Which parameter indices, when tainted, reach a sink.
    pub params_to_sink: Vec<ParamSinkFlow>,
}

/// Records that when parameter at `param_index` is tainted, it reaches
/// a specific sink identified by the rule that would fire.
#[derive(Debug, Clone)]
pub struct ParamSinkFlow {
    pub param_index: usize,
    pub sink_rule_id: String,
    pub sink_description: String,
}

/// Map from file path to the summaries of all exported functions in that file.
pub type CrossFileSummaryMap = HashMap<PathBuf, Vec<FunctionTaintSummary>>;
