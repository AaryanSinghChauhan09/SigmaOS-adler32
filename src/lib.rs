//! SigmaOS-adler32 — comprehensive Adler-32 checksum component.
//!
//! Provides Adler-32 checksum calculation for data integrity verification,
//! supporting incremental updates and various data formats.

use std::collections::HashMap;

/// Adler-32 checksum state
#[derive(Debug, Clone)]
pub struct Adler32State {
    /// A component of checksum
    a: u32,
    /// B component of checksum
    b: u32,
    /// Total bytes processed
    bytes_processed: u64,
}

impl Default for Adler32State {
    fn default() -> Self {
        Self {
            a: 1,
            b: 0,
            bytes_processed: 0,
        }
    }
}

impl Adler32State {
    /// Create new Adler-32 state
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Update checksum with data
    pub fn update(&mut self, data: &[u8]) {
        const MOD_ADLER: u32 = 65521;
        
        for &byte in data {
            self.a = (self.a + byte as u32) % MOD_ADLER;
            self.b = (self.b + self.a) % MOD_ADLER;
            self.bytes_processed += 1;
        }
    }
    
    /// Get current checksum value
    pub fn checksum(&self) -> u32 {
        (self.b << 16) | self.a
    }
    
    /// Get checksum as hex string
    pub fn checksum_hex(&self) -> String {
        format!("{:08x}", self.checksum())
    }
    
    /// Get bytes processed
    pub fn get_bytes_processed(&self) -> u64 {
        self.bytes_processed
    }
    
    /// Reset state
    pub fn reset(&mut self) {
        self.a = 1;
        self.b = 0;
        self.bytes_processed = 0;
    }
}

/// Adler-32 checksum calculator
#[derive(Debug, Clone)]
pub struct Adler32Calculator {
    /// Current state
    state: Adler32State,
    /// Checksum history
    history: Vec<ChecksumRecord>,
    /// Max history size
    max_history: usize,
}

impl Default for Adler32Calculator {
    fn default() -> Self {
        Self {
            state: Adler32State::default(),
            history: Vec::new(),
            max_history: 1000,
        }
    }
}

impl Adler32Calculator {
    /// Create new Adler-32 calculator
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Create calculator with max history
    pub fn with_max_history(max_history: usize) -> Self {
        Self {
            state: Adler32State::default(),
            history: Vec::new(),
            max_history,
        }
    }
    
    /// Calculate checksum for data
    pub fn calculate(&mut self, data: &[u8]) -> u32 {
        self.state.reset();
        self.state.update(data);
        let checksum = self.state.checksum();
        
        // Record in history
        self.record_checksum(data.len() as u64, checksum);
        
        checksum
    }
    
    /// Calculate checksum incrementally
    pub fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }
    
    /// Get current checksum
    pub fn get_checksum(&self) -> u32 {
        self.state.checksum()
    }
    
    /// Get current checksum as hex
    pub fn get_checksum_hex(&self) -> String {
        self.state.checksum_hex()
    }
    
    /// Get bytes processed
    pub fn get_bytes_processed(&self) -> u64 {
        self.state.get_bytes_processed()
    }
    
    /// Reset calculator
    pub fn reset(&mut self) {
        self.state.reset();
    }
    
    /// Verify checksum
    pub fn verify(&self, data: &[u8], expected_checksum: u32) -> bool {
        let mut temp_state = Adler32State::default();
        temp_state.update(data);
        temp_state.checksum() == expected_checksum
    }
    
    /// Verify checksum from hex string
    pub fn verify_hex(&self, data: &[u8], expected_hex: &str) -> bool {
        if let Ok(expected) = u32::from_str_radix(expected_hex, 16) {
            self.verify(data, expected)
        } else {
            false
        }
    }
    
    /// Record checksum in history
    fn record_checksum(&mut self, data_size: u64, checksum: u32) {
        let record = ChecksumRecord {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            data_size,
            checksum,
        };
        
        self.history.push(record);
        
        // Trim history if needed
        if self.history.len() > self.max_history {
            self.history.remove(0);
        }
    }
    
    /// Get checksum history
    pub fn get_history(&self) -> &[ChecksumRecord] {
        &self.history
    }
    
    /// Get last checksum record
    pub fn get_last_record(&self) -> Option<&ChecksumRecord> {
        self.history.last()
    }
    
    /// Clear history
    pub fn clear_history(&mut self) {
        self.history.clear();
    }
    
    /// Get checksum statistics
    pub fn get_statistics(&self) -> ChecksumStatistics {
        ChecksumStatistics {
            total_calculations: self.history.len() as u64,
            total_bytes_processed: self.history.iter().map(|r| r.data_size).sum(),
            last_checksum: self.history.last().map(|r| r.checksum),
            history_size: self.history.len(),
        }
    }
    
    /// Export calculator data
    pub fn export_data(&self) -> Adler32Export {
        Adler32Export {
            history: self.history.clone(),
        }
    }
    
    /// Import calculator data
    pub fn import_data(&mut self, export: Adler32Export) {
        self.history = export.history;
        self.state.reset();
    }
}

/// Checksum record
#[derive(Debug, Clone)]
pub struct ChecksumRecord {
    /// Timestamp
    pub timestamp: u64,
    /// Data size in bytes
    pub data_size: u64,
    /// Checksum value
    pub checksum: u32,
}

/// Checksum statistics
#[derive(Debug, Clone)]
pub struct ChecksumStatistics {
    /// Total calculations
    pub total_calculations: u64,
    /// Total bytes processed
    pub total_bytes_processed: u64,
    /// Last checksum
    pub last_checksum: Option<u32>,
    /// History size
    pub history_size: usize,
}

/// Adler-32 export data
#[derive(Debug, Clone)]
pub struct Adler32Export {
    /// Checksum history
    pub history: Vec<ChecksumRecord>,
}

/// Utility functions
pub mod utils {
    use super::*;
    
    /// Calculate Adler-32 checksum for data
    pub fn adler32(data: &[u8]) -> u32 {
        let mut state = Adler32State::default();
        state.update(data);
        state.checksum()
    }
    
    /// Calculate Adler-32 checksum as hex string
    pub fn adler32_hex(data: &[u8]) -> String {
        format!("{:08x}", adler32(data))
    }
    
    /// Verify Adler-32 checksum
    pub fn verify_adler32(data: &[u8], expected: u32) -> bool {
        adler32(data) == expected
    }
    
    /// Verify Adler-32 checksum from hex string
    pub fn verify_adler32_hex(data: &[u8], expected_hex: &str) -> bool {
        if let Ok(expected) = u32::from_str_radix(expected_hex, 16) {
            verify_adler32(data, expected)
        } else {
            false
        }
    }
    
    /// Calculate Adler-32 for string
    pub fn adler32_str(s: &str) -> u32 {
        adler32(s.as_bytes())
    }
    
    /// Calculate Adler-32 for string as hex
    pub fn adler32_str_hex(s: &str) -> String {
        adler32_hex(s.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_adler32_state_creation() {
        let state = Adler32State::new();
        assert_eq!(state.checksum(), 1); // Initial checksum is 1
        assert_eq!(state.get_bytes_processed(), 0);
    }
    
    #[test]
    fn test_adler32_calculation() {
        let mut state = Adler32State::new();
        state.update(b"hello");
        let checksum = state.checksum();
        assert_ne!(checksum, 1); // Checksum should change
        assert_eq!(state.get_bytes_processed(), 5);
    }
    
    #[test]
    fn test_adler32_known_values() {
        // Test with known values
        let mut state = Adler32State::new();
        state.update(b"Wikipedia");
        let checksum = state.checksum();
        assert_eq!(checksum, 0x11E60398); // Known Adler-32 for "Wikipedia"
    }
    
    #[test]
    fn test_adler32_incremental() {
        let mut state = Adler32State::new();
        state.update(b"hello");
        let checksum1 = state.checksum();
        
        state.update(b" world");
        let checksum2 = state.checksum();
        
        assert_ne!(checksum1, checksum2);
        assert_eq!(state.get_bytes_processed(), 11);
    }
    
    #[test]
    fn test_adler32_reset() {
        let mut state = Adler32State::new();
        state.update(b"hello");
        let checksum1 = state.checksum();
        
        state.reset();
        assert_eq!(state.checksum(), 1);
        assert_eq!(state.get_bytes_processed(), 0);
    }
    
    #[test]
    fn test_calculator_creation() {
        let calculator = Adler32Calculator::new();
        assert_eq!(calculator.get_bytes_processed(), 0);
        assert_eq!(calculator.get_checksum(), 1);
    }
    
    #[test]
    fn test_calculator_calculate() {
        let mut calculator = Adler32Calculator::new();
        let checksum = calculator.calculate(b"hello");
        assert_ne!(checksum, 1);
        assert_eq!(calculator.get_bytes_processed(), 5);
    }
    
    #[test]
    fn test_calculator_update() {
        let mut calculator = Adler32Calculator::new();
        calculator.update(b"hello");
        calculator.update(b" world");
        assert_eq!(calculator.get_bytes_processed(), 11);
    }
    
    #[test]
    fn test_calculator_verify() {
        let mut calculator = Adler32Calculator::new();
        let data = b"hello world";
        let checksum = calculator.calculate(data);
        
        assert!(calculator.verify(data, checksum));
        assert!(!calculator.verify(data, 0)); // Wrong checksum
    }
    
    #[test]
    fn test_calculator_verify_hex() {
        let mut calculator = Adler32Calculator::new();
        let data = b"hello world";
        let checksum = calculator.calculate(data);
        let checksum_hex = calculator.get_checksum_hex();
        
        assert!(calculator.verify_hex(data, &checksum_hex));
        assert!(!calculator.verify_hex(data, "00000000")); // Wrong checksum
    }
    
    #[test]
    fn test_checksum_history() {
        let mut calculator = Adler32Calculator::new();
        calculator.calculate(b"data1");
        calculator.calculate(b"data2");
        calculator.calculate(b"data3");
        
        assert_eq!(calculator.get_history().len(), 3);
        assert!(calculator.get_last_record().is_some());
    }
    
    #[test]
    fn test_checksum_statistics() {
        let mut calculator = Adler32Calculator::new();
        calculator.calculate(b"data1");
        calculator.calculate(b"data2");
        
        let stats = calculator.get_statistics();
        assert_eq!(stats.total_calculations, 2);
        assert_eq!(stats.total_bytes_processed, 10); // 5 + 5
        assert!(stats.last_checksum.is_some());
    }
    
    #[test]
    fn test_export_import() {
        let mut calculator = Adler32Calculator::new();
        calculator.calculate(b"data1");
        calculator.calculate(b"data2");
        
        let export = calculator.export_data();
        
        let mut calculator2 = Adler32Calculator::new();
        calculator2.import_data(export);
        
        assert_eq!(calculator2.get_history().len(), 2);
    }
    
    #[test]
    fn test_utility_functions() {
        let data = b"hello world";
        let checksum = utils::adler32(data);
        let checksum_hex = utils::adler32_hex(data);
        
        assert_ne!(checksum, 1);
        assert_eq!(checksum_hex.len(), 8);
        assert!(utils::verify_adler32(data, checksum));
        assert!(utils::verify_adler32_hex(data, &checksum_hex));
    }
    
    #[test]
    fn test_string_functions() {
        let s = "hello world";
        let checksum = utils::adler32_str(s);
        let checksum_hex = utils::adler32_str_hex(s);
        
        assert_ne!(checksum, 1);
        assert_eq!(checksum_hex.len(), 8);
    }
    
    #[test]
    fn test_empty_data() {
        let checksum = utils::adler32(b"");
        assert_eq!(checksum, 1); // Adler-32 of empty data is 1
    }
    
    #[test]
    fn test_large_data() {
        let data = vec![0u8; 1000];
        let checksum = utils::adler32(&data);
        assert_ne!(checksum, 1);
    }
}
