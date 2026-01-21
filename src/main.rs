// Copyright (C) 2024, 2025 Hydra-Pool Developers (see AUTHORS)
//
// This file is part of Hydra-Pool.
//
// Hydra-Pool is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// Hydra-Pool is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// Hydra-Pool. If not, see <https://www.gnu.org/licenses/>.

use clap::Parser;
use p2poolv2_api::start_api_server;
use p2poolv2_lib::accounting::stats::metrics;
use p2poolv2_lib::config::Config;
use p2poolv2_lib::logging::setup_logging;
use p2poolv2_lib::node::actor::NodeHandle;
use p2poolv2_lib::shares::chain::chain_store::ChainStore;
use p2poolv2_lib::shares::share_block::ShareBlock;
use p2poolv2_lib::store::Store;
use p2poolv2_lib::stratum::client_connections::start_connections_handler;
use p2poolv2_lib::stratum::emission::Emission;
use p2poolv2_lib::stratum::server::StratumServerBuilder;
use p2poolv2_lib::stratum::work::gbt::start_gbt;
use p2poolv2_lib::stratum::work::notify::start_notify;
use p2poolv2_lib::stratum::work::tracker::start_tracker_actor;
use p2poolv2_lib::stratum::zmq_listener::{ZmqListener, ZmqListenerTrait};
use std::fs;
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;
use toml::Value;
use tracing::error;
use tracing::info;

/// Interval in seconds to poll for new block templates since the last zmq signal
const GBT_POLL_INTERVAL: u64 = 10; // seconds

/// Maximum number of pending shares from all clients connected to stratum server
const STRATUM_SHARES_BUFFER_SIZE: usize = 1000;

/// Prefix bytes for the signature standard: TAG (0x54 0x41 0x47)
const COINBASE_TAG_MAGIC_BYTES: &[u8] = &[0x54, 0x41, 0x47];

/// Field prefix bytes for [coinbase_tag] section fields
const FIELD_PREFIX_POOL: u8 = 0x01;
const FIELD_PREFIX_MINER: u8 = 0x02;
const FIELD_PREFIX_SOFTWARE: u8 = 0x03;
const FIELD_PREFIX_WEBSITE: u8 = 0x04;
const FIELD_PREFIX_CUSTOM: u8 = 0xFF;

/// Coinbase tag configuration fields from [coinbase_tag] section
#[derive(Debug, Default)]
struct CoinbaseTagConfig {
    pool: Option<String>,
    miner: Option<String>,
    software: Option<String>,
    website: Option<String>,
    custom: Option<String>,
}

/// Parse the [coinbase_tag] section from a TOML config file
fn parse_coinbase_tag_config(config_path: &str) -> Result<CoinbaseTagConfig, String> {
    let contents = fs::read_to_string(config_path)
        .map_err(|e| format!("Failed to read config file: {e}"))?;
    
    let value: Value = contents.parse()
        .map_err(|e| format!("Failed to parse TOML: {e}"))?;
    
    let mut coinbase_tag_config = CoinbaseTagConfig::default();
    
    if let Some(coinbase_tag_table) = value.get("coinbase_tag").and_then(|v| v.as_table()) {
        coinbase_tag_config.pool = coinbase_tag_table.get("pool")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());
        
        coinbase_tag_config.miner = coinbase_tag_table.get("miner")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());
        
        coinbase_tag_config.software = coinbase_tag_table.get("software")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());
        
        coinbase_tag_config.website = coinbase_tag_table.get("website")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());
        
        coinbase_tag_config.custom = coinbase_tag_table.get("custom")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());
    }
    
    Ok(coinbase_tag_config)
}

/// Compose the signature according to the standard:
/// [TAG][[TLV_entry1]|[TLV_entry2]|[TLV_entry3]|...]
/// where TLV_entry is [type][len][value]
/// type is a single byte prefix for the field
/// len is the length of the value
/// value is the value of the field
/// 
/// Example:
/// [TAG][[0x01][0x07][testpool]|[0x02][0x06][miner1]|[0x03][0x08][hydrapool]|[0x04][0x011][hydrapool.org]|[0xFF][0x0A][customdata]]
/// 
/// Returns empty Vec if no fields are filled
fn compose_signature(coinbase_tag_config: &CoinbaseTagConfig) -> Vec<u8> {
    // First, collect all TLV entries
    let mut tlv_entries = Vec::new();
    
    // Add pool entry if present
    if let Some(ref pool) = coinbase_tag_config.pool {
        let bytes = pool.as_bytes();
        if bytes.len() <= 255 {
            tlv_entries.push(FIELD_PREFIX_POOL);
            tlv_entries.push(bytes.len() as u8);
            tlv_entries.extend_from_slice(bytes);
        }
    }
    
    // Add miner entry if present
    if let Some(ref miner) = coinbase_tag_config.miner {
        let bytes = miner.as_bytes();
        if bytes.len() <= 255 {
            tlv_entries.push(FIELD_PREFIX_MINER);
            tlv_entries.push(bytes.len() as u8);
            tlv_entries.extend_from_slice(bytes);
        }
    }
    
    // Add software entry if present
    if let Some(ref software) = coinbase_tag_config.software {
        let bytes = software.as_bytes();
        if bytes.len() <= 255 {
            tlv_entries.push(FIELD_PREFIX_SOFTWARE);
            tlv_entries.push(bytes.len() as u8);
            tlv_entries.extend_from_slice(bytes);
        }
    }
    
    // Add website entry if present
    if let Some(ref website) = coinbase_tag_config.website {
        let bytes = website.as_bytes();
        if bytes.len() <= 255 {
            tlv_entries.push(FIELD_PREFIX_WEBSITE);
            tlv_entries.push(bytes.len() as u8);
            tlv_entries.extend_from_slice(bytes);
        }
    }
    
    // Add custom entry if present
    if let Some(ref custom) = coinbase_tag_config.custom {
        let bytes = custom.as_bytes();
        if bytes.len() <= 255 {
            tlv_entries.push(FIELD_PREFIX_CUSTOM);
            tlv_entries.push(bytes.len() as u8);
            tlv_entries.extend_from_slice(bytes);
        }
    }
    
    // If no TLV entries, return empty signature
    if tlv_entries.is_empty() {
        return Vec::new();
    }
    
    // Build the final signature: [TAG][TLV entries...]
    let mut signature = Vec::new();
    signature.extend_from_slice(COINBASE_TAG_MAGIC_BYTES);
    signature.extend_from_slice(&tlv_entries);
    
    signature
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    config: String,
}

#[tokio::main]
async fn main() -> Result<(), String> {
    info!("Starting Hydrapool...");
    // Parse command line arguments
    let args = Args::parse();

    // Load configuration
    let config = Config::load(&args.config);
    if config.is_err() {
        let err = config.unwrap_err();
        error!("Failed to load config: {err}");
        return Err(format!("Failed to load config: {err}"));
    }

    let mut config = config.unwrap();
    
    // Parse [coinbase_tag] section and compose signature
    let coinbase_tag_config = match parse_coinbase_tag_config(&args.config) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to parse coinbase_tag config: {e}");
            return Err(format!("Failed to parse coinbase_tag config: {e}"));
        }
    };
    
    let signature_bytes = compose_signature(&coinbase_tag_config);
    if !signature_bytes.is_empty() {
        // Convert bytes to String (using from_utf8_lossy to handle any non-UTF8 bytes)
        config.stratum.pool_signature = Some(String::from_utf8_lossy(&signature_bytes).to_string());
    }

    // Configure logging based on config
    let logging_result = setup_logging(&config.logging);
    // hold guard to ensure logging is set up correctly
    let _guard = match logging_result {
        Ok(guard) => {
            info!("Logging set up successfully");
            guard
        }
        Err(e) => {
            error!("Failed to set up logging: {e}");
            return Err(format!("Failed to set up logging: {e}"));
        }
    };

    let genesis = ShareBlock::build_genesis_for_network(config.stratum.network);
    let store = Arc::new(Store::new(config.store.path.clone(), false).unwrap());
    let chain_store = Arc::new(ChainStore::new(
        store.clone(),
        genesis,
        config.stratum.network,
    ));

    let tip = chain_store.store.get_chain_tip();
    let height = chain_store.get_tip_height();
    info!("Latest tip {:?} at height {:?}", tip, height);

    let background_tasks_store = store.clone();
    p2poolv2_lib::store::background_tasks::start_background_tasks(
        background_tasks_store,
        Duration::from_secs(config.store.background_task_frequency_hours * 3600),
        Duration::from_secs(config.store.pplns_ttl_days * 3600 * 24),
    );

    let stratum_config = config.stratum.clone().parse().unwrap();
    let bitcoinrpc_config = config.bitcoinrpc.clone();

    let (stratum_shutdown_tx, stratum_shutdown_rx) = tokio::sync::oneshot::channel();
    let (notify_tx, notify_rx) = tokio::sync::mpsc::channel(1);
    let tracker_handle = start_tracker_actor();

    let notify_tx_for_gbt = notify_tx.clone();
    let bitcoinrpc_config_cloned = bitcoinrpc_config.clone();
    // Setup ZMQ publisher for block notifications
    let zmq_trigger_rx = match ZmqListener.start(&stratum_config.zmqpubhashblock) {
        Ok(rx) => rx,
        Err(e) => {
            error!("Failed to set up ZMQ publisher: {e}");
            return Err("Failed to set up ZMQ publisher".into());
        }
    };

    tokio::spawn(async move {
        if let Err(e) = start_gbt(
            bitcoinrpc_config_cloned,
            notify_tx_for_gbt,
            GBT_POLL_INTERVAL,
            stratum_config.network,
            zmq_trigger_rx,
        )
        .await
        {
            tracing::error!("Failed to fetch block template. Shutting down. \n {e}");
            exit(1);
        }
    });

    let connections_handle = start_connections_handler().await;
    let connections_cloned = connections_handle.clone();

    let tracker_handle_cloned = tracker_handle.clone();
    let store_for_notify = chain_store.clone();

    let cloned_stratum_config = stratum_config.clone();
    tokio::spawn(async move {
        info!("Starting Stratum notifier...");
        // This will run indefinitely, sending new block templates to the Stratum server as they arrive
        start_notify(
            notify_rx,
            connections_cloned,
            store_for_notify,
            tracker_handle_cloned,
            &cloned_stratum_config,
            None,
        )
        .await;
    });

    let (emissions_tx, emissions_rx) =
        tokio::sync::mpsc::channel::<Emission>(STRATUM_SHARES_BUFFER_SIZE);

    let metrics_handle = match metrics::start_metrics(config.logging.stats_dir.clone()).await {
        Ok(handle) => handle,
        Err(e) => {
            return Err(format!("Failed to start metrics: {e}"));
        }
    };
    let metrics_cloned = metrics_handle.clone();
    let store_for_stratum = chain_store.clone();
    let tracker_handle_cloned = tracker_handle.clone();

    tokio::spawn(async move {
        let mut stratum_server = StratumServerBuilder::default()
            .shutdown_rx(stratum_shutdown_rx)
            .connections_handle(connections_handle.clone())
            .emissions_tx(emissions_tx)
            .hostname(stratum_config.hostname)
            .port(stratum_config.port)
            .start_difficulty(stratum_config.start_difficulty)
            .minimum_difficulty(stratum_config.minimum_difficulty)
            .maximum_difficulty(stratum_config.maximum_difficulty)
            .ignore_difficulty(stratum_config.ignore_difficulty)
            .network(stratum_config.network)
            .version_mask(stratum_config.version_mask)
            .store(store_for_stratum)
            .build()
            .await
            .unwrap();
        info!("Starting Stratum server...");
        let result = stratum_server
            .start(
                None,
                notify_tx,
                tracker_handle_cloned,
                bitcoinrpc_config,
                metrics_cloned,
            )
            .await;
        if result.is_err() {
            error!("Failed to start Stratum server: {}", result.unwrap_err());
        }
        info!("Stratum server stopped");
    });

    let api_shutdown_tx = match start_api_server(
        config.api.clone(),
        chain_store.clone(),
        metrics_handle.clone(),
        tracker_handle,
        stratum_config.network,
        stratum_config.pool_signature,
    )
    .await
    {
        Ok(shutdown_tx) => shutdown_tx,
        Err(e) => {
            info!("Error starting server: {}", e);
            return Err("Failed to start API Server. Quitting.".into());
        }
    };
    info!(
        "API server started on host {} port {}",
        config.api.hostname, config.api.port
    );

    match NodeHandle::new(config, chain_store, emissions_rx, metrics_handle).await {
        Ok((_node_handle, stopping_rx)) => {
            info!("Pool started");
            if (stopping_rx.await).is_ok() {
                info!("Pool shutting down ...");

                stratum_shutdown_tx
                    .send(())
                    .expect("Failed to send shutdown signal to Stratum server");

                let _ = api_shutdown_tx.send(());

                info!("Pool stopped");
            }
        }
        Err(e) => {
            error!("Failed to start node: {e}");
            return Err(format!("Failed to start node: {e}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compose_signature_empty() {
        let coinbase_tag_config = CoinbaseTagConfig::default();
        let signature = compose_signature(&coinbase_tag_config);
        // Should be empty when no fields are filled
        assert_eq!(signature, Vec::<u8>::new());
    }

    #[test]
    fn test_compose_signature_pool_only() {
        let mut coinbase_tag_config = CoinbaseTagConfig::default();
        coinbase_tag_config.pool = Some("testpool".to_string());
        let signature = compose_signature(&coinbase_tag_config);
        
        // Expected: [TAG][0x01][len(8)][testpool]
        // "testpool" is 8 bytes
        let expected = vec![
            0x54, 0x41, 0x47, // TAG
            0x01, // pool prefix (Type)
            0x08, // length (Length) - "testpool" is 8 bytes
            b't', b'e', b's', b't', b'p', b'o', b'o', b'l', // "testpool" (Value)
        ];
        assert_eq!(signature, expected);
    }

    #[test]
    fn test_compose_signature_all_fields() {
        let coinbase_tag_config = CoinbaseTagConfig {
            pool: Some("mypool".to_string()),
            miner: Some("miner1".to_string()),
            software: Some("hydrapool".to_string()),
            website: Some("hydrapool.org".to_string()),
            custom: Some("customdata".to_string()),
        };
        let signature = compose_signature(&coinbase_tag_config);
        
        // Verify TAG is at the start
        assert_eq!(signature[0..3], [0x54, 0x41, 0x47]);
        
        // Verify all field prefixes are present
        assert!(signature.contains(&FIELD_PREFIX_POOL));
        assert!(signature.contains(&FIELD_PREFIX_MINER));
        assert!(signature.contains(&FIELD_PREFIX_SOFTWARE));
        assert!(signature.contains(&FIELD_PREFIX_WEBSITE));
        assert!(signature.contains(&FIELD_PREFIX_CUSTOM));
        
        // Verify structure: [TAG][0x01][6][mypool][0x02][6][miner1][0x03][8][hydrapool][0x04][11][hydrapool.org][0xFF][10][customdata]
        assert_eq!(signature[0..3], [0x54, 0x41, 0x47]); // TAG
        
        let mut pos = 3; // After TAG
        
        // Check pool field
        assert_eq!(signature[pos], FIELD_PREFIX_POOL);
        pos += 1;
        assert_eq!(signature[pos], 6);
        pos += 1;
        assert_eq!(&signature[pos..pos + 6], b"mypool");
        pos += 6;
        
        // Check miner field
        assert_eq!(signature[pos], FIELD_PREFIX_MINER);
        pos += 1;
        assert_eq!(signature[pos], 6);
        pos += 1;
        assert_eq!(&signature[pos..pos + 6], b"miner1");
        pos += 6;
        
        // Check software field
        assert_eq!(signature[pos], FIELD_PREFIX_SOFTWARE);
        pos += 1;
        assert_eq!(signature[pos], 9); // "hydrapool" is 9 bytes
        pos += 1;
        assert_eq!(&signature[pos..pos + 9], b"hydrapool");
        pos += 9;
        
        // Check website field
        assert_eq!(signature[pos], FIELD_PREFIX_WEBSITE);
        pos += 1;
        assert_eq!(signature[pos], 13); // "hydrapool.org" is 13 bytes
        pos += 1;
        assert_eq!(&signature[pos..pos + 13], b"hydrapool.org");
        pos += 13;
        
        // Check custom field
        assert_eq!(signature[pos], FIELD_PREFIX_CUSTOM);
        pos += 1;
        assert_eq!(signature[pos], 10);
        pos += 1;
        assert_eq!(&signature[pos..pos + 10], b"customdata");
    }

    #[test]
    fn test_compose_signature_partial_fields() {
        let coinbase_tag_config = CoinbaseTagConfig {
            pool: Some("pool".to_string()),
            miner: None,
            software: Some("software".to_string()),
            website: None,
            custom: None,
        };
        let signature = compose_signature(&coinbase_tag_config);
        
        // Should contain TAG + pool + software
        assert_eq!(signature[0..3], [0x54, 0x41, 0x47]);
        
        // Check that pool and software fields are present by verifying TLV structure
        let mut pos = 3; // After TAG
        
        // Check pool field exists
        assert_eq!(signature[pos], FIELD_PREFIX_POOL);
        pos += 1;
        assert_eq!(signature[pos], 4); // length of "pool"
        pos += 1;
        assert_eq!(&signature[pos..pos + 4], b"pool");
        pos += 4;
        
        // Check software field exists
        assert_eq!(signature[pos], FIELD_PREFIX_SOFTWARE);
        pos += 1;
        assert_eq!(signature[pos], 8); // length of "software"
        pos += 1;
        assert_eq!(&signature[pos..pos + 8], b"software");
        
        // Verify other fields are NOT present by checking the signature doesn't contain their type bytes
        // Note: We can't use contains() because length bytes might match type bytes
        // Instead, verify the signature only has the expected fields
        let mut i = 3;
        while i < signature.len() {
            let field_type = signature[i];
            assert!(field_type == FIELD_PREFIX_POOL || field_type == FIELD_PREFIX_SOFTWARE,
                "Unexpected field type: 0x{:02x}", field_type);
            i += 1; // skip type
            let len = signature[i] as usize;
            i += 1 + len; // skip length and value
        }
    }

    #[test]
    fn test_compose_signature_long_field() {
        let mut coinbase_tag_config = CoinbaseTagConfig::default();
        // Create a field longer than 255 bytes
        let long_value = "a".repeat(300);
        coinbase_tag_config.pool = Some(long_value);
        let signature = compose_signature(&coinbase_tag_config);
        
        // Should be empty since the only field is too long and gets skipped
        assert_eq!(signature, Vec::<u8>::new());
    }
    
    #[test]
    fn test_compose_signature_long_field_with_valid_field() {
        let mut coinbase_tag_config = CoinbaseTagConfig::default();
        // Create a field longer than 255 bytes
        let long_value = "a".repeat(300);
        coinbase_tag_config.pool = Some(long_value);
        // Add a valid field
        coinbase_tag_config.miner = Some("valid".to_string());
        let signature = compose_signature(&coinbase_tag_config);
        
        // Should contain TAG + valid miner field, pool field should be skipped
        assert_eq!(signature[0..3], [0x54, 0x41, 0x47]);
        assert_eq!(signature[3], FIELD_PREFIX_MINER);
        assert_eq!(signature[4], 5); // length of "valid"
        assert_eq!(&signature[5..10], b"valid");
        // Should not contain pool prefix since it was skipped
        assert!(!signature.contains(&FIELD_PREFIX_POOL));
    }
}
