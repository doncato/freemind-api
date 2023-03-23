use confy;
use log::LevelFilter;
use simplelog::*;
use std::fs;
use std::path::Path;

mod http_server;
pub use crate::http_server::request_handler;

mod data;
pub use crate::data::mysql_handler;
pub use crate::data::data_types;



/// Initialize the logger
/// 
/// Takes a log level and a File Path to write the log file to.
fn init_logger(log_level: LevelFilter, log_path: &Path) {
    WriteLogger::init(
        log_level,
        ConfigBuilder::new().set_time_format_rfc3339().build(),
        fs::OpenOptions::new().append(true).create(true).open(log_path).expect("Failed to generate log file"),
    )
    .expect("Failed to initialize logger")
}

/// Optains the config file
/// 
/// loads the config file in the working directory called 'freemind.config'
/// creates the file using defaults if it doesn't exist yet
fn get_config() -> Result<data_types::AppConfig, confy::ConfyError> {
    confy::load_path("./freemind.config")
}

/// Initializes the Programm
/// 
/// Obtains the main configuration and initializes the logger on success
/// Returns the AppConfig (main configuration) and panics if it fails to do so
fn init() -> data_types::AppConfig {
    match get_config() {
        Ok(cfg) => {
            init_logger(data_types::level_filter_from_int(&cfg.log_level), &cfg.log_path);
            return cfg;
        },
        Err(err) => {
            panic!("Failed to read config: {:?}", err);
        }
    }
}

/// Main Entry Point
fn main() {
    let cfg: data_types::AppConfig = init(); // Obtain the main config
    log::debug!("Config Loaded. Starting Server..."); 
    let state = data_types::AppState::from_config(&cfg); // Create an AppState from the main config, later used by the webserver to store important stuff
    let result = match state { // Check if the AppState was returned successfully 
        Ok(stat) => request_handler::run(stat), // Start the webserver & start accepting incoming connections using the AppState
        Err(err) => panic!("Failed to Start! Could not create pooled SQL Connection: {}", err), // Panic if no AppState could be created
    };
    if result.is_err() { // Handle the result of the webserver process
        log::error!("{}", result.err().unwrap());
    }
}
