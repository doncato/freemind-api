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


fn init_logger(log_level: LevelFilter, log_path: &Path) {
    WriteLogger::init(
        log_level,
        ConfigBuilder::new().set_time_format_rfc3339().build(),
        fs::OpenOptions::new().append(true).create(true).open(log_path).expect("Failed to generate log file"),
    )
    .expect("Failed to initialize logger")
}

fn get_config() -> Result<data_types::AppConfig, confy::ConfyError> {
    confy::load_path("./freemind.config")
}

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

fn main() {
    let cfg: data_types::AppConfig = init();
    log::debug!("Config Loaded. Starting Server...");
    let state = data_types::AppState::from_config(&cfg);
    let result = match state {
        Ok(stat) => request_handler::run(stat),
        Err(err) => panic!("Failed to Start! Could not create pooled SQL Connection: {}", err),
    };
    if result.is_err() {
        log::error!("{}", result.err().unwrap());
    }
}
