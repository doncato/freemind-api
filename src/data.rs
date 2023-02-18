pub mod data_types {
    use log::LevelFilter;
    use serde::{Deserialize, Serialize};
    use std::path::{Path, PathBuf};
    use mysql;

    #[derive(Serialize, Deserialize)]
    pub struct AppConfig {
        pub database_username: String,
        pub database_password: String,
        pub database_host: String,
        pub database_database: String,
        pub port: u16,
        pub user_files_path: PathBuf,
        pub log_path: PathBuf,
        pub log_level: u8,
        pub workers: u8,
        pub max_submit_size: u32,
    }

    impl ::std::default::Default for AppConfig {
        fn default() -> Self {
            Self {
                database_username: "freemind".to_string(),
                database_password: "".to_string(),
                database_host: "localhost".to_string(),
                database_database: "freemind".to_string(),
                port: 8008,
                user_files_path: Path::new("./users/").to_path_buf(),
                log_path: Path::new("/var/log/freemind.log").to_path_buf(),
                log_level: 3,
                workers: 4,
                max_submit_size: 5_242_880, // == 5 MiB
            }
        }
    }

    #[derive(Clone)]
    pub struct AppState {
        pub port: u16,
        pub workers: u8,
        pub pool: mysql::Pool,
        pub user_files_path: PathBuf,
        pub max_payload_size: u32,
    }

    impl AppState {
        pub fn from_config(config: &AppConfig) -> Result<Self, mysql::Error> {
            let opts = mysql::OptsBuilder::new()
                .user(Some(&config.database_username))
                .pass(Some(&config.database_password))
                .ip_or_hostname(Some(&config.database_host))
                .db_name(Some(&config.database_database));
            let pool = mysql::Pool::new(opts)?;
            Ok(Self {
                port: config.port,
                workers: config.workers,
                pool: pool,
                user_files_path: config.user_files_path.clone(),
                max_payload_size: config.max_submit_size
            })
        }
    }


    pub fn level_filter_from_int(level: &u8) -> LevelFilter {
        match level {
            0 => LevelFilter::Off,
            1 => LevelFilter::Error,
            2 => LevelFilter::Warn,
            3 => LevelFilter::Info,
            4 => LevelFilter::Debug,
            5 => LevelFilter::Trace,
            _ => LevelFilter::Info,
        }
    }
}

pub mod xml_engine {
    use quick_xml::reader::Reader as XmlReader;
    use quick_xml::events::Event as XmlEvent;
    use quick_xml;

    pub async fn validate_xml_payload(path: &std::path::PathBuf) -> Result<bool, quick_xml::Error> {
        let mut registry_count: u8 = 0;

        let mut xml_reader = XmlReader::from_file(path)?; // I just hope this doesn't error
        let mut buf = Vec::new();
        loop {
            match xml_reader.read_event_into(&mut buf)? {
                XmlEvent::Start(e) => {
                    match e.name().as_ref() {
                        b"registry" => registry_count += 1,
                        _ => (),
                    }
                }
                XmlEvent::Eof => break,
                _ => (),
            }
        }
        Ok(registry_count == 1)
    }
}

pub mod mysql_handler {
    use mysql;
    use mysql::prelude::Queryable;

    pub fn verify_user(pool: mysql::Pool, user: &str, token: &str) -> Result<Option<String>, mysql::Error> {
        let mut conn = pool.get_conn()?;
        let stmt = conn.as_mut().prep("SELECT username FROM logins WHERE username = ? AND token = ?")?;
        let res = conn.exec_first(stmt,(user, token))?;
        Ok(res)
    }
}