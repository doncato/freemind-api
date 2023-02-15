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
        pub log_path: PathBuf,
        pub log_level: u8,
        pub workers: u8,
    }

    impl ::std::default::Default for AppConfig {
        fn default() -> Self {
            Self {
                database_username: "freemind".to_string(),
                database_password: "".to_string(),
                database_host: "localhost".to_string(),
                database_database: "freemind".to_string(),
                port: 8008,
                log_path: Path::new("/var/log/freemind.log").to_path_buf(),
                log_level: 3,
                workers: 4,
            }
        }
    }

    #[derive(Clone)]
    pub struct AppState {
        pub port: u16,
        pub workers: u8,
        pub pool: mysql::Pool
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