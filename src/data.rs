/// Contains the custom datatypes used throughout the project
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

/// Does all of the nice xml parsing and handling
/// - knows what xml is
pub mod xml_engine {
    use quick_xml::reader::Reader as XmlReader;
    use quick_xml::events::Event as XmlEvent;
    use quick_xml;

    /// Validates any xml document located under *path*
    pub async fn validate_xml_payload(path: &std::path::PathBuf) -> Result<bool, quick_xml::Error> {
        let mut registry_count: u8 = 0; // Counter to check how often a registry node exists

        let mut xml_reader = XmlReader::from_file(path)?; // I just hope this doesn't error // Reader for the xml file
        let mut buf = Vec::new(); // A buffer to read into
        loop { // Iterate over the xml reader
            match xml_reader.read_event_into(&mut buf)? {
                XmlEvent::Start(e) => { // As if I'd know what is going on here
                    match e.name().as_ref() { // ???
                        b"registry" => registry_count += 1, // If a registry node is found increase the counter
                        _ => (), 
                    }
                }
                XmlEvent::Eof => break, // Stop the iteration when the file ends
                _ => (),
            }
        }
        Ok(registry_count == 1) // There should be only one registry so yeah guess the rest
    }
}

/// Does all of the wild SQL shit
/// - knows how to talk SQL
/// - knows how to bcrypt
pub mod mysql_handler {
    use bcrypt;
    use chrono::{DateTime, offset::Utc};
    use mysql;
    use mysql::prelude::Queryable;

    /// Verify a user using a token against the database
    pub fn verify_user<'a>(pool: mysql::Pool, user: &'a str, token: &str) -> Result<Option<&'a str>, mysql::Error> {
        let mut conn: mysql::PooledConn = pool.get_conn()?; // Obtain a pooled connection to the database
        let stmt = conn.as_mut().prep("SELECT token FROM logins WHERE username = ?")?; // Prepare a Select statement to get the hashed token associated with the user
        let res: Option<String> = conn.exec_first(stmt,(user,))?;
        let mut valid = false;
        if let Some(tok) = res {
            valid = bcrypt::verify(token, tok.as_ref()).unwrap_or(false); // Verify the found token from the database with the provided one using bcrypt
        }
        if valid { // Return the result
            log::debug!("User {:#?} was successfully verified.", &user);
            Ok(Some(user))
        } else {
            log::debug!("User {:#?} tried to verify but verification failed.", &user);
            Ok(None)
        }
    }

    /// Verify an ongoing session against the database
    pub fn verify_session<'a>(pool: mysql::Pool, user: &'a str, session_id: &str) -> Result<Option<&'a str>, mysql::Error> {
        let mut conn: mysql::PooledConn = pool.get_conn()?; // Obtain a pooled connection to the database
        let stmt = conn.as_mut().prep("SELECT expires FROM sessions WHERE username = ? AND session = ?")?; // Prepare a Select statement to get the expiration date from the session of the provided username and session
        let expires: Option<String> = conn.exec_first(stmt, (user, session_id))?; 
        let timestamp: i64 = match DateTime::parse_from_rfc3339(expires.unwrap_or("".to_string()).as_ref()) { // Parse the expired string into a timestamp
            Ok(val) => val.timestamp(),
            Err(_) => 0,
        };
        let now: i64 = Utc::now().timestamp();

        // Delete expired sessions every now and then
        if (now % 5) == 0 {
            log::debug!("Starting to delete expired sessions");
            delete_expired_sessions(pool)?; // This is not really expected to fail as it should just execute SQL statements which was already done before
            log::debug!("Finished to delete expired sessions");
        }

        // Compare the timestamp from the database with the actual time and return the result
        if timestamp > now {
            log::debug!("User {:#?} was successfully verified.", &user);
            Ok(Some(user))
        } else {
            log::debug!("User {:#?} tried to verify but verification failed.", &user);
            Ok(None)
        }
    }

    /// Deletes all sessions from the database which have expired
    fn delete_expired_sessions(pool: mysql::Pool) -> Result<(), mysql::Error> {
        log::debug!("Fetching all sessions from the databse");
        let mut conn: mysql::PooledConn = pool.get_conn()?;
        let all_sessions: Vec<Vec<String>> = conn.query_map(
            "SELECT session, expires FROM sessions",
            |(session, expires)| {
                vec![session, expires]
            }
        )?;
        
        let now: i64 = Utc::now().timestamp();

        for row in all_sessions.iter() {
            let session = &row[0];
            let expires = &row[1];

            let timestamp: i64 = match DateTime::parse_from_rfc3339(expires) {
                Ok(val) => val.timestamp(),
                Err(_) => 0,
            };

            if now > timestamp {
                log::debug!("Deleting session");
                let stmt = conn.as_mut().prep("DELETE FROM sessions WHERE session = ?")?;
                let _: Vec<String> = conn.exec(stmt, (session,))?;
            }

        }
        Ok(())
    }


}