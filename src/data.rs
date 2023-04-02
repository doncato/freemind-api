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
    use core::ops::Range;
    use quick_xml::events::{Event as XmlEvent, BytesStart};
    use quick_xml::reader::Reader as XmlReader;
    use quick_xml;
    use std::fs::File;
    use std::io::{BufReader, SeekFrom, Seek, Read, Take};

    /// Gets the value of the id attribute of any node
    fn get_id_attribute<'a>(reader: &XmlReader<BufReader<File>>, element: BytesStart<'a>) -> Result<Option<u16>, quick_xml::Error> {
        for attribute in element.attributes() {
            if let Ok(val) = attribute {
                if val.key.local_name().as_ref() == b"id" {
                    let v = val.decode_and_unescape_value(&reader)?.to_string();
                    return match v.parse::<u16>() {
                        Ok(val) => Ok(Some(val)),
                        Err(_) => Ok(None),
                    }
                }
            }
        }
        Ok(None)
    }

    /// Read through event and  nodes in the registry. Calls this function
    /// recursively if it finds a directory entry
    fn read_registry_nodes(reader: &mut XmlReader<BufReader<File>>) -> Result<Option<Vec<u16>>, quick_xml::Error> {
        //let xml_reader = XmlReader::from_reader(reader);
        let mut buf: Vec<u8> = Vec::new();
        let mut ids: Vec<u16> = Vec::new();

        loop { // Iterate over the xml reader
            match reader.read_event_into(&mut buf)? {
                XmlEvent::Start(e) if e.name().as_ref() == b"entry" => {
                    if let Some(id) = get_id_attribute(&reader, e)? {
                        ids.push(id);
                    } else {
                        return Ok(None) // Meaning there was an entry without an id which is illegal
                    }
                }
                XmlEvent::Start(e) if e.name().as_ref() == b"directory" => {
                    if let Some(id) = get_id_attribute(&reader, e)? {
                        ids.push(id);
                        if let Some(contained_ids) = read_registry_nodes(reader)? {
                            ids.extend(contained_ids);
                        } else {
                            return Ok(None)
                        }
                    } else {
                        return Ok(None)
                    }
                }
                XmlEvent::Start(_e) => {}
                XmlEvent::End(e) if e.name().as_ref() == b"directory" => break,
                XmlEvent::End(e) if e.name().as_ref() == b"registry" => break,
                XmlEvent::Eof => break, // Maybe it should return false in this case as when it reaches this point there wasn't an end tag for the registry
                _ => (),
            }

        }
        Ok(Some(ids))
    }

    ///  Reads through the content of a registry to find a node with matching id.
    /// Calls the function recursively to go through directories
    fn find_node_by_id(reader: &mut XmlReader<BufReader<File>>, queried_id: u16) -> Result<Option<Range<usize>>, quick_xml::Error> {
        let mut buf: Vec<u8> = Vec::new();
        loop {
            match reader.read_event_into(&mut buf)? {
                XmlEvent::Start(e) if e.name().as_ref() == b"entry" => {
                    if let Some(id) = get_id_attribute(&reader, e.clone())? {
                        if id == queried_id {
                            let mut small_buf: Vec<u8> = Vec::new();
                            let ctx = reader.read_to_end_into(e.to_end().name(), &mut small_buf)?;
                            return Ok(Some(ctx));
                        }
                    }
                },
                XmlEvent::Start(e) if e.name().as_ref() == b"directory" => {
                    if let Some(id) = get_id_attribute(&reader, e.clone())? {
                        if id == queried_id {
                            let mut small_buf: Vec<u8> = Vec::new();
                            let ctx = reader.read_to_end_into(e.to_end().name(), &mut small_buf)?;
                            return Ok(Some(ctx));
                        }
                    }
                    if let Some(result) = find_node_by_id(reader, queried_id)? {
                        return Ok(Some(result));
                    }
                },
                XmlEvent::Start(_e) => {},
                XmlEvent::End(e) if e.name().as_ref() == b"directory" => break,
                XmlEvent::End(e) if e.name().as_ref() == b"registry" => break,
                XmlEvent::Eof => break,
                _ => (),
            }

        }

        Ok(None)
    }


    /// Gets a specified part of a document located under `path` and returns the
    /// underlying content from start byte to end byte, where start and end are
    /// defined with the range param
    fn get_partial_document(path: &std::path::PathBuf, range: Range<usize>) -> Result<Take<File>, std::io::Error> {
        let mut f = File::open(path)?;
        f.seek(SeekFrom::Start(range.start.try_into().unwrap()))?;
        let buf = f.take((range.end - range.start).try_into().unwrap());
        Ok(buf)
    }

    /// Returns any node identified by it's id attribute
    pub async fn get_node_by_id(path: &std::path::PathBuf, queried_id: u16) -> Result<Option<Take<File>>, quick_xml::Error> {
        let mut xml_reader = XmlReader::from_file(path)?;
        let mut buf: Vec<u8> = Vec::new();
        loop {
            match xml_reader.read_event_into(&mut buf)? {
                XmlEvent::Start(e) if e.name().as_ref() == b"registry" => {
                    if let Some(ctx) = find_node_by_id(&mut xml_reader, queried_id)? {
                        return Ok(Some(get_partial_document(path, ctx)?))
                    } else {
                        return Ok(None);
                    }
                },
                XmlEvent::Start(_e) => {},
                XmlEvent::Eof => break,
                _ => (),
            }
        }
        Ok(None)
    }

    /// Returns all IDs present in the registry (will return them sorted)
    /// Performs no validation at all!
    pub fn collect_all_ids(path: &std::path::PathBuf) -> Result<Vec<u16>, quick_xml::Error> {
        let mut xml_reader = XmlReader::from_file(path)?;
        let mut buf: Vec<u8> = Vec::new();
        let mut ids: Vec<u16> = Vec::new();
        loop {
            match xml_reader.read_event_into(&mut buf)? {
                XmlEvent::Start(e) if e.name().as_ref() == b"registry" => {
                    if let Some(res) = read_registry_nodes(&mut xml_reader)? {
                        ids.extend(res);
                    }
                    ids.sort_unstable(); // unstable is faster and lighter on memory says the documentation
                },
                XmlEvent::Start(_e) => {},
                XmlEvent::Eof => break, // Stop the iteration when the file ends
                _ => (),
            }
        }
        Ok(ids)
    }

    /// Validates any xml document located under *path*
    pub async fn validate_xml_payload(path: &std::path::PathBuf) -> Result<bool, quick_xml::Error> {
        let mut registry_count: u8 = 0;

        let mut xml_reader = XmlReader::from_file(path)?;
        let mut buf: Vec<u8> = Vec::new();
        let mut ids: Vec<u16> = Vec::new();
        loop {
            match xml_reader.read_event_into(&mut buf)? {
                XmlEvent::Start(e) if e.name().as_ref() == b"registry" => {
                    // Traverse through the registry
                    registry_count += 1;
                    if let Some(res) = read_registry_nodes(&mut xml_reader)? {
                        ids.extend(res);
                    } else {
                        return Ok(false)
                    }
                    let length_then = ids.len();
                    ids.sort_unstable(); // unstable is faster and lighter on memory says the documentation
                    ids.dedup();
                    let lenght_now = ids.len();
                    if lenght_now != length_then { // Meaning there were duplicates removed
                        return Ok(false) // Duplicates are not allowed
                    }
                },
                XmlEvent::Start(e) if e.name().as_ref() == b"meta" => {
                    // Traverse through the meta
                },
                XmlEvent::Start(_e) => {},
                XmlEvent::Eof => break, // Stop the iteration when the file ends
                _ => (),
            }
        }
        Ok(registry_count == 1) // There should be only one registry so yeah guess the rest
    }

    #[cfg(test)]
    mod tests {
        use crate::data::xml_engine;
        use quick_xml;
        use std::{path::PathBuf, io::Read};
        use tokio;

        /// Verifies that all xml documents are accepted or rejected as they should
        #[tokio::test]
        async fn test_xml_validation() -> Result<(), quick_xml::Error> {
            assert_eq!(
                xml_engine::validate_xml_payload(&PathBuf::from("./tests/documents/valid_1.xml")).await?,
                true
            );
            assert_eq!(
                xml_engine::validate_xml_payload(&PathBuf::from("./tests/documents/valid_2.xml")).await?,
                true
            );
            assert_eq!(
                xml_engine::validate_xml_payload(&PathBuf::from("./tests/documents/invalid_1.xml")).await?,
                false
            );
            assert_eq!(
                xml_engine::validate_xml_payload(&PathBuf::from("./tests/documents/invalid_2.xml")).await?,
                false
            );
            assert_eq!(
                xml_engine::validate_xml_payload(&PathBuf::from("./tests/documents/invalid_3.xml")).await?,
                false
            );
            Ok(())
        }

        /// Verifies that ids are collected correctly
        #[test]
        fn test_id_collection() -> Result<(), quick_xml::Error> {
            assert_eq!(
                xml_engine::collect_all_ids(&PathBuf::from("./tests/documents/valid_1.xml"))?,
                vec![5, 12845, 22222, 22223, 43362, 43363, 46233]
            );
            assert_eq!(
                xml_engine::collect_all_ids(&PathBuf::from("./tests/documents/valid_2.xml"))?,
                vec![12845, 22222, 22223, 43362, 46233]
            );
            Ok(())
        }

        /// Verifies that nodes are found by id correctly
        #[tokio::test]
        async fn test_id_fetching() -> Result<(), quick_xml::Error> {
            let r: Option<String>;
            let mut res: String = String::new();
            if let Some(mut take) = xml_engine::get_node_by_id(&PathBuf::from("./tests/documents/valid_1.xml"), 0).await? {
                take.read_to_string(&mut res)?;
                r = Some(res.trim().to_string());
            } else {
                r = None;
            }
            assert_eq!(
                r,
                None
            );
            
            let r: Option<String>;
            let mut res: String = String::new();
            if let Some(mut take) = xml_engine::get_node_by_id(&PathBuf::from("./tests/documents/valid_1.xml"), 5).await? {
                take.read_to_string(&mut res)?;
                r = Some(res.trim().to_string());
            } else {
                r = None;
            }
            assert_eq!(
                r,
                Some("<type>ToDo</type>
                <name>Element 4</name>
                <description>Lorem ipsum dolor sit amet</description>
                <due>1676134800</due>".to_string())
            );

            let r: Option<String>;
            let mut res: String = String::new();
            if let Some(mut take) = xml_engine::get_node_by_id(&PathBuf::from("./tests/documents/valid_2.xml"), 22223).await? {
                take.read_to_string(&mut res)?;
                r = Some(res.trim().to_string());
            } else {
                r = None;
            }
            assert_eq!(
                r,
                Some("".to_string())
            );
            Ok(())
        }
    }
}

/// Does all of the wild SQL shit
/// - knows how to talk SQL
/// - knows how to bcrypt
pub mod mysql_handler {
    use bcrypt;
    use chrono::{DateTime, offset::Utc};
    use mysql::prelude::Queryable;
    use mysql;

    /// Verify a user using a token against the database
    pub fn verify_user<'a>(pool: &mysql::Pool, user: &'a str, token: &str) -> Result<Option<&'a str>, mysql::Error> {
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
    pub fn verify_session<'a>(pool: &mysql::Pool, user: &'a str, session_id: &str) -> Result<Option<&'a str>, mysql::Error> {
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
    fn delete_expired_sessions(pool: &mysql::Pool) -> Result<(), mysql::Error> {
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
                let _: Vec<String> = conn.exec(stmt, (session,))?; // Type annotations needed for exec so an unused var is created
            }

        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use chrono::{naive::Days, offset::Utc};
        use crate::data::data_types::AppConfig;
        use crate::mysql_handler;
        use mysql::prelude::Queryable;
        use mysql;

        // Function to get an SQL connection directly from config file
        fn get_sql_pool() -> Result<mysql::Pool, mysql::Error> {
            let config: AppConfig = confy::load_path("./freemind.config").unwrap_or_default();
            let opts = mysql::OptsBuilder::new()
                    .user(Some(&config.database_username))
                    .pass(Some(&config.database_password))
                    .ip_or_hostname(Some(&config.database_host))
                    .db_name(Some(&config.database_database));
            let pool = mysql::Pool::new(opts)?;
            Ok(pool)
        }
    
        /// A function to create a new session for desting which can either be expired already or still valid
        fn create_test_session(pool: &mysql::Pool, user: &str, session_id: &str, expired: bool) -> Result<(), mysql::Error> {
            let now = Utc::now();
            
            let mut time = now + Days::new(1);
            if expired {
                time = now - Days::new(1);
            }
            
            let mut conn: mysql::PooledConn = pool.get_conn()?;
            let stmt = conn.as_mut().prep("INSERT INTO sessions (username, session, expires) VALUES (?, ?, ?)")?;
            let _: Vec<String> = conn.exec(stmt, (user, session_id, time.to_rfc3339()))?;
    
            Ok(())
        }

        /// Delete all test sessions matching the user
        fn delete_all_test_sessions(pool: &mysql::Pool, user: &str) -> Result<(), mysql::Error> {
            let mut conn: mysql::PooledConn = pool.get_conn()?;
            let stmt = conn.as_mut().prep("DELETE FROM sessions WHERE username = ?")?;
            let _: Vec<String> = conn.exec(stmt, (user,))?;
    
            Ok(())
        }
    
        /// Verifies a new session can be successfully validated
        #[test]
        fn test_session_validation() -> Result<(), mysql::Error> {
            let user = "testuser";
            let session_id = "0000_testsession_0000_0";
            let pool = get_sql_pool()?;
            create_test_session(&pool, user, session_id, false)?;

            let res = mysql_handler::verify_session(&pool, user, session_id)?;

            assert_eq!(Some(user), res);

            delete_all_test_sessions(&pool, user)?;

            let res = mysql_handler::verify_session(&pool, user, session_id)?;

            assert_eq!(None, res); // Session should now be invalid

            Ok(())
        }

        /// Verifies that old sessions are being deleted
        #[test]
        fn test_delete_old_session() -> Result<(), mysql::Error> {
            let user = "testuser";
            let expired_session_id = "0000_testsession_0000_1";
            let valid_session_id = "0000_testsession_0000_2";
            let pool = get_sql_pool()?;
            create_test_session(&pool, user, expired_session_id, true)?;
            create_test_session(&pool, user, valid_session_id, false)?;
    
            mysql_handler::delete_expired_sessions(&pool)?;
    
            let res_1 = mysql_handler::verify_session(&pool, user, expired_session_id)?;
            let res_2 = mysql_handler::verify_session(&pool, user, valid_session_id)?;

            assert_eq!(None, res_1);
            assert_eq!(Some(user), res_2);
        
            delete_all_test_sessions(&pool, user)?;

            Ok(())
        }
    }

}
