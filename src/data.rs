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
    use std::str;
    use std::fs::File;
    use std::io::{BufReader, SeekFrom, Seek, Read, Take};
    use std::path::PathBuf;

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

    /// Traverses through the registry to find all entries or directories which have a subnode (or even sub-subnode etc.)
    /// with matching name and value. As value '*' can also be used to match any values
    /// Returns two vecs: The first contains the ranges of the nodes, the second one is a vec containing the values of the searched subnodes (order should corresponds
    /// to the one of the first vec)
    fn search_registry_for_subnode(path: &PathBuf, reader: &mut XmlReader<BufReader<File>>, name: &String, value: &String) -> Result<(Vec<Range<usize>>, Vec<String>), quick_xml::Error> {
        let mut buf: Vec<u8> = Vec::new();
        let mut node_state: Vec<String> = Vec::new();
        let mut node_state_pos: Vec<usize> = Vec::new();
        let mut values: Vec<String> = Vec::new();
        let mut ranges: Vec<Range<usize>> = Vec::new();

        let mut found: bool = false;
        let mut saved_value: String = String::new();

        loop {
            match reader.read_event_into(&mut buf)? {
                XmlEvent::Start(e) if e.name().as_ref() == name.as_bytes() => {
                    let mut text = String::new();
                    let mut txt_buf: Vec<u8> = Vec::new();
                    let text_range = reader.read_to_end_into(e.to_end().name(), &mut txt_buf)?;
                    get_partial_document(&path, text_range)?.read_to_string(&mut text)?;

                    if &value == &"*" || &text.trim().to_string().to_lowercase() == &value.to_lowercase() {
                        saved_value = text.trim().to_string();
                        found = true;
                    }
                }
                XmlEvent::Start(e) => if !found && (e.name().as_ref() == b"directory" || e.name().as_ref() == b"entry") {
                    node_state.push(str::from_utf8(e.name().as_ref()).unwrap().to_string());
                    node_state_pos.push(reader.buffer_position());
                }
                XmlEvent::End(e) if !node_state.is_empty() && found && e.name().as_ref() == node_state.last().unwrap().as_bytes() => {
                    values.push(saved_value.clone());
                    ranges.push(Range {start: *node_state_pos.last().unwrap(), end: reader.buffer_position()-1}); // Don't even question

                    saved_value = String::new();
                    found = false;
                    node_state.pop();
                    node_state_pos.pop();
                }
                XmlEvent::End(e) if !node_state.is_empty() && !found  && e.name().as_ref() == node_state.last().unwrap().as_bytes() => {
                    node_state.pop();
                    node_state_pos.pop();
                }
                //XmlEvent::End(e) if e.name().as_ref() == b"directory" => break,
                XmlEvent::End(e) if e.name().as_ref() == b"registry" => break,
                XmlEvent::Eof => break,
                _ => (),
            }
        }

        Ok((ranges, values))
    }

    /// Read through event and directory nodes in the registry to find it's ids.
    /// Calls this function recursively if it finds a directory entry
    fn read_registry_nodes_for_ids(reader: &mut XmlReader<BufReader<File>>) -> Result<Option<Vec<u16>>, quick_xml::Error> {
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
                        if let Some(contained_ids) = read_registry_nodes_for_ids(reader)? {
                            ids.extend(contained_ids);
                        } else {
                            return Ok(None)
                        }
                    } else {
                        return Ok(None)
                    }
                }
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
    fn get_partial_document(path: &PathBuf, range: Range<usize>) -> Result<Take<File>, std::io::Error> {
        let mut f = File::open(path)?;
        f.seek(SeekFrom::Start(range.start.try_into().unwrap()))?;
        let buf = f.take((range.end - range.start).try_into().unwrap());
        Ok(buf)
    }

    /// Takes a range of underlying content of a file and searches before and after
    /// the specified range for xml openings and closings. It then returns a new
    /// modified range. Actually opens the file for this
    fn extend_partial_to_full_node(path: &PathBuf, range: Range<usize>) -> Result<Range<usize>, std::io::Error> {
        let mut f = File::open(path)?;
        
        let mut start: u64 = range.start.try_into().unwrap();
        let mut end: u64 = range.end.try_into().unwrap();

        // Look before the start
        f.seek(SeekFrom::Start(start))?;
        let mut buf: [u8; 1] = b" ".to_owned();
        while &buf != b"<" && buf != [0] {
            start = start - 1;
            f.seek(SeekFrom::Start(start))?;
            f.read(&mut buf)?;
        }

        // Look after the end
        f.seek(SeekFrom::Start(end))?;
        let mut buf: [u8; 1] = b" ".to_owned();
        while &buf != b">" && buf != [0] {
            f.read(&mut buf)?;
            end = f.stream_position()?;
        }

        return Ok(Range {start: start as usize, end: end as usize});
    }

    /// Generates a String object that represents a valid partial document
    /// uses the path to generate meta section automatically and fills in the
    /// content at the partial node
    pub fn generate_partial(path: &PathBuf, content: &mut Vec<Take<File>>) -> Result<String, quick_xml::Error> {
        let mut result = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><part><meta><existing_ids><id>".to_string();
        let ids = collect_all_ids(path)?
            .into_iter()
            .map(|e| e.to_string())
            .collect::<Vec<String>>()
            .join("</id><id>");
        result.push_str(&ids);
        result.push_str("</id></existing_ids></meta><data>");
        content.iter_mut().for_each(|cont: &mut Take<File>| {
            let mut part: String = "".to_string();
            // My plan here was to just pass the error through, as always, but
            // I couldn't do it as I couldn't figure out how to return something
            // from a closure. However, read_to_string only fails in case of
            // invalid encoding in which case other functions should have failed
            // previously so I guess it is not that important. Still if you
            // know how to return through closures fixme pls!
            match cont.read_to_string(&mut part) {
                Ok(_) => {result.push_str(&part)},
                Err(_) => {return}
            };
        });
        result.push_str("</data></part>");

        return Ok(result)
    }

    /// Gets all elements with the highest priority (lowest value)
    pub fn get_highest_priority(path: &PathBuf) -> Result<Vec<Take<File>>, quick_xml::Error> {
        let mut xml_reader = XmlReader::from_file(path)?;
        let mut buf: Vec<u8> = Vec::new();
        loop {
            match xml_reader.read_event_into(&mut buf)? {
                XmlEvent::Start(e) if e.name().as_ref() == b"registry" => {
                    let mut final_take: Vec<Take<File>> = Vec::new();
                    let (f_1, f_2) = search_registry_for_subnode(path, &mut xml_reader, &"priority".to_string(), &"*".to_string())?;
                    if f_1.len() != f_2.len() {
                        break // Todo: Better error handling here
                    }
                    let mut fi_1 = f_1.into_iter();
                    let mut fi_2 = f_2.into_iter();

                    let min_priority: u16 = match fi_2.clone().filter_map(|e| e.parse::<u16>().ok()).min() {
                        Some(val) => val,
                        None => break // Array empty
                    };

                    loop {
                        let this_1 = fi_1.next();
                        let this_2 = fi_2.next();
                        if this_1.is_none() || this_2.is_none() {
                            break
                        }
                        let this_1 = this_1.unwrap();
                        let this_2 = this_2.unwrap();
                        let prio = match this_2.parse::<u16>() {
                            Ok(val) => val,
                            Err(_) => continue,
                        };
                        if prio <= min_priority {
                            final_take.push(
                                get_partial_document(
                                    path, extend_partial_to_full_node(path, this_1)?
                                )?
                            );
                        }
                    }
                    return Ok(final_take)
                }
                XmlEvent::Eof => break,
                _ => (),
            }
        }
        return Ok(Vec::new())
    }

    /// Gets all elements which priority is below the supplied threshold.
    pub fn filter_by_priority(path: &PathBuf, priority_thresh: u16) -> Result<Vec<Take<File>>, quick_xml::Error> {
        let mut xml_reader = XmlReader::from_file(path)?;
        let mut buf: Vec<u8> = Vec::new();
        loop {
            match xml_reader.read_event_into(&mut buf)? {
                XmlEvent::Start(e) if e.name().as_ref() == b"registry" => {
                    let mut final_take: Vec<Take<File>> = Vec::new();
                    let (f_1, f_2) = search_registry_for_subnode(path, &mut xml_reader, &"priority".to_string(), &"*".to_string())?;
                    if f_1.len() != f_2.len() {
                        break // Todo: Better error handling here
                    }
                    let mut fi_1 = f_1.into_iter();
                    let mut fi_2 = f_2.into_iter();

                    loop {
                        let this_1 = fi_1.next();
                        let this_2 = fi_2.next();
                        if this_1.is_none() || this_2.is_none() {
                            break
                        }
                        let this_1 = this_1.unwrap();
                        let this_2 = this_2.unwrap();
                        let prio = match this_2.parse::<u16>() {
                            Ok(val) => val,
                            Err(_) => continue,
                        };
                        if prio <= priority_thresh {
                            final_take.push(
                                get_partial_document(
                                    path, extend_partial_to_full_node(path, this_1)?
                                )?
                            );
                        }
                    }
                    return Ok(final_take)
                }
                XmlEvent::Eof => break,
                _ => (),
            }
        }
        return Ok(Vec::new())
    }

    /// Filters the document using the due node. Only elements with the due
    /// subnode set which value falls in the specified range is returned
    pub fn filter_by_due(path: &PathBuf, in_between: Range<u32>) -> Result<Vec<Take<File>>, quick_xml::Error> {
        let mut xml_reader = XmlReader::from_file(path)?;
        let mut buf: Vec<u8> = Vec::new();
        loop {
            match xml_reader.read_event_into(&mut buf)? {
                XmlEvent::Start(e) if e.name().as_ref() == b"registry" => {
                    let mut final_take: Vec<Take<File>> = Vec::new();
                    let (f_1, f_2) = search_registry_for_subnode(path, &mut xml_reader, &"due".to_string(), &"*".to_string())?;
                    if f_1.len() != f_2.len() {
                        break // Todo: Better error handling here
                    }
                    let mut fi_1 = f_1.into_iter();
                    let mut fi_2 = f_2.into_iter();

                    loop {
                        let this_1 = fi_1.next();
                        let this_2 = fi_2.next();
                        if this_1.is_none() || this_2.is_none() {
                            break
                        }
                        let this_1 = this_1.unwrap();
                        let this_2 = this_2.unwrap();
                        let time = match this_2.parse::<u32>() {
                            Ok(val) => val,
                            Err(_) => continue,
                        };
                        if time > in_between.start && time < in_between.end {
                            final_take.push(
                                get_partial_document(
                                    path, extend_partial_to_full_node(path, this_1)?
                                )?
                            );
                        }
                    }
                    return Ok(final_take)
                }
                XmlEvent::Eof => break,
                _ => (),
            }
        }
        return Ok(Vec::new())
    }

    /// Filters the document for any Entry/Directory Nodes which subnodes (or even sub-subnodes)
    /// match the requested name and value
    pub fn filter_subnode(path: &PathBuf, name: String, value: String) -> Result<Vec<Take<File>>, quick_xml::Error> {
        let mut xml_reader = XmlReader::from_file(path)?;
        let mut buf: Vec<u8> = Vec::new();
        loop {
            match xml_reader.read_event_into(&mut buf)? {
                XmlEvent::Start(e) if e.name().as_ref() == b"registry" => {
                    return Ok(
                        search_registry_for_subnode(path, &mut xml_reader, &name, &value)?.0
                        .into_iter().filter_map(|e| {
                            extend_partial_to_full_node(path, e).ok()
                        }).filter_map(|e| {
                            get_partial_document(path, e).ok()
                        }).collect());
                        
                }
                XmlEvent::Eof => break,
                _ => (),

            }
        }
        return Ok(Vec::new())
    }

    /// Returns any node identified by it's id attribute
    /// Returns a Take of the provided file containig the node with the searched
    /// id or returns None if no such node exists.
    pub fn get_node_by_id(path: &PathBuf, queried_id: u16) -> Result<Vec<Take<File>>, quick_xml::Error> {
        let mut xml_reader = XmlReader::from_file(path)?;
        let mut buf: Vec<u8> = Vec::new();
        loop {
            match xml_reader.read_event_into(&mut buf)? {
                XmlEvent::Start(e) if e.name().as_ref() == b"registry" => {
                    if let Some(ctx) = find_node_by_id(&mut xml_reader, queried_id)? {
                        let extended_ctx = extend_partial_to_full_node(path, ctx)?;
                        return Ok(vec![get_partial_document(path, extended_ctx)?])
                    } else {
                        return Ok(Vec::new());
                    }
                },
                XmlEvent::Eof => break,
                _ => (),
            }
        }
        Ok(Vec::new())
    }

    /// Returns all IDs present in the registry (will return them sorted)
    /// Performs no validation at all!
    pub fn collect_all_ids(path: &PathBuf) -> Result<Vec<u16>, quick_xml::Error> {
        let mut xml_reader = XmlReader::from_file(path)?;
        let mut buf: Vec<u8> = Vec::new();
        let mut ids: Vec<u16> = Vec::new();
        loop {
            match xml_reader.read_event_into(&mut buf)? {
                XmlEvent::Start(e) if e.name().as_ref() == b"registry" => {
                    if let Some(res) = read_registry_nodes_for_ids(&mut xml_reader)? {
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
    pub fn validate_xml_payload(path: &PathBuf) -> Result<bool, quick_xml::Error> {
        let mut registry_found: bool = false;
        let mut xml_reader = XmlReader::from_file(path)?;
        let mut buf: Vec<u8> = Vec::new();
        let mut ids: Vec<u16> = Vec::new();
        loop {
            match xml_reader.read_event_into(&mut buf)? {
                XmlEvent::Start(e) if e.name().as_ref() == b"registry" => {
                    if registry_found {
                        return Ok(false);
                    } else {
                        registry_found = true;
                        if let Some(res) = read_registry_nodes_for_ids(&mut xml_reader)? {
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
                    }
                },
                XmlEvent::Start(e) if e.name().as_ref() == b"part" => {
                    // Traverse through the meta
                },
                XmlEvent::Start(_e) => {},
                XmlEvent::Eof => break, // Stop the iteration when the file ends
                _ => (),
            }
        }
        Ok(registry_found) // There should be only one registry so yeah guess the rest
    }

    #[cfg(test)]
    mod tests {
        use core::ops::Range;
        use crate::data::xml_engine;
        use quick_xml;
        use std::{path::PathBuf, io::Read};
        use std::fs::File;
        use std::io::Take;

        /// Removes double, triple, etc. whitespaces from strings
        fn remove_whitespaces(a: String) -> String {
            a.split_whitespace().filter(|e| !e.is_empty()).collect::<Vec<&str>>().join(" ")
        }

        /// Verifies Due filtering works
        #[test]
        fn test_due_filtering() -> Result<(), quick_xml::Error> {
            let mut result: String = String::new();
            let mut takes = xml_engine::filter_by_due(&PathBuf::from("./tests/documents/valid_2.xml"), Range {start: 1676134850, end: 1676134950})?;
            takes.iter_mut().for_each(|take: &mut Take<File>| {
                let mut part: String = "".to_string();
                match take.read_to_string(&mut part) {
                    Ok(_) => {result.push_str(&part)},
                    Err(_) => {}
                };
            });

            assert_eq!(
                remove_whitespaces(result),
                remove_whitespaces("<entry id=\"12845\">
                    <type>ToDo</type>
                    <name>Element 1</name>
                    <description>Lorem ipsum dolor sit amet</description>
                    <due>1676134900</due>
                    </entry>".to_string()
                )
            );

            let mut result: String = String::new();
            let mut takes = xml_engine::filter_by_due(&PathBuf::from("./tests/documents/valid_2.xml"), Range {start: 1676134750, end: 1676134950})?;
            takes.iter_mut().for_each(|take: &mut Take<File>| {
                let mut part: String = "".to_string();
                match take.read_to_string(&mut part) {
                    Ok(_) => {result.push_str(&part)},
                    Err(_) => {}
                };
            });

            assert_eq!(
                remove_whitespaces(result),
                remove_whitespaces("<entry id=\"12845\">
                    <type>ToDo</type>
                    <name>Element 1</name>
                    <description>Lorem ipsum dolor sit amet</description>
                    <due>1676134900</due>
                    </entry><entry id=\"46233\">
                    <type>ToDo</type>
                    <name>Element 3</name>
                    <description>Lorem ipsum dolor sit amet</description>
                    <due>1676134800</due>
                    </entry>".to_string()
                )
            );

            Ok(())
        }

        /// Verifies that all xml documents are accepted or rejected as they should
        #[test]
        fn test_xml_validation() -> Result<(), quick_xml::Error> {
            assert_eq!(
                xml_engine::validate_xml_payload(&PathBuf::from("./tests/documents/valid_1.xml"))?,
                true
            );
            assert_eq!(
                xml_engine::validate_xml_payload(&PathBuf::from("./tests/documents/valid_2.xml"))?,
                true
            );
            assert_eq!(
                xml_engine::validate_xml_payload(&PathBuf::from("./tests/documents/invalid_1.xml"))?,
                false
            );
            assert_eq!(
                xml_engine::validate_xml_payload(&PathBuf::from("./tests/documents/invalid_2.xml"))?,
                false
            );
            assert_eq!(
                xml_engine::validate_xml_payload(&PathBuf::from("./tests/documents/invalid_3.xml"))?,
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

        /// Verifies that things can be filtered
        #[test]
        fn test_filtering() -> Result <(), quick_xml::Error> {
            let mut result: String = String::new();
            let mut takes = xml_engine::filter_subnode(
                &PathBuf::from("./tests/documents/valid_1.xml"),
                "note".to_string(),
                "pick".to_string()
            )?;
            takes.iter_mut().for_each(|take: &mut Take<File>| {
                let mut part: String = "".to_string();
                match take.read_to_string(&mut part) {
                    Ok(_) => {result.push_str(&part)},
                    Err(_) => {}
                };
            });

            assert_eq!(
                remove_whitespaces(result),
                remove_whitespaces("<entry id=\"12845\">
                    <type>ToDo</type>
                    <name>Element 1</name>
                    <description>Lorem ipsum dolor sit amet</description>
                    <due>1676134800</due>
                    <note>pick</note>
                    </entry><directory id=\"22223\">
                    <info>
                    <note>pick</note>
                    </info>
                    <entry id=\"43363\">
                    <type>ToDo</type>
                    <name>Element 4</name>
                    <description>Lorem ipsum dolor sit amet</description>
                    <due>1676134800</due>
                    </entry>
                    <entry id=\"5\">
                    <type>ToDo</type>
                    <name>Element 4</name>
                    <description>Lorem ipsum dolor sit amet</description>
                    <due>1676134800</due>
                    </entry>
                    </directory>".to_string())
            );

            Ok(())
        }

        /// Verifies that nodes are found by id correctly
        #[test]
        fn test_id_fetching() -> Result<(), quick_xml::Error> {
            let r: Option<String>;
            let mut res: String = String::new();
            let mut take = xml_engine::get_node_by_id(&PathBuf::from("./tests/documents/valid_1.xml"), 0)?;
            if !take.is_empty() {
                take[0].read_to_string(&mut res)?;
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
            let mut take = xml_engine::get_node_by_id(&PathBuf::from("./tests/documents/valid_1.xml"), 5)?;
            if !take.is_empty() {
                take[0].read_to_string(&mut res)?;
                r = Some(remove_whitespaces(res.trim().to_string()));
            } else {
                r = None;
            }
            assert_eq!(
                r,
                Some(remove_whitespaces("<entry id=\"5\">
                    <type>ToDo</type>
                    <name>Element 4</name>
                    <description>Lorem ipsum dolor sit amet</description>
                    <due>1676134800</due>
                </entry>".to_string()))
            );

            let r: Option<String>;
            let mut res: String = String::new();
            let mut take = xml_engine::get_node_by_id(&PathBuf::from("./tests/documents/valid_2.xml"), 22223)?;
            if !take.is_empty() {
                take[0].read_to_string(&mut res)?;
                r = Some(res.trim().to_string());
            } else {
                r = None;
            }
            assert_eq!(
                r,
                Some("<directory id=\"22223\">
        </directory>".to_string())
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
    use crate::utils::util;

    /// Verify a user using a token against the database
    /// Verifies a user by their given username. Either an api token or the user
    /// password may be supplied as secret. When authentication through password
    /// is desired 'use_password' should be true
    /// Returns the user id if authentication was successful or none otherwise.
    pub fn verify_user<'a>(pool: &mysql::Pool, user: &'a str, secret: &str, use_password: bool) -> Result<Option<u64>, mysql::Error> {
        let mut conn: mysql::PooledConn = pool.get_conn()?; // Obtain a pooled connection to the database
        let stmt: mysql::Statement = if use_password {
            conn.as_mut().prep("SELECT password FROM logins WHERE username = ?")?
        } else {
            conn.as_mut().prep("SELECT token FROM logins WHERE username = ?")?
        };
        let res: Option<String> = conn.exec_first(stmt, (user,))?;
        
        let stmt: mysql::Statement = conn.as_mut().prep("SELECT id FROM logins WHERE username = ?")?;
        let user_id: Option<u64> = conn.exec_first(stmt, (user,))?;

        let mut valid: bool = false;
        if let Some(tok) = res {
            valid = bcrypt::verify(secret, tok.as_ref()).unwrap_or(false); // Verify the found token from the database with the provided one using bcrypt
        }
        if valid { // Return the result
            log::debug!("User {:#?} was successfully verified.", &user);
            Ok(user_id)
        } else {
            log::debug!("User {:#?} tried to verify but verification failed.", &user);
            Ok(None)
        }
    }

    /// Verify an ongoing session against the database
    pub fn verify_session<'a>(pool: &mysql::Pool, id: u64, session_id: &str) -> Result<Option<u64>, mysql::Error> {
        let mut conn: mysql::PooledConn = pool.get_conn()?; // Obtain a pooled connection to the database
        let stmt: mysql::Statement = conn.as_mut().prep("SELECT expires FROM sessions WHERE id = ? AND session = ?")?; // Prepare a Select statement to get the expiration date from the session of the provided username and session
        let expires: Option<String> = conn.exec_first(stmt, (id, session_id))?;
        let timestamp: i64 = match DateTime::parse_from_rfc3339(expires.unwrap_or("".to_string()).as_ref()) { // Parse the expired string into a timestamp
            Ok(val) => val.timestamp(),
            Err(_) => {0},
        };
        let now: i64 = Utc::now().timestamp();

        // Delete expired sessions every now and then
        if (now % 5) == 0 {
            println!("Random delete");
            log::debug!("Starting to delete expired sessions");
            delete_expired_sessions(pool)?; // This is not really expected to fail as it should just execute SQL statements which was already done before
            log::debug!("Finished to delete expired sessions");
        }

        // Compare the timestamp from the database with the actual time and return the result
        if timestamp > now {
            log::debug!("User {:#?} was successfully verified.", &id);
            Ok(Some(id))
        } else {
            log::debug!("User {:#?} tried to verify but verification failed.", &id);
            Ok(None)
        }
    }

    /// Starts a new session for the specified user with the initial expiry in
    /// 'seconds' seconds in the future. Returns the generated session id on success
    /// or none if the given user id is invalid.
    pub fn start_session<'a>(pool: &mysql::Pool, id: u64, seconds: u32) -> Result<Option<String>, mysql::Error> {
        let mut conn: mysql::PooledConn = pool.get_conn()?;
        let stmt: mysql::Statement = conn.as_mut().prep("SELECT id FROM logins WHERE username = ?")?;
        if let Some(user_id) = conn.exec_first::<u64, mysql::Statement, (u64,)>(stmt, (id,))? {
            let now: i64 = Utc::now().timestamp();
            let then: i64 = now + seconds as i64;
            let then_formatted: String = match DateTime::from_timestamp(then, 0) {
                Some(val) => val.to_rfc3339(),
                None => DateTime::from_timestamp(now, 0).unwrap().to_rfc3339(),
            };

            let session: String = util::get_random_string(18);

            let stmt: mysql::Statement = conn.as_mut().prep("INSERT INTO sessions (id, session, expires) VALUES (?, ?, ?)")?;
            let result: Option<String> = conn.exec_first(stmt, (user_id, &session, then_formatted))?;
            log::info!("{:?}", result);
            Ok(Some(session))
        } else {
            Ok(None)
        }
    }

    /// "Extends" an ongoing session in the database by the provided amount of seconds
    /// This will only set the 'expires' timestamp to the amount of seconds in the future
    /// This will not alter the 'expires' timestamp if the session lives already longer
    /// than the provided seconds or if the session is expired.
    /// Will return the new EPOCH Timestamp that was set in the database or none if it wasn't modified
    pub fn extend_session<'a>(pool: &mysql::Pool, id: u64, session_id: &str, seconds: u32) -> Result<Option<i64>, mysql::Error> {
        let mut conn: mysql::PooledConn = pool.get_conn()?; // Obtain a pooled connection to the database
        let stmt: mysql::Statement = conn.as_mut().prep("SELECT expires FROM sessions WHERE id = ? AND session = ?")?;
        let expires: Option<String> = conn.exec_first(stmt, (id, session_id))?;
        let timestamp: i64 = match DateTime::parse_from_rfc3339(expires.as_ref().unwrap_or(&"".to_string()).as_ref()) {
            Ok(val) => val.timestamp(),
            Err(_) => {0},
        };
        let now: i64 = Utc::now().timestamp();
        let then: i64 = now + seconds as i64;

        // Delete expired sessions every now and then
        if (now % 5) == 0 {
            log::debug!("Starting to delete expired sessions");
            delete_expired_sessions(pool)?; // This is not really expected to fail as it should just execute SQL statements which was already done before
            log::debug!("Finished to delete expired sessions");
        }
        
        if timestamp > now && timestamp < then {
            let then_formatted: String = match DateTime::from_timestamp(then, 0) {
                Some(val) => val.to_rfc3339(),
                None => expires.unwrap_or("".to_string())
            };
            let stmt: mysql::Statement = conn.as_mut().prep("UPDATE sessions SET expires = ? WHERE id = ? AND session = ?")?;
            let res: Option<String> = conn.exec_first(stmt, (then_formatted, id, session_id))?;
            log::info!("{:?}", res);
            Ok(Some(then))
        } else {
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
            let session: &String = &row[0];
            let expires: &String = &row[1];

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
        use test_log::test;

        /// Function to get an SQL connection directly from config file
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
        fn create_test_session(pool: &mysql::Pool, user: u64, session_id: &str, expired: bool) -> Result<(), mysql::Error> {
            let now: chrono::DateTime<Utc> = Utc::now();
            
            let mut time = now + Days::new(1);
            if expired {
                time = now - Days::new(2);
            }
            
            let mut conn: mysql::PooledConn = pool.get_conn()?;
            let stmt: mysql::Statement = conn.as_mut().prep("INSERT INTO sessions (id, session, expires) VALUES (?, ?, ?)")?;
            let _: Vec<String> = conn.exec(stmt, (user, session_id, time.to_rfc3339()))?;
    
            Ok(())
        }

        /// Delete all test sessions matching the user
        fn delete_all_test_sessions(pool: &mysql::Pool, user: u64) -> Result<(), mysql::Error> {
            let mut conn: mysql::PooledConn = pool.get_conn()?;
            let stmt: mysql::Statement = conn.as_mut().prep("DELETE FROM sessions WHERE id = ?")?;
            let _: Vec<String> = conn.exec(stmt, (user,))?;
    
            Ok(())
        }
    
        /// Verifies a new session can be successfully validated
        #[test]
        fn test_session_validation() -> Result<(), mysql::Error> {
            let user = 5;
            let session_id = "0000_testsession_0000_0";
            let pool = get_sql_pool()?;
            create_test_session(&pool, user, session_id, false)?;

            let res = mysql_handler::verify_session(&pool, user, session_id)?;

            assert_eq!(Some(user), res);

            delete_all_test_sessions(&pool, user)?;

            let res = mysql_handler::verify_session(&pool, user, session_id)?;

            assert_eq!(None, res); // Session should now be invalid

            delete_all_test_sessions(&pool, user)?;

            Ok(())
        }

        /// Verifies that old sessions are being deleted
        #[test]
        fn test_delete_old_session() -> Result<(), mysql::Error> {
            let user = 10;
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
