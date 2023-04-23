/// Does all the juicy web based request handling stuff
pub mod request_handler {
    use actix_files as actx_fs;
    use actix_web::{
        http::header::{ContentDisposition, DispositionType},
        post, web, App, HttpRequest, HttpResponse, HttpServer, Result,
        http::StatusCode, http::header::ContentType,
    };
    use crate::data::data_types::AppState;
    use crate::data::mysql_handler;
    use crate::data::xml_engine;
    use core::ops::Range;
    use chrono::prelude::*;
    use mime;
    use log;
    use std::io::ErrorKind;
    use futures::StreamExt;
    use std::fs;
    use tokio::io::AsyncWriteExt;
    use tokio::fs::File as TokioFile;

    // Constants for some return messages
    const MSG_AUTH_ERROR: &str = "Provided Credentials Invalid or Missing";
    const MSG_INTERNAL_ERROR: &str = "Internal Error";

    /// Verify any Incoming Requests
    /// 
    /// Look for provided headers as authentication and check the values against
    /// the database
    async fn verify_request<'a> (req: &'a HttpRequest, state: &web::Data<AppState>) -> Option<&'a str> {
        log::info!(
            "New request from {:#?}",
            req.connection_info().realip_remote_addr().unwrap_or("unknown")
        );
        log::debug!("Verifying request...");
        let user = match req.headers().get("user") { // Check for the user header
            Some(val) => val.to_str().ok(),
            None => { // Reject if the user header is missing
                log::debug!("Verification failed. No user provided.");
                log::info!(
                    "Rejecting request from {:#?}",
                    req.connection_info().realip_remote_addr().unwrap_or("unknown")
                );
                return None;
            }
        };
        let token = match req.headers().get("token") { // Check for the token header
            Some(val) => val.to_str().ok(),
            None => None
        };
        let session = match req.headers().get("session") { // Check for the session header
            Some(val) => val.to_str().ok(),
            None => None
        };

        if token.is_none() && session.is_none() { // Reject if neither the session nor the token header was provided
            log::debug!("Verification failed. Neither token nor session provided.");
            log::info!("Rejecting request from {:#?}", req.connection_info().realip_remote_addr().unwrap_or("unknown"));
            return None
        } else if token.is_none() && session.is_some() { // Verify the data with the database using the session information when only the session was provided
            log::debug!("Processing verification using session...");
            if let Ok(sql_content) = mysql_handler::verify_session(&state.pool, &user.unwrap_or("."), &session.unwrap_or(".")) {
                log::info!("Request from {:#?} accepted and authenticated as user {:#?}", req.connection_info().realip_remote_addr().unwrap_or("unknown"), &sql_content.unwrap_or("unknown"));
                return sql_content;
            }
        } else { // Verify the data with the database using the token information when a token was provided
            log::debug!("Processing verification using token...");
            if let Ok(sql_content) = mysql_handler::verify_user(&state.pool, &user.unwrap_or("."), &token.unwrap_or(".")) {
                log::info!("Request from {:#?} accepted and authenticated as user {:#?}", req.connection_info().realip_remote_addr().unwrap_or("unknown"), &sql_content.unwrap_or("unknown"));
                return sql_content;
            }
        }

        log::info!("Rejecting request from {:#?}", req.connection_info().realip_remote_addr().unwrap_or("unknown"));
        None
    }

    /// Write the body of a request to a file
    async fn write_body(path: &std::path::PathBuf, mut payload: web::Payload) -> Result<()> {
        let mut tk_file = TokioFile::create(path).await?; // Open the file (Creates the file any previous information will be overwritten)
        while let Some(chunk) = payload.next().await { // Iteratte over chunks of the message body
            let chunk = chunk?; 
            tk_file.write(&chunk).await?; // Write the chunks to the file
        }
        tk_file.flush().await?; // Flush the file (Puts the cursor back to start and ensures everything is written as far as I can recall)
        Ok(())
    }

    /// Builds an Actix HttpResponse representing an xml document with the given content
    /// as context
    fn build_xml_response_from_string(content: String) -> HttpResponse {
        let time: String = Utc::now().to_rfc2822().replace("+0000", "GMT");
        return {
            HttpResponse::build(StatusCode::OK)
                .content_type(ContentType::xml())
                .insert_header(("content-disposition", "attachment"))
                .insert_header(("last-modified", time))
                .body(content)
        }
    }

    /// Gets all elements which due falls into the between range
    fn post_xml_due(state: web::Data<AppState>, user: &str, between: Range<u32>) -> Result<HttpResponse> {
        let mut path: std::path::PathBuf = state.user_files_path.clone();
        path.push(format!("{}.xml", user));

        if let Ok(mut content_part) = xml_engine::filter_by_due(&path, between) {
            if let Ok(response) = xml_engine::generate_partial(&path, &mut content_part) {
                return Ok(build_xml_response_from_string(response))
            }
        }

        return Ok(HttpResponse::InternalServerError().body(MSG_INTERNAL_ERROR))
    }

    /// Endpoint for filtering all elements due tomorrow by matching their due date
    #[post(r"/xml/due/tomorrow")]
    async fn post_xml_due_tomorrow(req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse> {
        if let Some(user) = verify_request(&req, &state).await {
            let date = chrono::Utc::now().date_naive() + chrono::Days::new(1);

            let start_dt: u32 = chrono::NaiveDateTime::new(
                date, chrono::NaiveTime::from_hms_milli_opt(0,0,0,0).unwrap()
            ).timestamp().try_into().unwrap();
            let end_dt: u32 = chrono::NaiveDateTime::new(
                date, chrono::NaiveTime::from_hms_milli_opt(23,59,59,999).unwrap()
            ).timestamp().try_into().unwrap();

            let range: Range<u32> = Range {
                start: start_dt,
                end: end_dt,
            };
            return post_xml_due(state, user, range);
        } else {
            return Ok(HttpResponse::Unauthorized().body(MSG_AUTH_ERROR));
        }
    }

    /// Endpoint for filtering all elements due today by matching their due date
    #[post(r"/xml/due/today")]
    async fn post_xml_due_today(req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse> {
        if let Some(user) = verify_request(&req, &state).await {
            let date = chrono::Utc::now().date_naive();

            let start_dt: u32 = chrono::NaiveDateTime::new(
                date, chrono::NaiveTime::from_hms_milli_opt(0,0,0,0).unwrap()
            ).timestamp().try_into().unwrap();
            let end_dt: u32 = chrono::NaiveDateTime::new(
                date, chrono::NaiveTime::from_hms_milli_opt(23,59,59,999).unwrap()
            ).timestamp().try_into().unwrap();

            let range: Range<u32> = Range {
                start: start_dt,
                end: end_dt,
            };
            return post_xml_due(state, user, range);
        } else {
            return Ok(HttpResponse::Unauthorized().body(MSG_AUTH_ERROR));
        }
    }

    /// Endpoint for filtering all elements due in the past by matching their due date
    #[post(r"/xml/due/over")]
    async fn post_xml_due_over(req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse> {
        if let Some(user) = verify_request(&req, &state).await {
            let date = chrono::Utc::now().date_naive() - chrono::Days::new(1);

            let end_dt: u32 = chrono::NaiveDateTime::new(
                date, chrono::NaiveTime::from_hms_milli_opt(23,59,59,999).unwrap()
            ).timestamp().try_into().unwrap();

            let range: Range<u32> = Range {
                start: 0,
                end: end_dt,
            };
            return post_xml_due(state, user, range);
        } else {
            return Ok(HttpResponse::Unauthorized().body(MSG_AUTH_ERROR));
        }
    }

    /// Endpoint for filtering all elements due in the specified frame by matching their due date
    #[post(r"/xml/due/in/{start}/{end}")]
    async fn post_xml_due_within(req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse> {
        if let Some(user) = verify_request(&req, &state).await {
            let start_dt: u32 = match req.match_info().get("start").unwrap_or(".").parse() {
                Ok(val) => val,
                Err(_) => return Ok(HttpResponse::BadRequest().body("Supplied Start value is invalid"))
            };
            let mut end_dt: u32 = match req.match_info().get("end").unwrap_or(".").parse() {
                Ok(val) => val,
                Err(_) => return Ok(HttpResponse::BadRequest().body("Supplied End value is invalid"))
            };

            if end_dt == 0 {
                end_dt = u32::MAX;
            }
            
            let range: Range<u32> = Range {
                start: start_dt,
                end: end_dt,
            };
            return post_xml_due(state, user, range);
        } else {
            return Ok(HttpResponse::Unauthorized().body(MSG_AUTH_ERROR));
        }
    }

    /// Endpoint for filtering all elements by matching Name and Value of subnodes with the provided Name and Value
    #[post(r"/xml/filter/{name}/{value}")]
    async fn post_xml_filter(req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse> {
        if let Some(user) = verify_request(&req, &state).await {
            let query_name: String = req.match_info().get("name").unwrap_or("").parse().unwrap_or("".to_string());
            let query_value: String = req.match_info().get("value").unwrap_or("").parse().unwrap_or("".to_string());
            if query_name == "" || query_value == "" {
                return Ok(HttpResponse::BadRequest().body("Queried Name and/or Value is/are invalid"));
            } else {
                let mut path: std::path::PathBuf = state.user_files_path.clone();
                path.push(format!("{}.xml", user));

                log::debug!("Got a request to filter the document");

                if let Ok(mut content_part) = xml_engine::filter_subnode(&path, query_name, query_value) {
                    if let Ok(response) = xml_engine::generate_partial(&path, &mut content_part) {
                        return Ok(build_xml_response_from_string(response))
                    }
                }

                return Ok(HttpResponse::InternalServerError().body(MSG_INTERNAL_ERROR))
            }
        } else {
            return Ok(HttpResponse::Unauthorized().body(MSG_AUTH_ERROR));
        }
    }

    /// Endpoint for getting an Element by ID
    #[post(r"/xml/get_by_id/{id}")]
    async fn post_xml_get_by_id(req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse> {
        if let Some(user) = verify_request(&req, &state).await {
            let queried_id: u16 = req.match_info().get("id").unwrap_or("0").parse().unwrap_or(0);
            if queried_id == 0 {
                return Ok(HttpResponse::BadRequest().body("Queried ID is Invalid"))
            } else {
                let mut path: std::path::PathBuf = state.user_files_path.clone();
                path.push(format!("{}.xml", user));

                log::debug!("Got a request to get by id");

                if let Ok(mut content_part) = xml_engine::get_node_by_id(&path, queried_id) {
                    if let Ok(response) = xml_engine::generate_partial(&path, &mut content_part) {
                        return Ok(build_xml_response_from_string(response))
                    } else {
                        return Ok(HttpResponse::InternalServerError().body(MSG_INTERNAL_ERROR))    
                    }
                } else {
                    return Ok(HttpResponse::InternalServerError().body(MSG_INTERNAL_ERROR))
                }
            }
        } else {
            return Ok(HttpResponse::Unauthorized().body(MSG_AUTH_ERROR)); 
        }
    }

    /// Endpoint for fetching the whole document
    #[post(r"/xml/fetch")]
    async fn post_xml_fetch(req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse> {
        if let Some(user) = verify_request(&req, &state).await {        // Verify the request
            let mut path: std::path::PathBuf = state.user_files_path.clone(); // Obtain the user file directory
            path.push(format!("{}.xml", user));                               // Create the whole path to the users document file

            log::debug!("Got a fetch request.");

            match actx_fs::NamedFile::open(path) {  // Open the users file
                Ok(file) => {
                    log::debug!("Successfully returned requested file");

                    // Send the users file
                    let response = file
                        .use_last_modified(true)
                        .set_content_disposition(ContentDisposition {
                            disposition: DispositionType::Attachment,
                            parameters: vec![]
                        }   
                    );
                    Ok(response.into_response(&req))
                },
                Err(err) => { // On Error match the status code a bit and send an empty xml document
                    log::debug!("Failed to fetch requested file");

                    let status: u16 = match err.kind() {
                        ErrorKind::NotFound => 404,
                        ErrorKind::PermissionDenied => 403,
                        _ => 500,
                    };
                    let time = Utc::now().to_rfc2822().replace("+0000", "GMT");
                    Ok(
                        HttpResponse::build(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)) // Unwrap should not need to come in use here but the compiler is happy
                            .content_type(ContentType::xml())
                            .insert_header(("content-disposition", "attachment"))
                            .insert_header(("last-modified", time))
                            .body("<?xml version=\"1.0\" encoding=\"UTF-8\"?><registry version=\"1.0\"></registry>")
                    )
                }

            }
        } else {
            return Ok(HttpResponse::Unauthorized().body(MSG_AUTH_ERROR)); 
        }

    }

    /// Endpoint for uploading new documents
    #[post(r"/xml/update")]
    async fn post_xml_update(payload: web::Payload, req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse> {
        if let Some(user) = verify_request(&req, &state).await {         // Verify the request
            let mut path: std::path::PathBuf = state.user_files_path.clone();  // Obtain the users file directory
            path.push(format!("{}.tmp.xml", user));                            // Create the whole path to a temporary user file
            let mut final_path: std::path::PathBuf = state.user_files_path.clone(); // Create another path to the final user file
            final_path.push(format!("{}.xml", user));

            log::debug!("Got an update request, writing body into temporary file");

            write_body(&path, payload).await?; // Write the path to a temporary file

            let mut response = HttpResponse::Ok().body("Success");
            
            log::debug!("Validating temporary file");
            if let Ok(valid) = xml_engine::validate_xml_payload(&path) { // Validate the xml document lying under the temporary path
                if valid {
                    log::debug!("Submitted File valid! Copying temporary file in final place..."); 
                    fs::copy(&path, &final_path)?; //When the file is valid copy the temporary file to the final location
                } else {
                    log::debug!("Submitted File invalid!");
                    response = HttpResponse::BadRequest().body("Provided XML Document is invalid"); // When the file is invalid return an error
                }
            } else {
                response = HttpResponse::InternalServerError().body(MSG_INTERNAL_ERROR);
            };
            log::debug!("Deleting temporary file");
            fs::remove_file(&path)?; // Finally delete the temporary file
            return Ok(response)
        } else {
            return Ok(HttpResponse::Unauthorized().body(MSG_AUTH_ERROR)); 
        }
    }

    /// Endpoint for just validating documents but not saving them
    #[post(r"/xml/validate")]
    async fn post_xml_validate(payload: web::Payload, req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse> {
        if let Some(user) = verify_request(&req, &state).await {          // Verify the request
            let mut path: std::path::PathBuf = state.user_files_path.clone();   // Obtain users file directory
            path.push(format!("{}.tmp.xml", user));                             // Create the whole path to a temporary user file

            log::debug!("Got a verify request, writing body into temporary file.");

            write_body(&path, payload).await?; // Write the path to a temporary file

            let mut response = HttpResponse::Ok().body("Success");
            
            log::debug!("Validating temporary file");
            if let Ok(valid) = xml_engine::validate_xml_payload(&path) { // Validate the xml document lying under the temporary path and return according status codes
                if valid {
                    log::debug!("File passed validation returning success.");
                } else {
                    log::debug!("File failed validation.");
                    response = HttpResponse::BadRequest().body("Provided XML Document is invalid");
                }
            } else {
                response = HttpResponse::InternalServerError().body(MSG_INTERNAL_ERROR);
            };
            log::debug!("Deleting temporary file");
            fs::remove_file(&path)?; // Delete the temporary file
            return Ok(response)
        } else {
            return Ok(HttpResponse::Unauthorized().body(MSG_AUTH_ERROR)); 
        }
    }

    /// Start point for webserver
    #[actix_web::main]
    pub async fn run(state: AppState) -> std::io::Result<()> {
        let port = state.port; // Use the port from the config
        let workers = state.workers as usize; // Use the count of workers from the config
        HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(state.clone())) // Clone the AppState for each worker
                .app_data(web::PayloadConfig::new(state.max_payload_size as usize).mimetype(mime::TEXT_XML)) // Only accept text/xml bodies // Maybe the Mimetype should not be restricted like that as JSON could also be accepted some day
                .service(post_xml_due_tomorrow)
                .service(post_xml_due_today)
                .service(post_xml_due_over)
                .service(post_xml_due_within)
                .service(post_xml_filter)
                .service(post_xml_get_by_id)
                .service(post_xml_fetch)
                .service(post_xml_update)
                .service(post_xml_validate)
        })
        .workers(workers)
        .bind(("0.0.0.0", port))?
        .run()
        .await
    }
}
