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
    use chrono::prelude::*;
    use mime;
    use log;
    use std::io::ErrorKind;
    use futures::StreamExt;
    use std::fs;
    use tokio::io::AsyncWriteExt;
    use tokio::fs::File as TokioFile;

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
            if let Ok(sql_content) = mysql_handler::verify_session(state.pool.clone(), &user.unwrap_or("."), &session.unwrap_or(".")) {
                log::info!("Request from {:#?} accepted and authenticated as user {:#?}", req.connection_info().realip_remote_addr().unwrap_or("unknown"), &sql_content.unwrap_or("unknown"));
                return sql_content;
            }
        } else { // Verify the data with the database using the token information when a token was provided
            log::debug!("Processing verification using token...");
            if let Ok(sql_content) = mysql_handler::verify_user(state.pool.clone(), &user.unwrap_or("."), &token.unwrap_or(".")) {
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

    /// Endpoint for fetching the whole document
    #[post(r"/v1/xml/fetch")]
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
            return Ok(HttpResponse::Unauthorized().body("401 - Unauthorized")); 
        }

    }

    /// Endpoint for uploading new documents
    #[post(r"/v1/xml/update")]
    async fn post_xml_update(payload: web::Payload, req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse> {
        if let Some(user) = verify_request(&req, &state).await {         // Verify the request
            let mut path: std::path::PathBuf = state.user_files_path.clone();  // Obtain the users file directory
            path.push(format!("{}.tmp.xml", user));                            // Create the whole path to a temporary user file
            let mut final_path: std::path::PathBuf = state.user_files_path.clone(); // Create another path to the final user file
            final_path.push(format!("{}.xml", user));

            log::debug!("Got an update request, writing body into temporary file");

            write_body(&path, payload).await?; // Write the path to a temporary file

            let mut response = HttpResponse::Ok().body("200 - OK");
            
            log::debug!("Validating temporary file");
            if let Ok(valid) = xml_engine::validate_xml_payload(&path).await { // Validate the xml document lying under the temporary path
                if valid {
                    log::debug!("Submitted File valid! Copying temporary file in final place..."); 
                    fs::copy(&path, &final_path)?; //When the file is valid copy the temporary file to the final location
                } else {
                    log::debug!("Submitted File invalid!");
                    response = HttpResponse::BadRequest().body("400 - Bad Request"); // When the file is invalid return an error
                }
            } else {
                response = HttpResponse::InternalServerError().body("500 - Internal Server Error");
            };
            log::debug!("Deleting temporary file");
            fs::remove_file(&path)?; // Finally delete the temporary file
            return Ok(response)
        } else {
            return Ok(HttpResponse::Unauthorized().body("401 - Unauthorized")); 
        }
    }

    /// Endpoint for just validating documents but not saving them
    #[post(r"/v1/xml/validate")]
    async fn post_xml_validate(payload: web::Payload, req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse> {
        if let Some(user) = verify_request(&req, &state).await {          // Verify the request
            let mut path: std::path::PathBuf = state.user_files_path.clone();   // Obtain users file directory
            path.push(format!("{}.tmp.xml", user));                             // Create the whole path to a temporary user file

            log::debug!("Got a verify request, writing body into temporary file.");

            write_body(&path, payload).await?; // Write the path to a temporary file

            let mut response = HttpResponse::Ok().body("200 - OK");
            
            log::debug!("Validating temporary file");
            if let Ok(valid) = xml_engine::validate_xml_payload(&path).await { // Validate the xml document lying under the temporary path and return according status codes
                if valid {
                    log::debug!("File passed validation returning success.");
                } else {
                    log::debug!("File failed validation.");
                    response = HttpResponse::BadRequest().body("400 - Bad Request");
                }
            } else {
                response = HttpResponse::InternalServerError().body("500 - Internal Server Error");
            };
            log::debug!("Deleting temporary file");
            fs::remove_file(&path)?; // Delete the temporary file
            return Ok(response)
        } else {
            return Ok(HttpResponse::Unauthorized().body("401 - Unauthorized")); 
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
