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

    async fn verify_request(req: &HttpRequest, state: &web::Data<AppState>) -> Option<String> {
        let user = match req.headers().get("user") {
            Some(val) => val.to_str().ok(),
            None => {return None;}
        };
        let token = match req.headers().get("token") {
            Some(val) => val.to_str().ok(),
            None => {return None;}
        };

        if let Ok(sql_content) = mysql_handler::verify_user(state.pool.clone(), &user.unwrap_or("."), &token.unwrap_or(".")) {
            return sql_content;
        }
        None
    }

    async fn write_body(path: &std::path::PathBuf, mut payload: web::Payload) -> Result<()> {
        let mut tk_file = TokioFile::create(path).await?;
        while let Some(chunk) = payload.next().await {
            let chunk = chunk?;
            tk_file.write(&chunk).await?;
        }
        tk_file.flush().await?;
        Ok(())
    }

    #[post(r"/v1/xml/fetch")]
    async fn post_xml_fetch(req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse> {
        if let Some(user) = verify_request(&req, &state).await {
            let mut path: std::path::PathBuf = state.user_files_path.clone();
            path.push(format!("{}.xml", user));

            match actx_fs::NamedFile::open(path) {
                Ok(file) => {
                    let response = file
                        .use_last_modified(true)
                        .set_content_disposition(ContentDisposition {
                            disposition: DispositionType::Attachment,
                            parameters: vec![]
                        }   
                    );
                    Ok(response.into_response(&req))
                },
                Err(err) => {
                    let status: u16 = match err.kind() {
                        ErrorKind::NotFound => 404,
                        ErrorKind::PermissionDenied => 403,
                        _ => 500,
                    };
                    let time = Utc::now().to_rfc2822().replace("+0000", "GMT");
                    Ok(
                        HttpResponse::build(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
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

    #[post(r"/v1/xml/update")]
    async fn post_xml_update(payload: web::Payload, req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse> {
        if let Some(user) = verify_request(&req, &state).await {
            let mut path: std::path::PathBuf = state.user_files_path.clone();
            path.push(format!("{}.tmp.xml", user));
            let mut final_path: std::path::PathBuf = state.user_files_path.clone();
            final_path.push(format!("{}.xml", user));

            log::debug!("Got an update request, writing body into temporary file");

            write_body(&path, payload).await?;

            let mut response = HttpResponse::Ok().body("200 - OK");
            
            log::debug!("Validating temporary file");
            if let Ok(valid) = xml_engine::validate_xml_payload(&path).await {
                if valid {
                    log::debug!("Submitted File valid! Copying temporary file in final place...");
                    fs::copy(&path, &final_path)?;
                } else {
                    response = HttpResponse::BadRequest().body("400 - Bad Request");
                }
            } else {
                response = HttpResponse::InternalServerError().body("500 - Internal Server Error");
            };
            log::debug!("Deleting temporary file");
            fs::remove_file(&path)?;
            return Ok(response)
        } else {
            return Ok(HttpResponse::Unauthorized().body("401 - Unauthorized")); 
        }
    }

    #[post(r"/v1/xml/validate")]
    async fn post_xml_validate(payload: web::Payload, req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse> {
        if let Some(user) = verify_request(&req, &state).await {
            let mut path: std::path::PathBuf = state.user_files_path.clone();
            path.push(format!("{}.tmp.xml", user));

            log::debug!("Got a verify request, writing body into temporary file");

            write_body(&path, payload).await?;

            let mut response = HttpResponse::Ok().body("200 - OK");
            
            log::debug!("Validating temporary file");
            if let Ok(valid) = xml_engine::validate_xml_payload(&path).await {
                if valid {
                    log::debug!("File passed validation returning success");
                } else {
                    response = HttpResponse::BadRequest().body("400 - Bad Request");
                }
            } else {
                response = HttpResponse::InternalServerError().body("500 - Internal Server Error");
            };
            log::debug!("Deleting temporary file");
            fs::remove_file(&path)?;
            return Ok(response)
        } else {
            return Ok(HttpResponse::Unauthorized().body("401 - Unauthorized")); 
        }
    }

    #[actix_web::main]
    pub async fn run(state: AppState) -> std::io::Result<()> {
        let port = state.port;
        let workers = state.workers as usize;
        HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(state.clone()))
                .app_data(web::PayloadConfig::new(state.max_payload_size as usize).mimetype(mime::TEXT_XML)) // Maybe the Mimetype should not be restricted like that as JSON could also be accepted some day
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
