pub mod request_handler {
    use crate::data::data_types::AppState;
    use crate::data::mysql_handler;
    use actix_web::{
        post, web, App, HttpRequest, HttpResponse, HttpServer,
        Result,
    };
    use actix_web::http::header::{ContentDisposition, DispositionType};
    use actix_files as actx_fs;


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

    #[post(r"/v1/xml/fetch")]
    async fn post_xml_fetch(req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse> {
        if let Some(user) = verify_request(&req, &state).await {
            let mut path: std::path::PathBuf = state.user_files_path.clone();
            path.push(user);
            let file = actx_fs::NamedFile::open(path)?;

            let response = file
                .use_last_modified(true)
                .set_content_disposition(ContentDisposition {
                    disposition: DispositionType::Attachment,
                    parameters: vec![]
                }
            );
            return Ok(response.into_response(&req));
        } else {
            return Ok(HttpResponse::Unauthorized().body("401 - Unauthorized")); 
        }

    }

    #[post(r"/v1/xml/update")]
    async fn post_xml_update(req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse> {
        if let Some(_user) = verify_request(&req, &state).await {
            return Ok(HttpResponse::Ok().body("200 - OK"));
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
                .service(post_xml_fetch)
        })
        .workers(workers)
        .bind(("0.0.0.0", port))?
        .run()
        .await
    }
}
