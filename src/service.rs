use crate::{
    model::{
        AppState, DisableOTPSchema, GenerateOTPSchema, User, UserLoginSchema, UserRegisterSchema,
        VerifyOTPSchema,
    },
    response::{GenericResponse, UserData, UserResponse},
};
use actix_web::{get, post, web, HttpResponse, Responder};
use base32;
use chrono::prelude::*;
use rand::Rng;
use serde_json::json;
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;

#[get("/healthchecker")]
async fn health_checker_handler() -> impl Responder {
    const MESSAGE: &str = "How to  Implement Two-Factor Authentication (2FA) in Rust";

    HttpResponse::Ok().json(json!({"status": "success", "message": MESSAGE}))
}

#[post("/auth/register")]
async fn register_user_handler(
    body: web::Json<UserRegisterSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    let mut vec = data.db.lock().unwrap();

    for user in vec.iter() {
        if user.email == body.email.to_lowercase() {
            let error_response = GenericResponse {
                status: "fail".to_string(),
                message: format!("User with email: {} already exists", user.email),
            };
            return HttpResponse::Conflict().json(error_response);
        }
    }

    let uuid_id = Uuid::new_v4();
    let datetime = Utc::now();

    let user = User {
        id: Some(uuid_id.to_string()),
        email: body.email.to_owned().to_lowercase(),
        name: body.name.to_owned(),
        password: body.password.to_owned(),
        otp_enabled: Some(false),
        otp_verified: Some(false),
        otp_base32: None,
        otp_auth_url: None,
        createdAt: Some(datetime),
        updatedAt: Some(datetime),
    };

    vec.push(user);

    HttpResponse::Ok()
        .json(json!({"status": "success", "message": "Registered successfully, please login"}))
}

#[post("/auth/login")]
async fn login_user_handler(
    body: web::Json<UserLoginSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    let vec = data.db.lock().unwrap();

    let user = vec
        .iter()
        .find(|user| user.email == body.email.to_lowercase());

    if user.is_none() {
        return HttpResponse::BadRequest()
            .json(json!({"status": "fail", "message": "Invalid email or password"}));
    }

    let user = user.unwrap().clone();

    let json_response = UserResponse {
        status: "success".to_string(),
        user: user_to_response(&user),
    };

    HttpResponse::Ok().json(json_response)
}

#[post("/auth/otp/generate")]
async fn generate_otp_handler(
    body: web::Json<GenerateOTPSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    let mut vec = data.db.lock().unwrap();

    let user = vec
        .iter_mut()
        .find(|user| user.id == Some(body.user_id.to_owned()));

    if user.is_none() {
        let json_error = GenericResponse {
            status: "fail".to_string(),
            message: format!("No user with Id: {} found", body.user_id),
        };

        return HttpResponse::NotFound().json(json_error);
    }

    let mut rng = rand::thread_rng();
    let data_byte: [u8; 21] = rng.gen();
    let base32_string = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &data_byte);

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(base32_string).to_bytes().unwrap(),
    )
    .unwrap();

    let otp_base32 = totp.get_secret_base32();
    let email = body.email.to_owned();
    let issuer = "CodevoWeb";
    let otp_auth_url =
        format!("otpauth://totp/{issuer}:{email}?secret={otp_base32}&issuer={issuer}");

    // let otp_auth_url = format!("otpauth://totp/<issuer>:<account_name>?secret=<secret>&issuer=<issuer>");
    let user = user.unwrap();
    user.otp_base32 = Some(otp_base32.to_owned());
    user.otp_auth_url = Some(otp_auth_url.to_owned());

    HttpResponse::Ok()
        .json(json!({"base32":otp_base32.to_owned(), "otpauth_url": otp_auth_url.to_owned()} ))
}

#[post("/auth/otp/verify")]
async fn verify_otp_handler(
    body: web::Json<VerifyOTPSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    let mut vec = data.db.lock().unwrap();

    let user = vec
        .iter_mut()
        .find(|user| user.id == Some(body.user_id.to_owned()));

    if user.is_none() {
        let json_error = GenericResponse {
            status: "fail".to_string(),
            message: format!("No user with Id: {} found", body.user_id),
        };

        return HttpResponse::NotFound().json(json_error);
    }

    let user = user.unwrap();

    let otp_base32 = user.otp_base32.to_owned().unwrap();

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(otp_base32).to_bytes().unwrap(),
    )
    .unwrap();

    let is_valid = totp.check_current(&body.token).unwrap();

    if !is_valid {
        let json_error = GenericResponse {
            status: "fail".to_string(),
            message: "Token is invalid or user doesn't exist".to_string(),
        };

        return HttpResponse::Forbidden().json(json_error);
    }

    user.otp_enabled = Some(true);
    user.otp_verified = Some(true);

    HttpResponse::Ok().json(json!({"otp_verified": true, "user": user_to_response(user)}))
}

#[post("/auth/otp/validate")]
async fn validate_otp_handler(
    body: web::Json<VerifyOTPSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    let vec = data.db.lock().unwrap();

    let user = vec
        .iter()
        .find(|user| user.id == Some(body.user_id.to_owned()));

    if user.is_none() {
        let json_error = GenericResponse {
            status: "fail".to_string(),
            message: format!("No user with Id: {} found", body.user_id),
        };

        return HttpResponse::NotFound().json(json_error);
    }

    let user = user.unwrap();

    if !user.otp_enabled.unwrap() {
        let json_error = GenericResponse {
            status: "fail".to_string(),
            message: "2FA not enabled".to_string(),
        };

        return HttpResponse::Forbidden().json(json_error);
    }

    let otp_base32 = user.otp_base32.to_owned().unwrap();

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(otp_base32).to_bytes().unwrap(),
    )
    .unwrap();

    let is_valid = totp.check_current(&body.token).unwrap();

    if !is_valid {
        return HttpResponse::Forbidden()
            .json(json!({"status": "fail", "message": "Token is invalid or user doesn't exist"}));
    }

    HttpResponse::Ok().json(json!({"otp_valid": true}))
}

#[post("/auth/otp/disable")]
async fn disable_otp_handler(
    body: web::Json<DisableOTPSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    let mut vec = data.db.lock().unwrap();

    let user = vec
        .iter_mut()
        .find(|user| user.id == Some(body.user_id.to_owned()));

    if user.is_none() {
        let json_error = GenericResponse {
            status: "fail".to_string(),
            message: format!("No user with Id: {} found", body.user_id),
        };

        return HttpResponse::NotFound().json(json_error);
    }

    let user = user.unwrap();

    user.otp_enabled = Some(false);
    user.otp_verified = Some(false);
    user.otp_auth_url = None;
    user.otp_base32 = None;

    HttpResponse::Ok().json(json!({"user": user_to_response(user), "otp_disabled": true}))
}

fn user_to_response(user: &User) -> UserData {
    UserData {
        id: user.id.to_owned().unwrap(),
        name: user.name.to_owned(),
        email: user.email.to_owned(),
        otp_auth_url: user.otp_auth_url.to_owned(),
        otp_base32: user.otp_base32.to_owned(),
        otp_enabled: user.otp_enabled.unwrap(),
        otp_verified: user.otp_verified.unwrap(),
        createdAt: user.createdAt.unwrap(),
        updatedAt: user.updatedAt.unwrap(),
    }
}

pub fn config(conf: &mut web::ServiceConfig) {
    let scope = web::scope("/api")
        .service(health_checker_handler)
        .service(register_user_handler)
        .service(login_user_handler)
        .service(generate_otp_handler)
        .service(verify_otp_handler)
        .service(validate_otp_handler)
        .service(disable_otp_handler);

    conf.service(scope);
}
