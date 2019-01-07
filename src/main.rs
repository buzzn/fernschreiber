#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use] extern crate rocket;

extern crate multipart;
use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::str;

use rocket::fairing::AdHoc;
use rocket::response::content;
use rocket::data::{self, FromDataSimple};
use rocket::{Request, Data, Outcome, State};
use rocket::http::Status;
use multipart::server::{Multipart};
use rocket::response::status::BadRequest;

mod lib;
use lib::helpers::read_cleaned;
use lib::mscons;
use lib::edifact_mail;

const MESSAGE: &'static str = "⚡ EDIFACT/MSCONS Fernschreiber";

use edifact_mail::SmtpSettings;

struct FernschreiberConfig {
    crypto_directory: String,
    smtp_settings: SmtpSettings
}

#[derive(Debug)]
struct UploadMultipart {
    message: String,
    payload_filename: String,
    payload: Vec<u8>
}

impl FromDataSimple for UploadMultipart {
    type Error = ();

    fn from_data(request: &Request, data: Data) -> data::Outcome<Self, Self::Error> {
        let ct = request.headers().get_one("Content-Type").expect("no content-type");
        let idx = ct.find("boundary=").expect("no boundary");
        let boundary = &ct[(idx + "boundary=".len())..];

        let mut d = Vec::new();
        data.stream_to(&mut d).expect("Unable to read");


        let mut mp = Multipart::with_body(Cursor::new(d), boundary);

        let mut message = None;
        let mut payload = None;
        let mut payload_filename = None;

        mp.foreach_entry(|mut entry| {
            match entry.headers.name.as_str() {
                "message" => {
                    let mut buffer = Vec::new();
                    match entry.data.read_to_end(&mut buffer) {
                        Ok(_size) => {
                            let message_str = String::from_utf8(buffer).expect("message is not a string");
                            message = Some(message_str);
                        },
                        Err(_e) => {
                            panic!("read error")
                        }
                    };
                },
                "payload" => {
                    let mut buffer = Vec::new();
                    match entry.data.read_to_end(&mut buffer) {
                        Ok(_size) => {
                            payload = Some(buffer);
                            payload_filename = entry.headers.filename;
                        },
                        Err(_e) => {
                            panic!("read error")
                        }
                    }
                },
                other => panic!("No known key {}", other),
            }
        }).expect("Unable to iterate");

        let v = UploadMultipart {
            message: message.expect("message not set"),
            payload: payload.expect("file not set"),
            payload_filename: payload_filename.expect("filename not set")
        };

        // End custom

        Outcome::Success(v)
    }
}

#[get("/", format = "text/html")]
fn index() -> content::Html<String> {
    let x = format!("
<html>
<title>{message}</title>
<style>
form {{
  padding: 5px;
}}
</style>
<body>
  <h1>{message}</h1>
  <form method=\"post\" enctype=\"multipart/form-data\">
    <h2>Message</h2>
    <textarea name=\"message\" cols=\"50\" rows=\"7\">
Diese Mail beinhaltet eine EDIFACT-Nachricht im Anhang.
    </textarea>
    <h2>Payload</h2>
    <input name=\"payload\" type=\"file\" accept=\"text/*\">
    <br>
    <br>
    <br>
    <button>Transmit</button>
  </form>
</body>
</html>
    ", message=MESSAGE);
    content::Html(x)
}

#[get("/info", format = "text/html")]
fn info(config: State<FernschreiberConfig>) -> Result<content::Html<String>, Status> {
    let header = format!("
<html>
<title>{message} Info</title>
<body>
  <h1>{message} Info</h1>
    ", message=MESSAGE);
    let footer = format!("
</body>
</html>
");
    let fernschreiber_path = Path::new(&config.crypto_directory);
    let fernschreiber_abs_path_str = match fernschreiber_path.canonicalize() {
        Ok(v) => v.to_str().unwrap().to_owned(),
        Err(_e) => {
            return Err(Status::InternalServerError);
        }
    };

    let mut certdb : HashMap<std::string::String, RecipientCertificate> = HashMap::new();
    if !read_certificates(fernschreiber_path, &mut certdb) {
        return Err(Status::InternalServerError);
    }

    let mut content = header;
    content += &format!("certificate/config path: {cert_path}<br>", cert_path=fernschreiber_abs_path_str);
    content += "<h2>Installed certificates / recipients</h2>";
    content += "
<table>
  <tr>
    <th>Name</th>
    <th>UNB</th>
    <th>CertPath</th>
    <th>Email</th>
  </tr>";
    for (_unb, cert) in certdb {
        let certificate_path = match cert.certificate_path.to_str() {
            Some(v) => v,
            None => "error"
        };
        content += &format!("
<tr>
  <td>{name}</td>
  <td>{unb}</td>
  <td>{certpath}</td>
  <td>{email}</td>
</tr>", name=cert.name, unb=cert.unb_recipient, certpath=certificate_path, email=cert.email_recipient);
    }
    content += "</table>";
    content += &footer;
    Ok(content::Html(content))
}

// FIXME implement application/json result
#[post("/", data= "<data>")]
fn transmit(config: State<FernschreiberConfig>, data: UploadMultipart) -> Result<content::Html<String>, BadRequest<String>> {
    let segments : Vec<std::string::String>;

    match mscons::parse_into_segments(data.payload.as_slice()) {
        Ok(v) => segments = v,
        Err(e) => {
            return Err(BadRequest(Some(e)))
        }
    }

    let mscons_message = match mscons::parse_message(segments) {
        Ok(v) => v,
        Err(e) => {
            return Err(BadRequest(Some(e)))
        }
    };

    let fernschreiber_path = Path::new(&config.crypto_directory);
    let priv_dir_buf = fernschreiber_path.join("priv").to_owned();
    let from_email_file_path = priv_dir_buf.join("email");
    let bcc_email_file_path  = priv_dir_buf.join("bcc");
    let mut certdb : HashMap<std::string::String, RecipientCertificate> = HashMap::new();

    if !read_certificates(fernschreiber_path, &mut certdb) {
        return Err(BadRequest(Some("Could access cert db.".to_owned())));
    }

    if !certdb.contains_key(&mscons_message.unb.interchange_recipient.sender_identification_code) {
        return Err(BadRequest(Some("UNB Receiver not in database.".to_owned())));
    }

    let cert = &certdb[&mscons_message.unb.interchange_recipient.sender_identification_code];

    let from_email = match read_cleaned(&from_email_file_path) {
        Ok(v) => v,
        Err(_) => return Err(BadRequest(Some("Could not read priv/email.".to_owned()))),
    };

    let bcc_mail = match read_cleaned(&bcc_email_file_path) {
        Ok(v) => Some(v),
        Err(_) => None,
    };

    let message = match edifact_mail::build_email_body(&data.message, &data.payload_filename, &data.payload) {
        Ok(b) => b,
        Err(e) => {
            return Err(BadRequest(Some(e)))
        }
    };

    //println!("{:?}", String::from_utf8(message.clone()));

    let signed_message = match edifact_mail::sign_message(&priv_dir_buf, &message) {
        Ok(s) => s,
        Err(e) => {
            return Err(BadRequest(Some(e)))
        }
    };

    //println!("{:?}", String::from_utf8(signed_message.clone()));

    let certificate_path_str = cert.certificate_path.to_str().unwrap();

    let encrypted_message = match edifact_mail::encrypt_message(&signed_message, certificate_path_str) {
        Ok(s) => s,
        Err(e) => {
            return Err(BadRequest(Some(e)))
        }
    };

    //println!("{:?}", String::from_utf8(encrypted_message.clone()));

    let mail_response = match edifact_mail::send_email(&config.smtp_settings,
                                                       encrypted_message,
                                                       &from_email,
                                                       &cert.email_recipient,
                                                       &bcc_mail,
                                                       &data.payload_filename) {
        Ok(_) => "OK".to_owned(),
        Err(e) => {
            e
        }
    };

    let copy_recipient = match bcc_mail {
        Some(v) => v.clone(),
        None => "Not defined. Please create / fill `priv/bcc`".to_owned()
    };

    let response =
        format!("
<html>
  <title>{message}</title>
  <body>
    <h1>{message}</h1>
    <ol>
      <li>Sender: {sender}</li>
      <li>Recipient: {recipient}</li>
      <li>Copy Recipient: {copy_recipient}</li>
      <li>Selected Email: {email}</li>
      <li>Mail Response: {mail_response}</li>
    </ol>
    <a href=\"/\">Back</a>
  </body>
</html>",
                message=MESSAGE,
                email=cert.email_recipient,
                sender=mscons_message.unb.interchange_sender.sender_identification_code,
                copy_recipient=copy_recipient,
                recipient=mscons_message.unb.interchange_recipient.sender_identification_code,
                mail_response=mail_response
        );

    Ok(content::Html(response.to_string()))
}

#[derive(Debug)]
struct RecipientCertificate {
    name: String,
    unb_recipient: String,
    email_recipient: String,
    certificate_path: PathBuf,
}

fn read_certificate(directory: &Path, unb_recipient: &str) -> Result<RecipientCertificate, std::string::String> {
    let config_path = Path::new(&directory).join(unb_recipient);
    let mut cert = RecipientCertificate {
        name: "".to_owned(),
        unb_recipient: "".to_owned(),
        email_recipient: "".to_owned(),
        certificate_path: PathBuf::new()
    };
    if !config_path.exists() {
        return Err("config path not found".to_owned());
    }
    cert.unb_recipient = unb_recipient.to_owned();

    let email_recipient_path = config_path.join("email");
    match read_cleaned(&email_recipient_path) {
        Ok(v) => cert.email_recipient = v,
        Err(e) => return Err(e)
    }
    let name_path = config_path.join("name");
    match read_cleaned(&name_path) {
        Ok(v) => cert.name = v,
        Err(e) => return Err(e)
    }
    cert.certificate_path = config_path.join("cert").canonicalize().unwrap();

    Ok(cert)
}

fn read_certificates(directory: &Path, db: &mut HashMap<std::string::String, RecipientCertificate>) -> bool
{
    if !directory.is_dir() {
        return false;
    }

    let list = std::fs::read_dir(directory).unwrap();

    for l in list {
        let entry = l.unwrap();
        let path = entry.path();
        if path.is_dir() {
          let filename = path.file_name().unwrap();
          let path_as_str = filename.to_str().unwrap();
          let path_as_string = String::from(path_as_str);
          match read_certificate(directory, path_as_str) {
              Ok(v) => {
                  db.insert(path_as_string, v);
                  ()
              },
              Err(_) => {},
          };
        }
    }
    return true
}

fn preflight_check(crypto_directory: &std::string::String) {
    let fernschreiber_path = Path::new(&crypto_directory);
    if !fernschreiber_path.exists() {
        panic!("Please create the directory '{}' or (re)set the env variable FERNSCHREIBER_CODE_DIR", crypto_directory);
    }
    let fernschreiber_certs_path = Path::new(&crypto_directory).join("certs");
    let fernschreiber_priv_path = Path::new(&crypto_directory).join("priv");
    if !fernschreiber_certs_path.exists() {
        panic!("Please create the directory '{}'", fernschreiber_certs_path.to_str().unwrap());
    }
    if !fernschreiber_priv_path.exists() {
        panic!("Please create the directory '{}'", fernschreiber_priv_path.to_str().unwrap());
    }
}

fn main() {

    rocket::ignite()
        .mount("/", routes![index, info, transmit])
        .attach(AdHoc::on_attach("Settings", |rocket| {
            let smtp_user = match rocket.config().get_str("smtp_user") {
                Ok(v) => v.to_string(),
                Err(_) => panic!("smtp_user not set")
            };
            let smtp_password = match rocket.config().get_str("smtp_password") {
                Ok(v) => v.to_string(),
                Err(_) => panic!("smtp_password not set")
            };
            let smtp_host = match rocket.config().get_str("smtp_host") {
                Ok(v) => v.to_string(),
                Err(_) => panic!("smtp_host not set")
            };
            let smtp_server = match rocket.config().get_str("smtp_server") {
                Ok(v) => v.to_string(),
                Err(_) => panic!("smtp_server not set")
            };
            let crypto_directory = match rocket.config().get_str("crypto_directory") {
                Ok(v) => v.to_string(),
                Err(_) => "fernschreiber_codes".to_owned()
            };
            let is_stub = match rocket.config().get_bool("stub") {
                Ok(v) => v,
                Err(_) => false,
            };

            preflight_check(&crypto_directory);

            Ok(rocket.manage(FernschreiberConfig { crypto_directory: crypto_directory.to_owned(),
                                                   smtp_settings: SmtpSettings {
                                                       server : smtp_server,
                                                       user : smtp_user,
                                                       password : smtp_password,
                                                       host : smtp_host,
                                                       stub : is_stub,
                                                   }
            }))
        }))
        .launch();
}
