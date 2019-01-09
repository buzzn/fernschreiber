pub mod helpers {
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;
    use std;

    pub fn clean_string(value: &str) -> std::string::String {
        value.replace("\n", "").replace("\r", "").trim().to_owned()
    }

    pub fn read_cleaned(path: &Path) -> Result<std::string::String, std::string::String> {
        match File::open(path) {
            Ok(mut f) => {
                let mut tmp = std::string::String::from("");
                match f.read_to_string(&mut tmp) {
                    Ok(_) => {},
                    Err(_) => return Err("Error while reading from String".to_owned())
                };
                Ok(clean_string(tmp.as_str()))
            }
            Err(_) => Err("Error opening file".to_owned()),
        }
    }
}

pub mod edifact_mail {
    extern crate lettre_email;
    extern crate lettre;
    extern crate mime;
    extern crate tempfile;
    extern crate uuid;
    extern crate chrono;
    extern crate native_tls;
    use self::native_tls::TlsConnector;
    use self::lettre_email::EmailBuilder;
    use self::lettre::smtp::authentication::{Credentials, Mechanism};

    use self::lettre::{ClientTlsParameters, ClientSecurity};
    use self::lettre::{EmailAddress, Envelope, SendableEmail, Transport};
    use self::lettre::smtp::client::net::DEFAULT_TLS_PROTOCOLS;

    use self::lettre::smtp::SmtpClient;
    use self::lettre::stub::StubTransport;

    use self::lettre::smtp::ConnectionReuseParameters;
    use self::tempfile::TempDir;
    use self::uuid::Uuid;
    use std;
    use std::str;
    use std::io::Read;
    use std::fs::File;
    use std::path::Path;
    use std::io::Write;
    use std::process::Command;

    use self::chrono::prelude::*;

    #[derive(Debug)]
    pub struct SmtpSettings {
        pub stub: bool,
        pub host: String,
        pub user: String,
        pub password: String,
        pub server: String,
    }

    pub fn send_email(settings: &SmtpSettings, message: Vec<u8>, from_email: &str, to_email: &str, bcc_email: &Option<String>, subject: &str) -> Result<(), std::string::String> {
        let now = Local::now();
        let message_id = Uuid::new_v4();
        let header_message_id = format!("Message-ID: <{}.fernschreiber@{}>\n", message_id, settings.host);
        let header_from = format!("From: {}\n", from_email);
        let header_to = format!("To: {}\n", to_email);
        let header_subject = format!("Subject: {}\n", subject);
        let header_date = format!("Date: {}\n", now.to_rfc2822());

        let mut whole_message = Vec::new();
        whole_message.append(&mut header_from.into_bytes());
        whole_message.append(&mut header_to.into_bytes());
        whole_message.append(&mut header_subject.into_bytes());
        whole_message.append(&mut header_message_id.into_bytes());
        whole_message.append(&mut header_date.into_bytes());
        whole_message.extend_from_slice(&message.as_slice());

        let mut addressees = Vec::new();
        addressees.push(EmailAddress::new(to_email.to_string()).unwrap());
        if bcc_email.is_some() {
            addressees.push(EmailAddress::new(bcc_email.as_ref().unwrap().to_string()).unwrap());
        }

        let semail = SendableEmail::new(
          Envelope::new(
              Some(EmailAddress::new(from_email.to_string()).unwrap()),
              addressees,
          ).unwrap(),
            message_id.to_string(),
            whole_message);

        let mut tls_builder = TlsConnector::builder();
        tls_builder.min_protocol_version(Some(DEFAULT_TLS_PROTOCOLS[0]));
        tls_builder.danger_accept_invalid_certs(true);
        let tls_parameters = ClientTlsParameters::new(
            settings.server.clone(),
            tls_builder.build().unwrap()
        );

        let client = match SmtpClient::new(
            (settings.server.as_ref(), 465), ClientSecurity::Wrapper(tls_parameters)) {
            Ok(m) => m,
            Err(e) => return Err(format!("Could not create mail client. {:?}", e))
        };
        if settings.stub == true {
            let mut mailer = StubTransport::new_positive();
            let result = mailer.send(semail.into());
            if result.is_ok() {
              Ok(())
            } else {
              Err(format!("Could not send email. {:?}", result))
            }
        } else {
            let mut mailer = client.credentials(Credentials::new(settings.user.clone(), settings.password.clone()))
                .smtp_utf8(true).authentication_mechanism(Mechanism::Plain)
                .connection_reuse(ConnectionReuseParameters::ReuseUnlimited).transport();
            let result = mailer.send(semail.into());
            if result.is_ok() {
                Ok(())
            } else {
                Err(format!("Could not send email. {:?}", result))
            }
        }
    }

    pub fn build_email_body(message: &str, payload_filename: &str, payload: &Vec<u8>) -> Result<Vec<u8>, std::string::String> {
        let mut email = EmailBuilder::new().text(message);
        email = match email.attachment(payload.as_ref(), payload_filename, &mime::TEXT_PLAIN) {
            Ok(em) => em,
            Err(_) => return Err("Could not attach payload.".to_owned())
        };

        match email.build_body() {
            Ok(v) => {
                //println!("build_email_body called: {:?}", str::from_utf8(&v));
                Ok(v)
            },
            Err(_) => Err("Could not build email.".to_owned())
        }
    }

    pub fn encrypt_message(message: &Vec<u8>, recipient_cert_path: &str) -> Result<Vec<u8>, std::string::String> {
        let tmp_dir = match TempDir::new() {
            Ok(t) => t,
            Err(_) => return Err("Could not create temp dir".to_owned())
        };
        let tmp_path = tmp_dir.path();
        let file_path = tmp_path.join("signed.txt");
        let file_path_str = file_path.to_str().unwrap();
        let mut tmp_file = match File::create(&file_path) {
            Ok(f) => f,
            Err(_) => return Err("Could not create temp file".to_owned())
        };
        match tmp_file.write_all(message) {
            Ok(_) => {},
            Err(_) => return Err("Could not write to temp file".to_owned())
        };

        let encrypted_path = tmp_dir.path().join("encryped.txt");
        let encrypted_path_str = encrypted_path.to_str().unwrap();

        let mut openssl_command = Command::new("openssl");
        let encrypt_command = openssl_command.arg("cms").arg("-encrypt").arg("-in").arg(&file_path_str).arg("-recip").arg(recipient_cert_path).arg("-keyopt").arg("rsa_padding_mode:oaep").arg("-keyopt").arg("rsa_oaep_md:sha256").arg("-aes-192-cbc").arg("-out").arg(&encrypted_path_str);

        match encrypt_command.status() {
            Ok(status) => {
                if status.success() {
                    match File::open(&encrypted_path) {
                        Ok(mut f) => {
                            let mut buf = Vec::new();
                            match f.read_to_end(&mut buf) {
                                Ok(_) => Ok(buf),
                                Err(_) => Err("Could not read file".to_owned())
                            }
                        }
                        Err(_) => Err("Error opening file".to_owned()),
                    }
                } else {
                    return Err("openssl called failed".to_owned())
                }
            },
            Err(_) => return Err("Could not launch openssl".to_owned())
        }
    }

    pub fn sign_message(priv_dir: &Path, message: &Vec<u8>) -> Result<Vec<u8>, std::string::String> {
        let tmp_dir = match TempDir::new() {
            Ok(t) => t,
            Err(_) => return Err("Could not create temp dir".to_owned())
        };
        let tmp_path = tmp_dir.path();
        let file_path = tmp_path.join("email.txt");
        let file_path_str = file_path.to_str().unwrap();
        let mut tmp_file = match File::create(&file_path) {
            Ok(f) => f,
            Err(_) => return Err("Could not create temp file".to_owned())
        };
        match tmp_file.write_all(message) {
            Ok(_) => {},
            Err(_) => return Err("Could not write to temp file".to_owned())
        };

        let priv_dir_buf = priv_dir.to_owned();

        let private_key_file_path = priv_dir_buf.join("private");
        let public_key_file_path = priv_dir_buf.join("public");
        let private_key_file_path_str = private_key_file_path.to_str().unwrap();
        let public_key_file_path_str = public_key_file_path.to_str().unwrap();

        let signed_path = tmp_dir.path().join("signed.txt");
        let signed_path_str = signed_path.to_str().unwrap();

        let mut openssl_command = Command::new("openssl");
        let sign_command = openssl_command.arg("cms").arg("-sign").arg("-in").arg(&file_path_str).arg("-signer").arg(&public_key_file_path_str).arg("-inkey").arg(private_key_file_path_str).arg("-keyopt").arg("rsa_padding_mode:pss").arg("-md").arg("sha256").arg("-out").arg(&signed_path_str);

        match sign_command.status() {
            Ok(status) => {
                if status.success() {
                    match File::open(&signed_path) {
                        Ok(mut f) => {
                            let mut buf = Vec::new();
                            match f.read_to_end(&mut buf) {
                                Ok(_) => Ok(buf),
                                Err(_) => Err("Could not read file".to_owned())
                            }
                        }
                        Err(_) => Err("Error opening file".to_owned()),
                    }
                } else {
                    return Err("openssl called failed".to_owned())
                }
            },
            Err(_) => return Err("Could not launch openssl".to_owned())
        }
    }
}

pub mod mscons {
    extern crate encoding;
    extern crate chrono;
    use std;
    #[allow(unused_imports)]
    use std::fs::File;
    #[allow(unused_imports)]
    use std::io::Read;
    use std::default::Default;

    use self::encoding::{Encoding, DecoderTrap};
    use self::encoding::all::{ISO_8859_1, ASCII, UTF_8};

    const SEGMENT_DELIMITER: &'static str = "'";
    const DATA_ELEMENT_SEPARATOR: &'static str = "+";
    const COMPONENT_DATA_ELEMENT_SEPARATOR: &'static str = ":";

    const HEADER_SEGMENT_BEGIN: &'static str = "UNB";
    const REDUCED_CHARACTER_SET: &'static str = "UNOA";
    const EXTENDED_CHARACTER_SET: &'static str = "UNOB";
    const LATIN_CHARACTER_SET: &'static str = "UNOC";
    const UTF8_CHARACTER_SET: &'static str = "UNOX";

    #[derive(Debug)]
    pub struct SyntaxIdentifier {
        pub syntax_identifier: String,
        pub syntax_version_number: u8,
        pub service_code_list_directory_version_number: Option<u16>,
        pub character_encoding_coded: Option<u8>,
    }

    impl Default for SyntaxIdentifier {
        fn default() -> SyntaxIdentifier {
            SyntaxIdentifier {
                syntax_identifier: "".to_owned(),
                syntax_version_number: 0,
                service_code_list_directory_version_number: None,
                character_encoding_coded: None,
            }
        }
    }

    #[derive(Debug)]
    pub struct InterchangeParty {
        pub sender_identification_code: String,
        pub partner_identification: Option<String>,
        pub address: Option<String>
    }

    impl Default for InterchangeParty {
        fn default() -> InterchangeParty {
            InterchangeParty {
                sender_identification_code: "".to_owned(),
                partner_identification: None,
                address: None
            }
        }
    }

    #[derive(Debug)]
    pub struct UNB {
        pub syntax_identifier: SyntaxIdentifier,
        pub interchange_sender: InterchangeParty,
        pub interchange_recipient: InterchangeParty,
        // TODO Implement remaining fields :P
        //date_time_of_preparation: DateTime<Utc>,
    }

    impl Default for UNB {
        fn default() -> UNB {
            UNB {
                syntax_identifier: SyntaxIdentifier{ ..Default::default() },
                interchange_sender: InterchangeParty{ ..Default::default() },
                interchange_recipient: InterchangeParty{ ..Default::default() },
            }
        }
    }

    #[derive(Debug)]
    pub struct MSCONS {
        pub unb: UNB,
        // TODO Implement remaining fields :P
    }

    impl Default for MSCONS {
        fn default() -> MSCONS {
            MSCONS {
                unb: UNB { ..Default::default() },
            }
        }
    }

    fn convert_to_string(payload: &[u8]) -> Result<String, String> {
        if payload.len() <= 10 {
            return Err("Message to short".to_string())
        }
        // remove leading and tailing control characters
        let mut front_count = 0;
        let mut back_count = payload.len()-1;
        while payload[front_count] < 0x21 {
            front_count += 1;
        }
        while payload[back_count] < 0x21 {
            back_count -= 1;
        }
        let edifact = &payload[front_count..back_count];

        let mut unb_front = 0;
        for i in 0..edifact.len()-3 {
            if edifact[i] == 'U' as u8 &&
                edifact[i+1] == 'N' as u8 &&
                edifact[i+2] == 'B' as u8
            {
                unb_front = i;
                break;
            }
        }
        // the parser will fail if UNB is not present
        let unb_header = &edifact[unb_front..];

        let result = match std::str::from_utf8(&unb_header[0..3]) {
            Ok(v) => {
                match v {
                    HEADER_SEGMENT_BEGIN => {
                        match unb_header[3] as char {
                            '+' => {
                                match std::str::from_utf8(&unb_header[4..8]) {
                                    Ok(v) => {
                                        match v {
                                          // TODO trap all invalid characters here
                                          REDUCED_CHARACTER_SET => {
                                              Ok(ASCII.decode(edifact, DecoderTrap::Strict))
                                          },
                                          EXTENDED_CHARACTER_SET => {
                                              Ok(ASCII.decode(edifact, DecoderTrap::Strict))
                                          },
                                          LATIN_CHARACTER_SET => {
                                              Ok(ISO_8859_1.decode(edifact, DecoderTrap::Strict))
                                          },
                                          // TODO implement other encodings
                                          UTF8_CHARACTER_SET => {
                                              Ok(UTF_8.decode(edifact, DecoderTrap::Strict))
                                          },
                                          _ => Err("Unsupported encoding".to_string())
                                        }
                                    },
                                    Err(_e) => Err("Unexpected error".to_string())
                                }
                            },
                            ':' => {
                                Ok(ASCII.decode(edifact, DecoderTrap::Strict))
                            },
                            _ => Err("Unexpected character found".to_string())
                        }
                    },
                    _ => Err("Not an EDIFACT message".to_string())
                }
            },
            Err(_e) => Err("Unexpected error".to_string())
        };
        match result {
            Ok(decoded) => {
                match decoded {
                    Ok(decoded) => Ok(decoded.to_string()),
                    Err(_) => Err("Encoding error".to_string())
                }
            }
            Err(x) => Err(x)
        }
    }

    pub fn parse_into_segments(bytes: &[u8]) -> Result<Vec<std::string::String>, std::string::String> {
        match convert_to_string(bytes) {
            Ok(message) => {
                let mut v = Vec::new();
                for segment in message.split(SEGMENT_DELIMITER) {
                    v.push(segment.to_owned());
                }
                Ok(v)
            },
            Err(e) => {
                Err(e)
            }
        }
    }

    pub fn parse_syntax_identifier(syni: &str) -> Result<SyntaxIdentifier, std::string::String> {
        let mut syntax_identifier : SyntaxIdentifier = Default::default();
        for (i, item) in syni.split(COMPONENT_DATA_ELEMENT_SEPARATOR).enumerate() {
            match i {
                0 => syntax_identifier.syntax_identifier = item.to_owned(),
                1 => match item.parse::<u8>() {
                    Ok(v) => syntax_identifier.syntax_version_number = v,
                    Err(_) => return Err("invalid version number: NaN".to_string())
                },
                2 => match item.parse::<u16>() {
                    Ok(v) => syntax_identifier.service_code_list_directory_version_number = Some(v),
                    Err(_) => return Err("invalid service code list directory version number: NaN".to_string())
                },
                4 => match item.parse::<u8>() {
                    Ok(v) => syntax_identifier.character_encoding_coded = Some(v),
                    Err(_) => return Err("invalid character encoding: NaN".to_string())
                },
                _ => return Err("too many elements".to_string())
            }
        }
        return Ok(syntax_identifier)
    }

    pub fn parse_interchange_party(party: &str) -> Result<InterchangeParty, std::string::String> {
        let mut interchange_party : InterchangeParty = Default::default();
        for (i, item) in party.split(COMPONENT_DATA_ELEMENT_SEPARATOR).enumerate() {
            match i {
                0 => interchange_party.sender_identification_code = item.to_owned(),
                1 => interchange_party.partner_identification = Some(item.to_owned()),
                2 => interchange_party.address = Some(item.to_owned()),
                _ => return Err("too many elements".to_string())
            }
        }
        return Ok(interchange_party)
    }

    pub fn parse_unb(segment: &std::string::String) -> Result<UNB, std::string::String> {
        let mut message : UNB = Default::default();

        let elements : Vec<&str> = segment.split(DATA_ELEMENT_SEPARATOR).collect();


        if elements.len() < 6 {
            return Err("invalid UNB".to_string());
        }

        // element 0
        // UNB
        // ignore

        // element 1
        // UNOC:3
        match parse_syntax_identifier(elements[1]) {
            Ok(v) => message.syntax_identifier = v,
            Err(e) => return Err(e)
        }

        // element 2
        // 9910960000001:500
        match parse_interchange_party(elements[2]) {
            Ok(v) => message.interchange_sender = v,
            Err(e) => return Err(e)
        }

        // element 3
        // "9907248000001:500
        match parse_interchange_party(elements[3]) {
            Ok(v) => message.interchange_recipient = v,
            Err(e) => return Err(e)
        }

        return Ok(message)
    }

    #[test]
    fn parses_unb_ok() {
        const UNB_TEST: &'static str = "UNB+UNOC:3+9910960000001:500+9907084000009:500+180808:0312+B7339230S000++TL";

        let result = parse_unb(&UNB_TEST.to_owned());
        assert!(result.is_ok());
        let unb = result.unwrap();
        assert_eq!(unb.syntax_identifier.syntax_identifier, "UNOC");
        assert_eq!(unb.syntax_identifier.syntax_version_number, 3);
        assert_eq!(unb.syntax_identifier.character_encoding_coded, None);
        assert_eq!(unb.syntax_identifier.service_code_list_directory_version_number, None);

        assert_eq!(unb.interchange_sender.sender_identification_code, "9910960000001");
        assert_eq!(unb.interchange_sender.partner_identification, Some("500".to_owned()));
        assert_eq!(unb.interchange_sender.address, None);

        assert_eq!(unb.interchange_recipient.sender_identification_code, "9907084000009");
        assert_eq!(unb.interchange_recipient.partner_identification, Some("500".to_owned()));
        assert_eq!(unb.interchange_recipient.address, None);

    }

    pub fn parse_message(segments: Vec<std::string::String>) -> Result<MSCONS, std::string::String> {
        let mut mscons_message : MSCONS = MSCONS { ..Default::default() };
        for segment in segments {
            if segment.starts_with("UNB") {
                match parse_unb(&segment) {
                    Ok(v) => mscons_message.unb = v,
                    Err(e) => return Err(e)
                }
            }
        }
        return Ok(mscons_message)
    }

    #[test]
    fn parses_segments_ok() {
        let mut f = File::open("./src/example_data/MSCONS_TL_9910960000001_9907084000009_20180808_B7339230S000.txt").expect("file not found");
        let mut contents = Vec::new();
        f.read_to_end(&mut contents).expect("something went wrong reading the file");
        let segments = parse_into_segments(contents.as_slice()).unwrap();
        assert_eq!(segments.len(), 1558);
        let result = parse_message(segments);
        assert!(result.is_ok());
    }

    #[test]
    fn parses_segments_ok_with_UNA() {
        let with_una_str = "UNA:+.? 'UNB+UNOC:3+9910960000001:500+9907399000009:500+180824:1137+0JL7SYX58I0118'UNH+0JL7SYX58M0376+CONTRL:D:3:UN:2.0'";

        let contents = with_una_str.to_owned().into_bytes();
        let segments = parse_into_segments(contents.as_slice()).unwrap();
        assert_eq!(segments.len(), 3);
        let result = parse_message(segments);
        assert!(result.is_ok());
    }
}
