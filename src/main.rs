use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    env,
    sync::{Arc, Mutex}
};

use dotenvy::dotenv;

use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::{Credentials, Mechanism};

use postgres::{Client, NoTls};

fn get_secure_4digit() -> Result<u16, getrandom::Error> {
    let mut buf = [0u8; 2]; // Only need 2 bytes for u16
    getrandom::fill(&mut buf)?;
    let num = u16::from_ne_bytes(buf);

    // Map it into the 1000–9999 range
    let four_digit = 1000 + (num % 9000);
    Ok(four_digit)
}

fn get_start_end_idx(msg: &[u8], start: usize) -> (usize, usize) {
    let first_digit = msg[start] - 48;
    let second_digit = msg[start + 1] - 48;
    let total_len    = first_digit * 10 + second_digit;

    let start_idx = start + 2; // the first 2 bytes are the length
    let end_idx = start_idx + usize::from(total_len);
    (start_idx, end_idx)
}

fn send_otp(to_email: &str) -> Result<(u16), Box<dyn std::error::Error>> {
    let code = get_secure_4digit().map_err(|e| {
        eprintln!("Failed to generate code: {}", e);
        "OTP generation failed"
    })?;

    println!("4-digit secure code: {}", code);

    let smtp_email = env::var("SMTP_EMAIL").expect("SMTP_USER not set");
    let smtp_pass = env::var("SMTP_PASS").expect("SMTP_PASS not set");

    let email = Message::builder()
        .from(smtp_email.parse().unwrap())
        .to(to_email.parse().unwrap())
        .subject("Hello from Rust!")
        .body(format!("Your verification code is: {}", code))
        .unwrap();

    let creds = Credentials::new(smtp_email.to_string(), smtp_pass.to_string());

    let mailer = SmtpTransport::relay("smtp.gmail.com")
        .unwrap()
        .credentials(creds)
        .authentication(vec![Mechanism::Plain])
        .build();

    mailer.send(&email)?; // uses `?` to propagate the error
    Ok(code)
}

fn handle_otp_verification(
    stream: &mut TcpStream,
    email: &str,
) -> std::io::Result<Option<u16>> {
    match send_otp(email) {
        Ok(code) => {
            println!("Email sent successfully!");
            stream.write_all(b"07success;10email sent")?;
            Ok(Some(code))
        }
        Err(e) => {
            eprintln!("Failed to send email: {}", e);
            stream.write_all(b"05error;17send email failed")?;
            Ok(None)
        }
    }
}

fn read_otp_from_stream(stream: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<Option<u16>> {
    let n = stream.read(buf)?;
    if n == 0 {
        println!("Client closed the connection!");
        return Ok(None);
    }

    let otp_bytes = &buf[0..4];
    let otp_code: u16 = match std::str::from_utf8(otp_bytes) {
        Ok(s) => match s.trim_end_matches(['\r', '\n']).parse() {
            Ok(code) => code,
            Err(e) => {
                eprintln!("OTP is not a valid integer: {e}");
                return Ok(None);
            }
        },
        Err(e) => {
            eprintln!("Invalid UTF-8 in OTP: {e}");
            return Ok(None);
        }
    };

    Ok(Some(otp_code))
}

fn insert_user(
    db: Arc<Mutex<Client>>,
    username: &str,
    email: &str,
    hashed_password: &str
) -> Result<u64, postgres::Error> {
    let mut client = db.lock().unwrap();
    let rows = client.execute(
        "INSERT INTO public.\"Users\" (username, email, hashed_password) VALUES ($1, $2, $3)",
        &[&username, &email, &hashed_password],
    )?;
    Ok(rows)
}


fn update_password_by_email(
    db: Arc<Mutex<Client>>,
    email: &str,
    new_hashed_password: &str,
) -> Result<u64, postgres::Error> {
    let mut client = db.lock().unwrap();

    let result = client.execute(
        "UPDATE \"Users\" SET hashed_password = $1 WHERE email = $2",
        &[&new_hashed_password, &email],
    )?;

    Ok(result) // returns number of rows updated
}

fn respond_to_otp_result(
    stream: &mut TcpStream,
    is_valid: bool,
) -> std::io::Result<()> {
    if is_valid {
        println!("OTP Valid!");
        stream.write_all(b"07success;09OTP Valid")
    } else {
        println!("OTP Invalid!");
        stream.write_all(b"05error;11OTP Invalid")
    }
}

fn match_username_password(
    db: Arc<Mutex<Client>>,
    username: &str,
    hashed_password: &str,
) -> Result<bool, postgres::Error> {
    let mut client = db.lock().unwrap();
    let row = client.query_opt(
        r#"
    SELECT id, username, email, hashed_password
    FROM "Users"
    WHERE username = $1
    LIMIT 1
    "#,
        &[&username]
    )?;
    if let Some(user) = row {
        let stored_hash: &str = user.get("hashed_password");

        if stored_hash == hashed_password {
            Ok(true)
        } else {
            Ok(false)
        }
    } else {
        println!("Invalid username or password");
        Ok(false)
    }
}

fn user_exists(
    db: Arc<Mutex<Client>>,
    username: &str,
    email: &str,
) -> Result<bool, postgres::Error> {
    let mut client = db.lock().unwrap();
    let rows = client.query(
        "SELECT 1 FROM \"Users\" WHERE username = $1 OR email = $2 LIMIT 1",
        &[&username, &email],
    )?;

    Ok(!rows.is_empty())
}

fn email_exists(
    db: Arc<Mutex<Client>>,
    email: &str,
) -> Result<bool, postgres::Error> {
    let mut client = db.lock().unwrap();
    let rows = client.query(
        "SELECT 1 FROM \"Users\" WHERE email = $1 LIMIT 1",
        &[&email],
    )?;

    Ok(!rows.is_empty())
}

fn handle_client(
    mut stream: TcpStream,
    db: Arc<Mutex<Client>>
) -> std::io::Result<()> {
    let mut buf = [0u8; 1024];
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            println!("Client closed the connection!");
            break;
        }

        let (start, end) = get_start_end_idx(&buf, 0);
        let received_str = match std::str::from_utf8(&buf[start..end]) {
            Ok(hashed) => hashed,
            Err(e) => {
                eprintln!("Invalid UTF-8 in hashed password: {}", e);
                continue;
            }
        };
        println!("received: {}", received_str);

        if &buf[start..end] == b"login"
        {
            let n = stream.read(&mut buf)?;
            if n == 0 {
                println!("Client closed the connection!");
                break;
            }

            let (start, end) = get_start_end_idx(&buf, 0);
            let username_bytes = &buf[start..end];

            let username = match std::str::from_utf8(username_bytes) {
                Ok(name) => name,
                Err(e) => {
                    eprintln!("Invalid UTF-8 in username: {}", e);
                    continue;
                }
            };

            // skip ';'
            let hashed_pass_bytes = &buf[end+1..n];
            let hashed_pass = match std::str::from_utf8(hashed_pass_bytes) {
                Ok(hashed) => hashed,
                Err(e) => {
                    eprintln!("Invalid UTF-8 in hashed password: {}", e);
                    continue;
                }
            };

            println!("Username: {}", username);
            println!("Hashed pass: {}", hashed_pass);

            match match_username_password(Arc::clone(&db), username, hashed_pass) {
                Ok(true) => {
                    stream.write_all(b"07success;16Login successful")?;
                    eprintln!("Login successful.");
                },
                Ok(false) => {
                    stream.write_all(b"05error;28Invalid username or password")?;
                    eprintln!("Login failed.");
                    continue;
                },
                Err(e) => {
                    stream.write_all(b"05error;14Database error")?;
                    eprintln!("Database error: {}", e);
                    continue;
                },
            }
        }
        else if &buf[start..end] == b"register" {
            let n = stream.read(&mut buf)?;
            if n == 0 {
                println!("Client closed the connection!");
                break;
            }

            let (start, end) = get_start_end_idx(&buf, 0);
            let username_bytes = &buf[start..end];

            let username = match std::str::from_utf8(username_bytes) {
                Ok(name) => name,
                Err(e) => {
                    eprintln!("Invalid UTF-8 in username: {}", e);
                    continue;
                }
            };

            // +1 for ';'
            let (start, end) = get_start_end_idx(&buf, end + 1);
            let email_bytes = &buf[start..end];

            let email = match std::str::from_utf8(email_bytes) {
                Ok(email) => email,
                Err(e) => {
                    eprintln!("Invalid UTF-8 in username: {}", e);
                    continue;
                }
            };

            // parse hashed password
            // +1 for ';'
            let hashed_password_bytes = &buf[end+1..n];
            let hashed_pass = match std::str::from_utf8(hashed_password_bytes) {
                Ok(hashed_pass) => hashed_pass,
                Err(e) => {
                    eprintln!("Invalid UTF-8 in username: {}", e);
                    continue;
                }
            };

            println!("Username: {}", username);
            println!("Email: {}", email);
            println!("Hashed pass: {}", hashed_pass);

            match user_exists(Arc::clone(&db), username, email) {
                Ok(true) => {
                    stream.write_all(b"05error;32Username or email already exists")?;
                    eprintln!("Username or email already exists.");
                    continue;
                },
                Ok(false) => {
                    // Proceed with registration
                },
                Err(e) => {
                    eprintln!("Database error: {}", e);
                    continue;
                },
            }

            let number = match handle_otp_verification(&mut stream, email)? {
                Some(code) => code,
                None => continue, // email sending failed, skip to next loop iteration
            };
            let username = username.to_string();
            let email = email.to_string();
            let hashed_pass = hashed_pass.to_string();

            // get OTP
            match read_otp_from_stream(&mut stream, &mut buf)? {
                Some(otp_code) => {
                    match respond_to_otp_result(&mut stream, otp_code == number) {
                        Ok(_) => {
                            if otp_code == number {
                                match insert_user(Arc::clone(&db), &username, &email, &hashed_pass) {
                                    Ok(_) => println!("User registered successfully"),
                                    Err(e) => eprintln!("Failed to register user to database: {}", e),
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to respond to OTP result: {}", e);
                            continue;
                        }
                    }
                },
                None => continue,
            }
        }
        else if &buf[start..end] == b"reset password" {
            let n = stream.read(&mut buf)?;
            if n == 0 {
                println!("Client closed the connection!");
                break;
            }

            let (start, end) = get_start_end_idx(&buf, 0);
            let email_bytes = &buf[start..end];
            let email = match std::str::from_utf8(email_bytes) {
                Ok(email) => email,
                Err(e) => {
                    eprintln!("Invalid UTF-8 in email: {}", e);
                    continue;
                }
            };
            
            match email_exists(Arc::clone(&db), &email) {
                Ok(true) => {
                    let number = match handle_otp_verification(&mut stream, email)? {
                        Some(code) => code,
                        None => continue, // email sending failed, skip to next loop iteration
                    };

                    let email = email.to_string(); // clone email early to break the borrow
                    // get OTP
                    match read_otp_from_stream(&mut stream, &mut buf)? {
                        Some(otp_code) => {
                            let is_valid = otp_code == number;
                            respond_to_otp_result(&mut stream, is_valid)?;
                            if is_valid {
                                let n = stream.read(&mut buf)?;
                                if n == 0 {
                                    println!("Client closed the connection!");
                                    break;
                                }

                                // Clone buffer content to prevent borrow conflict
                                let hashed_password = match std::str::from_utf8(&buf[..60]) {
                                    Ok(pw) => pw.to_string(), // clone to end borrow
                                    Err(e) => {
                                        eprintln!("Invalid UTF-8 in password: {}", e);
                                        continue;
                                    }
                                };

                                match update_password_by_email(Arc::clone(&db), &email, &hashed_password) {
                                    Ok(_) => {
                                        println!("Password updated successfully");
                                        stream.write_all(b"07success;17Password updated!")?;
                                    }
                                    Err(e) => {
                                        stream.write_all(b"05error;14Database error")?;
                                        eprintln!("Failed to update password: {}", e);
                                        // Optionally: stream.write_all(b"05error;25Failed to update password")?;
                                    }
                                }
                            }
                        },
                        None => continue,
                    }
                },
                Ok(false) => {
                    stream.write_all(b"05error;21Email does not exist!")?;
                },
                Err(e) => {
                    stream.write_all(b"05error;14Database error")?;
                    eprintln!("Database error: {}", e);
                }
            }
        }
        else {
            println!("Unrecognized Command");
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();

    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL not set");
    let client = Client::connect(&db_url, NoTls)?; // this may fail, so use `?`
    let db = Arc::new(Mutex::new(client));

    let listener = TcpListener::bind("0.0.0.0:1234")?;
    println!("Listening on 0.0.0.0:1234");

    for stream in listener.incoming() {
        let db = Arc::clone(&db);
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(e) = handle_client(stream, db) {
                        eprintln!("Client error: {}", e);
                    }
                });
            }
            Err(e) => eprintln!("Accept error: {}", e),
        }
    }

    Ok(())
}
