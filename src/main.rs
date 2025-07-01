use std::{io::{Read, Write}, net::{TcpListener, TcpStream}, thread, env, sync::{Arc, Mutex}, time::SystemTime};
use std::collections::HashMap;

use dotenvy::dotenv;

use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::{Credentials, Mechanism};

use postgres::{Client, NoTls};
use serde_json::{json, Value, from_slice};

use tokio;
use lapin::{
    options::{BasicPublishOptions, QueueDeclareOptions},
    types::FieldTable,
    BasicProperties, Channel, Connection, ConnectionProperties,
};


fn add_follow(db: Arc<Mutex<Client>>, follower_name: &str, following_name: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let mut client = db.lock().unwrap();
    let mut transaction = client.transaction()?;
    let row1 = transaction.query_one("SELECT id FROM \"Users\" WHERE username = $1", &[&follower_name])?;
    let follower_id: i32 = row1.get(0);
    let row2 = transaction.query_one("SELECT id FROM \"Users\" WHERE username = $1", &[&following_name])?;
    let following_id: i32 = row2.get(0);
    let rows_affected = transaction.execute("INSERT INTO public.\"Follows\" (follower_id, following_id) VALUES ($1, $2) ON CONFLICT DO NOTHING", &[&follower_id, &following_id])?;
    transaction.commit()?;
    Ok(rows_affected)
}

fn get_following_list(db: Arc<Mutex<Client>>, username: &str) -> Result<Vec<String>, postgres::Error> {
    let mut client = db.lock().unwrap();
    let user_row = client.query_opt("SELECT id FROM \"Users\" WHERE username = $1", &[&username])?;
    let user_id: i32 = match user_row {
        Some(row) => row.get(0),
        None => return Ok(Vec::new()),
    };
    let rows = client.query(r#"
        SELECT u.username FROM "Follows" f1 JOIN "Users" u ON u.id = f1.following_id
        WHERE f1.follower_id = $1 AND EXISTS (
            SELECT 1 FROM "Follows" f2
            WHERE f2.follower_id = f1.following_id AND f2.following_id = f1.follower_id
        )
    "#, &[&user_id])?;
    let following_list: Vec<String> = rows.iter().map(|row| row.get(0)).collect();
    Ok(following_list)
}

fn get_secure_4digit() -> Result<u16, getrandom::Error> {
    let mut buf = [0u8; 2];
    getrandom::fill(&mut buf)?;
    Ok(1000 + (u16::from_ne_bytes(buf) % 9000))
}

fn send_otp(to_email: &str) -> Result<u16, Box<dyn std::error::Error>> {
    let code = get_secure_4digit()?;
    println!("4-digit secure code: {}", code);
    let smtp_email = env::var("SMTP_EMAIL").expect("SMTP_USER not set");
    let smtp_pass = env::var("SMTP_PASS").expect("SMTP_PASS not set");
    let email = Message::builder()
        .from(smtp_email.parse().unwrap())
        .to(to_email.parse().unwrap())
        .subject("Your Verification Code")
        .body(format!("Your verification code is: {}", code))
        .unwrap();
    let creds = Credentials::new(smtp_email.to_string(), smtp_pass.to_string());
    let mailer = SmtpTransport::relay("smtp.gmail.com")?
        .credentials(creds)
        .authentication(vec![Mechanism::Plain])
        .build();
    mailer.send(&email)?;
    Ok(code)
}

fn insert_user(db: Arc<Mutex<Client>>, username: &str, email: &str, hashed_password: &str) -> Result<u64, postgres::Error> {
    let mut client = db.lock().unwrap();
    client.execute("INSERT INTO public.\"Users\" (username, email, hashed_password) VALUES ($1, $2, $3)", &[&username, &email, &hashed_password])
}

fn insert_pk(db: Arc<Mutex<Client>>, username: &str, map: &HashMap<String, Value>) -> Result<Option<i32>, postgres::Error> {
    let mut client = db.lock().unwrap();
    let user_id: i32 = match client.query_opt("SELECT id FROM \"Users\" WHERE username = $1 LIMIT 1", &[&username])? {
        Some(row) => row.get(0),
        None => return Ok(None),
    };
    let ik_p_str = map.get("IK_p").unwrap().as_str().unwrap();
    let opk_p_str = map.get("OPK_p").unwrap().as_str().unwrap();
    let spk_p_str = map.get("SPK_p").unwrap().as_str().unwrap();
    let spk_sig_str = map.get("SPK_sig").unwrap().as_str().unwrap();
    let upsert_sql = r#"
        INSERT INTO public."PublicKeys" (user_id, "IK_p", "SPK_p", "SPK_sig", "OPK_p") VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (user_id) DO UPDATE SET "IK_p" = EXCLUDED."IK_p", "SPK_p" = EXCLUDED."SPK_p", "SPK_sig" = EXCLUDED."SPK_sig", "OPK_p" = EXCLUDED."OPK_p"
        RETURNING id
    "#;
    let pk_id: i32 = client.query_one(upsert_sql, &[&user_id, &ik_p_str, &spk_p_str, &spk_sig_str, &opk_p_str])?.get(0);
    client.execute("DELETE FROM public.\"OneTimePreKeys\" WHERE pk_id = $1", &[&pk_id])?;
    let opks_array = map.get("OPKs_p").unwrap().as_array().unwrap();
    let opks_to_insert: Vec<String> = opks_array.iter().map(|v| v.as_str().unwrap().to_string()).collect();
    if !opks_to_insert.is_empty() {
        let bulk_insert_sql = r#"INSERT INTO public."OneTimePreKeys" (pk_id, "OPK") SELECT $1, opk_value FROM UNNEST($2::text[]) AS t(opk_value)"#;
        client.execute(bulk_insert_sql, &[&pk_id, &opks_to_insert])?;
    }
    Ok(Some(user_id))
}

fn get_pk(db: Arc<Mutex<Client>>, username: &str) -> Result<Option<HashMap<String, Value>>, Box<dyn std::error::Error>> {
    let mut client = db.lock().unwrap();
    let mut transaction = client.transaction()?;
    let main_keys_sql = r#"SELECT pk.id, pk."IK_p", pk."SPK_p", pk."SPK_sig" FROM "Users" u JOIN "PublicKeys" pk ON u.id = pk.user_id WHERE u.username = $1 LIMIT 1"#;
    
    let (pk_id, ik_p, spk_p, spk_sig): (i32, String, String, String) = match transaction.query_opt(main_keys_sql, &[&username])? {
        Some(row) => (row.get("id"), row.get("IK_p"), row.get("SPK_p"), row.get("SPK_sig")),
        None => return Ok(None),
    };

    let (otk_id, single_opk): (i32, String) = match transaction.query_opt(r#"SELECT id, "OPK" FROM "OneTimePreKeys" WHERE pk_id = $1 LIMIT 1 FOR UPDATE"#, &[&pk_id])? {
        Some(row) => (row.get("id"), row.get("OPK")),
        None => return Err("User is out of One-Time Pre-Keys.".into()),
    };
    
    transaction.execute("DELETE FROM \"OneTimePreKeys\" WHERE id = $1", &[&otk_id])?;
    
    let mut key_map = HashMap::new();
    key_map.insert("IK_p".to_string(), json!(ik_p));
    key_map.insert("SPK_p".to_string(), json!(spk_p));
    key_map.insert("SPK_sig".to_string(), json!(spk_sig));
    key_map.insert("OPK_p".to_string(), json!(single_opk.clone()));
    key_map.insert("OPKs_p".to_string(), json!(vec![single_opk]));
    
    transaction.commit()?;
    
    Ok(Some(key_map))
}

fn update_password_by_email(db: Arc<Mutex<Client>>, email: &str, new_hashed_password: &str) -> Result<u64, postgres::Error> {
    let mut client = db.lock().unwrap();
    client.execute("UPDATE \"Users\" SET hashed_password = $1 WHERE email = $2", &[&new_hashed_password, &email])
}

fn match_username_password(db: Arc<Mutex<Client>>, username: &str, hashed_password: &str) -> Result<bool, postgres::Error> {
    let mut client = db.lock().unwrap();
    match client.query_opt(r#"SELECT hashed_password FROM "Users" WHERE username = $1 LIMIT 1"#, &[&username])? {
        Some(user) => Ok(user.get::<_, &str>("hashed_password") == hashed_password),
        None => Ok(false),
    }
}

fn user_exists(db: Arc<Mutex<Client>>, username: &str, email: &str) -> Result<bool, postgres::Error> {
    let mut client = db.lock().unwrap();
    let rows = client.query("SELECT 1 FROM \"Users\" WHERE username = $1 OR email = $2 LIMIT 1", &[&username, &email])?;
    Ok(!rows.is_empty())
}

fn email_exists(db: Arc<Mutex<Client>>, email: &str) -> Result<bool, postgres::Error> {
    let mut client = db.lock().unwrap();
    let rows = client.query("SELECT 1 FROM \"Users\" WHERE email = $1 LIMIT 1", &[&email])?;
    Ok(!rows.is_empty())
}

fn send_map_text_prefixed(stream: &mut TcpStream, key_map: &HashMap<String, Value>) -> std::io::Result<()> {
    let json_string = serde_json::to_string(key_map).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let header = format!("07success;{:05}", json_string.len());
    let payload = format!("{}{}", header, json_string);
    stream.write_all(payload.as_bytes())?;
    stream.flush()
}

fn handle_client(mut stream: TcpStream, db: Arc<Mutex<Client>>) -> std::io::Result<()> {
    fn read_message(stream: &mut TcpStream, len_bytes: usize) -> std::io::Result<Vec<u8>> {
        let mut len_buf = vec![0u8; len_bytes];
        stream.read_exact(&mut len_buf)?;
        let len_str = std::str::from_utf8(&len_buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let len = len_str.parse::<usize>()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if len == 0 { return Ok(Vec::new()); }
        let mut msg_buf = vec![0u8; len];
        stream.read_exact(&mut msg_buf)?;
        Ok(msg_buf)
    }

    loop {
        let command_payload = match read_message(&mut stream, 2) {
            Ok(payload) => payload,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof || e.kind() == std::io::ErrorKind::ConnectionReset {
                    println!("Client disconnected.");
                } else {
                    println!("Error reading command: {}. Closing connection.", e);
                }
                break;
            }
        };

        if command_payload.is_empty() { continue; }
        let command_str = String::from_utf8(command_payload).unwrap_or_default();
        println!("\nReceived command: {}", command_str);

        match command_str.as_str() {
            "register" => {
                let username_bytes = read_message(&mut stream, 2)?;
                let email_bytes = read_message(&mut stream, 2)?;
                let hashed_pass_bytes = read_message(&mut stream, 2)?;
                let username = std::str::from_utf8(&username_bytes).unwrap();
                let email = std::str::from_utf8(&email_bytes).unwrap();
                let hashed_pass = std::str::from_utf8(&hashed_pass_bytes).unwrap();
                
                if user_exists(Arc::clone(&db), username, email).unwrap_or(true) {
                    stream.write_all(b"05error;32Username or email already exists")?;
                    stream.flush()?;
                    continue;
                }

                let generated_otp = match send_otp(email) {
                    Ok(code) => { stream.write_all(b"07success;10email sent")?; stream.flush()?; code },
                    Err(_) => continue,
                };

                loop {
                    let mut otp_buf = [0u8; 4]; 
                    if stream.read_exact(&mut otp_buf).is_err() { break; }
                    let received_otp = std::str::from_utf8(&otp_buf).unwrap().parse::<u16>().unwrap_or(0);
                    let is_valid = received_otp == generated_otp;
                    
                    if is_valid { 
                        stream.write_all(b"07success;09OTP Valid")?;
                        stream.flush()?;
                        insert_user(Arc::clone(&db), username, email, hashed_pass).ok();

                        let pk_cmd_payload = read_message(&mut stream, 2)?;
                        if std::str::from_utf8(&pk_cmd_payload).unwrap() == "publish public key" {
                            stream.write_all(b"07success;24trying to set public key")?;
                            stream.flush()?;

                            let reg_username_bytes = read_message(&mut stream, 2)?;
                            stream.read_exact(&mut [0u8; 1])?;
                            let key_buf = read_message(&mut stream, 5)?;
                            let reg_username = std::str::from_utf8(&reg_username_bytes).unwrap();
                            let map_result: Result<HashMap<String, Value>, _> = from_slice(&key_buf);
                            
                            let response = match map_result {
                                Ok(map) => match insert_pk(db.clone(), &reg_username, &map) {
                                    Ok(Some(_)) => b"07success;33public key submitted successfully" as &'static [u8],
                                    _ => b"05error;25fail to submit public key" as &'static [u8],
                                },
                                Err(_) => b"05error;17Invalid JSON format" as &'static [u8],
                            };
                            stream.write_all(response)?;
                            stream.flush()?;
                        }
                        break; 
                    } else { 
                        stream.write_all(b"05error;11OTP Invalid")?;
                        stream.flush()?;
                    }
                }
            }
            "login" => {
                let username_bytes = read_message(&mut stream, 2)?;
                let hashed_pass_bytes = read_message(&mut stream, 2)?;
                let username = std::str::from_utf8(&username_bytes).unwrap();
                let hashed_pass = std::str::from_utf8(&hashed_pass_bytes).unwrap();

                let response = match match_username_password(Arc::clone(&db), username, hashed_pass) {
                    Ok(true) => b"07success;16Login successful" as &'static [u8],
                    Ok(false) => b"05error;28Invalid username or password" as &'static [u8],
                    Err(_) => b"05error;14Database error" as &'static [u8],
                };
                stream.write_all(response)?;
                stream.flush()?;
            }
            "reset password" => {
                let email_bytes = read_message(&mut stream, 2)?;
                let email = std::str::from_utf8(&email_bytes).unwrap();

                if !email_exists(Arc::clone(&db), &email).unwrap_or(false) {
                    stream.write_all(b"05error;21Email does not exist!")?;
                    stream.flush()?;
                    continue;
                }
                
                let generated_otp = match send_otp(email) {
                    Ok(code) => { stream.write_all(b"07success;10email sent")?; stream.flush()?; code },
                    Err(_) => continue,
                };
                
                loop {
                    let mut otp_buf = [0u8; 4];
                    if stream.read_exact(&mut otp_buf).is_err() { break; };
                    let received_otp = std::str::from_utf8(&otp_buf).unwrap().parse::<u16>().unwrap_or(0);
                    let is_valid = received_otp == generated_otp;
                    
                    if is_valid {
                        stream.write_all(b"07success;09OTP Valid")?;
                        stream.flush()?;
                        let mut pass_buf = [0u8; 60];
                        stream.read_exact(&mut pass_buf)?;
                        let new_hashed_password = std::str::from_utf8(&pass_buf).unwrap();
                        let response = if update_password_by_email(Arc::clone(&db), email, new_hashed_password).is_ok() {
                            b"07success;17Password updated!" as &'static [u8]
                        } else {
                            b"05error;14Database error" as &'static [u8]
                        };
                        stream.write_all(response)?;
                        stream.flush()?;
                        break;
                    } else {
                        stream.write_all(b"05error;11OTP Invalid")?;
                        stream.flush()?;
                    }
                }
            }
            "publish public key" => {
                stream.write_all(b"07success;24trying to set public key")?;
                stream.flush()?;

                let username_bytes = read_message(&mut stream, 2)?;
                stream.read_exact(&mut [0u8; 1])?;
                let key_buf = read_message(&mut stream, 5)?;
                let username = std::str::from_utf8(&username_bytes).unwrap();
            
                let map_result: Result<HashMap<String, Value>, _> = from_slice(&key_buf);
                let response = match map_result {
                    Ok(map) => match insert_pk(db.clone(), &username, &map) {
                        Ok(Some(_)) => b"07success;33public key submitted successfully" as &'static [u8],
                        _ => b"05error;25fail to submit public key" as &'static [u8],
                    },
                    Err(_) => b"05error;17Invalid JSON format" as &'static [u8],
                };
                stream.write_all(response)?;
                stream.flush()?;
            }
            "get public key" => {
                stream.write_all(b"07success;24trying to get public key")?;
                stream.flush()?;
                let username_bytes = read_message(&mut stream, 2)?;
                let username = std::str::from_utf8(&username_bytes).unwrap();

                match get_pk(db.clone(), username) {
                    Ok(Some(key_map)) => { send_map_text_prefixed(&mut stream, &key_map)?; }
                    Ok(None) => {
                        stream.write_all(b"05error;18Keys not found for user")?;
                        stream.flush()?;
                    },
                    Err(e) => {
                        eprintln!("Error getting PK: {}", e);
                        stream.write_all(b"05error;14Database error")?;
                        stream.flush()?;
                    },
                }
            }
            other_command => {
                if other_command.starts_with("follow user") {
                    let parts: Vec<&str> = other_command.split(';').collect();
                    if parts.len() == 3 {
                        let response = match add_follow(db.clone(), parts[1], parts[2]) {
                            Ok(0) => b"07success;19Already following user" as &'static [u8],
                            Ok(_) => b"07success;15User followed" as &'static [u8],
                            Err(_) => b"05error;22Failed to follow user" as &'static [u8],
                        };
                        stream.write_all(response)?;
                        stream.flush()?;
                    }
                } else if other_command.starts_with("get following") {
                     if let Some(username) = other_command.split(';').nth(1) {
                         match get_following_list(db.clone(), username) {
                            Ok(following) => {
                                let list_str = following.join(";");
                                let response = format!("07success;{}", list_str);
                                stream.write_all(response.as_bytes())?;
                                stream.flush()?;
                            }
                            Err(_) => {
                                stream.write_all(b"05error;29Failed to retrieve list")?;
                                stream.flush()?;
                            }
                        }
                    }
                } else {
                    let response = format!("05error;21Unrecognized command: {}", other_command);
                    stream.write_all(response.as_bytes())?;
                    stream.flush()?;
                }
            }
        }
    }
    Ok(())
}


async fn send_hello_message() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to RabbitMQ
    let conn = Connection::connect("amqp://guest:guest@localhost:5672", ConnectionProperties::default()).await?;

    // Open a channel
    let channel = conn.create_channel().await?;

    // Declare the queue
    declare_queue(&channel).await?;

    // Publish the message
    publish_message(&channel).await?;

    println!("[x] Sent 'Hello Worldcxcsdfsf!'");
    Ok(())
}

async fn declare_queue(channel: &Channel) -> Result<(), lapin::Error> {
    channel
        .queue_declare(
            "hello",
            QueueDeclareOptions::default(),
            FieldTable::default(),
        )
        .await?;
    Ok(())
}

async fn publish_message(channel: &Channel) -> Result<(), lapin::Error> {
    let confirm = channel
        .basic_publish(
            "",
            "hello",
            BasicPublishOptions::default(),
            b"Hello Worldasdad!",
            BasicProperties::default(),
        )
        .await?;

    confirm.await?; // wait for confirmation
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();

    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL not set");
    let client = Client::connect(&db_url, NoTls)?;
    let db = Arc::new(Mutex::new(client));
    
    //Manually create a tokio runtime just for sending message
    {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            if let Err(e) = send_hello_message().await {
                eprintln!("Error sending RabbitMQ message: {}", e);
            }
        });
    }

    let listener = TcpListener::bind("127.0.0.1:1234")?;
    println!("Listening on 127.0.0.1:1234");

    for stream in listener.incoming() {
        let db = Arc::clone(&db);
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(e) = handle_client(stream, db) {
                        println!("Connection error: {}", e);
                    }
                });
            }
            Err(e) => eprintln!("Accept error: {}", e),
        }
    }

    Ok(())
}
