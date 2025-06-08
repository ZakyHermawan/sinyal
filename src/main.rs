mod receive;
mod send;

use std::{io::{Read, Write}, net::{TcpListener, TcpStream}, thread, env, sync::{Arc, Mutex}};
use std::collections::HashMap;

use dotenvy::dotenv;

use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::{Credentials, Mechanism};

use postgres::{Client, NoTls};
use serde_json::{json, Value, Error as SerdeError, from_str};

fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>());
}

fn strip_chars(s: &str) -> &str {
    // --- STEP 1: Strip the first two characters ---
    // This is the same safe method we used before.
    let mut chars = s.chars();
    chars.next(); // Consume the first character
    chars.next(); // Consume the second character
    let after_front_stripped = chars.as_str();
    let after_nulls_stripped = after_front_stripped.trim_end_matches('\0');

    // --- STEP 2: Strip the last character from the *result* of Step 1 ---
    // We get an iterator that gives us the byte index of each character.
    let mut char_indices = after_nulls_stripped.char_indices();

    // `last()` finds the byte index of the last character.
    if let Some((index_of_last, _)) = char_indices.last() {
        // If we found a last character, slice the string from its beginning
        // up to the byte index where that last character started.
        &after_nulls_stripped[..index_of_last]
    } else {
        // If `after_front_stripped` was empty, there is no last character.
        // The result is an empty string.
        after_nulls_stripped
    }
}

// This function is correct as-is from the previous step.
fn clean_and_parse_json(raw_str: &str) -> Result<HashMap<String, Value>, SerdeError> {
    let unwrapped_str = raw_str
        .strip_prefix("b'")
        .and_then(|s| s.strip_suffix("'"))
        .unwrap_or(raw_str);

    let cleaned_json = unwrapped_str.replace('\n', "").replace('\r', "");
    let lookup: HashMap<String, Value> = from_str(&cleaned_json)?;
    Ok(lookup)
}

// Corrected version of this function
fn json_to_hashmap(json: &str , keys: Vec<&str>) -> Result<HashMap<String, Value>, SerdeError> {
    // FIX 1: Make `lookup` mutable so we can remove items from it.
    let mut lookup = clean_and_parse_json(json)?;

    let mut map = HashMap::new();
    for key in keys {
        // FIX 2: Use `remove_entry` which is more direct for this task.
        // It efficiently removes the entry and gives us ownership of both the key and value.
        if let Some((k, v)) = lookup.remove_entry(key) {
            map.insert(k, v);
        }
    }

    // FIX 3: Return the `map` we just built, not the original `lookup`.
    Ok(map)
}

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
    println!("{} {}", first_digit, second_digit);
    let total_len    = first_digit * 10 + second_digit;

    let start_idx = start + 2; // the first 2 bytes are the length
    let end_idx = start_idx + usize::from(total_len);
    (start_idx, end_idx)
}

fn get_key_bundle_start_end_idx(msg: &[u8], start: usize) -> (usize, usize) {
    let first_digit = msg[start] - 48;
    let second_digit = msg[start + 1] - 48;
    let third_digit = msg[start + 2] - 48;
    let fourth_digit = msg[start + 3] - 48;
    let fifth_digit = msg[start + 4] - 48;

    let total_len    = (first_digit as usize) * 10000 + (second_digit as usize) * 1000 + (third_digit as usize) * 100 + (fourth_digit as usize) * 10 + (fifth_digit as usize);

    let start_idx = start + 5; // the first 5 bytes are the length
    let end_idx = (start_idx) + usize::from(total_len);
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

// This is the corrected and simplified version of your function.
fn insert_pk(
    db: Arc<Mutex<Client>>,
    username: &str,
    map: &HashMap<String, Value>
) -> Result<Option<i32>, postgres::Error> {
    let mut client = db.lock().unwrap();

    // --- Step 1: Find the User's ID (No changes here) ---
    let user_row_option = client.query_opt(
        "SELECT id FROM \"Users\" WHERE username = $1 LIMIT 1",
        &[&username],
    )?;

    let user_id = match user_row_option {
        Some(row) => {
            let id: i32 = row.get(0);
            println!("User '{}' found with ID: {}", username, id);
            id
        }
        None => {
            println!("User '{}' not found. Aborting operation.", username);
            return Ok(None);
        }
    };


    // --- Step 2: Insert or Update the main public keys (Upsert) ---
    // This is the main modification.
    let ik_p_str = map.get("IK_p").expect("IK_p key must exist").as_str().expect("IK_p value must be a string");
    let opk_p_str = map.get("OPK_p").expect("OPK_p key must exist").as_str().expect("OPK_p value must be a string");
    let spk_p_str = map.get("SPK_p").expect("SPK_p key must exist").as_str().expect("SPK_p value must be a string");
    let spk_sig_str = map.get("SPK_sig").expect("SPK_sig key must exist").as_str().expect("SPK_sig value must be a string");

    // NEW SQL: This query uses `ON CONFLICT` to handle the "replace" logic atomically.
    // - ON CONFLICT(user_id): Specifies that a conflict occurs if we try to insert a duplicate `user_id`.
    // - DO UPDATE SET ...: If a conflict happens, it updates the existing row instead of failing.
    // - EXCLUDED.*: A special keyword that refers to the values from the new row we were trying to insert.
    // - RETURNING id: Always returns the ID of the affected row, whether it was inserted or updated.
    let upsert_sql = r#"
        INSERT INTO public."PublicKeys" (user_id, "IK_p", "SPK_p", "SPK_sig", "OPK_p")
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (user_id) DO UPDATE SET
            "IK_p" = EXCLUDED."IK_p",
            "SPK_p" = EXCLUDED."SPK_p",
            "SPK_sig" = EXCLUDED."SPK_sig",
            "OPK_p" = EXCLUDED."OPK_p"
        RETURNING id
    "#;

    println!("Upserting public keys for user_id: {}", user_id);
    let pk_row = client.query_one(upsert_sql, &[&user_id, &ik_p_str, &spk_p_str, &spk_sig_str, &opk_p_str])?;
    let pk_id: i32 = pk_row.get(0);
    println!("PublicKeys row is present with id: {}", pk_id);


    // --- Step 3: Replace the One-Time Pre-Keys for the given public key set ---
    // NEW SUB-STEP: Before inserting the new one-time keys, delete all old ones associated with this pk_id.
    // This ensures we have a clean replacement.
    println!("Deleting old one-time keys for pk_id: {}", pk_id);
    client.execute("DELETE FROM public.\"OneTimePreKeys\" WHERE pk_id = $1", &[&pk_id])?;

    // Now, bulk-insert the new one-time keys.
    let opks_array = map.get("OPKs_p").expect("Key 'OPKs_p' should exist").as_array().expect("'OPKs_p' should be an array");

    let opks_to_insert: Vec<String> = opks_array
        .iter()
        .map(|v| v.as_str().expect("All OPKs must be strings").to_string())
        .collect();

    if opks_to_insert.is_empty() {
        println!("No new one-time keys to insert.");
    } else {
        let bulk_insert_sql = r#"
            INSERT INTO public."OneTimePreKeys" (pk_id, "OPK")
            SELECT $1, opk_value
            FROM UNNEST($2::text[]) AS t(opk_value)
        "#;

        let rows_affected = client.execute(bulk_insert_sql, &[&pk_id, &opks_to_insert])?;
        println!("Successfully bulk-inserted {} new one-time keys.", rows_affected);
    }

    Ok(Some(user_id))
}

fn get_pk(
    db: Arc<Mutex<Client>>,
    username: &str,
) -> Result<Option<HashMap<String, Value>>, postgres::Error> {
    let mut client = db.lock().unwrap();

    // --- Step 1: Find the user and their main public keys in a single query ---
    // We JOIN Users and PublicKeys to be more efficient.
    let main_keys_sql = r#"
        SELECT
            pk.id,
            pk."IK_p",
            pk."SPK_p",
            pk."SPK_sig",
            pk."OPK_p"
        FROM "Users" u
        JOIN "PublicKeys" pk ON u.id = pk.user_id
        WHERE u.username = $1
        LIMIT 1
    "#;

    let main_key_row_option = client.query_opt(main_keys_sql, &[&username])?;

    // Use a match to handle the case where the user or their main keys don't exist.
    let (pk_id, ik_p, spk_p, spk_sig, opk_p) = match main_key_row_option {
        Some(row) => {
            // If a row is found, extract all the values.
            let pk_id: i32 = row.get("id");
            let ik_p: String = row.get("IK_p");
            let spk_p: String = row.get("SPK_p");
            let spk_sig: String = row.get("SPK_sig");
            let opk_p: String = row.get("OPK_p");
            println!("Found main keys for user '{}' with pk_id: {}", username, pk_id);
            (pk_id, ik_p, spk_p, spk_sig, opk_p)
        }
        None => {
            println!("No public keys found for user '{}'.", username);
            return Ok(None); // User or their main keys don't exist.
        }
    };


    // --- Step 2: Fetch all associated one-time pre-keys ---
    let otks_sql = r#"SELECT "OPK" FROM "OneTimePreKeys" WHERE pk_id = $1"#;
    let otks_rows = client.query(otks_sql, &[&pk_id])?;

    // Convert the rows of one-time keys into a Vec<String>.
    let one_time_keys: Vec<String> = otks_rows
        .iter()
        .map(|row| row.get("OPK"))
        .collect();
    println!("Found {} one-time keys.", one_time_keys.len());


    // --- Step 3: Construct the final HashMap ---
    let mut key_map = HashMap::new();
    key_map.insert("IK_p".to_string(), json!(ik_p));
    key_map.insert("OPK_p".to_string(), json!(opk_p));
    key_map.insert("SPK_p".to_string(), json!(spk_p));
    key_map.insert("SPK_sig".to_string(), json!(spk_sig));
    key_map.insert("OPKs_p".to_string(), json!(one_time_keys)); // Note: OPKs_p is plural

    Ok(Some(key_map))
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

fn send_map_text_prefixed(
    stream: &mut TcpStream,
    key_map: &HashMap<String, Value>
) -> std::io::Result<()> {
    // 1. Serialize the map to a JSON String.
    let json_string = serde_json::to_string(key_map)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    let json_len = json_string.len();

    // 2. Create the fixed-size 5-digit header.
    // This will panic if the JSON string is larger than 99999 bytes.
    // In a real app, you would handle this with an error.
    if json_len > 99999 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Message size exceeds 9999 bytes, cannot create 5-digit header."
        ));
    }
    let header = format!("07success;{:05}", json_len); // e.g., 123 becomes "00123"

    // 3. Create the final payload by concatenating the header and JSON.
    let payload = format!("{}{}", header, json_string);

    // 4. Write the entire payload to the stream.
    stream.write_all(payload.as_bytes())?;
    stream.flush()?;

    println!("[Rust Sender] Sent payload: {}...", &payload[..30]);
    Ok(())
}
use std::process;

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
        else if &buf[start..end] == b"publish public key" {
            stream.write_all(b"07success;24trying to set public key")?;
            let mut buf = [0u8; 1024 * 100];

            let n = stream.read(&mut buf)?;
            if n == 0 {
                println!("Client closed the connection!");
                break;
            }
            println!("buf: {}", String::from_utf8_lossy(&buf[..n]));
            let (start, end) = get_start_end_idx(&buf, 0);
            let username_bytes = &buf[start..end];
            println!("Username: {}", String::from_utf8_lossy(username_bytes));
            let username = match std::str::from_utf8(username_bytes) {
                Ok(username) => username,
                Err(e) => {
                    eprintln!("Invalid UTF-8 in email: {}", e);
                    continue;
                }
            };
            println!("Username from publish public key: {}", username);

            // +1 for ';'
            let (start, _) = get_key_bundle_start_end_idx(&buf, end + 1);
            let key_bundle_bytes = &buf[start..];

            let key_bundle_str = match std::str::from_utf8(key_bundle_bytes) {
                Ok(k) => { k },
                Err(e) => {
                    eprintln!("Invalid UTF-8 in email: {}", e);
                    continue;
                }
            };

            let chr = strip_chars(key_bundle_str);
            // println!("Key bundle from publish public key: {}", chr);
            let keys: Vec<&str> = vec!["IK_p", "SPK_p", "SPK_sig", "OPKs_p", "OPK_p"];
            let res = json_to_hashmap(chr, keys);
            let map = match res {
                // The Ok case: The variable `map` now holds the HashMap.
                Ok(map) => {
                    println!("Success! The HashMap contains:");
                    // To print the HashMap, use the Debug formatter `{:?}` or `{:#?}`
                    println!("{:#?}", map);
                    map
                }
                // The Err case: The variable `e` now holds the error.
                Err(e) => {
                    println!("Error! Failed to get data.");
                    // Use the Debug formatter `{:?}` for detailed error info
                    eprintln!("Debug details: {:?}", e);
                    continue;
                }
            };

            let result = insert_pk(db.clone(), &username, &map);
            match result {
                Ok(Some(user_id)) => {
                    // This is the full success case.
                    println!("\nSUCCESS: The entire operation completed for user_id: {}", user_id);
                    stream.write_all(b"07success;33public key submitted successfully")?;
                }
                Ok(None) => {
                    // This is the case where the user was not found to begin with.
                    println!("\nINFO: The operation was aborted");
                    stream.write_all(b"05error;25fail to submit public key")?;

                }
                Err(e) => {
                    // This happens if any database query fails.
                    eprintln!("\nCRITICAL ERROR: A database error occurred: {}", e);
                    stream.write_all(b"05error;25fail to submit public key")?;
                }
            }
        }
        else if &buf[start..end] == b"get public key" {
            stream.write_all(b"07success;24trying to get public key")?;
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf)?;
            if n == 0 {
                println!("Client closed the connection!");
                break;
            }
            let (start, end) = get_start_end_idx(&buf, 0);
            let username_bytes = &buf[start..end];
            println!("Username: {}", String::from_utf8_lossy(username_bytes));
            // std::process::exit(1);

            let username = match std::str::from_utf8(username_bytes) {
                Ok(username) => username,
                Err(e) => {
                    eprintln!("Invalid UTF-8 in email: {}", e);
                    continue;
                }
            };

            let result = get_pk(db.clone(), username);

            match result {
                Ok(Some(key_map)) => {
                    // This is the full success case.
                    println!("\nSUCCESS: Found all keys for user '{}'.", username);
                    println!("Retrieved Key Map:");
                    // Pretty-print the JSON map.
                    println!("{}", serde_json::to_string_pretty(&key_map)?);
                    match send_map_text_prefixed(&mut stream, &key_map) {
                        Ok(_) => println!("[Server] Data sent successfully."),
                        Err(e) => eprintln!("[Server] Failed to send data: {}", e),
                    }
                }
                Ok(None) => {
                    // This case handles when the user or their keys were not found.
                    println!("\nINFO: Could not retrieve keys because the user or their PublicKeys entry does not exist.");
                }
                Err(e) => {
                    // This happens if a database query fails.
                    eprintln!("\nCRITICAL ERROR: A database error occurred: {}", e);
                }
            }

        }
        else {
            println!("Unrecognized Command");
        }
    }
    Ok(())
}

use tokio;
use lapin::{
    options::{BasicPublishOptions, QueueDeclareOptions},
    types::FieldTable,
    BasicProperties, Channel, Connection, ConnectionProperties,
};

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
    let client = Client::connect(&db_url, NoTls)?; // this may fail, so use `?`
    let db = Arc::new(Mutex::new(client));

    // Manually create a tokio runtime just for sending message
    {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            if let Err(e) = send_hello_message().await {
                eprintln!("Error sending message: {}", e);
            }
        });
    }

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
