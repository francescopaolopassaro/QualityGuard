use std::process::Command;
use std::fs;

fn main() {
    let user_input = std::env::args().nth(1).unwrap_or_default();
    Command::new("sh")
        .arg("-c")
        .arg(user_input)
        .spawn()
        .unwrap();

    let path = format!("/tmp/{}", user_input);
    let content = fs::read_to_string(path).unwrap();

    let client = reqwest::Client::new();
    let url = format!("http://example.com/{}", user_input);
    client.get(url).send().unwrap();

    conn.query(format!("SELECT * FROM users WHERE id = {}", user_input)).unwrap();

    let password = "s3cr3t";
    println!("password={}", password);

    let n = rand::thread_rng().gen::<u32>();

    let p: *mut u8 = std::ptr::null_mut();
    unsafe {
        let v: Vec<u8> = Vec::from_raw_parts(p, 0, 0);
    }

    let x = 10;
    let x = x + 1;
    let ok = x == true;
    loop {
        println!("running");
    }
}
