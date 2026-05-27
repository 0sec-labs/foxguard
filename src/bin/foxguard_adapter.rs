use foxguard::adapter::{adapter_error_response, execute_adapter_request, AdapterRequest};
use std::io::Read;

fn main() {
    let mut input = String::new();
    if let Err(error) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("failed to read adapter request: {error}");
        std::process::exit(2);
    }

    let response = match serde_json::from_str::<AdapterRequest>(&input) {
        Ok(request) => execute_adapter_request(request),
        Err(error) => {
            adapter_error_response(None, None, format!("invalid adapter request: {error}"))
        }
    };

    match serde_json::to_string_pretty(&response) {
        Ok(json) => {
            println!("{json}");
        }
        Err(error) => {
            eprintln!("failed to serialize adapter response: {error}");
            std::process::exit(2);
        }
    }
}
