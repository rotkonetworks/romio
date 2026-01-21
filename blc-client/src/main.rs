use clap::{Parser, Subcommand};
use blc_client::{parse_blc_text, encode_blc, Term};
use blc_client::blc::prelude;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio_tungstenite::{connect_async, tungstenite::Message};

#[derive(Parser)]
#[command(name = "blc")]
#[command(about = "binary lambda calculus client for jam corevm")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// parse blc from hex or lambda notation
    Parse {
        /// input (hex like 0x20 or lambda like \\.0)
        input: String,
    },
    /// encode blc term to hex
    Encode {
        /// lambda notation (e.g. \\.0 for identity)
        input: String,
    },
    /// show common blc terms
    Prelude {
        /// term name (identity, true, false, zero, one, s, k, i)
        name: String,
    },
    /// evaluate blc directly via blc service rpc
    Eval {
        /// blc program (hex or lambda)
        program: String,
        /// max reduction steps
        #[arg(short, long, default_value = "10000")]
        steps: u64,
        /// blc service endpoint (separate from jam node)
        #[arg(short, long, default_value = "ws://localhost:19801")]
        rpc: String,
    },
    /// submit blc to corevm service via jam node rpc (romio-specific)
    Refine {
        /// blc program (hex or lambda)
        program: String,
        /// service id
        #[arg(short, long, default_value = "1")]
        service: u32,
        /// jam node rpc endpoint
        #[arg(short, long, default_value = "ws://localhost:19800")]
        rpc: String,
    },
    /// query service storage
    Storage {
        /// service id
        service: u32,
        /// storage key (hex)
        key: String,
        /// rpc endpoint
        #[arg(short, long, default_value = "ws://localhost:19800")]
        rpc: String,
    },
}

#[derive(Serialize)]
struct RpcRequest<T> {
    jsonrpc: &'static str,
    id: u64,
    method: String,
    params: T,
}

#[derive(Deserialize)]
struct RpcResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: u64,
    result: Option<serde_json::Value>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

async fn rpc_call(endpoint: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
    let url = url::Url::parse(endpoint).map_err(|e| format!("invalid url: {}", e))?;
    let (mut ws, _) = connect_async(url).await.map_err(|e| format!("connect failed: {}", e))?;

    let req = RpcRequest {
        jsonrpc: "2.0",
        id: 1,
        method: method.to_string(),
        params,
    };
    let msg = serde_json::to_string(&req).unwrap();
    ws.send(Message::Text(msg)).await.map_err(|e| format!("send failed: {}", e))?;

    while let Some(msg) = ws.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                let resp: RpcResponse = serde_json::from_str(&text)
                    .map_err(|e| format!("parse response failed: {}", e))?;
                if let Some(err) = resp.error {
                    return Err(format!("rpc error {}: {}", err.code, err.message));
                }
                return Ok(resp.result.unwrap_or(serde_json::Value::Null));
            }
            Ok(Message::Close(_)) => break,
            Err(e) => return Err(format!("ws error: {}", e)),
            _ => {}
        }
    }
    Err("connection closed".to_string())
}

fn print_term(term: &Term) {
    let encoded = encode_blc(term);
    println!("term: {}", term);
    println!("hex:  0x{}", hex::encode(&encoded));
    println!("bits: {}", format_bits(&encoded));
}

fn format_bits(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:08b}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Parse { input } => {
            match parse_blc_text(&input) {
                Ok(term) => print_term(&term),
                Err(e) => eprintln!("error: {}", e),
            }
        }
        Commands::Encode { input } => {
            match parse_blc_text(&input) {
                Ok(term) => {
                    let encoded = encode_blc(&term);
                    println!("0x{}", hex::encode(&encoded));
                }
                Err(e) => eprintln!("error: {}", e),
            }
        }
        Commands::Prelude { name } => {
            let term = match name.to_lowercase().as_str() {
                "identity" | "id" | "i" => prelude::identity(),
                "true" | "t" | "k" => prelude::church_true(),
                "false" | "f" => prelude::church_false(),
                "zero" | "0" => prelude::church_zero(),
                "one" | "1" => prelude::church_one(),
                "s" => prelude::s_combinator(),
                _ => {
                    eprintln!("unknown term: {}", name);
                    eprintln!("available: identity, true, false, zero, one, s, k, i");
                    return;
                }
            };
            print_term(&term);
        }
        Commands::Eval { program, steps, rpc } => {
            let term = match parse_blc_text(&program) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("parse error: {}", e);
                    return;
                }
            };
            let encoded = encode_blc(&term);
            let hex_payload = format!("0x{}", hex::encode(&encoded));

            println!("evaluating {}", hex_payload);
            println!("term: {}", term);

            // use blc_eval rpc: [blc_hex, max_steps]
            let params = serde_json::json!([hex_payload, steps]);

            match rpc_call(&rpc, "blc_eval", params).await {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap_or(result.to_string()));
                }
                Err(e) => eprintln!("error: {}", e),
            }
        }
        Commands::Refine { program, service, rpc } => {
            let term = match parse_blc_text(&program) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("parse error: {}", e);
                    return;
                }
            };
            let encoded = encode_blc(&term);
            let hex_payload = format!("0x{}", hex::encode(&encoded));

            println!("submitting {} to service {}", hex_payload, service);

            // use romio_refine rpc (romio-specific, not jip-2)
            let params = serde_json::json!([service, hex_payload, 1_000_000_000_u64]);

            match rpc_call(&rpc, "romio_refine", params).await {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap_or(result.to_string()));
                }
                Err(e) => eprintln!("error: {}", e),
            }
        }
        Commands::Storage { service, key, rpc } => {
            let key_hex = if key.starts_with("0x") {
                key[2..].to_string()
            } else {
                key
            };

            let params = serde_json::json!({
                "service_id": service,
                "key": format!("0x{}", key_hex)
            });

            match rpc_call(&rpc, "jam_getStorage", params).await {
                Ok(result) => println!("{}", result),
                Err(e) => eprintln!("error: {}", e),
            }
        }
    }
}
