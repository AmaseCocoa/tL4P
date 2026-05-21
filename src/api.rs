use std::str::FromStr;
use std::net::IpAddr;
use std::{time::Duration};

use axum::{Json, Router, extract::State, routing::{get, post}};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::signal;
use tokio::sync::watch::{self, Sender};

use crate::firewall::Firewall;

#[derive(Deserialize)]
struct AddIPRequest {
    address: String,
}

#[derive(Deserialize)]
struct AddIPsRequest {
    addresses: Vec<String>,
}
#[derive(Serialize)]
struct TL4PAPIResponse {
    success: bool,
    reason: Option<String>
}

fn parse_to_ipnet(s: &str) -> Result<IpNet, String> {
    if s.contains('/') {
        return IpNet::from_str(s).map_err(|e| e.to_string());
    }

    let ip = IpAddr::from_str(s).map_err(|e| e.to_string());
    
    match ip {
        Ok(IpAddr::V4(v4)) => Ok(IpNet::V4(ipnet::Ipv4Net::new(v4, 32).unwrap())),
        Ok(IpAddr::V6(v6)) => Ok(IpNet::V6(ipnet::Ipv6Net::new(v6, 128).unwrap())),
        Err(e) => Err(e),
    }
}

async fn shutdown_signal(fw: Firewall, shutdown_tx: Sender<bool>) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    let _ = shutdown_tx.send(true);
    if let Err(e) = fw.save_to_file() {
        eprintln!("Failed to save firewall rules: {}", e);
    }
}

#[derive(Clone)]
pub struct TL4PApi {
    fw: Firewall
}

impl TL4PApi {
    pub fn new(fw: Firewall) -> TL4PApi {
        TL4PApi { fw }
    }

    pub fn into_router(self) -> Router {
        Router::new()
            .route("/", get("tL4P is ready :D"))
            .route("/api/v1/save", get(Self::save))
            .route("/api/v1/get_ips", get(Self::get_ips))
            .route("/api/v1/add_ip", post(Self::add_ip))
            .route("/api/v1/remove_ip", post(Self::remove_ip))
            .route("/api/v1/add_ips", post(Self::add_ips))
            .route("/api/v1/override_rule", post(Self::override_rule))
            .with_state(self)
    }
    
    pub async fn run_api(&self) {
        let app = self.clone().into_router();
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        
        let fw = self.fw.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let fw_clone = fw.clone();
                        let res = tokio::task::spawn_blocking(move || {
                            fw_clone.save_to_file()
                        }).await;
                
                        match res {
                            Ok(Ok(_)) => println!("Successfully saved."),
                            Ok(Err(err)) => eprintln!("Error when saving rules: {}", err),
                            Err(join_err) => eprintln!("Task panicked: {}", join_err),
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            println!("Shutdown signal received in background task. Exiting loop...");
                            break;
                        }
                    }
                }
            }
        });
        
        let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal(self.fw.clone(), shutdown_tx))
            .await
            .unwrap();
    }
    
    async fn get_ips(State(app): State<Self>) -> Json<Vec<String>> {
        Json(app.fw.get_rules_as_strings())
    }
    
    async fn override_rule(State(app): State<Self>, Json(payload): Json<AddIPsRequest>) -> Json<TL4PAPIResponse> {
        let mut parsed_address: Vec<IpNet> = vec![];
        for address in payload.addresses {
            match parse_to_ipnet(&address) {
                Ok(ip_addr) => {
                    parsed_address.push(ip_addr);
                },
                Err(_) => {}
            };
        };
        app.fw.replace_rules(parsed_address);
        Json(TL4PAPIResponse {
            success: true,
            reason: None
        })
    }
    
    async fn add_ips(State(app): State<Self>, Json(payload): Json<AddIPsRequest>) -> Json<TL4PAPIResponse> {
        for address in payload.addresses {
            match parse_to_ipnet(&address) {
                Ok(ip_addr) => {
                    if !app.fw.contains_net(&ip_addr) {
                        app.fw.add_network(ip_addr);
                    }
                },
                Err(_) => {}
            };
        };
        Json(TL4PAPIResponse {
            success: true,
            reason: None
        })
    }
    
    async fn remove_ip(State(app): State<Self>, Json(payload): Json<AddIPRequest>) -> Json<TL4PAPIResponse> {
        match parse_to_ipnet(&payload.address) {
            Ok(ip_addr) => {
                app.fw.remove_network(&ip_addr);
                Json(TL4PAPIResponse {
                    success: true,
                    reason: None
                })
            },
            Err(e) => {
                Json(TL4PAPIResponse {
                    success: false,
                    reason: Some(format!("{}", e))
                })
            }
        }
    }
    
    async fn add_ip(State(app): State<Self>, Json(payload): Json<AddIPRequest>) -> Json<TL4PAPIResponse> {
        match parse_to_ipnet(&payload.address) {
            Ok(ip_addr) => {
                if !app.fw.contains_net(&ip_addr) {
                    app.fw.add_network(ip_addr);
                }
                Json(TL4PAPIResponse {
                    success: true,
                    reason: None
                })
            },
            Err(e) => {
                Json(TL4PAPIResponse {
                    success: false,
                    reason: Some(format!("{}", e))
                })
            }
        }
    }
}
