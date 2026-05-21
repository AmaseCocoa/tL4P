use std::str::FromStr;
use std::net::IpAddr;
use std::{time::Duration};

use axum::{Json, Router, extract::State, routing::{get, post}};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::signal;

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
struct AddIPResponse {
    success: bool,
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

async fn shutdown_signal(fw: Firewall) {
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

        let fw = self.fw.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            interval.tick().await; 
    
            loop {
                interval.tick().await;
                match fw.save_to_file() {
                    Ok(_) => {},
                    Err(err) => eprintln!("Error when saving rules: {}", err)
                }
            }
        });
        
        let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal(self.fw.clone()))
            .await
            .unwrap();
    }

    async fn save(State(app): State<Self>) -> Json<AddIPResponse> {
        let res = app.fw.save_to_file();
        Json(AddIPResponse {
            success: res.is_ok()
        })
    }
    
    async fn get_ips(State(app): State<Self>) -> Json<Vec<String>> {
        Json(app.fw.get_rules_as_strings())
    }
    
    async fn override_rule(State(app): State<Self>, Json(payload): Json<AddIPsRequest>) -> Json<AddIPResponse> {
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
        Json(AddIPResponse {
            success: true
        })
        
    }
    
    async fn add_ips(State(app): State<Self>, Json(payload): Json<AddIPsRequest>) -> Json<AddIPResponse> {
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
        Json(AddIPResponse {
            success: true
        })
    }
    
    async fn remove_ip(State(app): State<Self>, Json(payload): Json<AddIPRequest>) -> Json<AddIPResponse> {
        match parse_to_ipnet(&payload.address) {
            Ok(ip_addr) => {
                app.fw.remove_network(&ip_addr);
                Json(AddIPResponse {
                    success: true
                })
            },
            Err(_) => {
                Json(AddIPResponse {
                    success: false
                })
            }
        }
    }
    
    async fn add_ip(State(app): State<Self>, Json(payload): Json<AddIPRequest>) -> Json<AddIPResponse> {
        match parse_to_ipnet(&payload.address) {
            Ok(ip_addr) => {
                if !app.fw.contains_net(&ip_addr) {
                    app.fw.add_network(ip_addr);
                }
                Json(AddIPResponse {
                    success: true
                })
            },
            Err(_) => {
                Json(AddIPResponse {
                    success: false
                })
            }
        }
    }
}
