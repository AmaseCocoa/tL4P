use std::str::FromStr;
use std::net::IpAddr;

use axum::{Json, Router, extract::State, routing::{get, post}};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::firewall::Firewall;

#[derive(Deserialize)]
struct AddIPRequest {
    address: String,
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
            .route("/api/v1/get_ips", get(Self::get_ips))
            .route("/api/v1/add_ip", post(Self::add_ip))
            .with_state(self)
    }
    
    pub async fn run_api(&self) {
        let app = self.clone().into_router();
    
        let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
        axum::serve(listener, app).await.unwrap();
    }

    async fn get_ips(State(app): State<Self>) -> Json<Vec<String>> {
        Json(app.fw.get_rules_as_strings())
    }
    
    async fn add_ip(State(app): State<Self>, Json(payload): Json<AddIPRequest>) -> Json<AddIPResponse> {
        match parse_to_ipnet(&payload.address) {
            Ok(ip_addr) => {
                app.fw.add_network(ip_addr);
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
