mod proxy;
mod firewall;
mod api;

use firewall::Firewall;
use api::TL4PApi;

use ipnet::IpNet;
#[cfg(all(target_os = "linux", not(feature_tokio_engine)))]
use proxy::linux;

#[cfg(any(not(target_os = "linux"), feature_tokio_engine))]
use proxy::generic;

const BUFFER_SIZE: usize = 65536;
const LISTEN_ADDR: &str = "0.0.0.0:8080";
const TARGET_ADDR: &str = "127.0.0.1:9000";

#[tokio::main]
async fn main() -> std::io::Result<()> {
    
    let allowed_ips = vec![
        "127.0.0.1/32".parse::<IpNet>().unwrap(),
        "0.0.0.0/32".parse::<IpNet>().unwrap(),
    ];
    
    let fw = Firewall::new(allowed_ips);
    
    let fw_clone = fw.clone();
    tokio::spawn(async {
        let api_server = TL4PApi::new(fw_clone);
        api_server.run_api().await
    });
    
    #[cfg(all(target_os = "linux", not(feature_tokio_engine)))]
    {
        linux::run_proxy(LISTEN_ADDR, TARGET_ADDR, BUFFER_SIZE, fw)
    }

    #[cfg(any(not(target_os = "linux"), feature_tokio_engine))]
    {
        generic::run_proxy(LISTEN_ADDR, TARGET_ADDR, BUFFER_SIZE, fw)
    }
}
