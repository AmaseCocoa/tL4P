fn main() {
    println!("cargo::rustc-check-cfg=cfg(feature_tokio_engine)");
    
    println!("cargo:rerun-if-env-changed=PROXY_ENGINE");
    
    if let Ok(engine) = std::env::var("PROXY_ENGINE") {
        if engine.to_lowercase() == "tokio" {
            println!("cargo::rustc-cfg=feature_tokio_engine");
        }
    }
}
