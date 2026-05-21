use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::firewall::Firewall;

#[allow(dead_code)]
pub fn run_proxy(listen_addr: &str, target_addr: &str, buffer_size: usize, fw: Firewall) -> std::io::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async {
        let listener = TcpListener::bind(listen_addr).await?;
        let fw_worker = fw.clone();

        loop {
            let (mut client_stream, client_addr) = listener.accept().await?;
            let target_addr_owned = target_addr.to_string();
            
            if !fw_worker.is_allowed(&client_addr.ip()) {
                continue;
            }

            tokio::spawn(async move {
                let mut target_stream = match tokio::net::TcpStream::connect(target_addr_owned).await {
                    Ok(stream) => stream,
                    Err(_) => return,
                };

                let _ = client_stream.set_nodelay(true);
                let _ = target_stream.set_nodelay(true);

                let (client_reader, client_writer) = client_stream.split();
                let (target_reader, target_writer) = target_stream.split();

                let mut client_buf = vec![0u8; buffer_size];
                let mut target_buf = vec![0u8; buffer_size];

                let mut client_reader = std::pin::pin!(client_reader);
                let mut client_writer = std::pin::pin!(client_writer);
                let mut target_reader = std::pin::pin!(target_reader);
                let mut target_writer = std::pin::pin!(target_writer);

                loop {
                    tokio::select! {
                        res = client_reader.read(&mut client_buf) => {
                            match res {
                                Ok(0) => break,
                                Ok(n) => {
                                    if target_writer.write_all(&client_buf[..n]).await.is_err() { break; }
                                }
                                Err(_) => break,
                            }
                        }
                        res = target_reader.read(&mut target_buf) => {
                            match res {
                                Ok(0) => break,
                                Ok(n) => {
                                    if client_writer.write_all(&target_buf[..n]).await.is_err() { break; }
                                }
                                Err(_) => break,
                            }
                        }
                    }
                }
            });
        }
    })
}
