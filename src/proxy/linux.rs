use std::{net::TcpListener, rc::Rc};
use tokio_uring::buf::BoundedBuf;
use std::net::SocketAddr;
use socket2::{Socket, Domain, Type};

use crate::firewall::Firewall;

fn gen_socket(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let port: i32 = i32::from(*&addr.port());
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    
    socket.set_reuse_port(true)?;
    socket.bind(&addr.into())?;
    socket.listen(port)?;

    let listener: TcpListener = socket.into();
    Ok(listener)
}

#[allow(dead_code)]
pub fn run_proxy(listen_addr: &str, target_addr: &str, buffer_size: usize, fw: Firewall) -> std::io::Result<()> {
    let num_cores = num_cpus::get();
    let addr: SocketAddr = listen_addr.parse().unwrap();
    let target_addr: SocketAddr = target_addr.parse().unwrap();

    let mut threads = Vec::new();
    
    for worker_num in 0..num_cores {
        let fw_worker = fw.clone();
        threads.push(std::thread::spawn(move || {
            tokio_uring::start(async move {
                match gen_socket(addr) {
                    Ok(std_listener) => {
                        std_listener.set_nonblocking(true).unwrap();
                        let listener = tokio_uring::net::TcpListener::from_std(std_listener);
        
                        loop {
                            let (client_stream, client_addr) = match listener.accept().await {
                                Ok(res) => res,
                                Err(_) => continue,
                            };

                            if !fw_worker.is_allowed(&client_addr.ip()) {
                                continue;
                            }
        
                            tokio_uring::spawn(async move {
                                let target_stream = match tokio_uring::net::TcpStream::connect(target_addr).await {
                                    Ok(stream) => stream,
                                    Err(_) => return,
                                };
        
                                let client_stream = Rc::new(client_stream);
                                let target_stream = Rc::new(target_stream);
        
                                let c_stream = Rc::clone(&client_stream);
                                let t_stream = Rc::clone(&target_stream);
                                tokio_uring::spawn(async move {
                                    let mut buf = vec![0u8; buffer_size];
                                    loop {
                                        let (res, returned_buf) = c_stream.read(buf).await;
                                        buf = returned_buf;
                                        match res {
                                            Ok(0) => break,
                                            Ok(n) => {
                                                let (write_res, returned_slice) = t_stream.write_all(buf.slice(..n)).await;
                                                buf = returned_slice.into_inner();
                                                if write_res.is_err() { break; }
                                            }
                                            Err(_) => break,
                                        }
                                    }
                                });
        
                                let c_stream = Rc::clone(&client_stream);
                                let t_stream = Rc::clone(&target_stream);
                                tokio_uring::spawn(async move {
                                    let mut buf = vec![0u8; buffer_size];
                                    loop {
                                        let (res, returned_buf) = t_stream.read(buf).await;
                                        buf = returned_buf;
                                        match res {
                                            Ok(0) => break,
                                            Ok(n) => {
                                                let (write_res, returned_slice) = c_stream.write_all(buf.slice(..n)).await;
                                                buf = returned_slice.into_inner();
                                                if write_res.is_err() { break; }
                                            }
                                            Err(_) => break,
                                        }
                                    }
                                });
                            });
                        }
                        
                    },
                    Err(e) => eprintln!("Error when generating thread in worker {}: {}", worker_num, e)
                }
            });
        }));
    }

    for t in threads {
        let _ = t.join();
    }

    Ok(())
}
