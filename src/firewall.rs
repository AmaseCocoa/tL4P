use arc_swap::ArcSwap;
use ipnet::IpNet;
use std::fs::File;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone)]
pub struct Firewall {
    whitelist: Arc<ArcSwap<Vec<IpNet>>>,
    data: String
}

impl Firewall {
    pub fn new(mut initial_nets: Vec<IpNet>, rule_location: String) -> Self {
        initial_nets.sort();
        Self {
            whitelist: Arc::new(ArcSwap::from_pointee(initial_nets)),
            data: rule_location
        }
    }

    pub fn is_allowed(&self, ip: &IpAddr) -> bool {
        let current_nets = self.whitelist.load();
        current_nets
            .binary_search_by(|net| {
                if net.contains(ip) {
                    std::cmp::Ordering::Equal
                } else if ip < &net.addr() {
                    std::cmp::Ordering::Greater
                } else {
                    std::cmp::Ordering::Less
                }
            })
            .is_ok()
    }

    pub fn add_network(&self, net: IpNet) {
        let mut new_nets = (**self.whitelist.load()).clone();
        if let Err(pos) = new_nets.binary_search(&net) {
            new_nets.insert(pos, net);
            self.whitelist.store(Arc::new(new_nets));
        }
    }

    pub fn remove_network(&self, net: &IpNet) {
        let mut new_nets = (**self.whitelist.load()).clone();
        if let Ok(pos) = new_nets.binary_search(net) {
            new_nets.remove(pos);
            self.whitelist.store(Arc::new(new_nets));
        }
    }

    pub fn replace_rules(&self, mut new_nets: Vec<IpNet>) {
        new_nets.sort();

        self.whitelist.store(Arc::new(new_nets));
    }

    pub fn get_rules_as_strings(&self) -> Vec<String> {
        let current_nets = self.whitelist.load();

        current_nets.iter().map(|net| net.to_string()).collect()
    }

    pub fn save_to_file(&self) -> Result<(), Box<dyn std::error::Error>> {
        let file_loc = Path::new(&self.data);
        let current_nets = self.whitelist.load();
        let file = File::create(file_loc)?;
        serde_json::to_writer(file, &**current_nets)?;
        Ok(())
    }
    
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let file = File::open(&path)?;
        let mut nets: Vec<IpNet> = serde_json::from_reader(file)?;
        nets.sort();
        Ok(Self {
            whitelist: Arc::new(ArcSwap::from_pointee(nets)),
            data: path.as_ref().to_str().unwrap().to_string()
        })
    }

}
