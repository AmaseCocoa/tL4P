use arc_swap::ArcSwap;
use ipnet::IpNet;
use std::cmp::Ordering;
use std::fs::File;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone)]
pub struct Firewall {
    whitelist: Arc<ArcSwap<Vec<IpNet>>>,
    data: String,
}

impl Firewall {
    pub fn new(initial_nets: Vec<IpNet>, rule_location: String) -> Self {
        let aggregated = IpNet::aggregate(&initial_nets);
        Self {
            whitelist: Arc::new(ArcSwap::from_pointee(aggregated)),
            data: rule_location,
        }
    }

    pub fn is_allowed(&self, ip: &IpAddr) -> bool {
        let current_nets = self.whitelist.load();
        current_nets
            .binary_search_by(|net| {
                if net.contains(ip) {
                    Ordering::Equal
                } else if *ip < net.network() {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            })
            .is_ok()
    }

    pub fn contains_net(&self, target_net: &IpNet) -> bool {
        let current_nets = self.whitelist.load();
        current_nets
            .binary_search_by(|net| {
                if net.contains(target_net) {
                    Ordering::Equal
                } else if target_net.network() < net.network() {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            })
            .is_ok()
    }

    pub fn add_network(&self, net: IpNet) {
        let mut new_nets = (**self.whitelist.load()).clone();
        new_nets.push(net);
        
        let aggregated = IpNet::aggregate(&new_nets);
        self.whitelist.store(Arc::new(aggregated));
    }

    pub fn remove_network(&self, net: &IpNet) {
        let current_nets = self.whitelist.load();
        
        let filtered_nets: Vec<IpNet> = current_nets
            .iter()
            .filter(|existing_net| !net.contains(*existing_net))
            .cloned()
            .collect();

        let aggregated = IpNet::aggregate(&filtered_nets);
        self.whitelist.store(Arc::new(aggregated));
    }

    pub fn replace_rules(&self, new_nets: Vec<IpNet>) {
        let aggregated = IpNet::aggregate(&new_nets);
        self.whitelist.store(Arc::new(aggregated));
    }

    pub fn get_rules_as_strings(&self) -> Vec<String> {
        let current_nets = self.whitelist.load();
        current_nets.iter().map(|net| net.to_string()).collect()
    }

    pub fn save_to_file(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let file_loc = Path::new(&self.data);
        let current_nets = self.whitelist.load();
        let file = File::create(file_loc)?;
        serde_json::to_writer(file, &**current_nets)?;
        Ok(())
    }
    
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let file = File::open(&path)?;
        let nets: Vec<IpNet> = serde_json::from_reader(file)?;
        let aggregated = IpNet::aggregate(&nets);
        Ok(Self {
            whitelist: Arc::new(ArcSwap::from_pointee(aggregated)),
            data: path.as_ref().to_str().unwrap().to_string(),
        })
    }
}
