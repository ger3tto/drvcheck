use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
#[allow(dead_code)]
pub struct DriverEntry {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub author: String,
    #[serde(default, alias = "MitreID")]
    pub mitre_id: String,
    #[serde(default)]
    pub created: String,
    #[serde(default)]
    pub resources: Vec<String>,
    #[serde(default, alias = "KnownVulnerableSamples")]
    pub known_vulnerable_samples: Vec<VulnSample>,
}

#[derive(serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
#[allow(dead_code)]
pub struct VulnSample {
    #[serde(default)]
    pub filename: String,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub md5: String,
    #[serde(default)]
    pub sha1: String,
    #[serde(default)]
    pub publisher: String,
    #[serde(default)]
    pub company: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub product: String,
    #[serde(default, alias = "ProductVersion")]
    pub product_version: String,
    #[serde(default, alias = "FileVersion")]
    pub file_version: String,
    #[serde(default)]
    pub signature: String,
    #[serde(default, alias = "OriginalFilename")]
    pub original_filename: String,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct VulnMatch {
    pub driver_category: String,
    pub driver_tags: Vec<String>,
    pub driver_author: String,
    pub driver_mitre: String,
    pub driver_resources: Vec<String>,
    pub sample: VulnSample,
}

pub struct VulnDb {
    map: HashMap<[u8; 32], VulnMatch>,
}

impl VulnSample {
    pub fn display_name(&self) -> String {
        if !self.original_filename.is_empty() {
            self.original_filename.clone()
        } else if !self.filename.is_empty() {
            self.filename.clone()
        } else if !self.product.is_empty() {
            self.product.clone()
        } else {
            "<unknown>".into()
        }
    }

    pub fn publisher(&self) -> &str {
        if !self.publisher.is_empty() {
            &self.publisher
        } else if !self.company.is_empty() {
            &self.company
        } else {
            "<unknown>"
        }
    }
}

impl VulnMatch {
    pub fn risk_display(&self) -> String {
        if !self.driver_category.is_empty() {
            self.driver_category.clone()
        } else if !self.driver_tags.is_empty() {
            self.driver_tags.join(", ")
        } else {
            "N/A".into()
        }
    }
}

impl VulnDb {
    pub fn load(path: &Path) -> Result<Self, String> {
        let data = fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;

        let raw: serde_json::Value = serde_json::from_str(&data)
            .map_err(|e| format!("failed to parse JSON: {}", e))?;

        let entries = match &raw {
            serde_json::Value::Array(arr) => arr,
            serde_json::Value::Object(map) => {
                for key in ["VulnerableDrivers", "drivers", "entries", "data", "results"] {
                    if let Some(serde_json::Value::Array(arr)) = map.get(key) {
                        return Self::build_from_entries(arr);
                    }
                }
                return Err("no recognizable driver array found in JSON".into());
            }
            _ => return Err("unexpected JSON root type".into()),
        };

        Self::build_from_entries(entries)
    }

    fn build_from_entries(entries: &[serde_json::Value]) -> Result<Self, String> {
        let mut map = HashMap::new();

        for entry in entries {
            let driver: DriverEntry = match serde_json::from_value(entry.clone()) {
                Ok(d) => d,
                Err(_) => continue,
            };

            for sample in &driver.known_vulnerable_samples {
                let hash_str = sample.sha256.trim();
                if hash_str.is_empty() {
                    continue;
                }

                if let Ok(bytes) = hex::decode(hash_str) {
                    if bytes.len() == 32 {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&bytes);
                        map.entry(key).or_insert_with(|| VulnMatch {
                            driver_category: driver.category.clone(),
                            driver_tags: driver.tags.clone(),
                            driver_author: driver.author.clone(),
                            driver_mitre: driver.mitre_id.clone(),
                            driver_resources: driver.resources.clone(),
                            sample: sample.clone(),
                        });
                    }
                }
            }
        }

        Ok(VulnDb { map })
    }

    pub fn lookup(&self, sha256_hex: &str) -> Option<&VulnMatch> {
        let trimmed = sha256_hex.trim();
        let bytes = hex::decode(trimmed).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        self.map.get(&key)
    }

    pub fn count(&self) -> usize {
        self.map.len()
    }
}

pub fn print_vuln_alert(hash_result: &crate::hash::DriverHash, vuln: &VulnMatch) {
    let name = vuln.sample.display_name();
    let publisher = vuln.sample.publisher();
    let risk = vuln.risk_display();
    let resolved = &hash_result.resolved_path;
    let sha256 = hash_result.sha256.as_deref().unwrap_or("?");
    let desc = &vuln.sample.description;
    let product = &vuln.sample.product;
    let file_ver = &vuln.sample.file_version;

    eprintln!();
    eprintln!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    eprintln!("!!  VULNERABLE DRIVER DETECTED                                           !!");
    eprintln!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    eprintln!("  Driver Name    : {}", name);
    eprintln!("  Product        : {}", product);
    eprintln!("  Publisher      : {}", publisher);
    eprintln!("  Risk Level     : {}", risk);
    eprintln!("  File Path      : {}", resolved);
    eprintln!("  SHA256         : {}", sha256);
    if !vuln.driver_tags.is_empty() {
        eprintln!("  Tags           : {}", vuln.driver_tags.join(", "));
    }
    if !desc.is_empty() {
        eprintln!("  Description    : {}", desc);
    }
    if !file_ver.is_empty() {
        eprintln!("  File Version   : {}", file_ver);
    }
    if !vuln.driver_mitre.is_empty() {
        eprintln!("  MITRE          : {}", vuln.driver_mitre);
    }
    if !vuln.driver_resources.is_empty() {
        eprintln!("  References     : {}", vuln.driver_resources.join(", "));
    }
    eprintln!("  REMEDIATION    : Remove or quarantine the driver file. Block via HVCI/GPO.");
    eprintln!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    eprintln!();
}
