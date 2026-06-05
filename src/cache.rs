use crate::error::Result;
use crate::model::CacheData;
use std::fs;
use std::path::Path;

pub fn load_cache<P: AsRef<Path>>(path: P) -> Result<CacheData> {
    let content = fs::read_to_string(path)?;
    let cache: CacheData = serde_json::from_str(&content)?;
    Ok(cache)
}
