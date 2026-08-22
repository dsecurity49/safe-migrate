use crate::analysis::facts::{AttributeFact, ConnectionTarget, PublicationScope};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicationState {
    pub name: String,
    pub owner: Option<String>,
    pub scope: PublicationScope,
    pub params: Vec<AttributeFact>,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PublicationOverlay {
    Present(PublicationState),
    Dropped,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubscriptionState {
    pub name: String,
    pub owner: Option<String>,
    pub connection: ConnectionTarget,
    pub publications: Vec<String>,
    pub params: Option<Vec<AttributeFact>>,
    pub enabled: bool,
    pub slot_name: Option<String>,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SubscriptionOverlay {
    Present(SubscriptionState),
    Dropped,
}
