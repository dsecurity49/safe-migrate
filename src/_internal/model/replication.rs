use crate::_internal::analysis::facts::{AttributeFact, ConnectionTarget, PublicationScope};
use serde::{Deserialize, Serialize};

/// How PostgreSQL interprets a settable subscription parameter's value.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubscriptionValue {
    Boolean,
    /// `streaming` was a boolean before PostgreSQL 16 and an enum after it.
    Streaming,
    Text,
}

/// A settable subscription parameter and the release that introduced it.
/// PostgreSQL rejects an unrecognised parameter outright, so accepting one on
/// a server that lacks it is a false exact. `since` is `None` when every
/// supported release carries the parameter.
pub(crate) struct SubscriptionParam {
    pub name: &'static str,
    pub value: SubscriptionValue,
    pub since: Option<u32>,
}

/// Every option a subscription accepts, across `CREATE SUBSCRIPTION`,
/// `ALTER SUBSCRIPTION` and the publication/refresh/skip clauses.
pub(crate) const SUBSCRIPTION_PARAMS: &[SubscriptionParam] = &[
    SubscriptionParam {
        name: "connect",
        value: SubscriptionValue::Boolean,
        since: None,
    },
    SubscriptionParam {
        name: "create_slot",
        value: SubscriptionValue::Boolean,
        since: None,
    },
    SubscriptionParam {
        name: "enabled",
        value: SubscriptionValue::Boolean,
        since: None,
    },
    SubscriptionParam {
        name: "copy_data",
        value: SubscriptionValue::Boolean,
        since: None,
    },
    SubscriptionParam {
        name: "refresh",
        value: SubscriptionValue::Boolean,
        since: None,
    },
    SubscriptionParam {
        name: "slot_name",
        value: SubscriptionValue::Text,
        since: None,
    },
    SubscriptionParam {
        name: "synchronous_commit",
        value: SubscriptionValue::Text,
        since: None,
    },
    SubscriptionParam {
        name: "binary",
        value: SubscriptionValue::Boolean,
        since: Some(140_000),
    },
    SubscriptionParam {
        name: "streaming",
        value: SubscriptionValue::Streaming,
        since: Some(140_000),
    },
    SubscriptionParam {
        name: "two_phase",
        value: SubscriptionValue::Boolean,
        since: Some(150_000),
    },
    SubscriptionParam {
        name: "disable_on_error",
        value: SubscriptionValue::Boolean,
        since: Some(150_000),
    },
    SubscriptionParam {
        name: "lsn",
        value: SubscriptionValue::Text,
        since: Some(150_000),
    },
    SubscriptionParam {
        name: "password_required",
        value: SubscriptionValue::Boolean,
        since: Some(160_000),
    },
    SubscriptionParam {
        name: "run_as_owner",
        value: SubscriptionValue::Boolean,
        since: Some(160_000),
    },
    SubscriptionParam {
        name: "origin",
        value: SubscriptionValue::Text,
        since: Some(160_000),
    },
    SubscriptionParam {
        name: "failover",
        value: SubscriptionValue::Boolean,
        since: Some(170_000),
    },
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct PublicationState {
    pub name: String,
    pub owner: Option<String>,
    pub scope: PublicationScope,
    pub params: Vec<AttributeFact>,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PublicationOverlay {
    Present(PublicationState),
    Dropped,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct SubscriptionState {
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
pub(crate) enum SubscriptionOverlay {
    Present(SubscriptionState),
    Dropped,
}
