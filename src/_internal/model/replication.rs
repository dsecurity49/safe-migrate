use crate::_internal::analysis::facts::{AttributeFact, ConnectionTarget, PublicationScope};
use serde::{Deserialize, Serialize};

/// A settable subscription parameter and the release that introduced it.
/// PostgreSQL rejects an unrecognised parameter outright, so accepting one on
/// a server that lacks it is a false exact. `since` is `None` when every
/// supported release carries the parameter.
pub(crate) struct SubscriptionParam {
    pub name: &'static str,
    pub boolean: bool,
    pub since: Option<u32>,
}

/// Every option a subscription accepts, across `CREATE SUBSCRIPTION`,
/// `ALTER SUBSCRIPTION` and the publication/refresh/skip clauses.
pub(crate) const SUBSCRIPTION_PARAMS: &[SubscriptionParam] = &[
    SubscriptionParam {
        name: "connect",
        boolean: true,
        since: None,
    },
    SubscriptionParam {
        name: "create_slot",
        boolean: true,
        since: None,
    },
    SubscriptionParam {
        name: "enabled",
        boolean: true,
        since: None,
    },
    SubscriptionParam {
        name: "copy_data",
        boolean: true,
        since: None,
    },
    SubscriptionParam {
        name: "refresh",
        boolean: true,
        since: None,
    },
    SubscriptionParam {
        name: "slot_name",
        boolean: false,
        since: None,
    },
    SubscriptionParam {
        name: "synchronous_commit",
        boolean: false,
        since: None,
    },
    SubscriptionParam {
        name: "binary",
        boolean: true,
        since: Some(140_000),
    },
    SubscriptionParam {
        name: "streaming",
        boolean: false,
        since: Some(140_000),
    },
    SubscriptionParam {
        name: "two_phase",
        boolean: true,
        since: Some(150_000),
    },
    SubscriptionParam {
        name: "disable_on_error",
        boolean: true,
        since: Some(150_000),
    },
    SubscriptionParam {
        name: "lsn",
        boolean: false,
        since: Some(150_000),
    },
    SubscriptionParam {
        name: "password_required",
        boolean: true,
        since: Some(160_000),
    },
    SubscriptionParam {
        name: "run_as_owner",
        boolean: true,
        since: Some(160_000),
    },
    SubscriptionParam {
        name: "origin",
        boolean: false,
        since: Some(160_000),
    },
    SubscriptionParam {
        name: "failover",
        boolean: true,
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
