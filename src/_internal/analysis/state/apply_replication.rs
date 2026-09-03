use super::{AnalysisState, MutationResult, ObjectLookup};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::graph::{DependencyEdge, DependencyKind};
use crate::_internal::analysis::mutations::{
    AlterPublicationMutation, AlterSubscriptionMutation, CreatePublicationMutation,
    CreateSubscriptionMutation, DropPublicationMutation, DropSubscriptionMutation,
};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::replication::{PublicationOverlay, SubscriptionOverlay};
use std::collections::HashSet;

type PublicationLookup = ObjectLookup;
type SubscriptionLookup = ObjectLookup;

impl AnalysisState {
    fn publication_lookup(&self, name: &str) -> PublicationLookup {
        match self.local.publications.get(name) {
            Some(PublicationOverlay::Present(_)) => PublicationLookup::Present,
            Some(PublicationOverlay::Dropped) => PublicationLookup::Tombstone,
            None if self.baseline_is_available() => PublicationLookup::AuthoritativelyAbsent,
            None => PublicationLookup::Unknown,
        }
    }

    fn subscription_lookup(&self, name: &str) -> SubscriptionLookup {
        match self.local.subscriptions.get(name) {
            Some(SubscriptionOverlay::Present(_)) => SubscriptionLookup::Present,
            Some(SubscriptionOverlay::Dropped) => SubscriptionLookup::Tombstone,
            None if self.baseline_is_available() => SubscriptionLookup::AuthoritativelyAbsent,
            None => SubscriptionLookup::Unknown,
        }
    }

    pub(super) fn apply_create_publication(
        &mut self,
        p: &CreatePublicationMutation,
    ) -> MutationResult {
        match self.publication_lookup(&p.name) {
            PublicationLookup::Present => {
                return MutationResult::Conflict {
                    reason: format!("publication '{}' already exists", p.name),
                };
            }
            PublicationLookup::Unknown => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
            }
            PublicationLookup::Tombstone | PublicationLookup::AuthoritativelyAbsent => {}
            PublicationLookup::WrongKind => {
                unreachable!("publication names have a dedicated namespace")
            }
        }
        if let Err(reason) = self.validate_publication_scope(&p.scope) {
            return MutationResult::Conflict { reason };
        }
        self.taint_inheritance_sensitive_publication_scope(&p.scope);
        self.snapshot_publication(&p.name);
        self.snapshot_generation_counter();
        self.local.generation_counter += 1;
        let generation = self.local.generation_counter;

        let owner = self
            .local
            .current_role_known
            .then(|| self.local.current_role.clone());
        self.local.publications.insert(
            p.name.clone(),
            crate::_internal::model::replication::PublicationOverlay::Present(
                crate::_internal::model::replication::PublicationState {
                    name: p.name.clone(),
                    owner,
                    scope: p.scope.clone(),
                    params: p.params.clone(),
                    generation,
                },
            ),
        );

        if let crate::_internal::analysis::facts::PublicationScope::Explicit(objects) = &p.scope {
            self.snapshot_graph_full();
            for obj in objects {
                if let crate::_internal::analysis::facts::PublicationObjectFact::Table { name, .. } = obj {
                    let table_id = self.resolve_relation_id(name);
                    self.local.graph.add_edge(DependencyEdge::new(
                        table_id,
                        ObjectId::new("public", &p.name),
                        DependencyKind::PublicationIncludes {
                            publication_name: p.name.clone(),
                        },
                    ));
                }
            }
        }
        MutationResult::Applied
    }

    pub(super) fn apply_alter_publication(
        &mut self,
        p: &AlterPublicationMutation,
    ) -> MutationResult {
        match self.publication_lookup(&p.name) {
            PublicationLookup::Present => {}
            PublicationLookup::Tombstone | PublicationLookup::AuthoritativelyAbsent => {
                return MutationResult::Conflict {
                    reason: format!("publication '{}' does not exist", p.name),
                };
            }
            PublicationLookup::Unknown => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                return MutationResult::Skipped;
            }
            PublicationLookup::WrongKind => {
                unreachable!("publication names have a dedicated namespace")
            }
        }
        // Validate a rename destination before taking statement snapshots or
        // advancing generation state.  In a scoped/incomplete catalog an
        // absent destination is not authoritative, so applying the rename
        // would hide a possible namespace collision.
        if let crate::_internal::analysis::facts::AlterPublicationActionFact::Rename { to } = &p.action {
            match self.publication_lookup(to) {
                PublicationLookup::Present => {
                    return MutationResult::Conflict {
                        reason: format!("publication '{}' already exists", to),
                    };
                }
                PublicationLookup::Unknown => {
                    self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                    return MutationResult::Skipped;
                }
                PublicationLookup::Tombstone
                | PublicationLookup::AuthoritativelyAbsent
                | PublicationLookup::WrongKind => {}
            }
        }
        if let crate::_internal::analysis::facts::AlterPublicationActionFact::OwnerChange(role) = &p.action
            && let Some((owner, known)) = self.role_fact_identity(role)
            && known
            && self.local.roles_known
            && self.present_role(&owner).is_none()
        {
            return MutationResult::Conflict {
                reason: format!("role '{}' does not exist", owner),
            };
        }
        self.snapshot_publication(&p.name);
        self.snapshot_generation_counter();
        self.local.generation_counter += 1;
        let new_gen = self.local.generation_counter;
        use crate::_internal::analysis::facts::AlterPublicationActionFact;

        let current_scope = match self.local.publications.get(&p.name) {
            Some(crate::_internal::model::replication::PublicationOverlay::Present(publication)) => {
                publication.scope.clone()
            }
            _ => unreachable!("publication existence checked above"),
        };
        let mut replacement_scope = None;
        let mut rename_to = None;
        match &p.action {
            AlterPublicationActionFact::AddObjects(additions) => {
                let additions_scope =
                    crate::_internal::analysis::facts::PublicationScope::Explicit(additions.clone());
                if let Err(reason) = self.validate_publication_scope(&additions_scope) {
                    return MutationResult::Conflict { reason };
                }
                self.taint_inheritance_sensitive_publication_scope(&additions_scope);
                let crate::_internal::analysis::facts::PublicationScope::Explicit(mut objects) = current_scope
                else {
                    return MutationResult::Conflict {
                        reason: format!("publication '{}' already includes all tables", p.name),
                    };
                };
                let mut keys: HashSet<String> = objects
                    .iter()
                    .map(|object| self.publication_object_key(object))
                    .collect();
                for addition in additions {
                    let key = self.publication_object_key(addition);
                    if !keys.insert(key) {
                        return MutationResult::Conflict {
                            reason: format!(
                                "publication '{}' already contains the requested object",
                                p.name
                            ),
                        };
                    }
                    objects.push(addition.clone());
                }
                replacement_scope =
                    Some(crate::_internal::analysis::facts::PublicationScope::Explicit(objects));
            }
            AlterPublicationActionFact::SetObjects(scope) => {
                if let Err(reason) = self.validate_publication_scope(scope) {
                    return MutationResult::Conflict { reason };
                }
                self.taint_inheritance_sensitive_publication_scope(scope);
                replacement_scope = Some(scope.clone());
            }
            AlterPublicationActionFact::DropObjects(removals) => {
                self.taint_inheritance_sensitive_publication_scope(
                    &crate::_internal::analysis::facts::PublicationScope::Explicit(removals.clone()),
                );
                let crate::_internal::analysis::facts::PublicationScope::Explicit(mut objects) = current_scope
                else {
                    return MutationResult::Conflict {
                        reason: format!("publication '{}' includes all tables", p.name),
                    };
                };
                for removal in removals {
                    let key = self.publication_object_key(removal);
                    let Some(position) = objects
                        .iter()
                        .position(|object| self.publication_object_key(object) == key)
                    else {
                        return MutationResult::Conflict {
                            reason: format!(
                                "publication '{}' does not contain the requested object",
                                p.name
                            ),
                        };
                    };
                    objects.remove(position);
                }
                replacement_scope =
                    Some(crate::_internal::analysis::facts::PublicationScope::Explicit(objects));
            }
            AlterPublicationActionFact::SetOptions(options) => {
                if let Some(crate::_internal::model::replication::PublicationOverlay::Present(publication)) =
                    self.local.publications.get_mut(&p.name)
                {
                    for option in options {
                        publication
                            .params
                            .retain(|existing| existing.name != option.name);
                        publication.params.push(option.clone());
                    }
                }
            }
            AlterPublicationActionFact::OwnerChange(role) => {
                if let Some((owner, known)) = self.role_fact_identity(role) {
                    if known {
                        if !self.local.roles_known {
                            self.taint(
                                EvidenceCode::CatalogCoverageIncomplete,
                                EvidenceScope::Chain,
                            );
                        }
                        if let Some(crate::_internal::model::replication::PublicationOverlay::Present(
                            publication,
                        )) = self.local.publications.get_mut(&p.name)
                        {
                            publication.owner = Some(owner);
                        }
                    } else {
                        self.taint(EvidenceCode::UnresolvedReference, EvidenceScope::Chain);
                        if let Some(crate::_internal::model::replication::PublicationOverlay::Present(
                            publication,
                        )) = self.local.publications.get_mut(&p.name)
                        {
                            publication.owner = None;
                        }
                    }
                } else {
                    self.taint(EvidenceCode::UnresolvedReference, EvidenceScope::Chain);
                    if let Some(crate::_internal::model::replication::PublicationOverlay::Present(
                        publication,
                    )) = self.local.publications.get_mut(&p.name)
                    {
                        publication.owner = None;
                    }
                }
            }
            AlterPublicationActionFact::Rename { to } => {
                rename_to = Some(to.clone());
            }
        }

        if let Some(scope) = replacement_scope {
            if let Some(crate::_internal::model::replication::PublicationOverlay::Present(publication)) =
                self.local.publications.get_mut(&p.name)
            {
                publication.scope = scope.clone();
            }
            self.replace_publication_edges(&p.name, &scope);
        }
        if let Some(crate::_internal::model::replication::PublicationOverlay::Present(publication)) =
            self.local.publications.get_mut(&p.name)
        {
            publication.generation = new_gen;
        }
        if let Some(to) = rename_to {
            self.snapshot_publication(&to);
            let Some(crate::_internal::model::replication::PublicationOverlay::Present(mut publication)) =
                self.local.publications.remove(&p.name)
            else {
                unreachable!("publication existence checked above");
            };
            publication.name = to.clone();
            self.local.publications.insert(
                to.clone(),
                crate::_internal::model::replication::PublicationOverlay::Present(publication),
            );
            self.snapshot_graph_full();
            self.local.graph.rename_publication(&p.name, &to);
        }
        MutationResult::Applied
    }

    pub(super) fn apply_drop_publication(&mut self, p: &DropPublicationMutation) -> MutationResult {
        let mut present_names = Vec::new();
        let mut unknown_target = false;
        for name in &p.names {
            match self.publication_lookup(name) {
                PublicationLookup::Present => present_names.push(name.clone()),
                PublicationLookup::Tombstone => {
                    if !p.if_exists {
                        return MutationResult::Conflict {
                            reason: format!("publication '{}' does not exist", name),
                        };
                    }
                }
                PublicationLookup::AuthoritativelyAbsent if p.if_exists => {}
                PublicationLookup::Unknown if p.if_exists => {
                    self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                    unknown_target = true;
                }
                PublicationLookup::AuthoritativelyAbsent => {
                    return MutationResult::Conflict {
                        reason: format!("publication '{}' does not exist", name),
                    };
                }
                PublicationLookup::Unknown => {
                    self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                    return MutationResult::Skipped;
                }
                PublicationLookup::WrongKind => {
                    unreachable!("publication names have a dedicated namespace")
                }
            }
        }
        if unknown_target {
            return MutationResult::Skipped;
        }
        for name in &present_names {
            self.snapshot_publication(name);
            self.local.publications.insert(
                name.clone(),
                crate::_internal::model::replication::PublicationOverlay::Dropped,
            );
        }
        self.snapshot_graph_full();
        self.local.graph.retain_edges(|e| {
            !(matches!(e.kind, DependencyKind::PublicationIncludes { .. })
                && present_names.contains(&e.referenced.name))
        });
        if present_names.is_empty() {
            MutationResult::Skipped
        } else {
            MutationResult::Applied
        }
    }

    pub(super) fn apply_create_subscription(
        &mut self,
        s: &CreateSubscriptionMutation,
    ) -> MutationResult {
        let name = s.name.clone().unwrap_or_else(|| "unnamed_sub".into());
        match self.subscription_lookup(&name) {
            SubscriptionLookup::Present => {
                return MutationResult::Conflict {
                    reason: format!("subscription '{}' already exists", name),
                };
            }
            SubscriptionLookup::Unknown => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
            }
            SubscriptionLookup::Tombstone | SubscriptionLookup::AuthoritativelyAbsent => {}
            SubscriptionLookup::WrongKind => {
                unreachable!("subscription names have a dedicated namespace")
            }
        }

        let params = s.params.as_deref();
        if let Err(reason) = Self::validate_subscription_boolean_options(
            params,
            &[
                "connect",
                "create_slot",
                "enabled",
                "copy_data",
                "binary",
                "disable_on_error",
                "password_required",
                "run_as_owner",
                "failover",
                "two_phase",
            ],
        ) {
            return MutationResult::Conflict { reason };
        }
        let connects_to_publisher =
            Self::subscription_boolean_option(params, "connect") != Some(false);
        if !connects_to_publisher
            && ["create_slot", "enabled", "copy_data"]
                .iter()
                .any(|name| Self::subscription_boolean_option(params, name) == Some(true))
        {
            return MutationResult::Conflict {
                reason: format!(
                    "subscription '{}' cannot enable connection-dependent options when connect is false",
                    name
                ),
            };
        }
        let creates_slot = connects_to_publisher
            && Self::subscription_boolean_option(params, "create_slot") != Some(false);
        if !self.local.transactions.is_empty() && connects_to_publisher && creates_slot {
            return MutationResult::Conflict {
                reason: format!(
                    "subscription '{}' cannot create a replication slot inside a transaction",
                    name
                ),
            };
        }
        self.snapshot_subscription(&name);
        self.snapshot_generation_counter();
        self.local.generation_counter += 1;
        let generation = self.local.generation_counter;

        if connects_to_publisher {
            self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
        }

        let enabled = connects_to_publisher
            && Self::subscription_boolean_option(params, "enabled") != Some(false);
        let slot_name = match Self::subscription_option(params, "slot_name") {
            Some(value) if value.eq_ignore_ascii_case("none") => None,
            Some(value) => Some(value.to_string()),
            None => Some(name.clone()),
        };
        if slot_name.is_none() && (enabled || creates_slot) {
            return MutationResult::Conflict {
                reason: format!(
                    "subscription '{}' with slot_name NONE must disable enabled and create_slot",
                    name
                ),
            };
        }
        let mut unique_publications = HashSet::new();
        if !s
            .publications
            .iter()
            .all(|publication| unique_publications.insert(publication))
        {
            return MutationResult::Conflict {
                reason: format!(
                    "subscription '{}' lists the same publication more than once",
                    name
                ),
            };
        }

        let owner = self
            .local
            .current_role_known
            .then(|| self.local.current_role.clone());
        self.local.subscriptions.insert(
            name.clone(),
            crate::_internal::model::replication::SubscriptionOverlay::Present(
                crate::_internal::model::replication::SubscriptionState {
                    name,
                    owner,
                    connection: s.connection.clone(),
                    publications: s.publications.clone(),
                    params: s.params.clone(),
                    enabled,
                    slot_name,
                    generation,
                },
            ),
        );
        MutationResult::Applied
    }

    pub(super) fn apply_alter_subscription(
        &mut self,
        s: &AlterSubscriptionMutation,
    ) -> MutationResult {
        match self.subscription_lookup(&s.name) {
            SubscriptionLookup::Present => {}
            SubscriptionLookup::Tombstone | SubscriptionLookup::AuthoritativelyAbsent => {
                return MutationResult::Conflict {
                    reason: format!("subscription '{}' does not exist", s.name),
                };
            }
            SubscriptionLookup::Unknown => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                return MutationResult::Skipped;
            }
            SubscriptionLookup::WrongKind => {
                unreachable!("subscription names have a dedicated namespace")
            }
        }
        // As with publications, an unknown destination in an incomplete
        // catalog cannot be treated as free for a namespace rename.
        if let crate::_internal::analysis::facts::AlterSubscriptionActionFact::Rename { to } = &s.action {
            match self.subscription_lookup(to) {
                SubscriptionLookup::Present => {
                    return MutationResult::Conflict {
                        reason: format!("subscription '{}' already exists", to),
                    };
                }
                SubscriptionLookup::Unknown => {
                    self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                    return MutationResult::Skipped;
                }
                SubscriptionLookup::Tombstone
                | SubscriptionLookup::AuthoritativelyAbsent
                | SubscriptionLookup::WrongKind => {}
            }
        }
        if let crate::_internal::analysis::facts::AlterSubscriptionActionFact::OwnerChange(role) = &s.action
            && let Some((owner, known)) = self.role_fact_identity(role)
            && known
            && self.local.roles_known
            && self.present_role(&owner).is_none()
        {
            return MutationResult::Conflict {
                reason: format!("role '{}' does not exist", owner),
            };
        }
        let existing = match self.local.subscriptions.get(&s.name) {
            Some(crate::_internal::model::replication::SubscriptionOverlay::Present(subscription)) => {
                subscription
            }
            _ => unreachable!("subscription existence checked above"),
        };
        let in_transaction = !self.local.transactions.is_empty();
        match &s.action {
            crate::_internal::analysis::facts::AlterSubscriptionActionFact::Publications {
                mode,
                publications,
                params,
            } => {
                if let Err(reason) = Self::validate_subscription_boolean_options(
                    Some(params),
                    &["refresh", "copy_data"],
                ) {
                    return MutationResult::Conflict { reason };
                }
                if in_transaction
                    && Self::subscription_boolean_option(Some(params), "refresh") != Some(false)
                {
                    return MutationResult::Conflict {
                        reason: format!(
                            "subscription '{}' cannot refresh publications inside a transaction",
                            s.name
                        ),
                    };
                }

                let mut unique = HashSet::new();
                match mode {
                    crate::_internal::analysis::facts::SubscriptionPublicationMode::Set => {
                        if !publications
                            .iter()
                            .all(|publication| unique.insert(publication))
                        {
                            return MutationResult::Conflict {
                                reason: format!(
                                    "subscription '{}' lists the same publication more than once",
                                    s.name
                                ),
                            };
                        }
                    }
                    crate::_internal::analysis::facts::SubscriptionPublicationMode::Add => {
                        for publication in publications {
                            if !unique.insert(publication)
                                || existing.publications.contains(publication)
                            {
                                return MutationResult::Conflict {
                                    reason: format!(
                                        "subscription '{}' already includes publication '{}'",
                                        s.name, publication
                                    ),
                                };
                            }
                        }
                    }
                    crate::_internal::analysis::facts::SubscriptionPublicationMode::Drop => {
                        for publication in publications {
                            if !unique.insert(publication)
                                || !existing.publications.contains(publication)
                            {
                                return MutationResult::Conflict {
                                    reason: format!(
                                        "subscription '{}' does not include publication '{}'",
                                        s.name, publication
                                    ),
                                };
                            }
                        }
                    }
                }
            }
            crate::_internal::analysis::facts::AlterSubscriptionActionFact::RefreshPublication(_)
                if in_transaction =>
            {
                return MutationResult::Conflict {
                    reason: format!(
                        "subscription '{}' cannot refresh publications inside a transaction",
                        s.name
                    ),
                };
            }
            crate::_internal::analysis::facts::AlterSubscriptionActionFact::SetOptions(options) => {
                if let Err(reason) = Self::validate_subscription_boolean_options(
                    Some(options),
                    &[
                        "binary",
                        "disable_on_error",
                        "password_required",
                        "run_as_owner",
                        "failover",
                        "two_phase",
                    ],
                ) {
                    return MutationResult::Conflict { reason };
                }
                if existing.enabled
                    && options
                        .iter()
                        .any(|option| option.name.eq_ignore_ascii_case("slot_name"))
                {
                    return MutationResult::Conflict {
                        reason: format!(
                            "subscription '{}' must be disabled before changing slot_name",
                            s.name
                        ),
                    };
                }
                let changes_failover_or_two_phase = options.iter().any(|option| {
                    option.name.eq_ignore_ascii_case("failover")
                        || option.name.eq_ignore_ascii_case("two_phase")
                });
                if changes_failover_or_two_phase && existing.enabled {
                    return MutationResult::Conflict {
                        reason: format!(
                            "subscription '{}' must be disabled before changing failover or two_phase",
                            s.name
                        ),
                    };
                }
                let forbidden_in_transaction = options.iter().any(|option| {
                    option.name.eq_ignore_ascii_case("failover")
                        || (option.name.eq_ignore_ascii_case("two_phase")
                            && Self::postgres_boolean(&option.value) == Some(false))
                });
                if in_transaction && forbidden_in_transaction {
                    return MutationResult::Conflict {
                        reason: format!(
                            "subscription '{}' cannot change this setting inside a transaction",
                            s.name
                        ),
                    };
                }
            }
            crate::_internal::analysis::facts::AlterSubscriptionActionFact::SetEnabled(true)
                if existing.slot_name.is_none() =>
            {
                return MutationResult::Conflict {
                    reason: format!(
                        "subscription '{}' cannot be enabled without a slot_name",
                        s.name
                    ),
                };
            }
            _ => {}
        }
        self.snapshot_subscription(&s.name);
        self.snapshot_generation_counter();
        self.local.generation_counter += 1;
        let new_gen = self.local.generation_counter;
        use crate::_internal::analysis::facts::{AlterSubscriptionActionFact, SubscriptionPublicationMode};
        let mut rename_to = None;
        match &s.action {
            AlterSubscriptionActionFact::SetConnection(connection) => {
                if let Some(crate::_internal::model::replication::SubscriptionOverlay::Present(subscription)) =
                    self.local.subscriptions.get_mut(&s.name)
                {
                    subscription.connection = connection.clone();
                }
            }
            AlterSubscriptionActionFact::SetServer(server) => {
                if let Some(crate::_internal::model::replication::SubscriptionOverlay::Present(subscription)) =
                    self.local.subscriptions.get_mut(&s.name)
                {
                    subscription.connection =
                        crate::_internal::analysis::facts::ConnectionTarget::Server(server.clone());
                }
                self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
            }
            AlterSubscriptionActionFact::Publications {
                mode,
                publications,
                params,
            } => {
                let refreshes =
                    Self::subscription_boolean_option(Some(params), "refresh") != Some(false);
                if refreshes {
                    self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
                }
                if let Some(crate::_internal::model::replication::SubscriptionOverlay::Present(subscription)) =
                    self.local.subscriptions.get_mut(&s.name)
                {
                    match mode {
                        SubscriptionPublicationMode::Set => {
                            subscription.publications = publications.clone();
                        }
                        SubscriptionPublicationMode::Add => {
                            subscription
                                .publications
                                .extend(publications.iter().cloned());
                        }
                        SubscriptionPublicationMode::Drop => {
                            subscription
                                .publications
                                .retain(|existing| !publications.contains(existing));
                        }
                    }
                }
            }
            AlterSubscriptionActionFact::RefreshPublication(_) => {
                self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
            }
            AlterSubscriptionActionFact::SetEnabled(enabled) => {
                if let Some(crate::_internal::model::replication::SubscriptionOverlay::Present(subscription)) =
                    self.local.subscriptions.get_mut(&s.name)
                {
                    subscription.enabled = *enabled;
                }
            }
            AlterSubscriptionActionFact::SetOptions(options) => {
                if let Some(crate::_internal::model::replication::SubscriptionOverlay::Present(subscription)) =
                    self.local.subscriptions.get_mut(&s.name)
                {
                    for option in options {
                        Self::set_subscription_option(subscription, option);
                        if option.name.eq_ignore_ascii_case("slot_name") {
                            subscription.slot_name = (!option.value.eq_ignore_ascii_case("none"))
                                .then(|| option.value.clone());
                        }
                    }
                }
            }
            AlterSubscriptionActionFact::Skip(options) => {
                if let Some(crate::_internal::model::replication::SubscriptionOverlay::Present(subscription)) =
                    self.local.subscriptions.get_mut(&s.name)
                {
                    for option in options {
                        let mut normalized = option.clone();
                        normalized.name = "skip_lsn".to_string();
                        Self::set_subscription_option(subscription, &normalized);
                    }
                }
            }
            AlterSubscriptionActionFact::OwnerChange(role) => {
                if let Some((owner, known)) = self.role_fact_identity(role) {
                    if known {
                        if !self.local.roles_known {
                            self.taint(
                                EvidenceCode::CatalogCoverageIncomplete,
                                EvidenceScope::Chain,
                            );
                        }
                        if let Some(crate::_internal::model::replication::SubscriptionOverlay::Present(
                            subscription,
                        )) = self.local.subscriptions.get_mut(&s.name)
                        {
                            subscription.owner = Some(owner);
                        }
                    } else {
                        self.taint(EvidenceCode::UnresolvedReference, EvidenceScope::Chain);
                        if let Some(crate::_internal::model::replication::SubscriptionOverlay::Present(
                            subscription,
                        )) = self.local.subscriptions.get_mut(&s.name)
                        {
                            subscription.owner = None;
                        }
                    }
                } else {
                    self.taint(EvidenceCode::UnresolvedReference, EvidenceScope::Chain);
                    if let Some(crate::_internal::model::replication::SubscriptionOverlay::Present(
                        subscription,
                    )) = self.local.subscriptions.get_mut(&s.name)
                    {
                        subscription.owner = None;
                    }
                }
            }
            AlterSubscriptionActionFact::Rename { to } => {
                rename_to = Some(to.clone());
            }
        }

        if let Some(crate::_internal::model::replication::SubscriptionOverlay::Present(subscription)) =
            self.local.subscriptions.get_mut(&s.name)
        {
            subscription.generation = new_gen;
        }
        if let Some(to) = rename_to {
            self.snapshot_subscription(&to);
            let Some(crate::_internal::model::replication::SubscriptionOverlay::Present(mut subscription)) =
                self.local.subscriptions.remove(&s.name)
            else {
                unreachable!("subscription existence checked above");
            };
            subscription.name = to.clone();
            self.local.subscriptions.insert(
                to,
                crate::_internal::model::replication::SubscriptionOverlay::Present(subscription),
            );
        }
        MutationResult::Applied
    }

    pub(super) fn apply_drop_subscription(
        &mut self,
        s: &DropSubscriptionMutation,
    ) -> MutationResult {
        let has_slot = match self.subscription_lookup(&s.name) {
            SubscriptionLookup::Present => match self.local.subscriptions.get(&s.name) {
                Some(SubscriptionOverlay::Present(subscription)) => {
                    subscription.slot_name.is_some()
                }
                _ => unreachable!("subscription lookup established presence"),
            },
            SubscriptionLookup::Tombstone => {
                if !s.if_exists {
                    return MutationResult::Conflict {
                        reason: format!("subscription '{}' does not exist", s.name),
                    };
                }
                return MutationResult::Skipped;
            }
            SubscriptionLookup::AuthoritativelyAbsent => {
                if !s.if_exists {
                    return MutationResult::Conflict {
                        reason: format!("subscription '{}' does not exist", s.name),
                    };
                }
                return MutationResult::Skipped;
            }
            SubscriptionLookup::Unknown => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                return MutationResult::Skipped;
            }
            SubscriptionLookup::WrongKind => {
                unreachable!("subscription names have a dedicated namespace")
            }
        };
        if has_slot && !self.local.transactions.is_empty() {
            return MutationResult::Conflict {
                reason: format!(
                    "subscription '{}' has a replication slot and cannot be dropped inside a transaction",
                    s.name
                ),
            };
        }
        self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
        self.snapshot_subscription(&s.name);
        self.local.subscriptions.insert(
            s.name.clone(),
            crate::_internal::model::replication::SubscriptionOverlay::Dropped,
        );
        MutationResult::Applied
    }
}
