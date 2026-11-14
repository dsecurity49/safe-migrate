use super::*;

/// Which entries of one catalog family the current transition can read.
///
/// `None` clears the family so a reused snapshot cannot leak data from an
/// earlier mutation. Rule code sees the resulting maps unchanged; the scope only
/// controls how much of the live state is copied into them.
#[derive(Clone, Debug)]
pub(crate) enum ReadScope<K> {
    None,
    Selected(HashSet<K>),
    All,
}

// Deriving Default would require K: Default, which the key types do not
// implement even though the default variant carries no key.
#[allow(clippy::derivable_impls)]
impl<K> Default for ReadScope<K> {
    fn default() -> Self {
        Self::None
    }
}

impl<K> ReadScope<K>
where
    K: Eq + std::hash::Hash,
{
    pub(crate) fn selected(ids: impl IntoIterator<Item = K>) -> Self {
        Self::Selected(ids.into_iter().collect())
    }

    pub(crate) fn insert(&mut self, id: K) {
        match self {
            Self::None => *self = Self::Selected(HashSet::from([id])),
            Self::Selected(ids) => {
                ids.insert(id);
            }
            Self::All => {}
        }
    }

    pub(crate) fn require_all(&mut self) {
        *self = Self::All;
    }
}

/// The pre-state footprint of one transition.
///
/// Rules read pre-state through keyed lookups and a few whole-family scans.
/// This records exactly which families and keys those reads can touch, so the
/// engine does not rebuild the entire modeled catalog before every mutation.
#[derive(Clone, Debug, Default)]
pub(crate) struct PreStateReadSet {
    pub relations: ReadScope<ObjectId>,
    pub functions: ReadScope<ObjectId>,
    pub roles: ReadScope<ObjectId>,
    pub publications: ReadScope<String>,
    pub subscriptions: ReadScope<String>,
    pub sequences: ReadScope<ObjectId>,
    pub extensions: ReadScope<String>,
    pub types: ReadScope<ObjectId>,
    pub indexes: ReadScope<ObjectId>,
    pub constraints: ReadScope<(ObjectId, String)>,
    pub baseline_foreign_keys: ReadScope<(ObjectId, String)>,
}

impl PreStateReadSet {
    pub(crate) fn none() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub(crate) fn full() -> Self {
        Self {
            relations: ReadScope::All,
            functions: ReadScope::All,
            roles: ReadScope::All,
            publications: ReadScope::All,
            subscriptions: ReadScope::All,
            sequences: ReadScope::All,
            extensions: ReadScope::All,
            types: ReadScope::All,
            indexes: ReadScope::All,
            constraints: ReadScope::All,
            baseline_foreign_keys: ReadScope::All,
        }
    }
}

#[derive(Default)]
struct RelationColumnProvenance {
    present: Option<Vec<String>>,
    created: HashMap<String, bool>,
    dropped: HashMap<String, bool>,
}

impl RelationColumnProvenance {
    /// Reconcile the simulated state with the relation state before one
    /// mutation, inferring additions, drops, and same-position renames.
    fn observe_snapshot(&mut self, previous: &Option<RelationOverlay>) {
        let next_columns: Vec<String> = match previous {
            Some(RelationOverlay::Present(relation)) => relation
                .columns
                .iter()
                .map(|column| column.name.clone())
                .collect(),
            // The relation was absent or tombstoned, so this mutation
            // recreated it; every column in the following state is new.
            None | Some(RelationOverlay::Dropped) => {
                self.present = Some(Vec::new());
                self.created.clear();
                self.dropped.clear();
                return;
            }
        };

        match self.present.take() {
            None => {
                for name in &next_columns {
                    self.created.insert(name.clone(), false);
                }
            }
            Some(previous_columns) => {
                let removed: Vec<(usize, &String)> = previous_columns
                    .iter()
                    .enumerate()
                    .filter(|(_, name)| !next_columns.contains(name))
                    .collect();
                let added: Vec<(usize, &String)> = next_columns
                    .iter()
                    .enumerate()
                    .filter(|(_, name)| !previous_columns.contains(name))
                    .collect();

                let renamed = removed.len() == 1 && added.len() == 1 && removed[0].0 == added[0].0;
                if renamed {
                    let was_created = self.created.remove(removed[0].1).unwrap_or(false);
                    self.created.insert(added[0].1.clone(), was_created);
                } else {
                    for (_, name) in removed {
                        self.dropped
                            .insert(name.clone(), self.created.remove(name).unwrap_or(false));
                    }
                    for (_, name) in added {
                        self.created.insert(name.clone(), true);
                    }
                }
            }
        }

        self.present = Some(next_columns);
    }

    fn was_created(&self, column: &str) -> bool {
        self.created
            .get(column)
            .copied()
            .or_else(|| self.dropped.get(column).copied())
            .unwrap_or(false)
    }
}

impl AnalysisState {
    pub(crate) fn column_was_added_in_transaction(
        &self,
        table_id: &ObjectId,
        column: &str,
    ) -> bool {
        if self.local.transactions.is_empty() {
            return false;
        }

        // Replay pre-mutation snapshots chronologically, moving each relation's
        // provenance with its rename. The id is not stable: `ALTER TABLE ...
        // RENAME TO` (or a schema move) changes it mid-transaction, and a later
        // table may reuse the old name.
        let mut relations: HashMap<ObjectId, RelationColumnProvenance> = HashMap::new();
        for frame in &self.local.transactions {
            for change in &frame.undo_log {
                match change {
                    StateChange::RelationSnapshot { id, previous } => {
                        relations
                            .entry(id.clone())
                            .or_default()
                            .observe_snapshot(previous.as_ref());
                    }
                    StateChange::RelationRename { old_id, new_id, .. } => {
                        let moved = relations.remove(old_id).unwrap_or_default();
                        relations.insert(new_id.clone(), moved);
                    }
                    _ => {}
                }
            }
        }

        relations
            .get(table_id)
            .is_some_and(|relation| relation.was_created(column))
    }

    #[cfg(test)]
    pub(crate) fn capture_pre_state(&self) -> PreState {
        let mut pre_state = PreState::default();
        self.capture_pre_state_into(&mut pre_state, &PreStateReadSet::full());
        pre_state
    }

    pub(crate) fn capture_pre_state_into(&self, pre_state: &mut PreState, reads: &PreStateReadSet) {
        let PreState {
            relations,
            functions,
            roles,
            publications,
            subscriptions,
            sequences,
            extensions,
            types,
            indexes,
            constraints,
            baseline_foreign_keys,
        } = pre_state;

        sync_selected_map(
            relations,
            &self.local.relations,
            &reads.relations,
            |overlay| match overlay {
                RelationOverlay::Present(state) => Some(state),
                RelationOverlay::Dropped => None,
            },
        );
        sync_selected_map(
            functions,
            &self.local.functions,
            &reads.functions,
            |overlay| match overlay {
                crate::_internal::model::function::FunctionOverlay::Present(state) => Some(state),
                crate::_internal::model::function::FunctionOverlay::Dropped => None,
            },
        );
        sync_selected_map(
            roles,
            &self.local.roles,
            &reads.roles,
            |overlay| match overlay {
                crate::_internal::model::role::RoleOverlay::Present(state) => Some(state),
                crate::_internal::model::role::RoleOverlay::Dropped => None,
            },
        );
        sync_selected_map(
            publications,
            &self.local.publications,
            &reads.publications,
            |overlay| match overlay {
                crate::_internal::model::replication::PublicationOverlay::Present(state) => {
                    Some(state)
                }
                crate::_internal::model::replication::PublicationOverlay::Dropped => None,
            },
        );
        sync_selected_map(
            subscriptions,
            &self.local.subscriptions,
            &reads.subscriptions,
            |overlay| match overlay {
                crate::_internal::model::replication::SubscriptionOverlay::Present(state) => {
                    Some(state)
                }
                crate::_internal::model::replication::SubscriptionOverlay::Dropped => None,
            },
        );
        sync_selected_map(
            sequences,
            &self.local.sequences,
            &reads.sequences,
            |overlay| match overlay {
                SequenceOverlay::Present(state) => Some(state),
                SequenceOverlay::Dropped => None,
            },
        );
        sync_selected_map(
            extensions,
            &self.local.extensions,
            &reads.extensions,
            |overlay| match overlay {
                crate::_internal::model::extension::ExtensionOverlay::Present(state) => Some(state),
                crate::_internal::model::extension::ExtensionOverlay::Dropped => None,
            },
        );
        sync_selected_map(
            types,
            &self.local.types,
            &reads.types,
            |overlay| match overlay {
                TypeOverlay::Present(state) => Some(state),
                TypeOverlay::Dropped => None,
            },
        );

        match &reads.indexes {
            ReadScope::None => indexes.clear(),
            ReadScope::Selected(ids) => {
                indexes.clear();
                indexes.extend(
                    self.local
                        .graph
                        .edges_for_dependents(ids)
                        .filter(|edge| matches!(edge.kind, DependencyKind::IndexOnRelation { .. }))
                        .cloned(),
                );
            }
            ReadScope::All => {
                let mut index = 0;
                for edge in self
                    .local
                    .graph
                    .edges()
                    .iter()
                    .filter(|edge| matches!(edge.kind, DependencyKind::IndexOnRelation { .. }))
                {
                    if let Some(existing) = indexes.get_mut(index) {
                        if existing != edge {
                            existing.clone_from(edge);
                        }
                    } else {
                        indexes.push(edge.clone());
                    }
                    index += 1;
                }
                indexes.truncate(index);
            }
        }

        sync_selected_map(
            constraints,
            &self.local.constraints,
            &reads.constraints,
            |constraint| Some(constraint),
        );

        match &reads.baseline_foreign_keys {
            ReadScope::None => baseline_foreign_keys.clear(),
            ReadScope::Selected(pairs) => {
                baseline_foreign_keys.clear();
                baseline_foreign_keys.extend(
                    pairs
                        .iter()
                        .filter(|pair| self.baseline_foreign_keys.contains(*pair))
                        .cloned(),
                );
            }
            ReadScope::All => baseline_foreign_keys.clone_from(&self.baseline_foreign_keys),
        }
    }
}

fn sync_selected_map<K, V, O, F>(
    target: &mut HashMap<K, V>,
    source: &HashMap<K, O>,
    scope: &ReadScope<K>,
    present: F,
) where
    K: Clone + Eq + std::hash::Hash,
    V: Clone + PartialEq,
    F: for<'a> Fn(&'a O) -> Option<&'a V> + Copy,
{
    match scope {
        ReadScope::None => target.clear(),
        ReadScope::All => sync_present_map(target, source, present),
        ReadScope::Selected(ids) => {
            target.retain(|key, _| ids.contains(key));
            target.reserve(ids.len().saturating_sub(target.len()));
            for id in ids {
                match source.get(id).and_then(present) {
                    Some(value) => {
                        if let Some(existing) = target.get_mut(id) {
                            if existing != value {
                                existing.clone_from(value);
                            }
                        } else {
                            target.insert(id.clone(), value.clone());
                        }
                    }
                    None => {
                        target.remove(id);
                    }
                }
            }
        }
    }
}
