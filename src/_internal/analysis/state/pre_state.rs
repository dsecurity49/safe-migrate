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
            baseline_foreign_keys: ReadScope::All,
        }
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

        // Search from the oldest transaction frame to the newest
        for frame in &self.local.transactions {
            for change in &frame.undo_log {
                if let StateChange::RelationSnapshot { id, previous } = change
                    && id == table_id
                {
                    match previous.as_ref() {
                        None | Some(RelationOverlay::Dropped) => {
                            return true;
                        }
                        Some(RelationOverlay::Present(r)) => {
                            let col_existed = r.columns.iter().any(|c| c.name == column);
                            return !col_existed;
                        }
                    }
                }
            }
        }
        false
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
