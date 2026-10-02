use std::sync::{Mutex, MutexGuard, OnceLock};

/// Serializes every test that reads or mutates process-global state, and every
/// test that touches the live database.
///
/// The environment and the disposable test database are both process-wide, so
/// the lock has to be shared by all of them. Holding it on one side only is not
/// enough: a test that *writes* `DATABASE_URL` while another *reads* it without
/// the lock is still a data race, and the reader silently changes behaviour
/// depending on when it happens to run.
fn shared_state_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) struct EnvironmentValueGuard {
    _lock: MutexGuard<'static, ()>,
    name: &'static str,
    previous: Option<String>,
}

impl EnvironmentValueGuard {
    pub(crate) fn set(name: &'static str, value: &str) -> Self {
        let lock = shared_state_lock();
        let previous = std::env::var(name).ok();
        unsafe {
            std::env::set_var(name, value);
        }
        Self {
            _lock: lock,
            name,
            previous,
        }
    }

    pub(crate) fn remove(name: &'static str) -> Self {
        let lock = shared_state_lock();
        let previous = std::env::var(name).ok();
        unsafe {
            std::env::remove_var(name);
        }
        Self {
            _lock: lock,
            name,
            previous,
        }
    }
}

impl Drop for EnvironmentValueGuard {
    fn drop(&mut self) {
        // This guard still owns the process-wide lock.
        unsafe {
            if let Some(previous) = &self.previous {
                std::env::set_var(self.name, previous);
            } else {
                std::env::remove_var(self.name);
            }
        }
    }
}

/// Held for the whole body of a test that connects to the live database.
///
/// Acquiring it excludes environment-mutating tests, so a test can never observe
/// a `DATABASE_URL` that another test has temporarily replaced or removed, and
/// excludes other live tests, so they cannot collide over shared fixtures.
pub(crate) struct LiveDatabaseGuard(#[allow(dead_code)] MutexGuard<'static, ()>);

impl LiveDatabaseGuard {
    pub(crate) fn acquire() -> Self {
        Self(shared_state_lock())
    }

    /// The live database URL, or `None` when the variable is unset.
    ///
    /// Must be read through the guard: the value cannot be read safely without
    /// holding the lock that keeps other tests from replacing it. Deliberately
    /// unfiltered, so each caller keeps its own empty-value handling.
    pub(crate) fn url(&self) -> Option<String> {
        std::env::var("DATABASE_URL").ok()
    }
}
