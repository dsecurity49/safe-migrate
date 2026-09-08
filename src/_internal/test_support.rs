use std::sync::{Mutex, MutexGuard};

static ENVIRONMENT_LOCK: Mutex<()> = Mutex::new(());

pub(crate) struct EnvironmentValueGuard {
    _lock: MutexGuard<'static, ()>,
    name: &'static str,
    previous: Option<String>,
}

impl EnvironmentValueGuard {
    pub(crate) fn set(name: &'static str, value: &str) -> Self {
        let lock = ENVIRONMENT_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = std::env::var(name).ok();
        // The process-wide lock serializes every test helper that mutates the environment.
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
        let lock = ENVIRONMENT_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = std::env::var(name).ok();
        // The process-wide lock serializes every test helper that mutates the environment.
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
        // This guard still owns the process-wide environment lock.
        unsafe {
            if let Some(previous) = &self.previous {
                std::env::set_var(self.name, previous);
            } else {
                std::env::remove_var(self.name);
            }
        }
    }
}
