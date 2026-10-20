use super::*;

pub(super) fn write_cache(out_path: &Path, cache: DbCache, cache_encryption: bool) -> Result<()> {
    write_cache_with_protection(out_path, cache, |compressed| {
        protect_cache_bytes(compressed, cache_encryption)
    })
}

pub(super) fn write_cache_with_key(out_path: &Path, cache: DbCache, key: &[u8; 32]) -> Result<()> {
    write_cache_with_protection(out_path, cache, |compressed| {
        protect_cache_bytes_with_key(compressed, key)
    })
}

pub(super) fn write_cache_with_protection(
    out_path: &Path,
    cache: DbCache,
    protect: impl FnOnce(Vec<u8>) -> Result<Vec<u8>>,
) -> Result<()> {
    write_cache_with_protection_and_limits(
        out_path,
        cache,
        protect,
        MAX_CACHE_FILE_BYTES,
        MAX_CACHE_DECODE_BYTES,
    )
}

pub(super) fn write_cache_with_protection_and_limits(
    out_path: &Path,
    cache: DbCache,
    protect: impl FnOnce(Vec<u8>) -> Result<Vec<u8>>,
    max_file_bytes: u64,
    max_decode_bytes: usize,
) -> Result<()> {
    cache
        .validate_semantics()
        .map_err(anyhow::Error::msg)
        .context("Refusing to write a semantically invalid cache baseline")?;
    let parent = cache_parent(out_path);
    let mut temp_file = NamedTempFile::new_in(parent).with_context(|| {
        format!(
            "Failed to create temporary cache file beside {}",
            out_path.display()
        )
    })?;
    let mut compressed = Vec::new();
    let encoder = zstd::stream::Encoder::new(&mut compressed, 3)
        .context("Failed to init zstd compression")?;
    let mut encoder = SizeLimitedWriter::new(encoder, max_decode_bytes);

    if let Err(error) = encoder.write_all(CACHE_MAGIC) {
        if encoder.limit_exceeded() {
            anyhow::bail!(
                "Cache payload exceeds the {} MiB decoded-size limit",
                max_decode_bytes / (1024 * 1024)
            );
        }
        return Err(error).context("Failed to write cache payload header");
    }

    let versioned = DbCacheVersioned::current(cache);
    let bincode_config = bincode::config::standard().with_variable_int_encoding();

    let encode_result =
        bincode::serde::encode_into_std_write(&versioned, &mut encoder, bincode_config);
    if encoder.limit_exceeded() {
        anyhow::bail!(
            "Cache payload exceeds the {} MiB decoded-size limit",
            max_decode_bytes / (1024 * 1024)
        );
    }
    encode_result.context("Failed bincode schema compilation and write")?;

    let encoder = encoder.into_inner();
    encoder
        .finish()
        .context("Failed to flush final zstd stream to disk")?;

    let cache_bytes = protect(compressed)?;
    let cache_file_bytes = u64::try_from(cache_bytes.len()).unwrap_or(u64::MAX);
    if cache_file_bytes > max_file_bytes {
        anyhow::bail!(
            "Cache payload exceeds the {} MiB encoded-size limit",
            max_file_bytes / (1024 * 1024)
        );
    }
    temp_file
        .write_all(&cache_bytes)
        .context("Failed to write cache payload")?;
    temp_file.flush().context("Failed to flush cache payload")?;
    temp_file
        .as_file()
        .sync_all()
        .context("Failed to synchronize cache payload before installation")?;

    replace_cache(temp_file, out_path)?;

    Ok(())
}

pub(super) fn cache_parent(out_path: &Path) -> &Path {
    out_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

// This bounds decoded bytes entering zstd, not the compressed output size.
pub(super) struct SizeLimitedWriter<W> {
    inner: W,
    bytes_written: usize,
    max_bytes: usize,
    limit_exceeded: bool,
}

impl<W> SizeLimitedWriter<W> {
    fn new(inner: W, max_bytes: usize) -> Self {
        Self {
            inner,
            bytes_written: 0,
            max_bytes,
            limit_exceeded: false,
        }
    }

    fn limit_exceeded(&self) -> bool {
        self.limit_exceeded
    }

    fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for SizeLimitedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.max_bytes.saturating_sub(self.bytes_written) {
            self.limit_exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cache decoded-size limit exceeded",
            ));
        }

        let written = self.inner.write(bytes)?;
        self.bytes_written = self.bytes_written.saturating_add(written);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(not(windows))]
pub(super) fn replace_cache(temp_file: NamedTempFile, out_path: &Path) -> Result<()> {
    temp_file
        .persist(out_path)
        .map_err(|error| error.error)
        .with_context(|| {
            format!(
                "Failed to atomically replace cache file: {}",
                out_path.display()
            )
        })?;
    let parent = cache_parent(out_path);
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| {
            format!(
                "Installed cache but failed to synchronize its parent directory: {}",
                parent.display()
            )
        })?;
    Ok(())
}

#[cfg(windows)]
pub(super) fn replace_cache(temp_file: NamedTempFile, out_path: &Path) -> Result<()> {
    let backup = out_path.with_extension("safe-migrate.backup");
    if backup.exists() {
        if out_path.exists() {
            fs::remove_file(&backup).with_context(|| {
                format!(
                    "Failed to remove stale cache backup before replacement: {}",
                    backup.display()
                )
            })?;
        } else {
            fs::rename(&backup, out_path).with_context(|| {
                format!(
                    "Failed to restore interrupted cache replacement from backup: {}",
                    backup.display()
                )
            })?;
        }
    }

    if !out_path.exists() {
        temp_file
            .persist(out_path)
            .map_err(|error| error.error)
            .with_context(|| format!("Failed to install cache file: {}", out_path.display()))?;
        return Ok(());
    }

    fs::rename(out_path, &backup).with_context(|| {
        format!(
            "Failed to stage existing cache for replacement: {}",
            out_path.display()
        )
    })?;

    match temp_file.persist(out_path) {
        Ok(_) => {
            fs::remove_file(&backup).with_context(|| {
                format!(
                    "Installed new cache but failed to remove backup: {}",
                    backup.display()
                )
            })?;
            Ok(())
        }
        Err(error) => {
            let restore_result = fs::rename(&backup, out_path);
            let message = if let Err(restore_error) = restore_result {
                format!(
                    "Failed to install new cache: {}. The old cache could not be restored: {}",
                    error.error, restore_error
                )
            } else {
                format!(
                    "Failed to install new cache; restored the previous cache: {}",
                    error.error
                )
            };
            Err(anyhow::anyhow!(message))
        }
    }
}
