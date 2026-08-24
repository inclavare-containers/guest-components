use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Allocates unique filesystem locations for unpacked OCI layers.
#[derive(Clone, Default, Debug)]
pub struct LayerStore {
    /// OCI image layer data store directory.
    pub data_dir: PathBuf,

    /// Next layer index, shared by all clients cloned for concurrent pulls.
    layers_index: Arc<AtomicUsize>,
}

impl LayerStore {
    /// Compute the next numeric index from existing layer directories.
    ///
    /// Non-numeric names are ignored so installations created by the legacy
    /// digest-named layout continue to work after an upgrade.
    pub fn get_layer_index(data_dir: PathBuf) -> anyhow::Result<AtomicUsize> {
        if !data_dir.exists() {
            return Ok(AtomicUsize::new(0));
        }

        let mut next = 0;
        for entry in fs::read_dir(data_dir)? {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
                continue;
            };
            let Ok(index) = name.parse::<usize>() else {
                continue;
            };
            next = next.max(index.saturating_add(1));
        }

        Ok(AtomicUsize::new(next))
    }

    pub fn new(work_dir: PathBuf) -> anyhow::Result<Self> {
        let data_dir = work_dir.join("layers");
        Ok(Self {
            layers_index: Arc::new(Self::get_layer_index(data_dir.clone())?),
            data_dir,
        })
    }

    /// Return a unique store path without requiring the directory to exist yet.
    pub fn new_layer_store_path(&self) -> PathBuf {
        let index = self.layers_index.fetch_add(1, Ordering::Relaxed);
        self.data_dir.join(index.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn store_paths_are_unique_and_resume_after_restart() {
        let work_dir = tempfile::tempdir().unwrap();
        let store = LayerStore::new(work_dir.path().to_path_buf()).unwrap();
        let layer0 = store.new_layer_store_path();
        let layer1 = store.clone().new_layer_store_path();
        assert_eq!(layer0.file_name().unwrap(), "0");
        assert_eq!(layer1.file_name().unwrap(), "1");
        tokio::fs::create_dir_all(&layer0).await.unwrap();
        tokio::fs::create_dir_all(&layer1).await.unwrap();

        // A legacy digest-named directory must neither break migration nor
        // collide with newly allocated numeric locations.
        tokio::fs::create_dir_all(store.data_dir.join("sha256_deadbeef"))
            .await
            .unwrap();
        let restarted = LayerStore::new(work_dir.path().to_path_buf()).unwrap();
        assert_eq!(restarted.new_layer_store_path().file_name().unwrap(), "2");
    }
}
