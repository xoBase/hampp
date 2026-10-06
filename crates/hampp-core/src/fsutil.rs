use std::io::Write;
use std::path::Path;

/// Writes `data` to `path` via a temp file in the same directory and an atomic rename,
/// so a crash never leaves a half-written state file behind.
pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    let tmp = dir.join(format!(
        ".{}.tmp{}",
        name.to_string_lossy(),
        std::process::id()
    ));
    let result = (|| {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Adds the path to an io error so messages say *which* file failed.
pub fn io_ctx(path: &Path) -> impl FnOnce(std::io::Error) -> std::io::Error + '_ {
    move |e| std::io::Error::new(e.kind(), format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_replaces_content_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("state.json");
        write_atomic(&p, b"one").unwrap();
        write_atomic(&p, b"two").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "two");
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(
            names,
            vec!["state.json".to_string()],
            "no temp file may remain"
        );
    }

    #[test]
    fn failed_write_keeps_the_old_file_intact() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("state.json");
        write_atomic(&p, b"good").unwrap();
        // a directory squatting on the temp name makes the temp file impossible to create
        let tmp = dir
            .path()
            .join(format!(".state.json.tmp{}", std::process::id()));
        std::fs::create_dir(&tmp).unwrap();
        assert!(write_atomic(&p, b"new").is_err());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "good");
    }

    #[test]
    fn missing_parent_directory_is_an_error_and_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("nope").join("state.json");
        assert!(write_atomic(&p, b"x").is_err());
        assert!(!dir.path().join("nope").exists());
    }

    #[test]
    fn io_ctx_puts_the_path_into_the_message() {
        let e = std::fs::read_to_string("/definitely/not/here.json")
            .map_err(io_ctx(std::path::Path::new("/definitely/not/here.json")))
            .unwrap_err();
        assert!(e.to_string().contains("/definitely/not/here.json"), "{e}");
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
    }
}
