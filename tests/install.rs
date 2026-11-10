//! Exercise the real installer and binary, replacing only the download transport.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

struct Fixture {
    tmp: TempDir,
    asset: String,
}

impl Fixture {
    fn new() -> Self {
        let f = Self {
            tmp: tempfile::tempdir().unwrap(),
            asset: format!(
                "jinnang-{}-unknown-linux-musl.tar.gz",
                std::env::consts::ARCH
            ),
        };
        for dir in ["home", "tmp", "transport", "package"] {
            fs::create_dir(f.path(dir)).unwrap();
        }
        fs::copy(env!("CARGO_BIN_EXE_jinnang"), f.path("package/jinnang")).unwrap();
        f.pack();
        executable(
            &f.path("transport/curl"),
            r#"#!/usr/bin/env bash
set -euo pipefail
out=''
url=''
while (($#)); do
    case "$1" in
        --output) out=$2; shift 2 ;;
        --write-out) shift 2 ;;
        --fail|--silent|--show-error|--location|--head) shift ;;
        https://*) url=$1; shift ;;
        *) exit 2 ;;
    esac
done
printf '%s\n' "$url" >> "$FIXTURE/requests"
[[ ${FAIL_DOWNLOAD:-0} != 1 ]] || exit 22
case "$url" in
    https://github.com/MarioJames/JinNang/releases/latest)
        printf '%s' 'https://github.com/MarioJames/JinNang/releases/tag/main-test' ;;
    https://github.com/MarioJames/JinNang/releases/download/main-test/SHA256SUMS)
        cp "$FIXTURE/SHA256SUMS" "$out" ;;
    "https://github.com/MarioJames/JinNang/releases/download/main-test/$ASSET")
        cp "$FIXTURE/$ASSET" "$out" ;;
    *) exit 22 ;;
esac
"#,
        );
        f
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.tmp.path().join(rel)
    }

    fn pack(&self) {
        let tar = Command::new("tar")
            .arg("-czf")
            .arg(self.path(&self.asset))
            .arg("-C")
            .arg(self.path("package"))
            .arg("jinnang")
            .output()
            .unwrap();
        assert!(tar.status.success(), "{tar:?}");
        let sum = Command::new("sha256sum")
            .arg(&self.asset)
            .current_dir(self.tmp.path())
            .output()
            .unwrap();
        assert!(sum.status.success(), "{sum:?}");
        fs::write(self.path("SHA256SUMS"), sum.stdout).unwrap();
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new("bash");
        c.arg(concat!(env!("CARGO_MANIFEST_DIR"), "/install.sh"))
            .env_clear()
            .env("HOME", self.path("home"))
            .env("TMPDIR", self.path("tmp"))
            .env("FIXTURE", self.tmp.path())
            .env("ASSET", &self.asset)
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.path("transport").display()),
            );
        c
    }

    fn assert_clean(&self, install_dir: &Path) {
        assert_eq!(fs::read_dir(self.path("tmp")).unwrap().count(), 0);
        for entry in fs::read_dir(install_dir).unwrap() {
            assert!(
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".jinnang.")
            );
        }
    }
}

fn executable(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn success(out: Output) -> String {
    assert!(out.status.success(), "{out:?}");
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn installs_latest_binary_and_upgrades_in_place_without_touching_the_vault() {
    let f = Fixture::new();
    let vault = f.path("home/.local/share/jinnang/vault");
    fs::create_dir_all(&vault).unwrap();
    fs::write(vault.join("sentinel"), b"keep vault data").unwrap();
    let bin = f.path("home/.local/bin/jinnang");
    let text = success(f.cmd().output().unwrap());
    assert!(text.contains("Installed main-test"), "{text}");
    assert!(text.contains("export PATH="), "{text}");
    let expected = fs::read(env!("CARGO_BIN_EXE_jinnang")).unwrap();
    assert_eq!(fs::read(&bin).unwrap(), expected);
    assert!(success(Command::new(&bin).arg("--version").output().unwrap()).starts_with("jinnang "));
    fs::write(&bin, b"old version").unwrap();
    success(f.cmd().output().unwrap());
    assert_eq!(fs::read(&bin).unwrap(), expected);
    assert_eq!(
        fs::read(vault.join("sentinel")).unwrap(),
        b"keep vault data"
    );
    f.assert_clean(bin.parent().unwrap());
}

#[test]
fn installs_a_pinned_release_to_a_custom_directory_with_spaces() {
    let f = Fixture::new();
    let dir = f.path("custom bin");
    success(
        f.cmd()
            .env("JINNANG_VERSION", "main-test")
            .env("JINNANG_INSTALL_DIR", &dir)
            .output()
            .unwrap(),
    );
    assert_eq!(
        fs::read(dir.join("jinnang")).unwrap(),
        fs::read(env!("CARGO_BIN_EXE_jinnang")).unwrap()
    );
    let requests = fs::read_to_string(f.path("requests")).unwrap();
    assert!(!requests.contains("/releases/latest"), "{requests}");
    f.assert_clean(&dir);
}

#[test]
fn failed_download_bad_checksum_and_unusable_binary_preserve_old_install() {
    for failure in ["download", "checksum", "missing checksum", "binary"] {
        let f = Fixture::new();
        let dir = f.path("bin");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("jinnang"), b"old binary").unwrap();
        let mut c = f.cmd();
        c.env("JINNANG_INSTALL_DIR", &dir)
            .env("JINNANG_VERSION", "main-test");
        match failure {
            "download" => {
                c.env("FAIL_DOWNLOAD", "1");
            }
            "checksum" => {
                fs::write(f.path(&f.asset), b"corrupt download").unwrap();
            }
            "missing checksum" => {
                fs::write(f.path("SHA256SUMS"), b"").unwrap();
            }
            "binary" => {
                executable(&f.path("package/jinnang"), "#!/bin/sh\nexit 1\n");
                f.pack();
            }
            _ => unreachable!(),
        }
        let out = c.output().unwrap();
        assert!(!out.status.success(), "{failure}: {out:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        if failure == "checksum" {
            assert!(err.contains("SHA-256 verification failed"), "{err}");
        } else if failure == "missing checksum" {
            assert!(err.contains("missing or duplicate checksum"), "{err}");
        }
        assert_eq!(
            fs::read(dir.join("jinnang")).unwrap(),
            b"old binary",
            "{failure}"
        );
        f.assert_clean(&dir);
    }
}

#[test]
fn rejects_unsupported_platform_and_invalid_tags_before_downloading() {
    let f = Fixture::new();
    executable(&f.path("transport/uname"), "#!/bin/sh\nprintf Darwin\n");
    let out = f.cmd().output().unwrap();
    assert!(!out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("only Linux"));
    fs::remove_file(f.path("transport/uname")).unwrap();
    let out = f.cmd().env("JINNANG_VERSION", "../bad").output().unwrap();
    assert!(!out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("invalid release tag"));
    assert!(!f.path("requests").exists());
}
