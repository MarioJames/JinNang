//! End-to-end checks of the M1 storage guarantees through the real binary.

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

const PASS: &str = "correct horse battery staple";
const DB_PASSWORD: &str = "s3cr3t-db-password-7f9a";
const TOTP_SEED: &str = "JBSWY3DPEHPK3PXP";

struct Env {
    tmp: TempDir,
}

impl Env {
    fn new() -> Self {
        let env = Self {
            tmp: TempDir::new().unwrap(),
        };
        fs::write(env.path("pass"), format!("{PASS}\n")).unwrap();
        env
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.tmp.path().join(rel)
    }

    fn vault(&self) -> PathBuf {
        self.path("vault")
    }

    /// Runs jinnang against `vault` with an isolated HOME/state dir. `pass` selects
    /// the passphrase file (None = no passphrase source and no tty prompts expected).
    fn cmd_at(&self, vault: &Path, pass: Option<&str>) -> Command {
        let mut c = Command::cargo_bin("jinnang").unwrap();
        c.env_clear()
            .env("HOME", self.path("home"))
            .env("JINNANG_STATE_DIR", self.path("state"))
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .arg("--vault")
            .arg(vault);
        if let Some(p) = pass {
            c.env("JINNANG_PASSPHRASE_FILE", self.path(p));
        }
        c
    }

    fn cmd(&self) -> Command {
        self.cmd_at(&self.vault(), Some("pass"))
    }

    fn init(&self) {
        self.cmd()
            .args(["init", "--recovery-kit"])
            .arg(self.path("kit.json"))
            .assert()
            .success();
    }

    fn set_dsn(&self, password: &str) -> Output {
        let json = format!(
            r#"{{"driver":"postgres","host":"db.internal","port":"5432","database":"app","username":"app_rw","password":"{password}"}}"#
        );
        run(self
            .cmd()
            .args([
                "set",
                "jn://prod/acme/app-db",
                "--type",
                "dsn",
                "--stdin-json",
            ])
            .write_stdin(json))
    }

    fn manifest(&self) -> Value {
        let signed: Value =
            serde_json::from_slice(&fs::read(self.vault().join("manifest.json")).unwrap()).unwrap();
        serde_json::from_str(signed["body"].as_str().unwrap()).unwrap()
    }

    fn entry_dir(&self) -> PathBuf {
        let id = self.manifest()["entries"][0]["id"]
            .as_str()
            .unwrap()
            .to_string();
        self.vault().join("entries").join(id)
    }
}

struct Output {
    ok: bool,
    text: String,
}

fn run(cmd: &mut Command) -> Output {
    let out = cmd.output().unwrap();
    Output {
        ok: out.status.success(),
        text: format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    }
}

fn assert_no_secret(text: &str) {
    for secret in [DB_PASSWORD, TOTP_SEED, PASS] {
        assert!(!text.contains(secret), "secret leaked into output:\n{text}");
    }
}

#[test]
fn stores_entries_without_exposing_secret_values() {
    let env = Env::new();
    env.init();
    for path in ["vault", "vault/entries", "vault/pending"] {
        assert_eq!(mode(&env.path(path)), 0o700, "{path}");
    }
    for path in [
        "vault/identity.age",
        "vault/vault.json",
        "vault/manifest.json",
        "kit.json",
    ] {
        assert_eq!(mode(&env.path(path)), 0o600, "{path}");
    }

    let set = env.set_dsn(DB_PASSWORD);
    assert!(set.ok, "{}", set.text);
    assert!(set.text.contains("stored jn://prod/acme/app-db v1"));

    let ls = run(env.cmd().args(["ls", "--json"]));
    let inspect = run(env.cmd().args(["inspect", "jn://prod/acme/app-db"]));
    assert!(ls.ok && inspect.ok);
    let listed: Value = serde_json::from_str(&ls.text).unwrap();
    assert_eq!(listed[0]["public"]["host"], "db.internal");
    assert_eq!(listed[0]["secret_fields"], serde_json::json!(["password"]));
    assert!(inspect.text.contains("password                 <secret>"));
    for out in [&set.text, &ls.text, &inspect.text] {
        assert_no_secret(out);
    }
    // Nothing on disk outside the encrypted files carries the value.
    for file in ["vault/manifest.json", "vault/vault.json"] {
        assert_no_secret(&fs::read_to_string(env.path(file)).unwrap());
    }

    let deep = run(env.cmd().args(["verify", "--deep"]));
    assert!(deep.ok, "{}", deep.text);
    assert!(deep.text.contains("1 decrypted"));
}

#[test]
fn locked_writes_stay_pending_until_activated() {
    let env = Env::new();
    env.init();
    let json = format!(r#"{{"uri":"otpauth://totp/ACME:ops?secret={TOTP_SEED}&issuer=ACME"}}"#);
    let set = run(env
        .cmd_at(&env.vault(), None)
        .args([
            "set",
            "jn://test/acme/ops-otp",
            "--type",
            "totp",
            "--stdin-json",
            "--pending",
        ])
        .write_stdin(json));
    assert!(set.ok, "{}", set.text);
    assert!(set.text.contains("pending candidate"));
    assert!(
        run(env.cmd().arg("ls")).text.is_empty(),
        "candidate must not be listed before activation"
    );

    let ls = run(env.cmd().args(["pending", "ls"]));
    let id = ls.text.split_whitespace().next().unwrap().to_string();

    fs::write(env.path("wrong"), "not the passphrase at all\n").unwrap();
    let wrong = run(env
        .cmd_at(&env.vault(), Some("wrong"))
        .args(["pending", "activate", &id]));
    assert!(!wrong.ok);
    assert!(wrong.text.contains("wrong passphrase"));
    assert!(
        run(env.cmd().args(["pending", "ls"])).text.contains(&id),
        "candidate stays pending after failure"
    );

    let act = run(env.cmd().args(["pending", "activate", &id]));
    assert!(act.ok, "{}", act.text);
    let inspect = run(env
        .cmd()
        .args(["inspect", "jn://test/acme/ops-otp", "--json"]));
    let v: Value = serde_json::from_str(&inspect.text).unwrap();
    assert_eq!(v["public"]["issuer"], "ACME");
    assert_eq!(v["public"]["digits"], "6");
    assert_eq!(v["secret_fields"], serde_json::json!(["seed"]));
    for out in [&set.text, &ls.text, &wrong.text, &act.text, &inspect.text] {
        assert_no_secret(out);
    }
}

#[test]
fn rotation_keeps_history_and_rejects_conflicts() {
    let env = Env::new();
    env.init();
    assert!(env.set_dsn(DB_PASSWORD).ok);
    let again = env.set_dsn("other");
    assert!(!again.ok && again.text.contains("already exists"));

    // Two candidates for the same next version: the second one must not overwrite.
    let rotate = |pw: &str| {
        run(env
            .cmd()
            .args(["rotate", "jn://prod/acme/app-db", "--stdin-json", "--pending"])
            .write_stdin(format!(r#"{{"driver":"postgres","host":"db2","database":"app","username":"app_rw","password":"{pw}"}}"#)))
    };
    assert!(rotate("pw-two").ok && rotate("pw-three").ok);
    let act = run(env.cmd().args(["pending", "activate", "--all"]));
    assert!(!act.ok, "second candidate must conflict");
    assert!(act.text.contains("conflict"));
    let v: Value = serde_json::from_str(
        &run(env
            .cmd()
            .args(["inspect", "jn://prod/acme/app-db", "--json"]))
        .text,
    )
    .unwrap();
    assert_eq!(v["version"], 2);
    assert_eq!(v["versions"], serde_json::json!([1, 2]));
    assert_eq!(v["public"]["host"], "db2");
}

#[test]
fn tampered_or_swapped_ciphertexts_are_detected() {
    let env = Env::new();
    env.init();
    assert!(env.set_dsn(DB_PASSWORD).ok);

    // A pending candidate whose ciphertext is another entry's payload (unsigned
    // pending record pointing at copied ciphertext) must not be published.
    let stolen = fs::read(env.entry_dir().join("v1.age")).unwrap();
    let pend = run(env
        .cmd()
        .args([
            "set",
            "jn://dev/acme/other",
            "--type",
            "password",
            "--stdin-json",
            "--pending",
        ])
        .write_stdin(r#"{"password":"x"}"#));
    assert!(pend.ok);
    let id = run(env.cmd().args(["pending", "ls"]))
        .text
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    let meta_path = env.vault().join(format!("pending/{id}.json"));
    let mut meta: Value = serde_json::from_slice(&fs::read(&meta_path).unwrap()).unwrap();
    meta["digest"] = Value::String(sha256(&stolen));
    fs::write(&meta_path, serde_json::to_vec(&meta).unwrap()).unwrap();
    fs::write(env.vault().join(format!("pending/{id}.age")), &stolen).unwrap();
    let act = run(env.cmd().args(["pending", "activate", &id]));
    assert!(
        !act.ok && act.text.contains("payload does not match its record"),
        "{}",
        act.text
    );

    // Flipping a byte in a stored version breaks its digest.
    let path = env.entry_dir().join("v1.age");
    let mut ct = fs::read(&path).unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 1;
    fs::write(&path, ct).unwrap();
    let verify = run(env.cmd().arg("verify"));
    assert!(
        !verify.ok && verify.text.contains("digest mismatch"),
        "{}",
        verify.text
    );
}

#[test]
fn manifest_tampering_and_rollback_are_rejected() {
    let env = Env::new();
    env.init();
    assert!(env.set_dsn(DB_PASSWORD).ok);
    let old = fs::read(env.vault().join("manifest.json")).unwrap();
    assert!(run(env.cmd().args(["rm", "jn://prod/acme/app-db"])).ok);

    // Rolling the manifest back to a validly signed older copy is caught by the
    // pinned seq.
    fs::write(env.vault().join("manifest.json"), &old).unwrap();
    let ls = run(env.cmd().arg("ls"));
    assert!(
        !ls.ok && ls.text.contains("rollback detected"),
        "{}",
        ls.text
    );

    // Editing the signed body invalidates the signature.
    let mut signed: Value = serde_json::from_slice(&old).unwrap();
    signed["body"] = Value::String(
        signed["body"]
            .as_str()
            .unwrap()
            .replace("db.internal", "evil.example"),
    );
    fs::write(
        env.vault().join("manifest.json"),
        serde_json::to_vec(&signed).unwrap(),
    )
    .unwrap();
    let ls = run(env.cmd().arg("ls"));
    assert!(
        !ls.ok && ls.text.contains("signature is invalid"),
        "{}",
        ls.text
    );

    // Replacing the whole vault with another one at the same path is caught by the
    // pinned signing key.
    let other = Env::new();
    other.init();
    fs::remove_dir_all(env.vault()).unwrap();
    copy_dir(&other.vault(), &env.vault());
    let ls = run(env.cmd().arg("ls"));
    assert!(
        !ls.ok && ls.text.contains("changed since it was last used"),
        "{}",
        ls.text
    );
}

#[test]
fn backup_restores_with_recovery_kit_and_rekeys() {
    let env = Env::new();
    env.init();
    assert!(env.set_dsn(DB_PASSWORD).ok);
    fs::write(
        env.path("app.env"),
        "PORT=3000\nexport DATABASE_URL=\"postgres://u:p@h/db\"\n# comment\n",
    )
    .unwrap();
    let imp = run(env.cmd().arg("import-env").arg(env.path("app.env")).args([
        "jn://dev/acme/app-env",
        "--public",
        "PORT",
    ]));
    assert!(imp.ok, "{}", imp.text);
    let backup = env.path("vault.backup");
    assert!(run(env.cmd().arg("backup").arg("--out").arg(&backup)).ok);
    assert_no_secret(&String::from_utf8_lossy(&fs::read(&backup).unwrap()));

    // A recovery kit from another vault cannot open the backup; nothing is left behind.
    let other = Env::new();
    other.init();
    let target = env.path("restored");
    let bad = run(env
        .cmd_at(&target, Some("pass"))
        .arg("restore")
        .arg("--from")
        .arg(&backup)
        .arg("--recovery-kit")
        .arg(other.path("kit.json")));
    assert!(!bad.ok && !target.exists(), "{}", bad.text);

    fs::write(env.path("newpass"), "a brand new passphrase\n").unwrap();
    let ok = run(env
        .cmd_at(&target, Some("newpass"))
        .args(["restore", "--rekey", "--from"])
        .arg(&backup)
        .arg("--recovery-kit")
        .arg(env.path("kit.json")));
    assert!(ok.ok, "{}", ok.text);
    assert!(ok.text.contains("restored 2 entries"));

    let deep = run(env
        .cmd_at(&target, Some("newpass"))
        .args(["verify", "--deep"]));
    assert!(
        deep.ok && deep.text.contains("2 decrypted"),
        "{}",
        deep.text
    );
    let old_pass = run(env.cmd_at(&target, Some("pass")).args(["verify", "--deep"]));
    assert!(
        !old_pass.ok,
        "old passphrase must no longer unlock the rekeyed vault"
    );
    let inspect = run(env.cmd_at(&target, Some("newpass")).args([
        "inspect",
        "jn://dev/acme/app-env",
        "--json",
    ]));
    let v: Value = serde_json::from_str(&inspect.text).unwrap();
    assert_eq!(v["public"]["PORT"], "3000");
    assert_eq!(v["secret_fields"], serde_json::json!(["DATABASE_URL"]));
}

#[test]
fn need_points_humans_to_side_channel_entry() {
    let env = Env::new();
    env.init();
    let out = run(env.cmd().args([
        "need",
        "jn://prod/acme/cf-token",
        "--type",
        "api_token",
        "--reason",
        "deploy DNS",
    ]));
    assert!(out.ok);
    assert!(
        out.text
            .contains("jinnang set jn://prod/acme/cf-token --type api_token")
    );
    assert!(out.text.contains("Do not ask the user to paste"));
}

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for e in fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dest = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &dest);
        } else {
            fs::copy(e.path(), dest).unwrap();
        }
    }
}

#[test]
fn run_injects_fields_redacts_output_and_audits() {
    let env = Env::new();
    env.init();
    assert!(env.set_dsn(DB_PASSWORD).ok);
    let r = "jn://prod/acme/app-db";

    // env var injection: the child sees the value, the caller's output does not.
    let check =
        format!(r#"test "$PGPASSWORD" = '{DB_PASSWORD}' && echo "pw=$PGPASSWORD host=$JN_HOST""#);
    let out = run(env.cmd().args([
        "run",
        r,
        "--env",
        "PGPASSWORD=password",
        "--all-env",
        "--",
        "sh",
        "-c",
        &check,
    ]));
    assert!(out.ok, "{}", out.text);
    assert!(
        out.text.contains("pw=[jinnang:redacted] host=db.internal"),
        "{}",
        out.text
    );

    // stdin injection and exit-code propagation.
    let stdin_check = format!(r#"read v; test "$v" = '{DB_PASSWORD}'"#);
    assert!(
        run(env.cmd().args([
            "run",
            r,
            "--stdin",
            "password",
            "--",
            "sh",
            "-c",
            &stdin_check
        ]))
        .ok
    );
    let failing = env
        .cmd()
        .args(["run", r, "--", "sh", "-c", "exit 7"])
        .output()
        .unwrap();
    assert_eq!(failing.status.code(), Some(7));

    // Private files: path substituted for {NAME}, mode 0600, removed afterwards.
    let file_check = format!(
        r#"test "$(stat -c %a "$1")" = 600 && . "$2" && test "$JN_PASSWORD" = '{DB_PASSWORD}' && test "$(cat "$1")" = '{DB_PASSWORD}' && echo "$1""#
    );
    let out = run(env.cmd().args([
        "run",
        r,
        "--file",
        "PWFILE=password",
        "--env-file",
        "DOTENV",
        "--",
        "sh",
        "-c",
        &file_check,
        "sh",
        "{PWFILE}",
        "{DOTENV}",
    ]));
    assert!(out.ok, "{}", out.text);
    let path = out.text.trim();
    assert!(
        path.contains("jinnang-run-") && !Path::new(path).exists(),
        "temp file must be removed: {path}"
    );

    // Every use is in the audit log, without the value.
    let audit = fs::read_to_string(env.vault().join("audit.jsonl")).unwrap();
    assert_no_secret(&audit);
    let events: Vec<Value> = audit
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(
        events.iter().filter(|e| e["event"] == "run.start").count(),
        4
    );
    assert!(
        events
            .iter()
            .any(|e| e["event"] == "run.end" && e["exit_code"] == 7)
    );
    assert!(
        events
            .iter()
            .all(|e| e["event"] != "run.start" || e["ref"] == r)
    );
}

fn ls_refs(env: &Env, selector: &str) -> Vec<String> {
    let out = run(env.cmd().args(["ls", "--json", "-l", selector]));
    assert!(out.ok, "{}", out.text);
    let v: Value = serde_json::from_str(&out.text).unwrap();
    v.as_array()
        .unwrap()
        .iter()
        .map(|e| e["ref"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn labels_select_entries_and_selectors_must_be_unambiguous() {
    let env = Env::new();
    env.init();
    for (r, role, pw) in [
        ("jn://work/poc/qa-sales", "sales", "pw-sales-1111"),
        ("jn://work/poc/qa-root", "root", "pw-root-2222"),
        ("jn://personal/github", "owner", "pw-gh-3333"),
    ] {
        let tenant = if r.starts_with("jn://work/") {
            "tenant=poc"
        } else {
            "scope=personal"
        };
        let out = run(env
            .cmd()
            .args([
                "set",
                r,
                "--type",
                "account",
                "--stdin-json",
                "-l",
                tenant,
                "-l",
            ])
            .arg(format!("role={role}"))
            .write_stdin(format!(
                r#"{{"username":"{role}@example.com","password":"{pw}"}}"#
            )));
        assert!(out.ok, "{}", out.text);
    }

    assert_eq!(
        ls_refs(&env, "tenant=poc"),
        ["jn://work/poc/qa-root", "jn://work/poc/qa-sales"]
    );
    assert_eq!(
        ls_refs(&env, "tenant=poc,role in (sales,owner)"),
        ["jn://work/poc/qa-sales"]
    );
    assert_eq!(ls_refs(&env, "!tenant"), ["jn://personal/github"]);

    // A selector stands in for a reference only when it matches exactly one entry.
    let one = run(env.cmd().args([
        "run",
        "-l",
        "tenant=poc,role=sales",
        "--env",
        "P=password",
        "--",
        "sh",
        "-c",
        r#"test "$P" = pw-sales-1111"#,
    ]));
    assert!(one.ok, "{}", one.text);
    let many = run(env.cmd().args(["run", "-l", "tenant=poc", "--", "true"]));
    assert!(
        !many.ok && many.text.contains("2 entries match"),
        "{}",
        many.text
    );
    let none = run(env.cmd().args(["inspect", "-l", "tenant=nope"]));
    assert!(
        !none.ok && none.text.contains("no entry matches"),
        "{}",
        none.text
    );
    let both = run(env
        .cmd()
        .args(["inspect", "jn://personal/github", "-l", "role=owner"]));
    assert!(!both.ok);
    let inspect = run(env.cmd().args(["inspect", "-l", "role=owner", "--json"]));
    let v: Value = serde_json::from_str(&inspect.text).unwrap();
    assert_eq!(v["ref"], "jn://personal/github");
    assert_eq!(
        v["labels"],
        serde_json::json!({"role": "owner", "scope": "personal"})
    );

    // Relabel and rename keep the stored versions usable.
    let label = run(env
        .cmd()
        .args(["label", "jn://work/poc/qa-sales", "pool=poc-qa", "role-"]));
    assert!(
        label.ok && label.text.contains("pool=poc-qa,tenant=poc"),
        "{}",
        label.text
    );
    assert!(
        !run(env
            .cmd()
            .args(["label", "jn://work/poc/qa-sales", "missing-"]))
        .ok
    );
    assert!(
        run(env
            .cmd()
            .args(["mv", "jn://work/poc/qa-sales", "jn://work/poc/sales"]))
        .ok
    );
    assert!(
        !run(env
            .cmd()
            .args(["mv", "jn://work/poc/qa-root", "jn://work/poc/sales"]))
        .ok
    );
    assert_eq!(ls_refs(&env, "pool=poc-qa"), ["jn://work/poc/sales"]);
    let after = run(env.cmd().args([
        "run",
        "jn://work/poc/sales",
        "--env",
        "P=password",
        "--",
        "sh",
        "-c",
        r#"test "$P" = pw-sales-1111"#,
    ]));
    assert!(after.ok, "{}", after.text);

    // Rotation keeps labels unless overridden.
    let rot = run(env
        .cmd()
        .args([
            "rotate",
            "jn://work/poc/sales",
            "--stdin-json",
            "-l",
            "pool=poc-qa2",
        ])
        .write_stdin(r#"{"username":"sales@example.com","password":"pw-sales-4444"}"#));
    assert!(rot.ok, "{}", rot.text);
    assert_eq!(
        ls_refs(&env, "pool=poc-qa2,tenant=poc"),
        ["jn://work/poc/sales"]
    );

    let deep = run(env.cmd().args(["verify", "--deep"]));
    assert!(
        deep.ok && deep.text.contains("4 decrypted"),
        "{}",
        deep.text
    );
    for out in [&label.text, &inspect.text, &deep.text] {
        assert!(!out.contains("pw-"), "{out}");
    }
}

#[test]
fn generic_entries_take_custom_fields_secret_unless_public() {
    let env = Env::new();
    env.init();
    let out = run(env
        .cmd()
        .args([
            "set",
            "jn://saas/notion",
            "--public",
            "workspace",
            "--stdin-json",
            "-l",
            "kind=saas",
        ])
        .write_stdin(r#"{"workspace":"acme","api_key":"nt-secret-5555","EMPTY_OK":""}"#));
    assert!(out.ok, "{}", out.text);
    let v: Value =
        serde_json::from_str(&run(env.cmd().args(["inspect", "jn://saas/notion", "--json"])).text)
            .unwrap();
    assert_eq!(v["type"], "generic");
    assert_eq!(v["public"], serde_json::json!({"workspace": "acme"}));
    assert_eq!(
        v["secret_fields"],
        serde_json::json!(["EMPTY_OK", "api_key"])
    );

    // Typed fields keep their fixed secrecy; custom fields on typed entries are secret by default.
    let typed = run(env
        .cmd()
        .args([
            "set",
            "jn://work/ops",
            "--type",
            "account",
            "--public",
            "password",
            "--stdin-json",
        ])
        .write_stdin(r#"{"username":"ops","password":"pw-ops-6666"}"#));
    assert!(!typed.ok, "{}", typed.text);
    let extra = run(env
        .cmd()
        .args(["set", "jn://work/ops", "--type", "account", "--public", "tenant_slug", "--stdin-json"])
        .write_stdin(r#"{"username":"ops","password":"pw-ops-6666","tenant_slug":"poc","recovery_code":"rc-7777"}"#));
    assert!(extra.ok, "{}", extra.text);
    let v: Value =
        serde_json::from_str(&run(env.cmd().args(["inspect", "jn://work/ops", "--json"])).text)
            .unwrap();
    assert_eq!(v["public"]["tenant_slug"], "poc");
    assert_eq!(
        v["secret_fields"],
        serde_json::json!(["password", "recovery_code"])
    );

    // Custom field names become env names as-is for generic entries.
    let env_check = run(env.cmd().args([
        "run",
        "jn://saas/notion",
        "--all-env",
        "--",
        "sh",
        "-c",
        r#"test "$api_key" = nt-secret-5555 && test "$workspace" = acme"#,
    ]));
    assert!(env_check.ok, "{}", env_check.text);
}

#[test]
fn agents_discover_entries_by_keywords_and_descriptions() {
    let env = Env::new();
    env.init();
    let skill = run(env.cmd().arg("--skill"));
    assert!(
        skill.ok && skill.text.starts_with("---\nname: jinnang\n"),
        "{}",
        skill.text
    );
    let help = run(env.cmd().arg("--help"));
    assert!(help.text.contains("jinnang --skill"), "{}", help.text);

    let set = run(env
        .cmd()
        .args([
            "set",
            "jn://work/poc/qa-sales",
            "--type",
            "account",
            "--stdin-json",
            "-l",
            "tenant=poc",
            "--desc",
            "POC tenant sales QA account (was poc-qa-accounts.env QA_SALES_*)",
        ])
        .write_stdin(r#"{"username":"sales@example.com","password":"pw-sales-1111"}"#));
    assert!(set.ok, "{}", set.text);
    let ssh = run(env
        .cmd()
        .args([
            "set",
            "jn://ssh/web1",
            "--type",
            "ssh",
            "--stdin-json",
            "--pending",
        ])
        .write_stdin(r#"{"host":"10.0.0.7","user":"root","password":"pw-ssh-2222"}"#));
    assert!(ssh.ok, "{}", ssh.text);
    assert!(run(env.cmd().args(["pending", "activate", "--all"])).ok);

    let refs = |args: &[&str]| -> Vec<String> {
        let out = run(env.cmd().args(args));
        assert!(out.ok, "{}", out.text);
        let v: Value = serde_json::from_str(&out.text).unwrap();
        v.as_array()
            .unwrap()
            .iter()
            .map(|e| e["ref"].as_str().unwrap().to_string())
            .collect()
    };
    // Any mix of name, label, description, public value or field name; all terms must match.
    assert_eq!(
        refs(&["find", "--json", "POC", "Sales"]),
        ["jn://work/poc/qa-sales"]
    );
    assert_eq!(
        refs(&["find", "--json", "poc-qa-accounts.env"]),
        ["jn://work/poc/qa-sales"]
    );
    assert_eq!(refs(&["find", "--json", "10.0.0.7"]), ["jn://ssh/web1"]);
    assert_eq!(
        refs(&["find", "--json", "password"]),
        ["jn://ssh/web1", "jn://work/poc/qa-sales"]
    );
    assert!(refs(&["find", "--json", "poc", "10.0.0.7"]).is_empty());
    // Secret values are never searchable.
    assert!(refs(&["find", "--json", "pw-sales-1111"]).is_empty());

    let ls = run(env.cmd().arg("ls"));
    assert!(
        ls.text.contains("\n    POC tenant sales QA account"),
        "{}",
        ls.text
    );
    let none = run(env.cmd().args(["find", "nothing-like-this"]));
    assert!(
        none.ok && none.text.contains("jinnang need"),
        "{}",
        none.text
    );

    // Descriptions survive rotation, can be replaced or cleared, and are signed.
    let rot = run(env
        .cmd()
        .args(["rotate", "jn://work/poc/qa-sales", "--stdin-json"])
        .write_stdin(r#"{"username":"sales@example.com","password":"pw-sales-3333"}"#));
    assert!(rot.ok, "{}", rot.text);
    assert_eq!(
        refs(&["find", "--json", "QA_SALES"]),
        ["jn://work/poc/qa-sales"]
    );
    assert!(
        run(env
            .cmd()
            .args(["describe", "jn://ssh/web1", "build host for acme"]))
        .ok
    );
    assert_eq!(
        refs(&["find", "--json", "acme", "build"]),
        ["jn://ssh/web1"]
    );
    assert!(!run(env.cmd().args(["describe", "jn://ssh/web1", "two\nlines"])).ok);
    assert!(
        run(env
            .cmd()
            .args(["describe", "jn://work/poc/qa-sales", "--clear"]))
        .ok
    );
    assert!(refs(&["find", "--json", "QA_SALES"]).is_empty());
    let need = run(env.cmd().args([
        "need",
        "jn://work/acme/admin",
        "--type",
        "account",
        "--desc",
        "acme admin console owner",
    ]));
    assert!(
        need.text.contains("--desc 'acme admin console owner'"),
        "{}",
        need.text
    );
    let mut signed: Value =
        serde_json::from_slice(&fs::read(env.vault().join("manifest.json")).unwrap()).unwrap();
    signed["body"] = Value::String(
        signed["body"]
            .as_str()
            .unwrap()
            .replace("build host", "evil host"),
    );
    fs::write(
        env.vault().join("manifest.json"),
        serde_json::to_vec(&signed).unwrap(),
    )
    .unwrap();
    assert!(
        run(env.cmd().arg("ls"))
            .text
            .contains("signature is invalid")
    );

    for out in [&set.text, &ls.text, &none.text, &rot.text] {
        assert!(!out.contains("pw-"), "{out}");
    }
}

fn user_creds_available() -> bool {
    let dir = TempDir::new().unwrap();
    std::process::Command::new("systemd-creds")
        .args(["--user", "--name", "jinnang-probe", "encrypt", "-"])
        .arg(dir.path().join("probe.cred"))
        .stdin(std::process::Stdio::null())
        .output()
        .is_ok_and(|o| o.status.success())
}

#[test]
fn enrolled_vault_unlocks_without_any_passphrase_from_the_caller() {
    if !user_creds_available() {
        eprintln!("skipped: user-scoped systemd-creds unavailable");
        return;
    }
    let env = Env::new();
    env.init();
    assert!(env.set_dsn(DB_PASSWORD).ok);
    let locked = |args: &[&str]| run(env.cmd_at(&env.vault(), None).args(args));
    let check = format!(r#"test "$P" = '{DB_PASSWORD}'"#);
    let use_it = [
        "run",
        "jn://prod/acme/app-db",
        "--env",
        "P=password",
        "--",
        "sh",
        "-c",
        &check,
    ];

    let before = locked(&use_it);
    assert!(
        !before.ok && before.text.contains("jinnang unlock enroll"),
        "{}",
        before.text
    );
    assert!(locked(&["unlock", "status"]).text.contains("not enrolled"));

    // A wrong passphrase is never sealed.
    fs::write(env.path("wrong"), "not the passphrase at all\n").unwrap();
    let wrong = run(env
        .cmd_at(&env.vault(), Some("wrong"))
        .args(["unlock", "enroll"]));
    assert!(
        !wrong.ok && wrong.text.contains("wrong passphrase"),
        "{}",
        wrong.text
    );

    let enroll = run(env.cmd().args(["unlock", "enroll"]));
    assert!(enroll.ok, "{}", enroll.text);
    let sealed = fs::read(
        fs::read_dir(env.path("state"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.to_string_lossy().ends_with(".passphrase.cred"))
            .unwrap(),
    )
    .unwrap();
    assert!(!String::from_utf8_lossy(&sealed).contains(PASS));

    // The caller passes nothing; jinnang unseals the passphrase itself.
    let after = locked(&use_it);
    assert!(after.ok, "{}", after.text);
    assert!(
        locked(&["unlock", "status"])
            .text
            .contains("unseals and unlocks")
    );
    assert!(locked(&["verify", "--deep"]).ok);
    for out in [&enroll.text, &after.text] {
        assert_no_secret(out);
    }

    assert!(locked(&["unlock", "remove"]).ok);
    assert!(!locked(&use_it).ok);
}
