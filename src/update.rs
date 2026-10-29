//! The app's own updates. An installed app (Linux: `~/.local/share/herdr-app`,
//! macOS: `Herdr.app`) checks `releases.herdr.dev/app/latest.json` a little
//! after it opens and every hour, downloads a newer build for this
//! machine, checks its sha256 and unpacks it next to itself (`<install>.new`).
//! The frame then shows "Restart"; the swap happens on restart or the next
//! quit. The first start after a swap runs `hc update` for the core.
//!
//! A build from source never updates: only `scripts/package` (the release
//! builds) sets `HERDR_APP_RELEASE`. `scripts/install-macos` makes a
//! Herdr.app too, so the install's shape alone can't tell.
//!
//! The core is checked on the same clock (`core/latest.json`): a newer core
//! of the same generation is offered (also applied after an app update), unless
//! a package manager owns it. Within a generation a newer core only adds.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

const EVERY: Duration = Duration::from_secs(60 * 60);
/// After a failed check or download (offline, a damaged file).
const RETRY: Duration = Duration::from_secs(30 * 60);

/// Where this app is installed: the folder (Linux) or bundle (macOS) an
/// update replaces. Read once: after a swap this process's own file is gone.
fn root() -> Option<PathBuf> {
    static ROOT: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    ROOT.get_or_init(find_root).clone()
}

fn find_root() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
    let dir = exe.parent()?;
    if cfg!(target_os = "macos") {
        // Herdr.app/Contents/MacOS/Herdr
        let bundle = dir.parent()?.parent()?;
        (bundle.extension()? == "app").then(|| bundle.to_path_buf())
    } else {
        // The release folder holds the binary and its icon; cargo's target/ doesn't.
        dir.join("herdr-app.svg").is_file().then(|| dir.to_path_buf())
    }
}

/// The folder or bundle name inside a release tarball.
const PACKED: &str = if cfg!(target_os = "macos") { "Herdr.app" } else { "herdr-app" };

fn beside(root: &Path, suffix: &str) -> PathBuf {
    let mut name = root.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    // macOS: Spotlight skips a folder ending in `.noindex`, so a staged
    // `Herdr.app.new` never shows up in search under that name.
    if cfg!(target_os = "macos") {
        name.push(".noindex");
    }
    root.with_file_name(name)
}

fn target() -> String {
    let os = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(windows) {
        "windows"
    } else {
        "linux"
    };
    format!("{os}-{}", std::env::consts::ARCH)
}

fn releases() -> String {
    std::env::var("HERDR_RELEASES_URL").unwrap_or_else(|_| "https://releases.herdr.dev".into())
}

/// The version downloaded and waiting for a restart.
static READY: Mutex<Option<String>> = Mutex::new(None);

pub fn ready() -> Option<String> {
    READY.lock().unwrap().clone()
}

/// The core the app runs, from its `server.status`, and a newer release waiting.
#[derive(Clone, Default, serde::Serialize)]
pub struct CoreInfo {
    pub version: Option<String>,
    /// A package manager that owns it (homebrew, nix, mise): never updated by the app.
    pub managed: Option<String>,
    pub ready: Option<String>,
    pub updating: bool,
    pub error: Option<String>,
}

static CORE: Mutex<CoreInfo> = Mutex::new(CoreInfo { version: None, managed: None, ready: None, updating: false, error: None });
/// When the last check finished (unix seconds), for "checked at".
static CHECKED: Mutex<Option<u64>> = Mutex::new(None);
/// "Check now" wakes the checker early.
static WAKE: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
/// The checker runs (a release, or pointed at a test server), and is looking right now.
static RUNNING: AtomicBool = AtomicBool::new(false);
static CHECKING: AtomicBool = AtomicBool::new(false);

pub fn core() -> CoreInfo {
    CORE.lock().unwrap().clone()
}

/// What the connected core says about itself (on connect and every reconnect).
pub fn set_core(version: Option<String>, managed: Option<String>) {
    let mut c = CORE.lock().unwrap();
    if let (Some(have), Some(ready)) = (&version, &c.ready)
        && !newer(ready, have)
    {
        c.ready = None;
    }
    c.version = version;
    c.managed = managed;
}

fn checks_app() -> Option<PathBuf> {
    root().filter(|_| option_env!("HERDR_APP_RELEASE").is_some() || std::env::var_os("HERDR_RELEASES_URL").is_some())
}

/// A release build checks the core; a source build only when pointed at a test release server.
fn checks_core() -> bool {
    option_env!("HERDR_APP_RELEASE").is_some() || std::env::var_os("HERDR_RELEASES_URL").is_some()
}

/// For the settings screen: both programs, what's waiting, when we last looked.
pub fn status() -> serde_json::Value {
    serde_json::json!({
        "app": { "version": env!("CARGO_PKG_VERSION"), "ready": ready(), "updates": checks_app().is_some() },
        "notes": crate::update_notes::notes(ready().as_deref()),
        "core": core(),
        "checked": *CHECKED.lock().unwrap(),
        "checks": RUNNING.load(Ordering::Relaxed),
        "checking": CHECKING.load(Ordering::Relaxed),
    })
}

pub fn check_now() {
    if RUNNING.load(Ordering::Relaxed) {
        CHECKING.store(true, Ordering::Relaxed);
    }
    *WAKE.0.lock().unwrap() = true;
    WAKE.1.notify_all();
}

fn sleep(d: Duration) {
    let woken = WAKE.0.lock().unwrap();
    let (mut woken, _) = WAKE.1.wait_timeout_while(woken, d, |w| !*w).unwrap();
    *woken = false;
}

/// Starts checking in the background: the app if it's an installed release, the core too.
pub fn start() {
    let app = checks_app();
    let core = checks_core();
    if app.is_none() && !core {
        tracing::info!("a build from source: no updates");
        return;
    }
    RUNNING.store(true, Ordering::Relaxed);
    std::thread::spawn(move || {
        sleep(Duration::from_secs(10));
        loop {
            CHECKING.store(true, Ordering::Relaxed);
            let mut wait = EVERY;
            if let Some(root) = &app {
                match check(root) {
                    Ok(found) => {
                        if found.is_some() {
                            *READY.lock().unwrap() = found;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("update check: {e}");
                        crate::telemetry::count("app_update_failed");
                        wait = RETRY;
                    }
                }
            }
            if core && let Err(e) = check_core() {
                tracing::warn!("core update check: {e}");
                wait = RETRY;
            }
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            *CHECKED.lock().unwrap() = Some(now);
            CHECKING.store(false, Ordering::Relaxed);
            sleep(wait);
        }
    });
}

/// Looks for a newer core of this app's generation.
fn check_core() -> Result<(), String> {
    let (have, managed) = {
        let c = CORE.lock().unwrap();
        (c.version.clone(), c.managed.clone())
    };
    let Some(have) = have else { return Ok(()) };
    if managed.is_some() {
        return Ok(());
    }
    let latest = latest_core()?;
    let same = latest.generation == Some(crate::hc::GENERATION);
    CORE.lock().unwrap().ready = (same && newer(&latest.version, &have)).then_some(latest.version);
    Ok(())
}

#[derive(serde::Deserialize)]
struct CoreRelease {
    version: String,
    generation: Option<u64>,
}

fn latest_core() -> Result<CoreRelease, String> {
    let text = curl_text(&format!("{}/core/latest.json", releases()))?;
    serde_json::from_str(&text).map_err(|e| format!("core/latest.json: {e}"))
}

fn after_update_target<'a>(have: &str, latest: Option<&'a CoreRelease>, generation: u64, core_min: &'a str) -> Option<&'a str> {
    if newer("0.1.5", have) {
        return None;
    }
    Some(match latest {
        Some(latest) if latest.generation == Some(generation) && newer(&latest.version, have) => &latest.version,
        _ => core_min,
    })
}

/// `hc update` (terminals keep running; the app reconnects when the core restarts).
pub fn update_core() {
    {
        let mut c = CORE.lock().unwrap();
        if c.updating {
            return;
        }
        c.updating = true;
        c.error = None;
    }
    std::thread::spawn(|| {
        let result = crate::core_bin::update();
        let mut c = CORE.lock().unwrap();
        c.updating = false;
        match result {
            Ok(now) => {
                c.version = Some(now.trim_start_matches("hc ").to_owned());
                c.ready = None;
                crate::telemetry::count("core_update_ok");
            }
            Err(e) => {
                c.error = Some(e);
                crate::telemetry::count("core_update_failed");
            }
        }
    });
}

/// Downloads the latest release if it's newer. Ok(Some): a version is ready.
fn check(root: &Path) -> Result<Option<String>, String> {
    let path = "app/latest.json";
    let text = curl_text(&format!("{}/{path}", releases()))?;
    let manifest: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
    let version = manifest["version"].as_str().ok_or(format!("{path}: no version"))?;
    if !newer(version, env!("CARGO_PKG_VERSION")) {
        return Ok(None);
    }
    // Notes are optional: a missing feed must never hold up the update.
    if let Ok(text) = curl_text(&format!("{}/app/{version}/changelog.md", releases())) {
        crate::update_notes::cache(&text);
    }
    let staged = beside(root, ".new");
    if version_of(&staged).as_deref() == Some(version) {
        return Ok(Some(version.to_owned()));
    }
    let entry = &manifest["targets"][target()];
    let (Some(url), Some(sha)) = (entry["url"].as_str(), entry["sha256"].as_str()) else {
        return Ok(None);
    };
    tracing::info!("downloading Herdr {version}");
    let work = beside(root, ".download");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| format!("{}: {e}", work.display()))?;
    let result = unpack(url, sha, &work).and_then(|unpacked| {
        if version_of(&unpacked).as_deref() != Some(version) {
            return Err(format!("the download doesn't run as {version}"));
        }
        let _ = std::fs::remove_dir_all(&staged);
        std::fs::rename(&unpacked, &staged).map_err(|e| format!("{}: {e}", staged.display()))
    });
    let _ = std::fs::remove_dir_all(&work);
    result.map(|()| Some(version.to_owned()))
}

/// Downloads, checks and unpacks a release into `work`; returns the app inside.
fn unpack(url: &str, sha: &str, work: &Path) -> Result<PathBuf, String> {
    let tarball = work.join("app.tar.gz");
    run(crate::spawn::command(system("curl")).args(["-fsSL", "--max-time", "600", "-o"]).arg(&tarball).arg(url))?;
    let bytes = std::fs::read(&tarball).map_err(|e| e.to_string())?;
    if sha256(&bytes) != sha.to_ascii_lowercase() {
        return Err("the download is damaged (checksum mismatch)".into());
    }
    run(crate::spawn::command(system("tar")).arg("-xzf").arg(&tarball).arg("-C").arg(work))?;
    let app = work.join(PACKED);
    if cfg!(target_os = "macos") {
        let signature = Command::new("codesign").arg("-dv").arg(&app).output().map_err(|e| format!("codesign: {e}"))?;
        if certificate_signed(&String::from_utf8_lossy(&signature.stderr)) {
            run(Command::new("codesign").args(["--verify", "--deep", "--strict"]).arg(&app))?;
        } else {
            // Only dev builds may change the plist and lose their signature.
            let home = std::env::var("HOME").unwrap_or_default();
            let path = format!("{home}/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin");
            let plist = app.join("Contents/Info.plist");
            run(Command::new("/usr/libexec/PlistBuddy").arg("-c").arg(format!("Add :LSEnvironment:PATH string {path}")).arg(&plist))?;
            run(Command::new("codesign").args(["--force", "--sign", "-"]).arg(&app))?;
        }
    }
    Ok(app)
}

fn certificate_signed(signature: &str) -> bool {
    signature.lines().any(|line| line.starts_with("Authority="))
}

/// curl and tar: on Windows its own (System32), since Git's tar, often first
/// on PATH, takes `C:\...` for a remote host.
pub fn system(name: &str) -> PathBuf {
    match std::env::var_os("SystemRoot").filter(|_| cfg!(windows)) {
        Some(root) => PathBuf::from(root).join("System32").join(format!("{name}.exe")),
        None => PathBuf::from(name),
    }
}

pub(crate) fn sha256(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

fn curl_text(url: &str) -> Result<String, String> {
    let out = crate::spawn::command(system("curl")).args(["-fsSL", "--max-time", "30", url]).stdin(Stdio::null()).output().map_err(|e| format!("curl: {e}"))?;
    if !out.status.success() {
        return Err(format!("{url}: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    String::from_utf8(out.stdout).map_err(|e| e.to_string())
}

fn run(cmd: &mut Command) -> Result<(), String> {
    let out = cmd.stdin(Stdio::null()).output().map_err(|e| format!("{:?}: {e}", cmd.get_program()))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("{:?}: {}", cmd.get_program(), String::from_utf8_lossy(&out.stderr).trim()))
    }
}

fn exe_in(app: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        app.join("Contents/MacOS/Herdr")
    } else {
        app.join(format!("herdr-app{}", std::env::consts::EXE_SUFFIX))
    }
}

/// What `herdr-app --version` says in this folder or bundle (`0.2.0`).
fn version_of(app: &Path) -> Option<String> {
    let out = crate::spawn::command(exe_in(app)).arg("--version").stdin(Stdio::null()).stderr(Stdio::null()).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        return None;
    }
    text.trim().strip_prefix("herdr-app ").map(str::to_owned)
}

/// `a` is a later version than `b` (semver; `0.2.0-rc.1` comes before `0.2.0`).
pub(crate) fn newer(a: &str, b: &str) -> bool {
    fn parts(v: &str) -> (Vec<u64>, Option<&str>) {
        let (core, pre) = v.trim_start_matches('v').split_once('-').map_or((v.trim_start_matches('v'), None), |(c, p)| (c, Some(p)));
        (core.split('.').map(|n| n.parse().unwrap_or(0)).collect(), pre)
    }
    let ((ca, pa), (cb, pb)) = (parts(a), parts(b));
    match ca.cmp(&cb) {
        std::cmp::Ordering::Equal => match (pa, pb) {
            (None, Some(_)) => true,
            (Some(x), Some(y)) => x > y,
            _ => false,
        },
        o => o == std::cmp::Ordering::Greater,
    }
}

/// Puts the downloaded version in place of this one. The running app keeps
/// its files open, so it can go on until it quits. True if it swapped.
/// Windows lets a running program's folder be renamed, not deleted: the old
/// one goes on the next start (`after_update`).
pub fn apply() -> bool {
    let Some(root) = root() else { return false };
    let staged = beside(&root, ".new");
    if ready().is_none() || !staged.is_dir() {
        return false;
    }
    let old = beside(&root, ".old");
    let _ = std::fs::remove_dir_all(&old);
    if let Err(e) = std::fs::rename(&root, &old) {
        tracing::warn!("update: cannot move {} aside: {e}", root.display());
        return false;
    }
    if let Err(e) = std::fs::rename(&staged, &root) {
        tracing::warn!("update: cannot put the new version in place: {e}");
        let _ = std::fs::rename(&old, &root);
        return false;
    }
    let _ = std::fs::remove_dir_all(&old);
    *READY.lock().unwrap() = None;
    let _ = std::fs::write(marker(), "");
    true
}

/// Opens the app again once this process has exited (after `apply`).
#[cfg(windows)]
pub fn relaunch() {
    let Some(root) = root() else { return };
    let exe = exe_in(&root).to_string_lossy().replace('\'', "''");
    let script = format!("Wait-Process -Id {} -ErrorAction SilentlyContinue; Start-Process '{exe}'", std::process::id());
    let spawned = crate::spawn::command("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    if let Err(e) = spawned {
        tracing::warn!("update: cannot reopen the app: {e}");
    }
}

/// Starts this same build again, with the same arguments, once this process
/// has exited (switching backends).
pub fn restart() {
    let Ok(exe) = std::env::current_exe() else { return };
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    #[cfg(unix)]
    let spawned = {
        use std::os::unix::process::CommandExt;
        Command::new("sh")
            .arg("-c")
            .arg("pid=$1; shift; while kill -0 \"$pid\" 2>/dev/null; do sleep 0.1; done; exec \"$@\"")
            .arg("herdr-restart")
            .arg(std::process::id().to_string())
            .arg(&exe)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
    };
    #[cfg(windows)]
    let spawned = {
        let quoted: Vec<String> = args.iter().map(|a| format!("'{}'", a.to_string_lossy().replace('\'', "''"))).collect();
        let list = if quoted.is_empty() { String::new() } else { format!(" -ArgumentList {}", quoted.join(",")) };
        let exe = exe.to_string_lossy().replace('\'', "''");
        let script = format!("Wait-Process -Id {} -ErrorAction SilentlyContinue; Start-Process '{exe}'{list}", std::process::id());
        crate::spawn::command("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &script]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()
    };
    if let Err(e) = spawned {
        tracing::warn!("cannot restart the app: {e}");
    }
}

/// Opens the app again once this process has exited (after `apply`).
#[cfg(unix)]
pub fn relaunch() {
    let Some(root) = root() else { return };
    let open = if cfg!(target_os = "macos") { "open \"$1\"" } else { "exec \"$1/herdr-app\"" };
    let script = format!("while kill -0 \"$0\" 2>/dev/null; do sleep 0.1; done; {open}");
    let spawned = {
        use std::os::unix::process::CommandExt;
        Command::new("sh")
            .arg("-c")
            .arg(script)
            .arg(std::process::id().to_string())
            .arg(&root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
    };
    if let Err(e) = spawned {
        tracing::warn!("update: cannot reopen the app: {e}");
    }
}

/// Left by `apply`: the next start brings the core up to date too.
fn marker() -> PathBuf {
    crate::mods::app_dir().join(".updated")
}

/// The first start after an app update brings the core to the latest release
/// of this app's generation (`hc update --version`, terminals kept). If the
/// release check fails or offers another generation, keep the minimum pin.
/// Cores before 0.1.5 lack `--version`: they keep their same-generation update
/// path. A core a package manager owns is left alone (hc says so).
pub fn after_update() {
    if std::fs::remove_file(marker()).is_err() {
        return;
    }
    if let Some(root) = root() {
        let _ = std::fs::remove_dir_all(beside(&root, ".old"));
    }
    std::thread::spawn(|| {
        let have = crate::core_bin::version(&crate::core_bin::path()).unwrap_or_default();
        CORE.lock().unwrap().updating = true;
        let latest = latest_core().map_err(|e| tracing::warn!("core release check after app update: {e}")).ok();
        let target = after_update_target(have.trim_start_matches("hc "), latest.as_ref(), crate::hc::GENERATION, crate::hc::core_min());
        let result = crate::core_bin::update_to(target);
        let mut core = CORE.lock().unwrap();
        core.updating = false;
        match result {
            Ok(now) => {
                tracing::info!("herdr-core is {now}");
                core.version = Some(now.trim_start_matches("hc ").to_owned());
                core.error = None;
            }
            Err(e) => {
                tracing::warn!("herdr-core update: {e}");
                core.error = Some(e);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_signatures_are_preserved() {
        assert!(certificate_signed("Executable=/Herdr.app/Contents/MacOS/Herdr\nAuthority=Developer ID Application: Herdr (TEAM)\nAuthority=Developer ID Certification Authority\n"));
        assert!(!certificate_signed("Executable=/Herdr.app/Contents/MacOS/Herdr\nSignature=adhoc\nTeamIdentifier=not set\n"));
        assert!(!certificate_signed("/Herdr.app: code object is not signed at all\n"));
    }

    #[test]
    fn versions_compare_like_semver() {
        assert!(newer("0.2.0", "0.1.9"));
        assert!(newer("0.10.0", "0.9.0"));
        assert!(newer("1.0.0", "1.0.0-rc.1"));
        assert!(!newer("1.0.0-rc.1", "1.0.0"));
        assert!(!newer("0.1.0", "0.1.0"));
        assert!(!newer("0.0.9", "0.1.0"));
    }

    #[test]
    fn after_app_update_targets_latest_only_in_our_generation() {
        let release = |version: &str, generation| CoreRelease { version: version.into(), generation };
        let latest = release("0.1.13", Some(1));
        assert_eq!(after_update_target("0.1.12", Some(&latest), 1, "0.1.11"), Some("0.1.13"));
        for have in ["0.1.13", "0.1.14"] {
            assert_eq!(after_update_target(have, Some(&latest), 1, "0.1.11"), Some("0.1.11"));
        }
        for latest in [None, Some(release("0.2.0", Some(2))), Some(release("0.1.13", None))] {
            assert_eq!(after_update_target("0.1.12", latest.as_ref(), 1, "0.1.11"), Some("0.1.11"));
            assert_eq!(after_update_target("0.1.4", latest.as_ref(), 1, "0.1.11"), None);
        }
        assert_eq!(after_update_target("0.1.4", Some(&latest), 1, "0.1.11"), None);
        assert_eq!(after_update_target("0.1.5", Some(&latest), 1, "0.1.11"), Some("0.1.13"));
        assert_eq!(after_update_target("0.1.5", None, 1, "0.1.11"), Some("0.1.11"));
    }

    #[test]
    fn sha256_is_hex() {
        assert_eq!(sha256(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
