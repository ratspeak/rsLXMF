use std::fs;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::{Child, Stdio};
use std::process::{Command, Output};
#[cfg(unix)]
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after Unix epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("lxmd-cli-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).expect("create temp test directory");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn lxmd(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lxmd-rs"))
        .args(args)
        .output()
        .expect("lxmd-rs subprocess should run")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn combined_output(output: &Output) -> String {
    format!("{}{}", stdout(output), stderr(output))
}

fn write_rust_identity(path: &Path) {
    rns_identity::identity::Identity::new()
        .to_file(path)
        .expect("write Rust identity");
}

/// Kills and reaps the daemon on every path out of the test, panics included.
#[cfg(unix)]
struct Daemon(Option<Child>);

#[cfg(unix)]
impl Daemon {
    fn child(&mut self) -> &mut Child {
        self.0.as_mut().expect("daemon still owned")
    }

    fn output(mut self) -> Output {
        self.0
            .take()
            .expect("daemon still owned")
            .wait_with_output()
            .expect("collect lxmd-rs output")
    }
}

#[cfg(unix)]
impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(unix)]
fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("poll lxmd-rs child") {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn help_lists_cli_surface_without_starting_runtime() {
    let output = lxmd(&["--help"]);

    assert!(
        output.status.success(),
        "expected --help to succeed, got:\n{}",
        combined_output(&output)
    );
    let text = stdout(&output);
    assert!(text.contains("LXMF Propagation Daemon"));
    assert!(text.contains("Usage: lxmd-rs [OPTIONS]"));
    assert!(text.contains("--exampleconfig"));
    assert!(text.contains("--status"));
    assert!(text.contains("--peers"));
    assert!(text.contains("--sync <PEER_HASH>"));
    assert!(text.contains("-s, --service"));
    assert!(text.contains("--send <DEST_HASH> <CONTENT>"));
    assert!(text.contains("[possible values: opportunistic, direct, propagated]"));
}

#[cfg(unix)]
#[test]
fn ctrl_c_exits_during_deferred_start() {
    let lxmf_dir = TestDir::new("lxmf-ctrlc");
    let rns_dir = TestDir::new("rns-ctrlc");
    fs::write(
        lxmf_dir.path().join("config"),
        "\
[lxmf]
display_name = Test
announce_at_start = yes

[propagation]
enable_node = no
",
    )
    .expect("write LXMF config");
    fs::write(
        rns_dir.path().join("config"),
        "\
[reticulum]
share_instance = No
enable_transport = No
respond_to_probes = No
panic_on_interface_error = No
discover_interfaces = No

[interfaces]
",
    )
    .expect("write no-interface Reticulum config");

    // Declared after the directories so it is dropped first: the daemon must not outlive its config.
    let mut daemon = Daemon(Some(
        Command::new(env!("CARGO_BIN_EXE_lxmd-rs"))
            .arg("--config")
            .arg(lxmf_dir.path())
            .arg("--rnsconfig")
            .arg(rns_dir.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("lxmd-rs subprocess should start"),
    ));

    let identity_path = lxmf_dir.path().join("identity");
    // A loaded host can take seconds over a fresh debug binary's first exec.
    let startup_deadline = Instant::now() + Duration::from_secs(30);
    while !identity_path.exists() {
        if let Some(status) = daemon.child().try_wait().expect("poll lxmd-rs startup") {
            panic!(
                "lxmd-rs exited before startup announce wait ({status}):\n{}",
                combined_output(&daemon.output())
            );
        }
        assert!(
            Instant::now() < startup_deadline,
            "lxmd-rs did not reach startup announce wait"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(100));
    let signal_status = Command::new("kill")
        .arg("-INT")
        .arg(daemon.child().id().to_string())
        .status()
        .expect("send SIGINT to lxmd-rs");
    assert!(signal_status.success(), "kill -INT should succeed");

    if wait_with_timeout(daemon.child(), Duration::from_secs(3)).is_none() {
        let _ = daemon.child().kill();
        panic!(
            "lxmd-rs did not exit after Ctrl+C during startup announce wait:\n{}",
            combined_output(&daemon.output())
        );
    }

    let output = daemon.output();
    assert!(
        output.status.success(),
        "expected clean shutdown after Ctrl+C, got:\n{}",
        combined_output(&output)
    );
}

/// lxmd.py's startup lines with full `RNS.prettyhexrep` hashes: a loaded identity
/// with the propagation node on, a created one with it off.
#[cfg(unix)]
#[test]
fn startup_logs_full_identity_delivery_and_propagation_hashes() {
    use rns_identity::destination::Destination;
    use rns_identity::identity::Identity;

    for propagation in [true, false] {
        let lxmf_dir = TestDir::new("lxmf-startup-lines");
        let rns_dir = TestDir::new("rns-startup-lines");
        let identity_path = lxmf_dir.path().join("identity");
        if propagation {
            write_rust_identity(&identity_path);
        }
        fs::write(
            lxmf_dir.path().join("config"),
            format!(
                "[lxmf]\n\n[propagation]\nenable_node = {}\n",
                if propagation { "yes" } else { "no" }
            ),
        )
        .expect("write LXMF config");
        fs::write(
            rns_dir.path().join("config"),
            "\
[reticulum]
share_instance = No
enable_transport = No
respond_to_probes = No
panic_on_interface_error = No
discover_interfaces = No

[interfaces]
",
        )
        .expect("write no-interface Reticulum config");

        let log_path = rns_dir.path().join("lxmd-rs.log");
        let log = fs::File::create(&log_path).expect("create lxmd-rs log");
        let log_err = log.try_clone().expect("clone lxmd-rs log");
        let mut daemon = Daemon(Some(
            Command::new(env!("CARGO_BIN_EXE_lxmd-rs"))
                .arg("--config")
                .arg(lxmf_dir.path())
                .arg("--rnsconfig")
                .arg(rns_dir.path())
                .stdout(log)
                .stderr(log_err)
                .spawn()
                .expect("lxmd-rs subprocess should start"),
        ));

        let read_log = || fs::read_to_string(&log_path).unwrap_or_default();
        let deadline = Instant::now() + Duration::from_secs(30);
        while !read_log().contains("LXMF Daemon running") {
            if let Some(status) = daemon.child().try_wait().expect("poll lxmd-rs startup") {
                panic!("lxmd-rs exited during startup ({status}):\n{}", read_log());
            }
            assert!(
                Instant::now() < deadline,
                "lxmd-rs did not finish startup:\n{}",
                read_log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        drop(daemon);
        let text = read_log();

        let identity = Identity::from_file(&identity_path).expect("read lxmd-rs identity");
        let pretty = |hash: &[u8]| format!("<{}>", hex::encode(hash));
        let delivery =
            Destination::hash_from_name_and_identity("lxmf.delivery", Some(&identity.hash));
        let node =
            Destination::hash_from_name_and_identity("lxmf.propagation", Some(&identity.hash));
        let identity_line = if propagation {
            format!("Loaded Primary Identity {}", pretty(&identity.hash))
        } else {
            format!("Created new Primary Identity {}", pretty(&identity.hash))
        };
        let delivery_line = format!("LXMF Router ready to receive on {}", pretty(&delivery));
        let node_line = format!("LXMF Propagation Node started on {}", pretty(&node));

        let position = |line: &str| {
            text.find(line)
                .unwrap_or_else(|| panic!("missing {line:?} in lxmd-rs output:\n{text}"))
        };
        let running = position("LXMF Daemon running");
        assert!(
            position(&identity_line) < position(&delivery_line),
            "{text}"
        );
        if propagation {
            assert!(position(&delivery_line) < position(&node_line), "{text}");
            assert!(position(&node_line) < running, "{text}");
        } else {
            assert!(position(&delivery_line) < running, "{text}");
            assert!(
                !text.contains("LXMF Propagation Node started on"),
                "propagation line without a propagation node:\n{text}"
            );
        }
    }
}

#[test]
fn version_reports_binary_name_and_package_version() {
    let output = lxmd(&["--version"]);

    assert!(
        output.status.success(),
        "expected --version to succeed, got:\n{}",
        combined_output(&output)
    );
    assert_eq!(
        stdout(&output).trim(),
        format!(
            "lxmd-rs {} (LXMF {}, Reticulum {})",
            env!("CARGO_PKG_VERSION"),
            lxmf_tools::lxmd_cli::LXMF_COMPAT_VERSION,
            rns_tools::RETICULUM_COMPAT_VERSION
        )
    );
    assert!(stderr(&output).is_empty());
}

#[test]
fn rust_binary_runs_cli() {
    let output = lxmd(&["--version"]);

    assert!(
        output.status.success(),
        "expected lxmd-rs --version to succeed, got:\n{}",
        combined_output(&output)
    );
    assert_eq!(
        stdout(&output).trim(),
        format!(
            "lxmd-rs {} (LXMF {}, Reticulum {})",
            env!("CARGO_PKG_VERSION"),
            lxmf_tools::lxmd_cli::LXMF_COMPAT_VERSION,
            rns_tools::RETICULUM_COMPAT_VERSION
        )
    );
    assert!(stderr(&output).is_empty());
}

/// `-c` and `-V` are spellings the 1.3 and 1.4 releases accepted and
/// upstream never had: they still work and are announced on stderr.
#[test]
fn released_short_spellings_work_with_a_warning() {
    let long = lxmd(&["--config", "/nonexistent/lxmd", "--exampleconfig"]);
    assert!(long.status.success(), "{}", combined_output(&long));
    assert!(stderr(&long).is_empty());
    for short in [
        &["-c", "/nonexistent/lxmd", "--exampleconfig"][..],
        &["-c/nonexistent/lxmd", "--exampleconfig"],
    ] {
        let output = lxmd(short);
        assert!(output.status.success(), "{}", combined_output(&output));
        assert_eq!(stdout(&output), stdout(&long), "{short:?}");
        assert_eq!(
            stderr(&output),
            "lxmd-rs: warning: -c is deprecated, use --config\n",
            "{short:?}"
        );
    }

    let version = lxmd(&["--version"]);
    let short = lxmd(&["-V"]);
    assert!(short.status.success(), "{}", combined_output(&short));
    assert_eq!(stdout(&short), stdout(&version));
    assert_eq!(
        stderr(&short),
        "lxmd-rs: warning: -V is deprecated, use --version\n"
    );

    let help = stdout(&lxmd(&["--help"]));
    assert!(help.contains("--config") && help.contains("--version"));
    assert!(!help.contains("-c,") && !help.contains("-V,"), "{help}");
}

#[test]
fn example_config_exits_before_runtime_initialisation() {
    let output = lxmd(&["--exampleconfig"]);

    assert!(
        output.status.success(),
        "expected --exampleconfig to succeed, got:\n{}",
        combined_output(&output)
    );
    let text = stdout(&output);
    assert!(text.contains("[lxmf]"));
    assert!(text.contains("display_name = Anonymous Peer"));
    assert!(text.contains("announce_at_start = no"));
    assert!(text.contains("# stamp_cost = 12"));
    assert!(text.contains("delivery_transfer_max_accepted_size = 1"));
    assert!(text.contains("[propagation]"));
    assert!(text.contains("enable_node = no"));
    assert!(text.contains("announce_interval = 360"));
    assert!(text.contains("announce_at_start = yes"));
    assert!(text.contains("# sequential_pn_stamp_validation = yes"));
    assert!(text.contains("# static_peers_bypass_sequential = yes"));
    assert!(text.contains("# max_inbound_syncs = 3"));
    assert!(text.contains("[logging]"));
    assert!(text.contains("loglevel = 4"));
    assert!(!text.contains("[control]"));
    assert!(
        stderr(&output).is_empty(),
        "--exampleconfig should return before logging/runtime startup"
    );
}

#[test]
fn send_method_values_parse_without_network_runtime() {
    for mode in ["opportunistic", "direct", "propagated"] {
        let output = lxmd(&["--exampleconfig", "--send-method", mode]);

        assert!(
            output.status.success(),
            "expected send method {mode:?} to parse, got:\n{}",
            combined_output(&output)
        );
        assert!(stdout(&output).contains("[lxmf]"));
        assert!(stderr(&output).is_empty());
    }
}

#[test]
fn clap_rejects_invalid_send_method() {
    let output = lxmd(&["--send-method", "bogus"]);

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected Clap usage failure, got:\n{}",
        combined_output(&output)
    );
    let text = stderr(&output);
    assert!(text.contains("invalid value 'bogus' for '--send-method <SEND_METHOD>'"));
    assert!(text.contains("[possible values: opportunistic, direct, propagated]"));
}

#[test]
fn clap_requires_send_argument() {
    let output = lxmd(&["--send"]);

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected Clap usage failure, got:\n{}",
        combined_output(&output)
    );
    assert!(stderr(&output).contains("a value is required for '--send <DEST_HASH> <CONTENT>...'"));
}

#[test]
fn status_and_peers_time_out_without_a_reachable_node() {
    let lxmf_dir = TestDir::new("lxmf");
    let rns_dir = TestDir::new("rns");
    write_rust_identity(&lxmf_dir.path().join("identity"));
    fs::write(
        rns_dir.path().join("config"),
        "\
[reticulum]
share_instance = No
enable_transport = No
respond_to_probes = No
panic_on_interface_error = No
discover_interfaces = No

[interfaces]
",
    )
    .expect("write no-interface Reticulum config");

    // Python `if not args.timeout` turns 0 into the 5 s default.
    let started = std::time::Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_lxmd-rs"))
        .arg("--config")
        .arg(lxmf_dir.path())
        .arg("--rnsconfig")
        .arg(rns_dir.path())
        .arg("--status")
        .arg("--peers")
        .arg("--timeout")
        .arg("0")
        .arg("-v")
        .output()
        .expect("lxmd-rs subprocess should run");

    assert_eq!(
        output.status.code(),
        Some(200),
        "expected the control query to time out, got:\n{}",
        combined_output(&output)
    );
    assert_eq!(
        stdout(&output),
        "Getting lxmd statistics timed out, exiting now\n",
        "control commands print only the result on stdout"
    );
    assert!(
        (4..9).contains(&started.elapsed().as_secs()),
        "--timeout 0 must fall back to the default"
    );
    assert!(
        !lxmf_dir.path().join("storage").exists() && !lxmf_dir.path().join("config").exists(),
        "--status/--peers must not start local daemon state"
    );
}

#[test]
fn control_status_rejects_missing_identity_before_runtime() {
    let lxmf_dir = TestDir::new("lxmf-missing-identity");
    let rns_dir = TestDir::new("rns-missing-identity");
    fs::write(
        rns_dir.path().join("config"),
        "\
[reticulum]
share_instance = No

[interfaces]
",
    )
    .expect("write no-interface Reticulum config");

    let output = Command::new(env!("CARGO_BIN_EXE_lxmd-rs"))
        .arg("--config")
        .arg(lxmf_dir.path())
        .arg("--rnsconfig")
        .arg(rns_dir.path())
        .arg("--status")
        .output()
        .expect("lxmd-rs subprocess should run");

    assert_eq!(
        output.status.code(),
        Some(202),
        "expected Python-compatible missing identity exit, got:\n{}",
        combined_output(&output)
    );
    assert!(
        combined_output(&output)
            .contains("Identity file not found in specified configuration directory"),
        "missing identity error should be user-visible:\n{}",
        combined_output(&output)
    );
    assert!(
        !lxmf_dir.path().join("storage").exists(),
        "control preflight should fail before daemon state is created"
    );
}

#[test]
fn control_preflight_invalid_hashes_exit_203() {
    let lxmf_dir = TestDir::new("lxmf-invalid-control");
    let rns_dir = TestDir::new("rns-invalid-control");
    write_rust_identity(&lxmf_dir.path().join("identity"));
    fs::write(
        rns_dir.path().join("config"),
        "\
[reticulum]
share_instance = No

[interfaces]
",
    )
    .expect("write no-interface Reticulum config");

    for args in [
        vec!["--sync", "zz"],
        vec!["--sync", "00"],
        vec!["--break", "zz"],
        vec!["--status", "--remote", "zz"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_lxmd-rs"))
            .args(&args)
            .arg("--config")
            .arg(lxmf_dir.path())
            .arg("--rnsconfig")
            .arg(rns_dir.path())
            .output()
            .expect("lxmd-rs subprocess should run");

        assert_eq!(
            output.status.code(),
            Some(203),
            "expected invalid control hash exit for {args:?}, got:\n{}",
            combined_output(&output)
        );
        assert!(
            combined_output(&output).contains("Invalid"),
            "invalid hash error should be user-visible for {args:?}:\n{}",
            combined_output(&output)
        );
    }
}
