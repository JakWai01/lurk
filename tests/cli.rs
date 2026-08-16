use serde_json::Value;
use std::path::Path;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

fn lurk(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lurk"))
        .args(args)
        .output()
        .expect("failed to run lurk")
}

#[test]
fn preserves_stdio_and_tracee_exit_status() {
    let output = lurk(&["/bin/sh", "-c", "printf visible; exit 37"]);
    assert_eq!(output.status.code(), Some(37));
    assert_eq!(output.stdout, b"visible");

    let trace = String::from_utf8_lossy(&output.stderr);
    assert_eq!(trace.matches("execve(").count(), 1, "{trace}");

    let output = lurk(&["/bin/sh", "-c", "kill -TERM $$"]);
    assert_eq!(output.status.code(), Some(128 + 15));
}

#[test]
fn filters_apply_to_exec_and_summary_totals() {
    let output = lurk(&["-e", "trace=read", "/bin/true"]);
    assert!(output.status.success());
    let trace = String::from_utf8_lossy(&output.stderr);
    assert!(!trace.contains("execve("), "{trace}");
    assert!(trace.lines().all(|line| line.contains("read(")), "{trace}");

    let output = lurk(&["-c", "-e", "trace=kill", "/bin/true"]);
    assert!(output.status.success());
    let summary = String::from_utf8_lossy(&output.stderr);
    assert!(summary.contains("0        0     total"), "{summary}");
}

#[test]
fn json_exec_record_does_not_copy_the_environment() {
    let output = Command::new(env!("CARGO_BIN_EXE_lurk"))
        .env("LURK_TEST_SECRET", "must-not-appear")
        .args(["-j", "-e", "trace=execve", "/bin/true"])
        .output()
        .expect("failed to run lurk");
    assert!(output.status.success());
    let trace = String::from_utf8_lossy(&output.stderr);
    assert!(!trace.contains("must-not-appear"), "{trace}");
    let record: Value = serde_json::from_str(trace.trim()).expect("invalid JSON trace record");
    assert!(record["args"][2]["count"].is_number(), "{record}");
}

#[test]
fn follows_children_without_sharing_syscall_state() {
    let output = lurk(&[
        "-f",
        "-e",
        "trace=execve",
        "/bin/sh",
        "-c",
        "sleep 0.01 & wait",
    ]);
    assert!(output.status.success());
    let trace = String::from_utf8_lossy(&output.stderr);
    assert!(trace.contains("Attaching to child"), "{trace}");
    assert!(trace.contains("[\"sleep\", \"0.01\"]"), "{trace}");
    assert_eq!(trace.matches("execve(").count(), 2, "{trace}");
}

#[test]
fn unknown_syscalls_do_not_crash_the_tracer() {
    if !Path::new("/usr/bin/python3").exists() {
        return;
    }
    let output = lurk(&[
        "-e",
        "trace=!execve",
        "/usr/bin/python3",
        "-c",
        "import ctypes; ctypes.CDLL(None).syscall(470,0,0,0,0,0,0)",
    ]);
    assert!(output.status.success());
    let trace = String::from_utf8_lossy(&output.stderr);
    assert!(trace.contains("syscall_470("), "{trace}");
    assert!(!trace.contains("panicked"), "{trace}");
}

#[test]
fn full_width_unknown_syscall_numbers_do_not_abort_tracing() {
    if !Path::new("/usr/bin/python3").exists() {
        return;
    }
    let output = lurk(&[
        "-e",
        "trace=!execve",
        "/usr/bin/python3",
        "-S",
        "-c",
        "import ctypes; ctypes.CDLL(None).syscall(-1)",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let trace = String::from_utf8_lossy(&output.stderr);
    assert!(trace.contains("syscall_0xffffffffffffffff("), "{trace}");
}

#[test]
fn resumes_with_syscall_tracing_after_a_caught_signal() {
    if !Path::new("/usr/bin/python3").exists() {
        return;
    }
    let output = lurk(&[
        "-e",
        "trace=openat",
        "/usr/bin/python3",
        "-c",
        "import os,signal; signal.signal(signal.SIGUSR1,lambda *_:None); os.kill(os.getpid(),signal.SIGUSR1); open('/dev/null').close()",
    ]);
    assert!(output.status.success());
    let trace = String::from_utf8_lossy(&output.stderr);
    assert!(
        trace.lines().any(|line| line.contains("/dev/null")),
        "{trace}"
    );
}

#[test]
fn reads_output_buffers_at_syscall_exit() {
    if !Path::new("/usr/bin/python3").exists() {
        return;
    }
    let output = lurk(&[
        "-e",
        "trace=read",
        "/usr/bin/python3",
        "-c",
        "import os; r,w=os.pipe(); os.write(w,b'after'); os.read(r,5)",
    ]);
    assert!(output.status.success());
    let trace = String::from_utf8_lossy(&output.stderr);
    assert!(
        trace
            .lines()
            .any(|line| line.contains("read(") && line.contains("\"after\"")),
        "{trace}"
    );
}

#[test]
fn launched_tracees_remain_in_job_control_stops_until_sigcont() {
    if !Path::new("/usr/bin/python3").exists() {
        return;
    }
    let program = "import os,time,signal; p=os.fork(); (time.sleep(.2),os.kill(os.getppid(),signal.SIGCONT),os._exit(0)) if p==0 else (os.kill(os.getpid(),signal.SIGSTOP),os._exit(0))";
    let started = Instant::now();
    let output = lurk(&[
        "-e",
        "trace=exit_group",
        "/usr/bin/python3",
        "-S",
        "-c",
        program,
    ]);
    let elapsed = started.elapsed();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        elapsed >= Duration::from_millis(150),
        "elapsed: {elapsed:?}"
    );
}

#[test]
fn follow_attach_seizes_existing_threads() {
    if !Path::new("/usr/bin/python3").exists() {
        return;
    }
    let program = "import os,sys,time; p=os.fork(); code='import time,threading,ctypes; c=ctypes.CDLL(None); t=threading.Thread(target=lambda:[(c.syscall(39),time.sleep(.005)) for _ in range(40)]); t.start(); time.sleep(.3)'; (exec(code),os._exit(0)) if p==0 else (time.sleep(.05),os.execv(sys.argv[1],[sys.argv[1],'-f','-e','trace=getpid','-p',str(p)]))";
    let output = Command::new("/usr/bin/python3")
        .args(["-S", "-c", program, env!("CARGO_BIN_EXE_lurk")])
        .output()
        .expect("failed to run attach harness");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let trace = String::from_utf8_lossy(&output.stderr);
    assert!(trace.matches("getpid(").count() > 0, "{trace}");
}

#[test]
fn summary_uses_system_time_instead_of_blocked_wall_time() {
    if !Path::new("/usr/bin/python3").exists() {
        return;
    }
    let program = "import os,signal,time; r,w=os.pipe(); signal.signal(signal.SIGUSR1,lambda *_:None); signal.siginterrupt(signal.SIGUSR1,False); p=os.fork(); (time.sleep(.05),os.kill(os.getppid(),signal.SIGUSR1),time.sleep(.05),os.write(w,b'x'),os._exit(0)) if p==0 else (os.read(r,1),os.waitpid(p,0))";
    let output = lurk(&[
        "-c",
        "-e",
        "trace=read",
        "/usr/bin/python3",
        "-S",
        "-c",
        program,
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary = String::from_utf8_lossy(&output.stderr);
    let read_row = summary
        .lines()
        .find(|line| line.trim_end().ends_with("read │"))
        .unwrap_or_else(|| panic!("missing read row: {summary}"));
    let micros = read_row
        .split_whitespace()
        .find_map(|field| field.strip_suffix("µs"))
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_else(|| panic!("missing duration in row: {read_row}"));
    assert!(
        micros < 50_000,
        "summary used blocked wall time: {read_row}"
    );
}
