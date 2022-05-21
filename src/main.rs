mod system_call_names;

use linux_personality::personality;
use nix::sys::ptrace;
use nix::sys::wait::wait;
use nix::unistd::{fork, ForkResult, Pid};
use std::os::unix::process::CommandExt;
use std::process::{exit, Command};

fn main() {
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            run_tracee();
        }

        Ok(ForkResult::Parent { child }) => {
            run_tracer(child);
        }

        Err(err) => {
            panic!("[main] fork() failed: {}", err);
        }
    }
}

fn run_tracer(child: Pid) {
    let mut traced: bool = false;

    loop {
        wait().unwrap();

        if !traced {
            match ptrace::getregs(child) {
                Ok(x) => println!(
                    "Syscall number: {:?}",
                    system_call_names::SYSTEM_CALL_NAMES[(x.orig_rax) as usize]
                ),
                Err(_) => break,
            };
            traced = true;
        } else {
            traced = false;
        }

        match ptrace::syscall(child, None) {
            Ok(_) => continue,
            Err(_) => break,
        }
    }
}

fn run_tracee() {
    ptrace::traceme().unwrap();
    personality(linux_personality::ADDR_NO_RANDOMIZE).unwrap();

    Command::new("pwd").exec();

    exit(0)
}
