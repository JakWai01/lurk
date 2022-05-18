use nix::sys::ptrace;
use nix::unistd::{fork, ForkResult, Pid};

fn main() {
    match unsafe{fork()} {
        Ok(ForkResult::Child) => {
            run_child();
        }

        Ok(ForkResult::Parent {child}) => {
            run_parent(child);
        }

        Err(err) => {
            panic!("[main] fork() failed: {}", err);
        }
    }

    loop{}
}

fn run_parent(_child: Pid) {}

fn run_child() {
    ptrace::traceme().unwrap();
}