mod system_call_names;

use linux_personality::personality;
use nix::sys::ptrace;
use nix::sys::wait::wait;
use nix::unistd::{fork, ForkResult, Pid};
use std::os::unix::process::CommandExt;
use std::process::{exit, Command};
use libc::{c_long, c_void};
use nix::sys::ptrace::AddressType;
use byteorder::{LittleEndian, WriteBytesExt};


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
    loop {
        wait().unwrap();

        let reg;

        match ptrace::getregs(child) {
            Ok(x) => println!(
                "[{:?}]: {}() = {:?}",
                child.as_raw(),
                system_call_names::SYSTEM_CALL_NAMES[(x.orig_rax) as usize],
                {
                    reg = x.rdi;
                    x
                },
            ),
            Err(_) => break,
        };

        println!("{:?}", reg);
        // This isn't a valid condition to filter between addresses and non-addresses
        if reg > 100000 {
            let stringer = read_string(child, reg as *mut c_void);

            println!("{:?}", stringer);
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

    Command::new("ls").exec();

    exit(0)
}

fn read_string(pid: Pid, address: AddressType) -> String {
    let mut string = String::new();
    // Move 8 bytes up each time for next read.
    let mut count = 0;
    let word_size = 8;

    'done: loop {
        let mut bytes: Vec<u8> = vec![];
        let address = unsafe { address.offset(count) };

        println!("{:?}", address);
        
        let res: c_long = ptrace::read(pid, address).unwrap_or_else(|err| {
            panic!("Failed to read data for pid {}: {}", pid, err);
        });
        bytes.write_i64::<LittleEndian>(res).unwrap_or_else(|err| {
            panic!("Failed to write {} as i64 LittleEndian: {}", res, err);
        });

        for b in bytes {
            if b != 0 {
                string.push(b as char);
            } else {
                break 'done;
            }
        }
        count += word_size;
    }

    string
}