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

// The second rax contains the return value
// If this is larger than 10000, we can assume it is an address and has to be converted to hex
fn run_tracer(child: Pid) {
    loop {
        wait().unwrap();

        let reg;

        match ptrace::getregs(child) {
            Ok(x) => {
                
                if x.orig_rax == 0 || x.orig_rax == 1 || x.orig_rax == 2 {
                    reg = x.rsi;

                    let syscall_tuple = system_call_names::SYSTEM_CALLS[(x.orig_rax) as usize];

                    let argument_type_array: [system_call_names::SystemCallArgumentType; 6] = [syscall_tuple.1, syscall_tuple.2, syscall_tuple.3, syscall_tuple.4, syscall_tuple.5, syscall_tuple.6];
                    
                    println!("{:?}", system_call_names::SYSTEM_CALLS[(x.orig_rax) as usize].0);

                    let mut output = format!("[{:?}] {}(", child.as_raw(), system_call_names::SYSTEM_CALLS[(x.orig_rax) as usize].0);

                    for (i, arg) in argument_type_array.iter().enumerate() {
                        let value = match i {
                            0 => x.rdi,
                            1 => x.rsi,
                            2 => x.rdx,
                            3 => x.r10,
                            4 => x.r8,
                            5 => x.r9,
                            _ => panic!("Invalid system call definition!")
                        };


                        match arg {
                            system_call_names::SystemCallArgumentType::Integer => {
                                output.push_str(format!("{:?}, ", value).as_str());
                            },
                            system_call_names::SystemCallArgumentType::String => {
                                output.push_str(format!("{:?}, ", read_string(child, reg as *mut c_void)).as_str());
                            },
                            system_call_names::SystemCallArgumentType::Address => {
                                output.push_str(format!("{:?}, ", value).as_str());
                            },
                            system_call_names::SystemCallArgumentType::None => {
                                continue;
                            },
                        }
                    }

                    output.push_str(")");
                    println!("{:?}", output);
                } else {
                    println!(
                        "[{:?}]: {}() = {:?}",
                        child.as_raw(),
                        system_call_names::SYSTEM_CALL_NAMES[(x.orig_rax) as usize],
                        {
                            reg = x.rsi;
                            x
                        },
                    )}
                }
            ,
            Err(_) => break,
        };

        println!("{:?}", reg);
        let stringer = read_string(child, reg as *mut c_void);
        if stringer != "" {
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
        
        // let res: c_long = ptrace::read(pid, address).unwrap_or_else(|err| {
        //     // panic!("Failed to read data for pid {}: {}", pid, err);
        //     continue;
        // });

        let res: c_long;

        match ptrace::read(pid, address) {
            Ok(c_long) => {
                res = c_long
            },
            Err(_) => break 'done
        }

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