pub struct Config {
    // Whether to display system call numbers or not.
    pub syscall_number: bool,

    // Process to attach to
    pub attach: i32,

    // Command to trace
    pub command: String,

    // Maximum string size to print
    pub string_limit: i32,
}