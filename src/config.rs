pub struct Config {
    // Whether to display system call numbers or not.
    pub syscall_number: bool,

    // Process to attach to
    pub attach: i32,

    // Command to trace
    pub command: Vec<String>,

    // Maximum string size to print
    pub string_limit: i32,

    // Name of the file to print output to
    pub file: String,

    // Summary only
    pub summary_only: bool,

    // Summary in addition to the regular output
    pub summary: bool,

    // Print only successful syscalls
    pub successful_only: bool,

    // Print only failed syscalls
    pub failed_only: bool,

    // Print unabbreviated strings
    pub no_abbrev: bool,

    // Set or remove environment variables
    pub env: Vec<String>,

    // Run command with uid and gid of username
    pub username: String,
}
