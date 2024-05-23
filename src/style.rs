use console::Style;

use crate::syscall_info::RetCode;

#[derive(Clone, Debug)]
pub struct StyleConfig {
    pub pid: Style,
    pub syscall: Style,
    pub success: Style,
    pub error: Style,
    pub result: Style,
    pub use_colors: bool,
}

impl Default for StyleConfig {
    fn default() -> Self {
        Self {
            pid: Style::new().bold().blue(),
            syscall: Style::new().bold(),
            success: Style::new().green().bold(),
            error: Style::new().red().bold(),
            result: Style::new().yellow().bold(),
            use_colors: true,
        }
    }
}

impl StyleConfig {
    pub fn from_ret_code(&self, ret_code: RetCode) -> Style {
        match ret_code {
            RetCode::Ok(_) => self.success.clone(),
            RetCode::Err(_) => self.error.clone(),
            RetCode::Address(_) => self.result.clone(),
        }
    }
}
