use console::{style, Term, StyledObject};

pub struct Terminal {
    term: Term,
    width: u16,
    height: u16,
}

impl Terminal {
    pub fn new() -> Self {
        let term = Term::stdout();
        let (width, height) = term.size();
        Terminal { term, width, height }
    }

    pub fn write_line(&self, text: &str) {
        let _ = self.term.write_line(text);
    }

    pub fn write_str(&self, text: &str) {
        let _ = self.term.write_str(text);
    }

    pub fn clear_line(&self) {
        let _ = self.term.clear_line();
    }

    pub fn clear_screen(&self) {
        let _ = self.term.clear_screen();
    }

    pub fn move_cursor_up(&self, n: usize) {
        let _ = self.term.move_cursor_up(n);
    }

    pub fn move_cursor_down(&self, n: usize) {
        let _ = self.term.move_cursor_down(n);
    }

    pub fn write_line_at(&self, row: usize, col: usize, text: &str) {
        let _ = self.term.move_cursor_to(col, row);
        let _ = self.term.write_str(text);
    }

    pub fn hide_cursor(&self) { let _ = self.term.hide_cursor(); }
    pub fn show_cursor(&self) { let _ = self.term.show_cursor(); }

    pub fn set_title(&self, title: &str) {
        let _ = self.term.set_title(title);
    }

    pub fn size(&self) -> (u16, u16) { (self.width, self.height) }
}

pub fn green(text: &str) -> StyledObject<&str> { style(text).green() }
pub fn red(text: &str) -> StyledObject<&str> { style(text).red() }
pub fn yellow(text: &str) -> StyledObject<&str> { style(text).yellow() }
pub fn cyan(text: &str) -> StyledObject<&str> { style(text).cyan() }
pub fn bold(text: &str) -> StyledObject<&str> { style(text).bold() }
pub fn dim(text: &str) -> StyledObject<&str> { style(text).dim() }
pub fn white(text: &str) -> StyledObject<&str> { style(text).white() }
pub fn italic(text: &str) -> StyledObject<&str> { style(text).italic() }

pub fn colored_status(success: bool, text: &str) -> String {
    if success {
        style(text).green().bold().to_string()
    } else {
        style(text).red().to_string()
    }
}

pub fn truncate_middle(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        return text.to_string();
    }
    let half = (max_len.saturating_sub(3)) / 2;
    format!("{}...{}", &text[..half], &text[text.len() - half..])
}

pub fn pad_right(text: &str, width: usize) -> String {
    if text.len() >= width {
        text[..width].to_string()
    } else {
        let mut s = text.to_string();
        s.push_str(&" ".repeat(width - s.len()));
        s
    }
}

pub fn progress_bar_text(current: u64, total: u64, width: usize) -> String {
    if total == 0 {
        return " ".repeat(width);
    }
    let filled = ((current as f64 / total as f64) * width as f64) as usize;
    let filled = filled.min(width);
    let bar: String = std::iter::repeat('█').take(filled)
        .chain(std::iter::repeat('░').take(width.saturating_sub(filled)))
        .collect();
    style(bar).cyan().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_middle_short() {
        assert_eq!(truncate_middle("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_middle_long() {
        let result = truncate_middle("abcdefghijklmnopqrstuvwxyz", 10);
        assert_eq!(result.len(), 9);
        assert!(result.contains("..."));
        assert!(result.starts_with("abc"));
        assert!(result.ends_with("xyz"));
    }

    #[test]
    fn test_pad_right() {
        assert_eq!(pad_right("hi", 5), "hi   ");
        assert_eq!(pad_right("hello", 3), "hel");
    }

    #[test]
    fn test_progress_bar_text() {
        let bar = progress_bar_text(50, 100, 10);
        assert!(bar.contains('█') || bar.contains('░'));
        assert!(!bar.is_empty());
    }

    #[test]
    fn test_progress_bar_zero_total() {
        let bar = progress_bar_text(0, 0, 10);
        assert_eq!(bar, "          ");
    }

    #[test]
    fn test_truncate_middle_exact() {
        assert_eq!(truncate_middle("hello", 5), "hello");
    }
}
