use regex::Regex;

// Seqeuence parsing regex
lazy_static::lazy_static! { static ref RE_NUM: Regex = Regex::new(r"\d+").unwrap(); }
lazy_static::lazy_static! {
    static ref RE_CHR: Regex = Regex::new(r"[a-zA-Z]+").unwrap();
}

/// Vim modes
#[derive(PartialEq, Eq)]
pub enum Vim { Normal, Insert, }

/// Vim motions input handling
///
/// import the following in the file using the macro:
/// `use crossterm::event::{self, Event, KeyCode, KeyModifiers};`
macro_rules! input_handling {
    ($vim_mode: ident, $seq: ident, $input:ident, $cursor_pos:ident, $persis_y:ident) => {
        let mut n = RE_NUM.find_iter(&$seq)
            .map(|m| m.as_str().parse::<usize>().unwrap_or(0))
            .fold(0usize, |acc, x| acc.saturating_add(x))
            .min(999999);
        let k = RE_CHR.find_iter(&$seq).map(|m| m.as_str()).collect::<String>();
        let k = if k.is_empty() { None } else { Some(k.as_str()) };
        if event::poll(std::time::Duration::from_millis(100))? {
            let event = event::read()?;
            if let Event::Key(key) = event {
                match key.code {
                    // Universal
                    KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Left => {
                        $cursor_pos = $cursor_pos.saturating_sub(1);
                        $persis_y = 0;
                    },
                    KeyCode::Right => if $cursor_pos < $input.len() {
                        $cursor_pos += 1;
                        $persis_y = 0;
                    },
                    KeyCode::Up => {
                        let lines: Vec<&str> = $input.split('\n').collect();
                        let chars_before: Vec<char> = $input.chars().take($cursor_pos).collect();
                        let newlines_before = chars_before.iter().filter(|&&c| c == '\n').count();
                        let current_col = chars_before.iter().rev().take_while(|&&c| c != '\n').count();
                        
                        $persis_y = $persis_y.max(current_col);
                        if newlines_before > 0 {
                            let prev_line_len = lines[newlines_before - 1].chars().count();
                            let target_col = $persis_y.min(prev_line_len);
                            
                            $cursor_pos = $cursor_pos.saturating_sub(current_col + 1 + (prev_line_len - target_col));
                        }
                    },
                    KeyCode::Down => {
                        let lines: Vec<&str> = $input.split('\n').collect();
                        let chars_before: Vec<char> = $input.chars().take($cursor_pos).collect();
                        let newlines_before = chars_before.iter().filter(|&&c| c == '\n').count();
                        let current_col = chars_before.iter().rev().take_while(|&&c| c != '\n').count();
                        
                        $persis_y = $persis_y.max(current_col);
                        if newlines_before < lines.len() - 1 {
                            let current_line_len = lines[newlines_before].chars().count();
                            let next_line_len = lines[newlines_before + 1].chars().count();
                            let target_col = $persis_y.min(next_line_len);
                            
                            $cursor_pos += (current_line_len - current_col) + 1 + target_col;
                        }
                    },
                    KeyCode::Delete => {
                        if n==0 { n+=1 };
                        while n>0 {
                            if $cursor_pos < $input.len() {
                                $input.remove($cursor_pos);
                                if ($cursor_pos == $input.len()) {
                                    $cursor_pos = $cursor_pos.saturating_sub(1);
                                }
                            }
                            n = n.saturating_sub(1);
                        }
                        $seq.clear();
                    },
                    KeyCode::Enter if key.modifiers.contains(KeyModifiers::ALT) && $vim_mode == Vim::Insert => { // NOTE: Specific to this app, allows new lines in messages
                        $input.insert($cursor_pos, '\n');
                        $cursor_pos += 1;
                    },
                    KeyCode::Enter => { // NOTE: Specific to this app
                        if n==0 { n = 1 };
                        for _ in 0..n.min(10) {
std::fs::OpenOptions::new().create(true).append(true).open("file.txt")?.write_all(format!("{}\n", $input).as_bytes())?; // dbg: print/send n times (up to 10)
                        }
                        $seq.clear();
                        $input.clear();
                        $cursor_pos = 0;
                    },

                    // NORMAL mode handling
                    KeyCode::Char('0') if n==0 && $vim_mode == Vim::Normal => {
                        let start = $cursor_pos;
                        $cursor_pos = 0;
                        
                        match k {
                            Some("d") => {
                                $input.drain($cursor_pos..start);
                                $seq.clear();
                            },
                            Some("c") => {
                                $input.drain($cursor_pos..start);
                                $vim_mode = Vim::Insert;
                                execute!(io::stdout(), SetCursorStyle::SteadyBar);
                                $seq.clear();
                            },
                            _ => {}
                        }
                    },
                    KeyCode::Char(n) if n.is_ascii_digit() && $vim_mode == Vim::Normal => {
                        $seq.push(n);
                    }
                    KeyCode::Esc if $vim_mode == Vim::Normal => { $seq.clear() },
                    KeyCode::Char('h') if $vim_mode == Vim::Normal => {
                        if n==0 { n=1 };
                        let start = $cursor_pos;
                        let chars_before: Vec<char> = $input.chars().take($cursor_pos).collect();
                        let line_start = chars_before.iter().rposition(|&c| c == '\n')
                            .map(|pos| pos + 1)
                            .unwrap_or(0);

                        while n>0 && $cursor_pos > line_start {
                            $cursor_pos = $cursor_pos.saturating_sub(1);
                            n = n.saturating_sub(1);
                        }
                        
                        match k {
                            Some("d") => {
                                $input.drain($cursor_pos..start);
                                $seq.clear();
                            },
                            Some("c") => {
                                $input.drain($cursor_pos..start);
                                $vim_mode = Vim::Insert;
                                execute!(io::stdout(), SetCursorStyle::SteadyBar);
                                $seq.clear();
                            },
                            _ => { $seq.clear(); }
                        }
                    },
                    KeyCode::Char('l') if $vim_mode == Vim::Normal => {
                        if n==0 { n=1 };
                        let start = $cursor_pos;
                        let chars_after: Vec<char> = $input.chars().skip($cursor_pos).collect();
                        let line_end = chars_after.iter().position(|&c| c == '\n')
                            .map(|pos| $cursor_pos + pos)
                            .unwrap_or($input.len());

                        while n>0 && $cursor_pos < line_end.saturating_sub(1) {
                            if $cursor_pos < $input.len().saturating_sub(1) {
                                $cursor_pos += 1;
                            };
                            n = n.saturating_sub(1);
                        }
                        
                        match k {
                            Some("d") => {
                                $input.drain(start..$cursor_pos);
                                $cursor_pos = start;
                                $seq.clear();
                            },
                            Some("c") => {
                                $input.drain(start..$cursor_pos);
                                $cursor_pos = start;
                                $vim_mode = Vim::Insert;
                                execute!(io::stdout(), SetCursorStyle::SteadyBar);
                                $seq.clear();
                            },
                            _ => { $seq.clear(); }
                        }
                    },
                    KeyCode::Char('$') if $vim_mode == Vim::Normal => {
                        let start = $cursor_pos;
                        $cursor_pos = $input.len().saturating_sub(1);
                        
                        match k {
                            Some("d") => {
                                $input.drain(start..($cursor_pos + 1));
                                $cursor_pos = start.saturating_sub(1);
                                $seq.clear();
                            },
                            Some("c") => {
                                $input.drain(start..($cursor_pos + 1));
                                $cursor_pos = start;
                                $vim_mode = Vim::Insert;
                                execute!(io::stdout(), SetCursorStyle::SteadyBar);
                                $seq.clear();
                            },
                            _ => { $seq.clear(); }
                        }
                    },
                    KeyCode::Char(s) if $vim_mode == Vim::Normal && (s=='^' || s=='_') => {
                        let start = $cursor_pos;
                        
                        match $input.chars().nth(0) {
                            Some(' ') => {
                                $cursor_pos = 0;
                                while $cursor_pos < $input.len() && !$input.chars().nth($cursor_pos).unwrap().is_whitespace() {
                                    $cursor_pos += 1;
                                }
                                while $cursor_pos < $input.len() && $input.chars().nth($cursor_pos).unwrap().is_whitespace() {
                                    $cursor_pos += 1;
                                }
                                $cursor_pos = $cursor_pos.min($input.len().saturating_sub(1));
                            },
                            _ => { $cursor_pos = 0; }
                        }
                        
                        match k {
                            Some("d") => {
                                let (left, right) = if start < $cursor_pos {
                                    (start, $cursor_pos)
                                } else {
                                    ($cursor_pos, start)
                                };
                                $input.drain(left..right);
                                $cursor_pos = left;
                                $seq.clear();
                            },
                            Some("c") => {
                                let (left, right) = if start < $cursor_pos {
                                    (start, $cursor_pos)
                                } else {
                                    ($cursor_pos, start)
                                };
                                $input.drain(left..right);
                                $cursor_pos = left;
                                $vim_mode = Vim::Insert;
                                execute!(io::stdout(), SetCursorStyle::SteadyBar);
                                $seq.clear();
                            },
                            _ => { $seq.clear(); }
                        }
                    },
                    KeyCode::Char(w) if $vim_mode == Vim::Normal && (w=='w' || w=='W') => {
                        if n==0 { n=1 };
                        let start = $cursor_pos;
                        
                        while n>0 {
                            while $cursor_pos < $input.len() && !$input.chars().nth($cursor_pos).unwrap().is_whitespace() {
                                $cursor_pos += 1;
                            }
                            while $cursor_pos < $input.len() && $input.chars().nth($cursor_pos).unwrap().is_whitespace() {
                                $cursor_pos += 1;
                            }
                            $cursor_pos = $cursor_pos.min($input.len().saturating_sub(1));
                            n = n.saturating_sub(1);
                        }
                        
                        match k {
                            Some("d") => {
                                $input.drain(start..$cursor_pos);
                                $cursor_pos = start;
                                $seq.clear();
                            },
                            Some("c") => {
                                $input.drain(start..$cursor_pos);
                                $cursor_pos = start;
                                $vim_mode = Vim::Insert;
                                execute!(io::stdout(), SetCursorStyle::SteadyBar);
                                $seq.clear();
                            },
                            _ => { $seq.clear(); }
                        }
                    },
                    KeyCode::Char(b) if $vim_mode == Vim::Normal && (b=='b' || b=='B') => {
                        if n==0 { n=1 };
                        let start = $cursor_pos;
                        
                        while n>0 {
                            if $cursor_pos > 0 { $cursor_pos -= 1; }
                            while $cursor_pos > 0 && $input.chars().nth($cursor_pos).unwrap().is_whitespace() {
                                $cursor_pos -= 1;
                            }
                            while $cursor_pos > 0 && !$input.chars().nth($cursor_pos).unwrap().is_whitespace() {
                                $cursor_pos -= 1;
                            }
                            if $cursor_pos > 0 { $cursor_pos += 1; }
                            n = n.saturating_sub(1);
                        }
                        
                        match k {
                            Some("d") => {
                                $input.drain($cursor_pos..start);
                                $seq.clear();
                            },
                            Some("c") => {
                                $input.drain($cursor_pos..start);
                                $vim_mode = Vim::Insert;
                                execute!(io::stdout(), SetCursorStyle::SteadyBar);
                                $seq.clear();
                            },
                            _ => { $seq.clear(); }
                        }
                    },
                    KeyCode::Char(e) if $vim_mode == Vim::Normal && (e=='e' || e=='E') => {
                        if n==0 { n=1 };
                        let start = $cursor_pos;
                        
                        while n>0 {
                            match k {
                                Some("g") | Some("dg") | Some("cg") => {
                                    if $cursor_pos > 0 { $cursor_pos -= 1; }
                                    while $cursor_pos > 0 && $input.chars().nth($cursor_pos).unwrap().is_whitespace() {
                                        $cursor_pos -= 1;
                                    }
                                    while $cursor_pos > 0 && !$input.chars().nth($cursor_pos).unwrap().is_whitespace() {
                                        $cursor_pos -= 1;
                                    }
                                    while $cursor_pos < $input.len() && !$input.chars().nth($cursor_pos).unwrap().is_whitespace() {
                                        $cursor_pos += 1;
                                    }
                                    if $cursor_pos > 0 { $cursor_pos -= 1; }
                                },
                                _ => {
                                    if $cursor_pos < $input.len() { $cursor_pos += 1; }
                                    while $cursor_pos < $input.len() && $input.chars().nth($cursor_pos).unwrap().is_whitespace() {
                                        $cursor_pos += 1;
                                    }
                                    while $cursor_pos < $input.len() && !$input.chars().nth($cursor_pos).unwrap().is_whitespace() {
                                        $cursor_pos += 1;
                                    }
                                    if $cursor_pos > 0 { $cursor_pos -= 1; }
                                }
                            }
                            n = n.saturating_sub(1);
                        }

                        let (left, right) = if start < $cursor_pos {
                            (start, $cursor_pos + 1)
                        } else {
                            ($cursor_pos, start + 1)
                        };

                        match k {
                            Some("d") | Some("dg") => {
                                $input.drain(left..right);
                                $cursor_pos = left;
                                $seq.clear();
                            },
                            Some("c") | Some("cg") => {
                                $input.drain(left..right);
                                $cursor_pos = left;
                                $vim_mode = Vim::Insert;
                                execute!(io::stdout(), SetCursorStyle::SteadyBar);
                                $seq.clear();
                            },
                            _ => { $seq.clear(); }
                        }
                    },
                    KeyCode::Char('i') if $vim_mode == Vim::Normal => {
                        $seq.clear();
                        $vim_mode = Vim::Insert;
                        execute!(io::stdout(), SetCursorStyle::SteadyBar);
                    },
                    KeyCode::Char('I') if $vim_mode == Vim::Normal => {
                        $seq.clear();
                        match $input.chars().nth(0) {
                            Some(' ') => {
                                $seq.clear();
                                $cursor_pos = 0;
                                while $cursor_pos < $input.len() && !$input.chars().nth($cursor_pos).unwrap().is_whitespace() {
                                    $cursor_pos += 1;
                                }
                                while $cursor_pos < $input.len() && $input.chars().nth($cursor_pos).unwrap().is_whitespace() {
                                    $cursor_pos += 1;
                                }
                                $cursor_pos = $cursor_pos.min($input.len().saturating_sub(1));
                            },
                            _ => { $cursor_pos = 0; }
                        }
                        $vim_mode = Vim::Insert;
                        execute!(io::stdout(), SetCursorStyle::SteadyBar);
                    },
                    KeyCode::Char('a') if $vim_mode == Vim::Normal => {
                        $seq.clear();
                        if $cursor_pos < $input.len() { $cursor_pos += 1; };
                        $vim_mode = Vim::Insert;
                        execute!(io::stdout(), SetCursorStyle::SteadyBar);
                    },
                    KeyCode::Char('A') if $vim_mode == Vim::Normal => {
                        $seq.clear();
                        $cursor_pos = $input.len();
                        $vim_mode = Vim::Insert;
                        execute!(io::stdout(), SetCursorStyle::SteadyBar);
                    },
                    KeyCode::Char('g') if $vim_mode == Vim::Normal => {
                        match k {
                            Some("g") => {
                                $cursor_pos = n.saturating_sub(1);
                                $seq.clear();
                            },
                            _ => { $seq.push('g'); }
                        }
                    },
                    KeyCode::Char('S') if $vim_mode == Vim::Normal => {
                        $input.clear();
                        $seq.clear();
                        $cursor_pos = 0;
                    },
                    KeyCode::Char('s') if $vim_mode == Vim::Normal => {
                        if n==0 { n+=1 };
                        while n>0 {
                            if $cursor_pos < $input.len() {
                                $input.remove($cursor_pos);
                            }
                            n = n.saturating_sub(1);
                        }
                        $seq.clear();
                        $vim_mode = Vim::Insert;
                        execute!(io::stdout(), SetCursorStyle::SteadyBar);
                    },
                    KeyCode::Char(x) if $vim_mode == Vim::Normal && (x=='x' || x=='X') => {
                        if n==0 { n+=1 };
                        while n>0 {
                            if x == 'X' {
                                if $cursor_pos > 0 {
                                    $cursor_pos = $cursor_pos.saturating_sub(1);
                                    $input.remove($cursor_pos);
                                    if ($cursor_pos == 0) { continue; }
                                }
                            } else {
                                if $cursor_pos < $input.len() {
                                    $input.remove($cursor_pos);
                                    if ($cursor_pos == $input.len()) {
                                        $cursor_pos = $cursor_pos.saturating_sub(1);
                                        break;
                                    }
                                }
                            }
                            n = n.saturating_sub(1);
                        }
                        $seq.clear();
                    },
                    KeyCode::Char('d') if $vim_mode == Vim::Normal => {
                        match k {
                            Some("d") => {
                                $input.clear();
                                $seq.clear();
                                $cursor_pos = 0;
                            },
                            Some("g") => { $seq.clear(); },
                            Some("c") => { $seq.clear(); },
                            _ => { $seq.push('d'); }
                        }
                    },
                    KeyCode::Char('c') if $vim_mode == Vim::Normal => {
                        match k {
                            Some("c") => {
                                $input.clear();
                                $seq.clear();
                                $cursor_pos = 0;
                                $vim_mode = Vim::Insert;
                                execute!(io::stdout(), SetCursorStyle::SteadyBar);
                            },
                            Some("g") => { $seq.clear(); },
                            Some("d") => { $seq.clear(); },
                            _ => { $seq.push('c'); }
                        }
                    },
                    KeyCode::Char('D') if $vim_mode == Vim::Normal => {
                        while $cursor_pos != $input.len() {
                            $input.remove($cursor_pos);
                        }
                    },
                    KeyCode::Char('C') if $vim_mode == Vim::Normal => {
                        while $cursor_pos != $input.len() {
                            $input.remove($cursor_pos);
                        }
                        $vim_mode = Vim::Insert;
                        execute!(io::stdout(), SetCursorStyle::SteadyBar);
                    },

                    // INSERT mode handling
                    KeyCode::Backspace if $vim_mode == Vim::Insert => {
                        if $cursor_pos > 0 {
                            $cursor_pos -= 1;
                            $input.remove($cursor_pos);
                        }
                    },
                    KeyCode::Esc if $vim_mode == Vim::Insert => {
                        $cursor_pos = $cursor_pos.saturating_sub(1);
                        $vim_mode = Vim::Normal;
                        execute!(io::stdout(), SetCursorStyle::SteadyBlock);
                    },
                    KeyCode::Char(c) if $vim_mode == Vim::Insert => {
                        $input.insert($cursor_pos, c);
                        $cursor_pos += 1;
                    },
                    _ => {}
                }
            }
        }
    };
}

pub(crate) use input_handling;
