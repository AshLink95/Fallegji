//TODO: allow customization of border styles, max height, and colors using a toml-style dotfile. Parameters will be set in constants decided by the dotfile.
use std::io;
use anyhow::Result;
use regex::Regex;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    cursor::SetCursorStyle,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Alignment},
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph, BorderType},
    text::Line,
    Terminal,
};

// Seqeuence parsing regex
lazy_static::lazy_static!{static ref RE_NUM: Regex = Regex::new(r"\d+").unwrap();}
lazy_static::lazy_static!{static ref RE_CHR: Regex = Regex::new(r"[a-zA-Z]").unwrap();}

// Vim motions input handling
#[derive(PartialEq, Eq)]
enum Vim { Normal, Insert, }
macro_rules! input_handling {
    ($vim_mode: ident, $seq: ident, $input:ident, $cursor_pos:ident) => {
        //TODO: include a counter variable and a g variable for 'ge', a c variable for 'cc' and 'cn-hjkl', same for d [will be a sequence string that will get parsed using regex]
        //parse seq
        let mut n = RE_NUM.find_iter(&$seq)
            .map(|m| m.as_str().parse::<usize>().unwrap_or(0))
            .fold(0usize, |acc, x| acc.saturating_add(x))
            .min(999999);
        let k = RE_CHR.find(&$seq).map(|m| m.as_str());
        if event::poll(std::time::Duration::from_millis(100))? {
            let event = event::read()?;
            if let Event::Key(key) = event {
                match key.code {
                    // Universal
                    KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Left => {
                        if n==0 { n+=1 };
                        while n>0 {
                            $cursor_pos = $cursor_pos.saturating_sub(1);
                            n = n.saturating_sub(1);
                        }
                        $seq.clear();
                    },
                    KeyCode::Right => if $cursor_pos < $input.len() {
                        if n==0 { n+=1 };
                        while n>0 {
                            $cursor_pos += 1;
                            n = n.saturating_sub(1);
                        }
                        $seq.clear();
                    },
                    KeyCode::Delete => {
                        if n==0 { n+=1 };
                        while n>0 {
                            if $cursor_pos < $input.len() {
                                $input.remove($cursor_pos);
                            }
                            n = n.saturating_sub(1);
                        }
                        $seq.clear();
                    },
                    KeyCode::Enter => {
                        // dbg: print/send n times (up to 10)
                        $seq.clear();
                        $input.clear();
                        $cursor_pos = 0;
                    },

                    // NORMAL mode handling
                    KeyCode::Char('0') if $seq.is_empty() && $vim_mode == Vim::Normal => {
                        $cursor_pos = 0;
                    },
                    KeyCode::Char(n) if n.is_ascii_digit() && $vim_mode == Vim::Normal => {
                        $seq.push(n);
                    }
                    KeyCode::Esc if $vim_mode == Vim::Normal => { $seq.clear() },
                    //TODO: implement delete and change in h and l
                    KeyCode::Char('h') if $vim_mode == Vim::Normal => {
                        if n==0 { n+=1 };
                        while n>0 {
                            $cursor_pos = $cursor_pos.saturating_sub(1);
                            n = n.saturating_sub(1);
                        }
                        $seq.clear();
                    },
                    KeyCode::Char('l') if $vim_mode == Vim::Normal => {
                        if n==0 { n+=1 };
                        while n>0 {
                            if $cursor_pos < $input.len().saturating_sub(1) {
                                $cursor_pos += 1;
                            };
                            n = n.saturating_sub(1);
                        }
                        $seq.clear();
                    },
                    KeyCode::Char('$') if $vim_mode == Vim::Normal => {
                        $seq.clear();
                        $cursor_pos = $input.len().saturating_sub(1);
                    },
                    KeyCode::Char(s) if $vim_mode == Vim::Normal && (s=='^' || s=='_') => {
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
                    KeyCode::Char(w) if $vim_mode == Vim::Normal && (w=='w' || w=='W') => {
                        if n==0 { n+=1 };
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
                        $seq.clear();
                    },
                    KeyCode::Char(b) if $vim_mode == Vim::Normal && (b=='b' || b=='B') => {
                        if n==0 { n+=1 };
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
                        $seq.clear();
                    },
                    KeyCode::Char(e) if $vim_mode == Vim::Normal && (e=='e' || e=='E') => {
                        if n==0 { n+=1 };
                        while n>0 {
                            match k {
                                Some("g") => {
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
                        $seq.clear();
                    },
                    KeyCode::Char('i') if $vim_mode == Vim::Normal => {
                        $seq.clear();
                        $vim_mode = Vim::Insert;
                        execute!(io::stdout(), SetCursorStyle::SteadyBar);
                    },
                    KeyCode::Char('I') if $vim_mode == Vim::Normal => {
                        $seq.clear();
                        $cursor_pos = 0;
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
                            Some("d") => { $seq.clear(); },
                            Some("c") => { $seq.clear(); },
                            _ => { $seq.push('g'); }
                        }
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


#[derive(PartialEq, Eq)]
enum Screen { Onboarding, InitServer, InitClient, Chat }

macro_rules! onboarding {
    ($terminal:ident, $vim_mode: ident, $input:ident, $cursor_pos:ident, $curr_screen: ident) => {
        //TODO
    };
}

macro_rules! initServer {
    ($terminal:ident, $vim_mode: ident, $input:ident, $cursor_pos:ident, $curr_screen: ident) => {
        //TODO
    };
}

macro_rules! initClient {
    ($terminal:ident, $vim_mode: ident, $input:ident, $cursor_pos:ident, $curr_screen: ident) => {
        //TODO
    };
}

macro_rules! chat {
    ($terminal:ident, $vim_mode: ident, $seq:ident, $input:ident, $cursor_pos:ident, $curr_screen: ident) => {
        $terminal.draw(|f| {
            let size = f.area();
            let box_width = size.width.saturating_sub(2);
            
            // Split input into lines
            let lines: Vec<String> = if $input.is_empty() {
                vec![String::new()]
            } else {
                $input.chars()
                    .collect::<Vec<_>>()
                    .chunks(box_width as usize)
                    .map(|chunk| chunk.iter().collect())
                    .collect()
            };
            
            let line_count = (lines.len() as u16 + 2).min(7); // caps at 5
            
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Min(1),
                    Constraint::Length(line_count),
                ])
                .split(size);
            
            let mode = match $vim_mode {
                Vim::Normal => "NORMAL",
                Vim::Insert => "INSERT",
            };
            
            // Join lines with newlines
            let display_text = lines.join("\n");
            
            let input_box = Paragraph::new(display_text)
                .block(
                    Block::default().borders(Borders::ALL)
                        .title(format!(" {} ", "Input")) // dbg: Input will be the User name
                        .title_bottom(
                            Line::from(format!(" {} ", mode))
                                .style(Style::default().fg(match $vim_mode {
                                    Vim::Normal => Color::Rgb(0,212,255),
                                    Vim::Insert => Color::Rgb(255,102,204),
                                }))
                        )
                        .title_bottom(
                                Line::from(format!("{}",
                                    if !$seq.is_empty() {
                                        $seq.chars().take(6).collect::<String>()
                                    } else { "".to_string() }
                                ))
                                    .alignment(Alignment::Right)
                                    .style(Style::default().fg(Color::White))
                        )
                        .border_type(BorderType::Rounded)
                        .style(Style::default().fg(Color::DarkGray)) // box color
                )
                .style(Style::default().fg(Color::White)); // text color
            
            // Cursor position
            let box_width = chunks[1].width.saturating_sub(2);
            let cursor_x = chunks[1].x + 1 + ($cursor_pos as u16 % box_width);
            let cursor_y = chunks[1].y + 1 + ($cursor_pos as u16 / box_width);
            
            f.render_widget(input_box, chunks[1]);
            f.set_cursor_position((cursor_x, cursor_y));
        })?;

        // Handle input keys
        input_handling!($vim_mode, $seq, $input, $cursor_pos);
    };
}

pub fn app() -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut vim_mode = Vim::Normal;
    let mut seq = String::new();
    let mut input = String::new();
    let mut cursor_pos: usize = 0;

    let curr_screen = Screen::Chat; //dbg: should be mut and init to Onboarding

    #[allow(unused)] //macros are weird
    loop {
        if curr_screen == Screen::Onboarding {
            onboarding!(terminal, vim_mode, input, cursor_pos, curr_screen);
        } else if curr_screen == Screen::InitServer {
            initServer!(terminal, vim_mode, input, cursor_pos, curr_screen);
        } else if curr_screen == Screen::InitClient {
            initClient!(terminal, vim_mode, input, cursor_pos, curr_screen);
        } else if curr_screen == Screen::Chat {
            chat!(terminal, vim_mode, seq, input, cursor_pos, curr_screen);
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
