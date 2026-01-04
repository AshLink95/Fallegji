//TODO: allow customization of border styles, max height, and colors using a toml-style dotfile. Parameters will be set in constants decided by the dotfile.
use std::io::{self, Write};
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

use crate::vim::{Vim, input_handling};

// Seqeuence parsing regex
lazy_static::lazy_static! { static ref RE_NUM: Regex = Regex::new(r"\d+").unwrap(); }
lazy_static::lazy_static! {
    static ref RE_CHR: Regex = Regex::new(r"[a-zA-Z]+").unwrap();
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
                $input.split('\n')
                    .flat_map(|line| {
                        if line.is_empty() {
                            vec![String::new()]  // Preserve empty lines
                        } else {
                            line.chars()
                                .collect::<Vec<_>>()
                                .chunks(box_width as usize)
                                .map(|chunk| chunk.iter().collect())
                                .collect::<Vec<String>>()
                        }
                    })
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
                        .title(format!(" {} ", "Input")) // dbg: Input will be the User name (and color-customizable)
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
            let chars_before_cursor: Vec<char> = $input.chars().take($cursor_pos).collect();
            let newlines_before = chars_before_cursor.iter().filter(|&&c| c == '\n').count();
            let chars_in_current_line = chars_before_cursor.iter().rev()
                .take_while(|&&c| c != '\n')
                .count();
            
            let cursor_x = chunks[1].x + 1 + (chars_in_current_line as u16 % box_width);
            let cursor_y = chunks[1].y + 1 + newlines_before as u16 
            + (chars_in_current_line as u16 / box_width);
            
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
