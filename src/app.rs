// Allow customization for layouts, colorschemes, avatars in config file and allow for vim motions (automatically read .vimrc)
use std::io;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    cursor::SetCursorStyle,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::Text,
    widgets::{Block, Borders, Paragraph, Wrap},
    Terminal,
};

use anyhow::Result;

#[derive(PartialEq, Eq)]
enum Vim { Normal, Insert, Visual }
macro_rules! input_handling {
    ($vim_mode: ident, $input:ident, $cursor_pos:ident) => {
        //TODO: include a count variable and a g variable for 'ge', a c variable for 'cc' and 'cn-hjkl', same for d
        if event::poll(std::time::Duration::from_millis(100))? {
            let event = event::read()?;
            if let Event::Key(key) = event {
                match key.code {
                    // Universal
                    KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Left => { $cursor_pos = $cursor_pos.saturating_sub(1); },
                    KeyCode::Right => if $cursor_pos < $input.len() { $cursor_pos += 1; },
                    KeyCode::Delete => {
                        if $cursor_pos < $input.len() {
                            $input.remove($cursor_pos);
                        }
                    },
                    KeyCode::Enter => {
                        $input.clear();
                        $cursor_pos = 0;
                    },

                    // NORMAL mode handling
                    KeyCode::Char('h') if $vim_mode == Vim::Normal => {
                        $cursor_pos = $cursor_pos.saturating_sub(1);
                    },
                    KeyCode::Char('l') if $vim_mode == Vim::Normal => {
                        if $cursor_pos < $input.len()-1 { $cursor_pos += 1; };
                    },
                    KeyCode::Char(s) if $vim_mode == Vim::Normal && (s=='0' || s=='^' || s=='_') => {
                        $cursor_pos = 0;
                    },
                    KeyCode::Char('$') if $vim_mode == Vim::Normal => {
                        $cursor_pos = $input.len() - 1;
                    },
                    KeyCode::Char(w) if $vim_mode == Vim::Normal && (w=='w' || w=='W') => {
                        while $cursor_pos < $input.len() && !$input.chars().nth($cursor_pos).unwrap().is_whitespace() {
                            $cursor_pos += 1;
                        }
                        while $cursor_pos < $input.len() && $input.chars().nth($cursor_pos).unwrap().is_whitespace() {
                            $cursor_pos += 1;
                        }
                        $cursor_pos = $cursor_pos.min($input.len().saturating_sub(1));
                    },
                    KeyCode::Char(b) if $vim_mode == Vim::Normal && (b=='b' || b=='B') => {
                        if $cursor_pos > 0 { $cursor_pos -= 1; }
                        while $cursor_pos > 0 && $input.chars().nth($cursor_pos).unwrap().is_whitespace() {
                            $cursor_pos -= 1;
                        }
                        while $cursor_pos > 0 && !$input.chars().nth($cursor_pos).unwrap().is_whitespace() {
                            $cursor_pos -= 1;
                        }
                        if $cursor_pos > 0 { $cursor_pos += 1; }
                    },
                    KeyCode::Char(e) if $vim_mode == Vim::Normal && (e=='e' || e=='E') => {
                        if $cursor_pos < $input.len() { $cursor_pos += 1; }
                        while $cursor_pos < $input.len() && $input.chars().nth($cursor_pos).unwrap().is_whitespace() {
                            $cursor_pos += 1;
                        }
                        while $cursor_pos < $input.len() && !$input.chars().nth($cursor_pos).unwrap().is_whitespace() {
                            $cursor_pos += 1;
                        }
                        if $cursor_pos > 0 { $cursor_pos -= 1; }
                    },
                    KeyCode::Char('i') if $vim_mode == Vim::Normal => {
                        $vim_mode = Vim::Insert;
                        execute!(io::stdout(), SetCursorStyle::SteadyBar);
                    },
                    KeyCode::Char('I') if $vim_mode == Vim::Normal => {
                        $cursor_pos = 0;
                        $vim_mode = Vim::Insert;
                        execute!(io::stdout(), SetCursorStyle::SteadyBar);
                    },
                    KeyCode::Char('a') if $vim_mode == Vim::Normal => {
                        if $cursor_pos < $input.len() { $cursor_pos += 1; };
                        $vim_mode = Vim::Insert;
                        execute!(io::stdout(), SetCursorStyle::SteadyBar);
                    },
                    KeyCode::Char('A') if $vim_mode == Vim::Normal => {
                        $cursor_pos = $input.len();
                        $vim_mode = Vim::Insert;
                        execute!(io::stdout(), SetCursorStyle::SteadyBar);
                    },
                    //TODO next: delete and change

                    // INSERT mode handling
                    KeyCode::Backspace if $vim_mode == Vim::Insert => {
                        if $cursor_pos > 0 {
                            $cursor_pos -= 1;
                            $input.remove($cursor_pos);
                        }
                    },
                    KeyCode::Esc if $vim_mode == Vim::Insert => {
                        if $cursor_pos == $input.len() { $cursor_pos -= 1; };
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
    ($terminal:ident, $vim_mode: ident, $input:ident, $cursor_pos:ident, $curr_screen: ident) => {
        $terminal.draw(|f| {
            let size = f.area();

            // Split layout: main area + 3-line input box at bottom
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Min(1), // main area
                    Constraint::Length(3), // input box
                ])
                .split(size);

            // Input box
            let mode = match $vim_mode {
                Vim::Normal => "NORMAL",
                Vim::Insert => "INSERT",
                Vim::Visual => "VISUAL",
            };

            let input_box = Paragraph::new(Text::raw(&$input))
                .block(Block::default().borders(Borders::ALL)
                    .title(format!(" {} ({}) ", "Input", mode))
                    )
                .style(Style::default().fg(Color::White))
                .wrap(Wrap { trim: true });

            // Cursor position
            let cursor_x = chunks[1].x + 1 + $cursor_pos as u16;
            let cursor_y = chunks[1].y + 1;

            f.render_widget(input_box, chunks[1]);
            f.set_cursor_position((cursor_x, cursor_y));
        })?;

        // Handle input keys
        input_handling!($vim_mode, $input, $cursor_pos);
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
            chat!(terminal, vim_mode, input, cursor_pos, curr_screen);
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
