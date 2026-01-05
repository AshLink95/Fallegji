/// Chat screen, the meat
///
/// import the following in the file using the macro:
/// use crossterm::event::{self, Event, KeyCode, KeyModifiers};
/// use ratatui::{
///     layout::{Constraint, Direction, Layout, Alignment},
///     style::{Color, Style},
///     widgets::{Block, Borders, Paragraph, BorderType},
///     text::Line,
/// }
#[macro_export]
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

            // Scrolling
            let mut scroll_offset = 0usize;
            let chars_before_cursor: Vec<char> = $input.chars().take($cursor_pos).collect();
            let newlines_before = chars_before_cursor.iter().filter(|&&c| c == '\n').count();
            let chars_in_current_line = chars_before_cursor.iter().rev()
                .take_while(|&&c| c != '\n')
                .count();
            let visible_height = (line_count.saturating_sub(2)) as usize; // subtract borders
            let cursor_line = newlines_before + (chars_in_current_line as u16 / box_width) as usize;
            if cursor_line < scroll_offset {
                scroll_offset = cursor_line;
            } else if cursor_line >= scroll_offset + visible_height {
                scroll_offset = cursor_line.saturating_sub(visible_height - 1);
            }
            scroll_offset = scroll_offset.min(lines.len().saturating_sub(visible_height));
            
            // Join lines with newlines
            // let display_text = lines.join("\n");
let visible_lines = &lines[scroll_offset..(scroll_offset + visible_height).min(lines.len())];
let display_text = visible_lines.join("\n");
            
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
            // let cursor_y = chunks[1].y + 1 + newlines_before as u16 + (chars_in_current_line as u16 / box_width);
let cursor_y = chunks[1].y + 1 + (cursor_line - scroll_offset) as u16;
            
            f.render_widget(input_box, chunks[1]);
            f.set_cursor_position((cursor_x, cursor_y));
        })?;

        // Handle input keys
        input_handling!($vim_mode, $seq, $input, $cursor_pos);
    };
}
