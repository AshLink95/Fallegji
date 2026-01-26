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
    ($terminal:ident, $curr_screen: ident, $config: ident, $choice: ident, $chats: ident, $conn: ident, $chat: ident, $run_once: ident, $vim_mode: ident, $seq:ident, $input:ident, $cursor_pos:ident, $persis_y: ident) => {
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
            let line_count = (lines.len() as u16 + 2).min($config.max_height + 2);
            
            // TUI screen separation
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1),
                    Constraint::Min(1),
                    Constraint::Length(line_count),
                ])
                .split(size);
            
            // vim modes
            let mode = match $vim_mode {
                Vim::Normal => "NORMAL",
                Vim::Insert => "INSERT",
            };

            // Input Box Scrolling (TODO: make scrolling work by pushing extremes not just bottm line)
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

            // Text & Box
            let visible_lines = &lines[scroll_offset..(scroll_offset + visible_height).min(lines.len())];
            let display_text = visible_lines.join("\n");
            let input_box = Paragraph::new(display_text)
                .block(
                    Block::default().borders(Borders::ALL)
                        .title(format!(" {} ", $config.user_name.as_ref().unwrap()))
                        .title_bottom(
                            Line::from(format!(" {} ", mode))
                                .style(Style::default().fg(match $vim_mode {
                                    Vim::Normal => $config.normal_mode,
                                    Vim::Insert => $config.insert_mode,
                                }).bg($config.bg_color))
                        )
                        .title_bottom(
                                Line::from(format!("{}",
                                    if !$seq.is_empty() {
                                        $seq.chars().take(6).collect::<String>()
                                    } else { "".to_string() }
                                ))
                                    .alignment(Alignment::Right)
                                    .style(Style::default().fg($config.text_color).bg($config.bg_color))
                        )
                        .border_type($config.border_style)
                        .style(Style::default().fg($config.border_color).bg($config.bg_color)) // box color
                )
                .style(Style::default().fg($config.text_color).bg($config.bg_color)); // text color

            // Messages section (TODO: make text wrap, show multilines (with clear indicators, exp: line below user name until message end, follow text way of wrapping) add allow scrolling with a clickable sidebar)
            let message_history = $chat.message_history.read().unwrap();
            let members = $chat.members.read().unwrap();
            let current_user_id = $chat.current_user.get_id();

            let message_lines: Vec<Line> = message_history.iter().map(|msg| {
                let sender_id = msg.get_sender_id();
                let user_name = members.get(&sender_id)
                    .map(|u| u.get_name())
                    .unwrap_or_else(|| "Unknown".to_string());
                
                let name_color = if sender_id == current_user_id {
                    $config.my_color
                } else if sender_id == 0 {
                    $config.system_color
                } else {
                    $config.users_color
                };

                Line::from(vec![
                    Span::styled(format!("{}: ", user_name), Style::default().fg(name_color)),
                    Span::styled(msg.get_contents(), Style::default().fg($config.text_color)),
                ])
            }).collect();

            drop(message_history);
            drop(members);

            let messages_widget = Paragraph::new(message_lines)
                .block(
                    Block::default()
                        .borders(Borders::NONE)
                )
                .style(Style::default().bg($config.bg_color));

            // Cursor position
            let chars_before_cursor: Vec<char> = $input.chars().take($cursor_pos).collect();
            let newlines_before = chars_before_cursor.iter().filter(|&&c| c == '\n').count();
            let chars_in_current_line = chars_before_cursor.iter().rev()
                .take_while(|&&c| c != '\n')
                .count();
            
            let cursor_x = chunks[2].x + 1 + (chars_in_current_line as u16 % box_width);
            let cursor_y = chunks[2].y + 1 + (cursor_line - scroll_offset) as u16;

            // Title
            let title = Block::default()
                .borders(Borders::TOP)
                .border_type($config.border_style)
                .style(Style::default().fg($config.border_color).bg($config.bg_color))
                .title(Line::from($choice.clone()).alignment(Alignment::Center));

            // rendering
            f.render_widget(title, chunks[0]);
            f.render_widget(messages_widget, chunks[1]);
            f.render_widget(input_box, chunks[2]);
            f.set_cursor_position((cursor_x, cursor_y)); //ERROR (bugs when newline after wrapping)
        })?;

        // Handle input keys
        let is_admin = if let Some(role) = $chat.current_user.get_role() {
            role == Role::Admin
        } else { false };
        input_handling!($vim_mode, $seq, $input, $cursor_pos, $persis_y, $curr_screen, $config, $chats, $conn, $chat, $run_once, is_admin);
    };
}
