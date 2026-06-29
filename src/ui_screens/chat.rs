/// Chat screen, the meat
///
/// import the following in the file using the macro:
/// use crossterm::event::{self, Event, KeyCode, KeyModifiers};
/// use ratatui::{
///     layout::{Constraint, Direction, Layout, Alignment},
///     style::{Color, Style},
///     widgets::{Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState},
///     text::Line,
/// }
#[macro_export]
macro_rules! chat {
    ($terminal:ident, $curr_screen: ident, $config: ident, $choice: ident, $chats: ident, $conn: ident, $chat: ident, $run_once: ident, $vim_mode: ident, $seq:ident, $input:ident, $cursor_pos:ident, $persis_y: ident, $scroll_offset: ident, $requests: ident, $msg_window: ident, $msg_count: ident) => {
        let mut max_offset: u16 = 0;
        let mut msg_area = ratatui::layout::Rect::default(); // messages pane rect, hoisted out for mouse-drag scroll hit-testing
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

            let typing: Option<Vec<String>> = {
                let members = $chat.members.read().unwrap();
                let names: Vec<String> = $conn.peer_list().into_iter()
                    .filter(|(_, p)| p.is_typing())
                    .filter_map(|(id, _)| members.get(&id).map(|u| u.get_name()))
                    .collect();
                (!names.is_empty()).then_some(names)
            };
            // Status indicator (shown in the typing slot when no one is typing and we haven't
            // started typing): admin → pending join requests; anyone → "reached peers" once the
            // mesh is fully met up + synced. Typing and our own input both take priority.
            let status_indicator: Option<Line> = if typing.is_some() || !$input.is_empty() {
                None
            } else if $chat.current_user.get_role() == Some(Role::Admin)
                && { let r = $requests.lock().unwrap().len(); r > 0 } {
                let r = $requests.lock().unwrap().len();
                // Bold the count, like the names in the typing indicator.
                Some(Line::from(vec![
                    Span::styled(format!("{}", r), Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(format!(" request{} waiting", if r == 1 { "" } else { "s" })),
                ]))
            } else if $conn.reached_and_synced().is_some() {
                Some(Line::from("connected to peers"))
            } else {
                None
            };

            // TUI screen separation
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1),
                    Constraint::Min(1),
                    Constraint::Length(1),
                    Constraint::Length(line_count),
                ])
                .split(size);
            msg_area = chunks[1]; // capture the messages pane for scrollbar drag hit-testing after the closure

            // vim modes
            let mode = match $vim_mode {
                Vim::Normal => "NORMAL",
                Vim::Insert => "INSERT",
                Vim::Timeout => "TIMEOUT",
            };
            // Message at the length cap → warning-red text.
            let input_text_color = if $input.chars().count() >= $crate::messaging::MAX_MESSAGE_LEN { $config.warn_color() } else { $config.text_color };

            // Input Box Scrolling (TODO: make scrolling work by pushing extremes not just bottm line)
            let mut input_scroll_offset = 0usize;
            let chars_before_cursor: Vec<char> = $input.chars().take($cursor_pos).collect();
            let newlines_before = chars_before_cursor.iter().filter(|&&c| c == '\n').count();
            let chars_in_current_line = chars_before_cursor.iter().rev()
                .take_while(|&&c| c != '\n')
                .count();
            let visible_height = (line_count.saturating_sub(2)) as usize; // subtract borders
            let cursor_line = newlines_before + (chars_in_current_line as u16 / box_width) as usize;
            if cursor_line < input_scroll_offset {
                input_scroll_offset = cursor_line;
            } else if cursor_line >= input_scroll_offset + visible_height {
                input_scroll_offset = cursor_line.saturating_sub(visible_height - 1);
            }
            input_scroll_offset = input_scroll_offset.min(lines.len().saturating_sub(visible_height));

            // Text & Box
            let visible_lines = &lines[input_scroll_offset..(input_scroll_offset + visible_height).min(lines.len())];
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
                                    Vim::Timeout => $config.timeout_mode,
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
                .style(Style::default().fg(input_text_color).bg($config.bg_color)); // text color (red at the length cap)

            // Messages section (TODO: make text wrap, show multilines (with clear indicators, exp: line below user name until message end, follow text way of wrapping) add allow scrolling with a clickable sidebar)  — autoscroll-at-bottom done (None sentinel below)
            let message_history = $chat.message_history.read().unwrap();
            let members = $chat.members.read().unwrap();
            let current_user_id = $chat.current_user.get_id();

            let message_lines: Vec<Line> = message_history.iter().map(|msg| {
                let sender_id = msg.get_sender_id();
                let known = members.get(&sender_id);
                let user_name = known
                    .map(|u| u.get_name())
                    .unwrap_or_else(|| "[REDACTED]".to_string());

                // Deleted/kicked sender (gone from members) and system messages share the
                // system color — distinct from live users.
                let name_color = if known.is_none() || sender_id == 0 {
                    $config.system_color
                } else if sender_id == current_user_id {
                    $config.my_color
                } else {
                    $config.users_color
                };

                Line::from(vec![
                    Span::styled(format!("{}: ", user_name), Style::default().fg(name_color)),
                    Span::styled(msg.get_contents(), Style::default().fg($config.text_color)),
                ])
            }).collect();
            max_offset = message_lines.len().saturating_sub(chunks[1].height as usize) as u16;
            let eff_offset = $scroll_offset.unwrap_or(max_offset); // None on first draw → bottom

            drop(message_history);
            drop(members);

            let messages = Paragraph::new(message_lines)
                .block(Block::default().borders(Borders::NONE))
                .style(Style::default().bg($config.bg_color))
                .scroll((eff_offset, 0));

            let mut scroll_state = ScrollbarState::new(max_offset as usize)
                .position(eff_offset as usize);
            let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓"));

            // Cursor position
            let chars_before_cursor: Vec<char> = $input.chars().take($cursor_pos).collect();
            let newlines_before = chars_before_cursor.iter().filter(|&&c| c == '\n').count();
            let chars_in_current_line = chars_before_cursor.iter().rev()
                .take_while(|&&c| c != '\n')
                .count();
            
            let cursor_x = chunks[3].x + 1 + (chars_in_current_line as u16 % box_width);
            let cursor_y = chunks[3].y + 1 + (cursor_line - input_scroll_offset) as u16;

            // Title
            let title = Block::default()
                .borders(Borders::TOP)
                .border_type($config.border_style)
                .style(Style::default().fg($config.border_color).bg($config.bg_color))
                .title(Line::from($choice.clone()).alignment(Alignment::Center));

            // Typing indicator (falls back to the status indicator when no one is typing)
            let mut typers: Line = match typing {
                None => status_indicator.unwrap_or_else(|| Line::from("")),
                Some(list) if list.is_empty() => Line::from(""),
                Some(list) => {
                    let n = list.len();
                    let mut spans: Vec<Span> = Vec::new();
                    for (i, peer) in list.iter().enumerate() {
                        if i > 0 {
                            spans.push(Span::raw(if i == n - 1 { " and " } else { ", " }));
                        }
                        spans.push(Span::styled(
                            peer.clone(),
                            Style::default().add_modifier(Modifier::BOLD),
                        ));
                    }
                    spans.push(Span::raw(if n == 1 { " is typing" } else { " are typing" }));
                    let mut typing_line = Line::from(spans);
                    if (typing_line.width() as u16 > chunks[1].width) {
                        typing_line = Line::from(format!("{} ppl are typing", n));
                    }

                    typing_line
                }
            };

            // rendering
            f.render_widget(title, chunks[0]);
            f.render_widget(messages, chunks[1]);
            f.render_widget(typers, chunks[2]);
            f.render_widget(input_box, chunks[3]);

            f.set_cursor_position((cursor_x, cursor_y)); //ERROR (bugs when newline after wrapping) (up/down don't navigate through wrapped lines)
            f.render_stateful_widget(
                scrollbar,
                chunks[1].inner(Margin { vertical: 1, horizontal: 0 }),
                &mut scroll_state,
            );
        })?;

        // Handle input keys
        let is_admin = if let Some(role) = $chat.current_user.get_role() {
            role == Role::Admin
        } else { false };
        // Work on a concrete offset (first draw → bottom), then persist it back into the Option.
        let mut offset = $scroll_offset.unwrap_or(max_offset);
        input_handling!($vim_mode, $seq, $input, $cursor_pos, $persis_y, $curr_screen, $config, $chats, $conn, $chat, $run_once, is_admin, offset, max_offset, $msg_window, $msg_count, msg_area);
        // None = stick to bottom (autoscroll on new messages); Some only while scrolled up.
        $scroll_offset = if offset >= max_offset { None } else { Some(offset) };
    };
}
