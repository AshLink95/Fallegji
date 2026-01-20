// Server: A menu with every user and a box that allows selection (can come back to it from chat and vice-versa)
// Client: 1 box saying pending approval if the request went through, otherwise tells the user the address may not be valid. Retry option available after 3 minutes.

#[macro_export]
macro_rules! initServer {
    ($terminal:ident, $curr_screen: ident, $config: ident, $choice: ident, $chats: ident, $active_section: ident, $active_field: ident, $requests: ident, $input:ident) => {
        $terminal.draw(|f| {
            //TODO: update with actual peers list from connection. Also, find a way to update based on valid packets received (requests list update and peers online status). Use chat for viewing chat members (peers)
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
            drop(lines);
            
            // TUI screen separation
            let available_peers_count = 0; // TODO: replace with actual count
            let requests_guard = $requests.lock().unwrap();
            let requests_count = requests_guard.len();
            
            let peers_height = (available_peers_count as u16 + 2).max(3);
            let requests_height = (requests_count as u16 + 2).max(3);
            
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1),
                    Constraint::Length(peers_height),
                    Constraint::Length(requests_height),
                    Constraint::Min(1),
                    Constraint::Length(line_count),
                ])
                .split(size);

            // Title
            let title = Block::default()
                .borders(Borders::TOP)
                .border_type($config.border_style)
                .style(Style::default().fg($config.border_color).bg($config.bg_color))
                .title(Line::from($choice.clone()).alignment(Alignment::Center));

            // Peers section
            let peers_active = $active_section == 0;
            let peers_border_color = if peers_active { $config.text_color } else { $config.border_color };
            
            let peers_block = Block::default()
                .borders(Borders::ALL)
                .border_type($config.border_style)
                .border_style(Style::default().fg(peers_border_color))
                .style(Style::default().bg($config.bg_color))
                .title(Line::from(" Chat Members ").alignment(Alignment::Left));
            
            // TODO: Add actual peers list when available
            let peers_text = Paragraph::new("No peers available")
                .style(Style::default().fg($config.border_color).bg($config.bg_color))
                .block(peers_block);
            
            
            // Requests section
            let requests_active = $active_section == 1;
            let requests_border_color = if requests_active { $config.text_color } else { $config.border_color };
            let requests_block = Block::default()
                .borders(Borders::ALL)
                .border_type($config.border_style)
                .border_style(Style::default().fg(requests_border_color))
                .style(Style::default().bg($config.bg_color))
                .title(Line::from(" Requests ").alignment(Alignment::Left));
            
            let requests_text = if requests_guard.is_empty() {
                vec![Line::from(Span::styled("No requests", Style::default().fg($config.border_color)))]
            } else {
                requests_guard.iter()
                    .map(|(addr, _msg)| {
                        Line::from(Span::styled(
                            format!("{}", addr),
                            Style::default().fg($config.users_color)
                        ))
                    })
                    .collect()
            };
            let requests_paragraph = Paragraph::new(requests_text)
                .style(Style::default().bg($config.bg_color))
                .block(requests_block);
            drop(requests_guard);

            // Hop back button
            let button_active = $active_section == 2;
            let button_color = if button_active { $config.my_color } else { $config.border_color };
            let button = Paragraph::new("Hop back to chat")
                .centered()
                .style(Style::default().fg($config.text_color).bg(button_color))
                .block(
                    Block::default().borders(Borders::ALL)
                        .border_type($config.border_style)
                        .style(Style::default().fg(button_color).bg($config.bg_color))
                );

            // rendering
            f.render_widget(title, chunks[0]);
            f.render_widget(peers_text, chunks[1]);
            f.render_widget(requests_paragraph, chunks[2]);
            f.render_widget(button, chunks[4]);
        })?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char(aq) if key.modifiers.contains(KeyModifiers::CONTROL) && aq == 'a' || aq == 'q'=> {
                        $curr_screen = Screen::Chat;
                    },
                    KeyCode::Char('k') | KeyCode::Up if key.modifiers.contains(KeyModifiers::CONTROL) || $active_section > 0 => {
                        if $active_section > 0 {
                            $active_section -= 1;
                        }
                    },
                    KeyCode::Char('j') | KeyCode::Down if key.modifiers.contains(KeyModifiers::CONTROL) || $active_section < 2 => {
                        if $active_section < 2 {
                            $active_section += 1;
                        }
                    },
                    KeyCode::Enter if $active_section == 2 => {
                        $curr_screen = Screen::Chat;
                    },
                    _ => {}
                }
            }
        }
    };
}

#[macro_export]
macro_rules! initClient {
    ($terminal:ident, $curr_screen: ident, $config: ident) => {
        //TODO
    };
}

