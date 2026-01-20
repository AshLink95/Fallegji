// Client: 1 box saying pending approval if the request went through, otherwise tells the user the address may not be valid. Retry option available after 3 minutes.

#[macro_export]
macro_rules! initServer {
    ($terminal:ident, $curr_screen: ident, $config: ident, $choice: ident, $chats: ident, $active_section: ident, $active_row: ident, $active_col: ident, $requests: ident, $input:ident) => {
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
            let peers_count = 0; // TODO: replace with actual count
            let requests_guard = $requests.lock().unwrap();
            let requests_count = requests_guard.len();

            let peers_height = (peers_count as u16 + 2).max(3);
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

            let is_red = match $config.my_color {
                Color::Rgb(r, g, _) if (120..=255).contains(&r) && (0..=60).contains(&g) => true,
                _ => false,
            };

            let requests_inner = requests_block.inner(chunks[2]);
            f.render_widget(requests_block, chunks[2]);

            if requests_guard.is_empty() {
                let no_requests = Paragraph::new("No requests")
                    .style(Style::default().fg($config.border_color).bg($config.bg_color));
                f.render_widget(no_requests, requests_inner);
            } else {
                let request_chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints(
                        requests_guard.iter()
                            .map(|_| Constraint::Length(1))
                            .collect::<Vec<_>>()
                    )
                    .split(requests_inner);

                for (idx, (addr, name)) in requests_guard.iter().enumerate() {
                    let row_active = requests_active && $active_col == idx as i32;
                    
                    let button_layout = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints([
                            Constraint::Percentage(20),
                            Constraint::Percentage(5),
                            Constraint::Percentage(25),
                            Constraint::Percentage(5),
                            Constraint::Percentage(20),
                            Constraint::Percentage(5),
                            Constraint::Percentage(20),
                        ])
                        .split(request_chunks[idx]);

                    let text_req_color = if $active_section == 1 { $config.users_color } else { $config.border_color };
                    let name_text = Paragraph::new(format!("{}", name))
                        .style(Style::default().fg(text_req_color).bg($config.bg_color));
                    let addr_text = Paragraph::new(format!("{}", addr))
                        .style(Style::default().fg(text_req_color).bg($config.bg_color));
                    
                    let accept_active = row_active && $active_row;
                    let accept_color = if accept_active { $config.my_color } else { $config.border_color };
                    let accept_button = Paragraph::new("Accept")
                        .centered()
                        .style(Style::default().fg($config.text_color).bg(accept_color))
                        .block(
                            Block::default().borders(Borders::LEFT | Borders::RIGHT)
                                .border_type($config.border_style)
                                .style(Style::default().fg(accept_color).bg($config.bg_color))
                        );

                    let delete_active = row_active && !$active_row;
                    let delete_color = if delete_active {
                        if !is_red { 
                            Color::Red 
                        } else { 
                            Color::Rgb(255, 100, 0) 
                        }
                    } else {
                        $config.border_color
                    };
                    let delete_button = Paragraph::new("Delete")
                        .centered()
                        .style(Style::default().fg($config.text_color).bg(delete_color))
                        .block(
                            Block::default().borders(Borders::LEFT | Borders::RIGHT)
                                .border_type($config.border_style)
                                .style(Style::default().fg(delete_color).bg($config.bg_color))
                        );

                    f.render_widget(name_text, button_layout[0]);
                    f.render_widget(addr_text, button_layout[2]);
                    f.render_widget(accept_button, button_layout[4]);
                    f.render_widget(delete_button, button_layout[6]);
                }
            }
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
            f.render_widget(button, chunks[4]);
        })?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char(aq) if key.modifiers.contains(KeyModifiers::CONTROL) && aq == 'a' || aq == 'q'=> {
                        $curr_screen = Screen::Chat;
                    },
                    KeyCode::Char('k') | KeyCode::Up if !key.modifiers.contains(KeyModifiers::CONTROL) && $active_section == 1 => {
                        if $active_col > 0 {
                            $active_col -= 1;
                        }
                    },
                    KeyCode::Char('j') | KeyCode::Down if !key.modifiers.contains(KeyModifiers::CONTROL) && $active_section == 1 => {
                        let requests_guard = $requests.lock().unwrap();
                        let max_row = requests_guard.len() as i32 - 1;
                        drop(requests_guard);
                        if $active_col < max_row {
                            $active_col += 1;
                        }
                    },
                    KeyCode::Char('h') | KeyCode::Left if $active_section == 1 => {
                        $active_row = true;
                    },
                    KeyCode::Char('l') | KeyCode::Right if $active_section == 1 => {
                        $active_row = false;
                    },
                    KeyCode::Char('k') | KeyCode::Up if key.modifiers.contains(KeyModifiers::CONTROL) && $active_section > 0 => {
                        if $active_section > 0 {
                            $active_section -= 1;
                        }
                    },
                    KeyCode::Char('j') | KeyCode::Down if key.modifiers.contains(KeyModifiers::CONTROL) && $active_section < 2 => {
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

