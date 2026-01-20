// Server: A menu with every user and a box that allows selection (can come back to it from chat and vice-versa)
// Client: 1 box saying pending approval if the request went through, otherwise tells the user the address may not be valid. Retry option available after 3 minutes.

#[macro_export]
macro_rules! initServer {
    ($terminal:ident, $curr_screen: ident, $config: ident, $choice: ident, $chats: ident, $active_section: ident, $active_field: ident, $requests: ident, $input:ident) => {
        $terminal.draw(|f| {
        //TODO: border, chat name in the middle of the border, at the bottom. A box just where users can click enter to go to the chat (can do that with a key stroke as well). 2 sections before in a floating box, slightly smaller than available terminal screen for them: available peers and requests. these 2 should take exaclty as much as needed and have title on the border top left
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

            // Title
            let title = Block::default()
                .borders(Borders::TOP)
                .border_type($config.border_style)
                .style(Style::default().fg($config.border_color).bg($config.bg_color))
                .title(Line::from($choice.clone()).alignment(Alignment::Center));

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
            f.render_widget(button, chunks[2]);
        })?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => {

                        $chats = ChatChoice::load(CONFIG)?;
                        $curr_screen = Screen::Home;
                    },
                    KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
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

