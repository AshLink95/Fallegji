// partially prompt engineered
/// Home Screen
///
/// import the following in the file using the macro:
/// `use ratatui::{`
///     `layout::{Alignment, Constraint, Direction, Layout, Rect},`
///     `style::{Color, Style},`
///     `text::{Line, Span},`
///     `widgets::{Block, BorderType, Borders, Paragraph},`
/// `};`
/// `use crossterm::event::{self, Event, KeyCode, KeyModifiers};`
/// `use x25519_dalek::{PublicKey, StaticSecret};`
#[macro_export]
macro_rules! home {
    ($terminal:ident, $curr_screen: ident, $config: ident, $choice: ident, $chats: ident, $conn: ident, $chat: ident, $active_section: ident, $active_field: ident, $chat_name_input: ident, $user_name_input: ident, $rendezvous_input: ident, $chat_2_delete:ident, $anim_tick: ident, $run_once: ident, $requests: ident, $token: ident) => {
        // Validity checks
        let combo_exists = !$chat_name_input.is_empty() && !$user_name_input.is_empty() &&
            $chats.available.contains(&format!("{} @ {}", $user_name_input, $chat_name_input));
        let chat_name_valid = !$chat_name_input.is_empty() && !combo_exists;
        let user_name_valid = !$user_name_input.is_empty();
        let rendezvous_valid = !$rendezvous_input.is_empty() &&
            $rendezvous_input.parse::<std::net::SocketAddr>().is_ok();
        let is_red = match $config.my_color {
            Color::Rgb(r, g, _) if (120..=255).contains(&r) && (0..=60).contains(&g) => true,
            _ => false,
        };

        $terminal.draw(|frame| {
            let size = frame.area();

            // ASCII art
            let ascii_art = vec![
                "            ++########++-              ",
                "         ##-............-###           ",
                "      ##.  ....... ....  . +###        ",
                "   ##-. ..............  ..     ###     ",
                "  #  .......... ....  .. ... .   ##    ",
                " #...   ...... ... . ...  ......   ##  ",
                "#   ..-.........  .-..  ..... ....  ## ",
                "#.    .  .. .   ...      .   .     .  +",
                "#   ... ......-            .         # ",
                "#      ...  .     .###.....          # ",
                "##    .- .. .############++  .      ## ",
                " ## ..  . ..     ....         .   ###  ",
                "  ##     #...+--###+.#+-    .  -  ##   ",
                "   ## .. #####........#####-  ..  ##   ",
                "   ##. . ###.............##.   .. ##   ",
                "   # . ............    . ..    +  .#   ",
                "   # . ...........    .   ...  -  +#   ",
                "   #..   ..............     ... .+##   ",
                "   #... ......  . .  ...... ..  . ##   ",
                "   #-.  ..   ...        .... ...   #   ",
                "   ##-  ..         .  .. . . ..    #   ",
                "     #-# ##                  ..  ..#   ",
                "       +.+#+.           .   .     ##   ",
            ];

            // Calculate layout with ASCII art
            let ascii_height = ascii_art.len() as u16;
            let vertical_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length((size.height.saturating_sub(ascii_height + 14)) / 2),
                    Constraint::Length(ascii_height),
                    Constraint::Length(14),
                    Constraint::Min(0),
                ])
                .split(size);

            // Render ASCII art
            let ascii_text: Vec<Line> = ascii_art.iter()
                .map(|line| Line::from(Span::styled(*line, Style::default().fg($config.border_color))))
                .collect();
            let ascii_paragraph = Paragraph::new(ascii_text)
                .alignment(Alignment::Center);
            frame.render_widget(ascii_paragraph, vertical_chunks[1]);

            // Center the box
            let horizontal_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(20),
                    Constraint::Percentage(60),
                    Constraint::Percentage(20),
                ])
                .split(vertical_chunks[2]);

            let center_area = horizontal_chunks[1];

            // Create the box
            let block = Block::default()
                .borders(Borders::ALL)
                .border_type($config.border_style)
                .border_style(Style::default().fg($config.border_color))
                .style(Style::default().bg($config.bg_color));

            let inner = block.inner(center_area);
            frame.render_widget(block, center_area);

            // Split inner area for lines
            let lines_layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                ])
                .split(inner);

            // Line 1: "hop into < chatname >"
            let current_chat = $chats.current().unwrap_or(" ❌ ");
            let hop_active = $active_section == 0;
            let arrow_color = if hop_active { $config.text_color } else { $config.border_color };
            let hop_text_color = if hop_active { $config.text_color } else { $config.border_color };

            let hop_header = Paragraph::new(
                Line::from(vec![
                    Span::styled("hop into old chat", hop_text_color)
                ])
            )
            .alignment(Alignment::Center)
            .style(Style::default().bg($config.bg_color));
            let hop_color = if !$chat_2_delete.is_some_and(|chat| chat == $chats.choice) {
                $config.my_color
            } else {
                $anim_tick = $anim_tick.wrapping_add(1);
                if ($anim_tick/3) % 2 == 0 { $config.my_color } else {
                    if !is_red {
                        Color::Red
                    } else {
                        Color::Rgb(255, 100, 0)
                    }
                }
            };
            let hop_line = Line::from(vec![
                Span::styled("< ", Style::default().fg(arrow_color)),
                Span::styled(current_chat, Style::default().fg(hop_color)),
                Span::styled(" >", Style::default().fg(arrow_color)),
            ]);

            let hop_paragraph = Paragraph::new(hop_line)
                .alignment(Alignment::Center)
                .style(Style::default().bg($config.bg_color));

            frame.render_widget(hop_header, lines_layout[0]);
            frame.render_widget(hop_paragraph, lines_layout[2]);

            // Separator
            let separator = Paragraph::new("─".repeat(center_area.width.saturating_sub(2) as usize))
                .alignment(Alignment::Center)
                .style(Style::default().fg($config.border_color).bg($config.bg_color));
            frame.render_widget(&separator, lines_layout[3]);

            // Line: "create new chat"
            let create_active = $active_section == 1;
            let create_style = if create_active {
                Style::default().fg($config.text_color)
            } else {
                Style::default().fg($config.border_color)
            };

            let create_header = Paragraph::new(
                Line::from(vec![
                    Span::styled("create new chat", create_style)
                ])
            )
            .alignment(Alignment::Center)
            .style(Style::default().bg($config.bg_color));
            frame.render_widget(create_header, lines_layout[4]);

            // Chat name field
            let chat_name_color = if chat_name_valid {
                $config.my_color
            } else if !is_red {
                Color::Red
            } else {
                Color::Rgb(255, 100, 0)
            };
            let chat_name_active = create_active && $active_field == 0;
            let chat_name_label_color = if chat_name_active { $config.text_color } else { $config.border_color };

            let mut chat_name_spans = vec![
                Span::styled("chat name: ", Style::default().fg(chat_name_label_color)),
            ];
            if chat_name_active {
                chat_name_spans.push(Span::styled("> ", Style::default().fg($config.text_color)));
            }
            chat_name_spans.push(Span::styled(&$chat_name_input, Style::default().fg(chat_name_color)));

            let chat_name_line = Line::from(chat_name_spans);
            let chat_name_paragraph = Paragraph::new(chat_name_line)
                .style(Style::default().bg($config.bg_color));
            frame.render_widget(chat_name_paragraph, lines_layout[5]);

            // User name field
            let user_name_color = if !combo_exists {
                $config.my_color
            } else if !is_red {
                Color::Red
            } else {
                Color::Rgb(255, 100, 0)
            };
            let user_name_active = create_active && $active_field == 1;
            let user_name_label_color = if user_name_active { $config.text_color } else { $config.border_color };

            let mut user_name_spans = vec![
                Span::styled("user name: ", Style::default().fg(user_name_label_color)),
            ];
            if user_name_active {
                user_name_spans.push(Span::styled("> ", Style::default().fg($config.text_color)));
            }
            user_name_spans.push(Span::styled(&$user_name_input, Style::default().fg(user_name_color)));

            let user_name_line = Line::from(user_name_spans);
            let user_name_paragraph = Paragraph::new(user_name_line)
                .style(Style::default().bg($config.bg_color));
            frame.render_widget(user_name_paragraph, lines_layout[6]);

            // Rendezvous address field
            let rendezvous_color = if rendezvous_valid {
                $config.my_color
            } else if !is_red {
                Color::Red
            } else {
                Color::Rgb(255, 100, 0)
            };
            let rendezvous_active = create_active && $active_field == 2;
            let rendezvous_label_color = if rendezvous_active { $config.text_color } else { $config.border_color };

            let mut rendezvous_spans = vec![
                Span::styled("rendezvous: ", Style::default().fg(rendezvous_label_color)),
            ];
            if rendezvous_active {
                rendezvous_spans.push(Span::styled("> ", Style::default().fg($config.text_color)));
            }
            rendezvous_spans.push(Span::styled(&$rendezvous_input, Style::default().fg(rendezvous_color)));

            let rendezvous_line = Line::from(rendezvous_spans);
            let rendezvous_paragraph = Paragraph::new(rendezvous_line)
                .style(Style::default().bg($config.bg_color));
            frame.render_widget(rendezvous_paragraph, lines_layout[7]);

            // Separator
            frame.render_widget(&separator, lines_layout[8]);

            // Line: "join new chat"
            let join_active = $active_section == 2;
            let join_style = if join_active {
                Style::default().fg($config.text_color)
            } else {
                Style::default().fg($config.border_color)
            };

            let join_header = Paragraph::new(
                Line::from(vec![
                    Span::styled("join new chat", join_style)
                ])
            )
            .alignment(Alignment::Center)
            .style(Style::default().bg($config.bg_color));
            frame.render_widget(join_header, lines_layout[9]);

            // Join user name field
            let join_user_name_active = join_active && $active_field == 0;
            let join_user_name_label_color = if join_user_name_active { $config.text_color } else { $config.border_color };

            let mut join_user_name_spans = vec![
                Span::styled("user name: ", Style::default().fg(join_user_name_label_color)),
            ];
            if join_user_name_active {
                join_user_name_spans.push(Span::styled("> ", Style::default().fg($config.text_color)));
            }
            join_user_name_spans.push(Span::styled(&$user_name_input, Style::default().fg(user_name_color)));

            let join_user_name_line = Line::from(join_user_name_spans);
            let join_user_name_paragraph = Paragraph::new(join_user_name_line)
                .style(Style::default().bg($config.bg_color));
            frame.render_widget(join_user_name_paragraph, lines_layout[10]);

            // Join rendezvous address field
            let join_rendezvous_active = join_active && $active_field == 1;
            let join_rendezvous_label_color = if join_rendezvous_active { $config.text_color } else { $config.border_color };

            let mut join_rendezvous_spans = vec![
                Span::styled("rendezvous: ", Style::default().fg(join_rendezvous_label_color)),
            ];
            if join_rendezvous_active {
                join_rendezvous_spans.push(Span::styled("> ", Style::default().fg($config.text_color)));
            }
            join_rendezvous_spans.push(Span::styled(&$rendezvous_input, Style::default().fg(rendezvous_color)));

            let join_rendezvous_line = Line::from(join_rendezvous_spans);
            let join_rendezvous_paragraph = Paragraph::new(join_rendezvous_line)
                .style(Style::default().bg($config.bg_color));
            frame.render_widget(join_rendezvous_paragraph, lines_layout[11]);
        })?;

        // Handle input
        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => break,

                        KeyCode::Char('k') if $active_section == 0 || key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if $active_section == 1 && $active_field > 0 {
                                $active_field -= 1;
                            } else if $active_section == 1 && $active_field == 0 {
                                $active_section = 0;
                            } else if $active_section == 2 && $active_field > 0 {
                                $active_field -= 1;
                            } else if $active_section == 2 && $active_field == 0 {
                                $active_section = 1;
                                $active_field = 2;
                            }
                        }
                        KeyCode::Up => {
                            if $active_section == 1 && $active_field > 0 {
                                $active_field -= 1;
                            } else if $active_section == 1 && $active_field == 0 {
                                $active_section = 0;
                            } else if $active_section == 2 && $active_field > 0 {
                                $active_field -= 1;
                            } else if $active_section == 2 && $active_field == 0 {
                                $active_section = 1;
                                $active_field = 2;
                            }
                        }
                        KeyCode::Char('j') if $active_section == 0 || key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if $active_section == 0 {
                                $active_section = 1;
                                $active_field = 0;
                            } else if $active_section == 1 && $active_field < 2 {
                                $active_field += 1;
                            } else if $active_section == 1 && $active_field == 2 {
                                $active_section = 2;
                                $active_field = 0;
                            } else if $active_section == 2 && $active_field < 1 {
                                $active_field += 1;
                            }
                        }
                        KeyCode::Down => {
                            if $active_section == 0 {
                                $active_section = 1;
                                $active_field = 0;
                            } else if $active_section == 1 && $active_field < 2 {
                                $active_field += 1;
                            } else if $active_section == 1 && $active_field == 2 {
                                $active_section = 2;
                                $active_field = 0;
                            } else if $active_section == 2 && $active_field < 1 {
                                $active_field += 1;
                            }
                        }
                        KeyCode::Left | KeyCode::Char('h') if $active_section == 0 => {
                            if $chats.choice > 0 {
                                $chats.choice -= 1;
                            } else if !$chats.available.is_empty() {
                                $chats.choice = $chats.available.len() - 1;
                            }
                        }
                        KeyCode::Right | KeyCode::Char('l') if $active_section == 0 => {
                            if !$chats.available.is_empty() {
                                $chats.choice = ($chats.choice + 1) % $chats.available.len();
                            }
                        }
                        KeyCode::Char('X') | KeyCode::Char('d') | KeyCode::Delete | KeyCode::Backspace if $active_section == 0 => {
                            if $chat_2_delete.is_some_and(|chat| chat == $chats.choice) {
                                $chat_2_delete = None;
                                $conn = None;
                                $chat = None;
                                $chats.delete(CONFIG, SHARE);
                            } else {
                                $chat_2_delete = Some($chats.choice);
                            }
                        }
                        KeyCode::Esc if $active_section == 0 => {
                            $chat_2_delete = None;
                        }
                        KeyCode::Enter if $active_section == 0 => {
                            if let Some(chosen) = $chats.available.get($chats.choice) {
                                $config = Config::load(CONFIG, Some(chosen))?;
                                $choice = chosen.split(" @ ").last().unwrap_or(chosen.as_str()).to_string();
                                // Resume as host (admin) or as member, per our saved role.
                                let user_name = $config.user_name.clone().unwrap_or_default();
                                let users = Database::new(&format!("{}__{}.db", user_name, $choice))?.load_all_users().await?;
                                let is_admin = users.iter().any(|u| u.get_name() == user_name && u.get_role() == Some(Role::Admin));
                                let cc = if is_admin {
                                    startstuffold(&$choice, &$config, Arc::clone(&$requests), $token.clone(), &mut $run_once).await?
                                } else {
                                    joinstuffold(&$choice, &$config, $token.clone(), &mut $run_once).await?
                                };
                                $chat_2_delete = None;
                                $conn = Some(cc.0);
                                $chat = Some(cc.1);
                                $curr_screen = Screen::Chat;
                            }
                        }
                        KeyCode::Enter if $active_section == 1 => {
                            match $active_field {
                                0 if chat_name_valid => $active_field = 1,
                                1 if user_name_valid => $active_field = 2,
                                2 if rendezvous_valid && chat_name_valid && user_name_valid => {
                                    $choice = $chat_name_input.clone();
                                    let ccppup = startstuffnew(&$choice, &$user_name_input, &$rendezvous_input, Arc::clone(&$requests), $token.clone(), &mut $run_once).await?;
                                    $conn = Some(ccppup.0);
                                    $chat = Some(ccppup.1);
                                    let prvkey = ccppup.2;
                                    let pubkey = ccppup.3;
                                    let user_id = ccppup.4;
                                    let peer_id = ccppup.5;
                                    $config = Config::save(CONFIG, &$chat_name_input, &$user_name_input, &$rendezvous_input, user_id, peer_id, pubkey, prvkey)?;
                                    $curr_screen = Screen::InitServer;
                                }
                                _ => {}
                            }
                        }
                        KeyCode::Enter if $active_section == 2 => {
                            match $active_field {
                                0 if user_name_valid => $active_field = 1,
                                1 if rendezvous_valid && user_name_valid => {
                                    // No chat-name field on join; use the rendezvous as a local
                                    // handle until the admin's db sync renames things.
                                    $choice = $rendezvous_input.clone();
                                    let jc = joinstuffnew(&$choice, &$user_name_input, &$rendezvous_input, $token.clone(), &mut $run_once).await?;
                                    $conn = Some(jc.0);
                                    $chat = Some(jc.1);
                                    let prvkey = jc.2;
                                    let pubkey = jc.3;
                                    let user_id = jc.4;
                                    let peer_id = jc.5;
                                    $config = Config::save(CONFIG, &$choice, &$user_name_input, &$rendezvous_input, user_id, peer_id, pubkey, prvkey)?;
                                    $curr_screen = Screen::InitClient;
                                }
                                _ => {}
                            }
                        }
                        KeyCode::Char(c) if $active_section == 1 => {
                            match $active_field {
                                0 => $chat_name_input.push(c),
                                1 => $user_name_input.push(c),
                                2 => $rendezvous_input.push(c),
                                _ => {}
                            }
                        }
                        KeyCode::Char(c) if $active_section == 2 => {
                            match $active_field {
                                0 => $user_name_input.push(c),
                                1 => $rendezvous_input.push(c),
                                _ => {}
                            }
                        }
                        KeyCode::Backspace if $active_section == 1 => {
                            match $active_field {
                                0 => { $chat_name_input.pop(); },
                                1 => { $user_name_input.pop(); },
                                2 => { $rendezvous_input.pop(); },
                                _ => {}
                            }
                        }
                        KeyCode::Backspace if $active_section == 2 => {
                            match $active_field {
                                0 => { $user_name_input.pop(); },
                                1 => { $rendezvous_input.pop(); },
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
