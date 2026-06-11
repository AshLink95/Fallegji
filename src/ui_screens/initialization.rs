#[macro_export]
macro_rules! initServer {
    ($terminal:ident, $curr_screen: ident, $config: ident, $choice: ident, $chats: ident, $active_section: ident, $active_row: ident, $active_col: ident, $requests: ident, $input:ident, $conn: ident, $chat: ident) => {
        $terminal.draw(|f| {
            //TODO: update with actual peers list from connection.
            // Also, find a way to update based on valid packets (heartbeats) received (requests list update and peers online status).
            // Use chat for viewing chat members (peers)
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
            // Connected peers (excludes us): name (from chat members) + reachable addr + online dot.
            let me = $chat.current_user.get_id();
            let peers: Vec<(String, std::net::SocketAddr, bool)> = {
                let members = $chat.members.read().unwrap();
                $conn.peer_list().into_iter()
                    .filter(|(uid, _)| *uid != me)
                    .map(|(uid, p)| {
                        let name = members.get(&uid).map(|u| u.get_name()).unwrap_or_else(|| "?".to_string());
                        (name, p.get_addrs()[0], p.is_online())
                    })
                    .collect()
            };
            let peers_count = peers.len();
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

            let peers_lines: Vec<Line> = if peers.is_empty() {
                vec![Line::from(Span::styled("No peers connected", Style::default().fg($config.border_color)))]
            } else {
                peers.iter().map(|(name, addr, online)| {
                    let (dot_color, status) = if *online { ($config.my_color, "online") } else { ($config.border_color, "offline") };
                    Line::from(vec![
                        Span::styled("● ", Style::default().fg(dot_color)),
                        Span::styled(format!("{name}  "), Style::default().fg($config.users_color)),
                        Span::styled(format!("{addr} "), Style::default().fg($config.border_color)),
                        Span::styled(format!("({status})"), Style::default().fg(dot_color)),
                    ])
                }).collect()
            };
            let peers_text = Paragraph::new(peers_lines)
                .style(Style::default().bg($config.bg_color))
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

                for (idx, (addr, name, _pubkey, _uid)) in requests_guard.iter().enumerate() {
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
                    let addr_text = Paragraph::new(format!("{}", addr[0])) // reachable (post-NAT) addr
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
                if key.kind == KeyEventKind::Press {
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
                        KeyCode::Enter if $active_section == 1 => {
                            // active_row: accept (true) pushes the db to the peer; either way drop the request.
                            let req = { $requests.lock().unwrap().get($active_col as usize).map(|r| (r.0, r.1.clone(), r.2, r.3)) };
                            if let Some((addrs, name, pubkey, uid)) = req {
                                if $active_row {
                                    let _ = $conn.send_newpeer(addrs, pubkey, &name, uid, &$choice, &$chat).await;
                                }
                                let mut g = $requests.lock().unwrap();
                                if ($active_col as usize) < g.len() { g.remove($active_col as usize); }
                                if $active_col > 0 && $active_col as usize >= g.len() { $active_col -= 1; }
                            }
                        },
                        KeyCode::Enter if $active_section == 2 => {
                            $curr_screen = Screen::Chat;
                        },
                        _ => {}
                    }
                }
            }
        }
    };
}

#[macro_export]
macro_rules! initClient {
    ($terminal:ident, $curr_screen: ident, $config: ident, $rendezvous_input: ident, $anim_tick: ident, $conn: ident, $resend_at: ident, $resend_n: ident) => {
            // Transition to the chat is driven by the app loop once the slot fills.

            // ASCII art
            let ascii_loop1 = vec![
"                                                                            .+##    ##           ",
"                                                                      #####-+#####- ####+        ",
"                                                                  +##--##++++ --###     ###      ",
"                                                                 +        # .+.  .#####          ",
"                                                           ## #- .#           ...     +####      ",
"                                                         #   # #  -#  ####+.  +                  ",
"                                                      ######+### #   .-     .   #########        ",
"                                                          - ### -.+     -.#####-    -            ",
"                                                    ####- #.#     +-        . +#####             ",
"                                                    +#+.# #   ##.   +#+      .##                 ",
"                                                    +.#.# ##-. #.        +####                   ",
"                                                    +  #+.-#-    ##+#      .                     ",
"                                                   .#.#+ #  ##+#. .#+##. ##                      ",
"                                                   +  - #  ##    #   ######                      ",
"                                                   ##+#+#+#  +#- ## #. ##+                       ",
"                                                # +    ##  ###    #+#+###                        ",
"                                       -#######   ###..# +###- ##    .##                         ",
"                                        +###    # .# ##  ## ## #.###+.##                         ",
"                                         -##.##   .# .##  +### #  ####.                          ",
"                                    -++++ ####-.#. ## #++#     +#   +#                           ",
"                                 .-+-         # +#    -   +#   ##  -+#-                          ",
"                                .              #  #####   +# #     ##                            ",
"                                 **#####       + -#   ####-+ .#   .                              ",
"                                        ### ##### # # +#    -#####+                              ",
"                                          .####   #   -.   # - - .                               ",
"                                              ##### ++  ##..###-+###                             ",
"                                                  ###########.####    #######+++                 ",
"                                                             ##+####  #####-+###                 ",
"                                                                 ######+-  -. -##                ",
"                                                                    ############                 ",
"                                                                      ##                         ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
            ];

            let ascii_loop2 = vec![
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                 ##  +##         ",
"                                                                           ###+###     #####     ",
"                                                                +##.-##--+        #####+   -###  ",
"                                                          .-+##  ##+#   -...   -#+    #########  ",
"                                                    ++.++#### .##     -    +. -++###########+    ",
"     .           +++-  -#++-.       -++++ ####-..+.-  ##+#   #+.  #-##. #########                ",
"  .. +###.  . -###-##-# # +  .-##.-+-         # #####  # +#+##--##. +######                      ",
"   +###  ### #   #  # #  #+#####.              # -   -#+ ## # -  #####                           ",
"     ###  ##.##+####+#+##        **#####       +# ###. # .  #####+                               ",
"        ##  ##                       .##.### ## -# # # + ###.                                    ",
"                                         ###-.#    +## #### #### #                               ",
"                                              ##### ++  ##..###-+###                             ",
"                                                  ###########.####    #######+++                 ",
"                                                             ##+####  #####-+###                 ",
"                                                                 ######+-  -. -##                ",
"                                                                    ############                 ",
"                                                                      ##                         ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
"                                                                                                 ",
            ];

        $terminal.draw(|f| {
            let size = f.area();
            let box_width = size.width.saturating_sub(2);

            let line_count = 3;

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1),
                    Constraint::Min(1),
                    Constraint::Length(1),
                    Constraint::Length(line_count),
                ])
                .split(size);

            let title = Block::default()
                .borders(Borders::TOP)
                .border_type($config.border_style)
                .style(Style::default().fg($config.border_color).bg($config.bg_color))
                .title(Line::from($rendezvous_input.clone()).alignment(Alignment::Center));

            let status_color = $config.border_color; //TODO: my_color for seen, delete color for blocked or deleted
            let status_txt = "sent"; // TODO: (after 10 seconds, tell the client that the address is not valid), seen, deleted or blocked
            let status_anim = String::from(".").repeat(($anim_tick/2) % 3 + 1);
            let status = Paragraph::new(Line::from(vec![
                Span::styled("status: ", Style::default().fg($config.border_color).bg($config.bg_color)),
                Span::styled(format!("{status_txt}{status_anim}"), Style::default().fg(status_color).bg($config.bg_color)),
            ]))
            .style(Style::default().bg($config.bg_color));

            // border color while on cooldown, accent when ready to resend.
            let button_color = if std::time::Instant::now() < $resend_at { $config.border_color } else { $config.my_color };
            let button_txt   = "Resend Request"; //TODO: Resend Request or Unsend
            let button = Paragraph::new(button_txt)
                .centered()
                .style(Style::default().fg($config.text_color).bg(button_color))
                .block(
                    Block::default().borders(Borders::ALL)
                        .border_type($config.border_style)
                        .style(Style::default().fg(button_color).bg($config.bg_color))
                );

            let frame: &Vec<&str> = if ($anim_tick/3) % 2 == 0 { &ascii_loop1 } else { &ascii_loop2 };
            let area = chunks[1];
            let top_pad = (area.height as usize).saturating_sub(frame.len()) / 2;
            let mut anim_lines: Vec<Line> = (0..top_pad).map(|_| Line::from("")).collect();
            anim_lines.extend(frame.iter().map(|line| {
                Line::from(Span::styled(*line, Style::default().fg($config.border_color)))
            }));
            let anim = Paragraph::new(anim_lines)
                .alignment(Alignment::Center);

            f.render_widget(title, chunks[0]);
            f.render_widget(anim, chunks[1]);
            f.render_widget(status, chunks[2]);
            f.render_widget(button, chunks[3]);
        })?;

        $anim_tick = $anim_tick.wrapping_add(1);

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            execute!(io::stdout(), SetCursorStyle::SteadyBlock);
                            $curr_screen = Screen::Home;
                            $config = Config::load(CONFIG, None)?;
                        },
                        KeyCode::Enter => {
                            let now = std::time::Instant::now();
                            if now >= $resend_at {
                                let c = std::sync::Arc::clone($conn);
                                let name = $config.user_name.clone().unwrap_or_default();
                                tokio::spawn(async move { let _ = c.snd_requests(name).await; });
                                // 3 increasing shorts (3,6,9s) then 1 long (30s), cycling.
                                let cd = if $resend_n % 4 == 3 { 30 } else { 3 * ($resend_n % 4 + 1) as u64 };
                                $resend_at = now + std::time::Duration::from_secs(cd);
                                $resend_n += 1;
                            }
                        },
                        _ => {}
                    }
                }
            }
        }
    };
}
