use ratatui::{widgets::BorderType, style::Color};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::{Path, PathBuf}};
use std::fs;
use std::net::SocketAddr;
use x25519_dalek::StaticSecret;
use anyhow::Result;
use hex::{encode, decode};

#[derive(Debug, Deserialize, Serialize)]
pub struct TomlConfig {
    // Sectionless cosmetic configs
    #[serde(default = "default_border_style")]
    pub border_style: String,

    #[serde(default = "default_max_height")]
    pub max_height: u16,

    #[serde(default)]
    pub bg_color: Option<(u8, u8, u8)>,

    #[serde(default)]
    pub text_color: Option<(u8, u8, u8)>,

    #[serde(default)]
    pub border_color: Option<(u8, u8, u8)>,

    #[serde(default)]
    pub normal_mode: Option<(u8, u8, u8)>,

    #[serde(default)]
    pub insert_mode: Option<(u8, u8, u8)>,

    #[serde(default)]
    pub timeout_mode: Option<(u8, u8, u8)>,

    #[serde(default)]
    pub users_color: Option<(u8, u8, u8)>,

    #[serde(default)]
    pub my_color: Option<(u8, u8, u8)>,

    #[serde(default)]
    pub system_color: Option<(u8, u8, u8)>,

    #[serde(default)]
    pub online_color: Option<(u8, u8, u8)>,

    // Chat-specific sections
    #[serde(flatten)]
    pub chats: HashMap<String, ChatConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ChatConfig {
    pub user_id: Option<u64>,
    pub user_name: Option<String>,
    pub rendezvous: Option<SocketAddr>,
    pub prvkey: Option<String>,

    // Optional overrides for cosmetic configs
    pub border_style: Option<String>,
    pub max_height: Option<u16>,
    pub bg_color: Option<(u8, u8, u8)>,
    pub text_color: Option<(u8, u8, u8)>,
    pub border_color: Option<(u8, u8, u8)>,
    pub normal_mode: Option<(u8, u8, u8)>,
    pub insert_mode: Option<(u8, u8, u8)>,
    pub timeout_mode: Option<(u8, u8, u8)>,
    pub users_color: Option<(u8, u8, u8)>,
    pub my_color: Option<(u8, u8, u8)>,
    pub system_color: Option<(u8, u8, u8)>,
    pub online_color: Option<(u8, u8, u8)>,
}

pub struct ChatChoice {
    pub available: Vec<String>,
    pub choice: usize
}

#[derive(Clone)]
pub struct Config {
    pub user_id: Option<u64>,
    pub user_name: Option<String>,
    pub rendezvous: Option<SocketAddr>,
    pub prvkey: Option<StaticSecret>,

    pub border_style: BorderType,
    pub max_height: u16,

    pub bg_color: Color,
    pub text_color: Color,
    pub border_color: Color,
    pub normal_mode: Color,
    pub insert_mode: Color,
    pub timeout_mode: Color,
    pub users_color: Color,
    pub my_color: Color,
    pub system_color: Color,
    pub online_color: Color,
}

// Default functions for serde
fn default_border_style() -> String { "Rounded".to_string() }
fn default_max_height() -> u16 { 5 }

impl ChatChoice {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let toml_config: TomlConfig = toml::from_str(&content)?;

        let mut available: Vec<String> = toml_config.chats.keys().cloned().collect();
        available.sort(); // Optional: keep alphabetically sorted

        Ok(Self {
            available,
            choice: 0,
        })
    }

    pub fn current(&self) -> Option<&str> {
        self.available.get(self.choice).map(|s| s.as_str())
    }

    pub fn delete<P: AsRef<Path>>(&mut self, toml_path: P, db_dir: P) -> Result<()> {
        if let Some(choice) = self.available.get(self.choice).map(|s| s.as_str()) {
            let content = fs::read_to_string(&toml_path)?;
            let mut toml_config = toml::from_str::<TomlConfig>(&content)?;
            if let Some(removed) = toml_config.chats.remove(choice) {
                let chat_name = choice.split(" @ ").last().unwrap_or(choice);
                let user_name = removed.user_name.as_deref().unwrap_or(chat_name);
                let mut db_path = PathBuf::from(db_dir.as_ref()).join(format!("{}__{}", user_name, chat_name));
                db_path.set_extension("db");
                let _ = fs::remove_file(&db_path);
                fs::write(&toml_path, toml::to_string_pretty(&toml_config)?)?;
                self.available.remove(self.choice);
                self.choice = self.choice.min(self.available.len().saturating_sub(1));
            }
        }
        Ok(())
    }
}

impl Config {
    /// Warning color for invalid / at-limit fields and the TIMEOUT-ish states: red, but switched to
    /// orange when the user's own color (`my_color`) is already red, so it stays distinguishable.
    pub fn warn_color(&self) -> Color {
        match self.my_color {
            Color::Rgb(r, g, _) if (120..=255).contains(&r) && (0..=60).contains(&g) => Color::Rgb(255, 100, 0),
            _ => Color::Red,
        }
    }

    pub fn load<P: AsRef<Path>>(path: P, chat_name: Option<&str>) -> Result<Self> {
        match fs::read_to_string(&path) {
            Ok(content) => {
                match toml::from_str::<TomlConfig>(&content) {
                    Ok(toml_config) => Ok(Self::from_toml(toml_config, chat_name)),
                    Err(_) => {
                        Ok(Self::default())
                    }
                }
            }
            Err(_) => {
                // File doesn't exist, use defaults
                Ok(Self::default())
            }
        }
    }

    fn default() -> Self {
        Self {
            user_id: None,
            user_name: Some(String::from("Me")),
            rendezvous: None,
            prvkey: None,
            border_style: BorderType::Rounded,
            max_height: 5,
            bg_color: Color::Reset,
            text_color: Color::White,
            border_color: Color::DarkGray,
            normal_mode: Color::Rgb(0, 212, 255),
            insert_mode: Color::Rgb(255, 102, 204),
            timeout_mode: Color::Rgb(255, 49, 49), // neon red
            users_color: Color::Cyan,
            my_color: Color::Green,
            system_color: Color::DarkGray,
            online_color: Color::Green,
        }
    }

    fn from_toml(toml: TomlConfig, chat_name: Option<&str>) -> Self {
        // Get chat-specific config if available
        let chat_config = chat_name.and_then(|name| toml.chats.get(name));

        // Helper to get value with fallback priority: chat-specific > global > default
        let get_color = |chat_val: Option<Option<(u8, u8, u8)>>,
                         global_val: Option<(u8, u8, u8)>,
                         default: Color| -> Color {
            chat_val
                .flatten()
                .or(global_val)
                .map(|(r, g, b)| Color::Rgb(r, g, b))
                .unwrap_or(default)
        };

        let border_style_str = chat_config
            .and_then(|c| c.border_style.as_ref())
            .unwrap_or(&toml.border_style);

        let max_height = chat_config
            .and_then(|c| c.max_height)
            .unwrap_or(toml.max_height);

        let prvkey = chat_config
            .and_then(|c| c.prvkey.as_ref())
            .and_then(|s| decode(s).ok())
            .and_then(|bytes| {
                let arr: [u8; 32] = bytes.try_into().ok()?;
                Some(StaticSecret::from(arr))
            });

        Self {
            user_id: chat_config.and_then(|c| c.user_id),
            user_name: chat_config.and_then(|c| c.user_name.clone()),
            rendezvous: chat_config.and_then(|c| c.rendezvous),
            prvkey,

            border_style: parse_border_style(border_style_str),
            max_height,

            bg_color: get_color(
                chat_config.map(|c| c.bg_color),
                toml.bg_color,
                Color::Reset
            ),
            text_color: get_color(
                chat_config.map(|c| c.text_color),
                toml.text_color,
                Color::White
            ),
            border_color: get_color(
                chat_config.map(|c| c.border_color),
                toml.border_color,
                Color::DarkGray
            ),
            normal_mode: get_color(
                chat_config.map(|c| c.normal_mode),
                toml.normal_mode,
                Color::Rgb(0, 212, 255)
            ),
            insert_mode: get_color(
                chat_config.map(|c| c.insert_mode),
                toml.insert_mode,
                Color::Rgb(255, 102, 204)
            ),
            timeout_mode: get_color(
                chat_config.map(|c| c.timeout_mode),
                toml.timeout_mode,
                Color::Rgb(255, 49, 49)
            ),
            users_color: get_color(
                chat_config.map(|c| c.users_color),
                toml.users_color,
                Color::Cyan
            ),
            my_color: get_color(
                chat_config.map(|c| c.my_color),
                toml.my_color,
                Color::Green
            ),
            system_color: get_color(
                chat_config.map(|c| c.system_color),
                toml.system_color,
                Color::DarkGray
            ),
            online_color: get_color(
                chat_config.map(|c| c.online_color),
                toml.online_color,
                Color::Green
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn save<P: AsRef<Path>>(path: P, chat_name: &str, user_name: &str, rendezvous: &str, user_id: u64, prvkey: StaticSecret) -> Result<Self> {
        // Load existing config or create new
        let mut toml_config = if path.as_ref().exists() {
            let content = fs::read_to_string(&path)?;
            toml::from_str(&content).unwrap_or_else(|_| TomlConfig {
                border_style: default_border_style(),
                max_height: default_max_height(),
                bg_color: None,
                text_color: None,
                border_color: None,
                normal_mode: None,
                insert_mode: None,
                timeout_mode: None,
                users_color: None,
                my_color: None,
                system_color: None,
                online_color: None,
                chats: HashMap::new(),
            })
        } else {
            TomlConfig {
                border_style: default_border_style(),
                max_height: default_max_height(),
                bg_color: None,
                text_color: None,
                border_color: None,
                normal_mode: None,
                insert_mode: None,
                timeout_mode: None,
                users_color: None,
                my_color: None,
                system_color: None,
                online_color: None,
                chats: HashMap::new(),
            }
        };

        let display_key = format!("{} @ {}", user_name, chat_name);

        // Check if chat already exists
        if toml_config.chats.contains_key(&display_key) {
            return Err(anyhow::anyhow!("Chat '{}' already exists", display_key));
        }

        // Update chat-specific config
        let chat_config = ChatConfig {
            user_id: Some(user_id),
            user_name: Some(String::from(user_name)),
            rendezvous: Some(rendezvous.parse::<SocketAddr>()?),
            prvkey: Some(encode(prvkey.as_bytes())),
            border_style: None, // Don't save cosmetic overrides by default
            max_height: None,
            bg_color: None,
            text_color: None,
            border_color: None,
            normal_mode: None,
            insert_mode: None,
            timeout_mode: None,
            users_color: None,
            my_color: None,
            system_color: None,
            online_color: None,
        };
        toml_config.chats.insert(display_key, chat_config);

        let toml_string = toml::to_string_pretty(&toml_config)?;
        fs::write(path, toml_string)?;

        Ok(Self {
            user_id: Some(user_id),
            user_name: Some(String::from(user_name)),
            rendezvous: Some(rendezvous.parse::<SocketAddr>()?),
            prvkey: Some(prvkey),
            border_style: parse_border_style(&toml_config.border_style),
            max_height: toml_config.max_height,
            bg_color: toml_config.bg_color.map(|(r, g, b)| Color::Rgb(r, g, b)).unwrap_or(Color::Reset),
            text_color: toml_config.text_color.map(|(r, g, b)| Color::Rgb(r, g, b)).unwrap_or(Color::White),
            border_color: toml_config.border_color.map(|(r, g, b)| Color::Rgb(r, g, b)).unwrap_or(Color::DarkGray),
            normal_mode: toml_config.normal_mode.map(|(r, g, b)| Color::Rgb(r, g, b)).unwrap_or(Color::Rgb(0, 212, 255)),
            insert_mode: toml_config.insert_mode.map(|(r, g, b)| Color::Rgb(r, g, b)).unwrap_or(Color::Rgb(255, 102, 204)),
            timeout_mode: toml_config.timeout_mode.map(|(r, g, b)| Color::Rgb(r, g, b)).unwrap_or(Color::Rgb(255, 49, 49)),
            users_color: toml_config.users_color.map(|(r, g, b)| Color::Rgb(r, g, b)).unwrap_or(Color::Cyan),
            my_color: toml_config.my_color.map(|(r, g, b)| Color::Rgb(r, g, b)).unwrap_or(Color::Green),
            system_color: toml_config.system_color.map(|(r, g, b)| Color::Rgb(r, g, b)).unwrap_or(Color::DarkGray),
            online_color: toml_config.online_color.map(|(r, g, b)| Color::Rgb(r, g, b)).unwrap_or(Color::Green),
        })
    }
}

fn parse_border_style(s: &str) -> BorderType {
    match s.to_lowercase().as_str() {
        "plain" => BorderType::Plain,
        "thick" => BorderType::Thick,
        "double" => BorderType::Double,
        "rounded" => BorderType::Rounded,
        _ => BorderType::Rounded, // default
    }
}
