// prompt engineered
use ratatui::{widgets::BorderType, style::Color};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use x25519_dalek::{PublicKey, StaticSecret};
use anyhow::Result;

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
    pub users_color: Option<(u8, u8, u8)>,
    
    #[serde(default)]
    pub my_color: Option<(u8, u8, u8)>,
    
    #[serde(default)]
    pub system_color: Option<(u8, u8, u8)>,
    
    #[serde(default)]
    pub online_color: Option<(u8, u8, u8)>,
    
    #[serde(default)]
    pub time_color: Option<(u8, u8, u8)>,
    
    // Chat-specific sections
    #[serde(flatten)]
    pub chats: HashMap<String, ChatConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ChatConfig {
    pub user_id: Option<u64>,
    pub user_name: Option<String>,
    pub peer_id: Option<i32>,
    
    // Optional overrides for cosmetic configs
    pub border_style: Option<String>,
    pub max_height: Option<u16>,
    pub bg_color: Option<(u8, u8, u8)>,
    pub text_color: Option<(u8, u8, u8)>,
    pub border_color: Option<(u8, u8, u8)>,
    pub normal_mode: Option<(u8, u8, u8)>,
    pub insert_mode: Option<(u8, u8, u8)>,
    pub users_color: Option<(u8, u8, u8)>,
    pub my_color: Option<(u8, u8, u8)>,
    pub system_color: Option<(u8, u8, u8)>,
    pub online_color: Option<(u8, u8, u8)>,
    pub time_color: Option<(u8, u8, u8)>,
}

pub struct Config {
    pub user_id: Option<u64>,
    pub user_name: Option<String>,
    pub peer_id: Option<i32>,
    pub pubkey: Option<PublicKey>,
    pub prvkey: Option<StaticSecret>,

    pub border_style: BorderType,
    pub max_height: u16,

    pub bg_color: Color,
    pub text_color: Color,
    pub border_color: Color,
    pub normal_mode: Color,
    pub insert_mode: Color,
    pub users_color: Color,
    pub my_color: Color,
    pub system_color: Color,
    pub online_color: Color,
    pub time_color: Color,
}

// Default functions for serde
fn default_border_style() -> String { "Rounded".to_string() }
fn default_max_height() -> u16 { 5 }

impl Config {
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
            peer_id: None,
            pubkey: None,
            prvkey: None,
            border_style: BorderType::Rounded,
            max_height: 5,
            bg_color: Color::Reset,
            text_color: Color::White,
            border_color: Color::DarkGray,
            normal_mode: Color::Rgb(0, 212, 255),
            insert_mode: Color::Rgb(255, 102, 204),
            users_color: Color::Cyan,
            my_color: Color::Green,
            system_color: Color::DarkGray,
            online_color: Color::Green,
            time_color: Color::DarkGray,
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
        
        Self {
            user_id: chat_config.and_then(|c| c.user_id),
            user_name: chat_config.and_then(|c| c.user_name.clone()),
            peer_id: chat_config.and_then(|c| c.peer_id),
            pubkey: None, // These need separate handling/loading
            prvkey: None,
            
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
            time_color: get_color(
                chat_config.map(|c| c.time_color),
                toml.time_color,
                Color::DarkGray
            ),
        }
    }
    
    pub fn save<P: AsRef<Path>>(&self, path: P, chat_name: Option<&str>) -> Result<()> {
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
                users_color: None,
                my_color: None,
                system_color: None,
                online_color: None,
                time_color: None,
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
                users_color: None,
                my_color: None,
                system_color: None,
                online_color: None,
                time_color: None,
                chats: HashMap::new(),
            }
        };
        
        if let Some(chat) = chat_name {
            // Update chat-specific config
            let chat_config = ChatConfig {
                user_id: self.user_id,
                user_name: self.user_name.clone(),
                peer_id: self.peer_id,
                border_style: None, // Don't save cosmetic overrides by default
                max_height: None,
                bg_color: None,
                text_color: None,
                border_color: None,
                normal_mode: None,
                insert_mode: None,
                users_color: None,
                my_color: None,
                system_color: None,
                online_color: None,
                time_color: None,
            };
            toml_config.chats.insert(chat.to_string(), chat_config);
        }
        
        let toml_string = toml::to_string_pretty(&toml_config)?;
        fs::write(path, toml_string)?;
        
        Ok(())
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
