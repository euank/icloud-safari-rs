use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Dataset {
    Tabs,
    Bookmarks,
    History,
}

impl Dataset {
    pub const ALL: [Self; 3] = [Self::Tabs, Self::Bookmarks, Self::History];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tabs => "tabs",
            Self::Bookmarks => "bookmarks",
            Self::History => "history",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum DecodedValue {
    String { value: String },
    Integer { value: i64 },
    Double { value: f64 },
    Date { value: DateTime<Utc> },
    Plist { value: plist::Value },
    Bytes { base64: String },
    Reference { record_name: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RawRecord {
    pub name: String,
    pub record_type: String,
    pub fields: BTreeMap<String, DecodedValue>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unknown_fields_base64: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TabDevice {
    pub id: String,
    pub name: Option<String>,
    pub device_type: Option<String>,
    pub last_modified: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tab {
    pub id: String,
    pub owning_device_id: Option<String>,
    pub title: Option<String>,
    pub url: Option<String>,
    pub date_last_viewed: Option<DateTime<Utc>>,
    pub position: Option<DecodedValue>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bookmark {
    pub id: String,
    pub kind: String,
    pub parent_id: Option<String>,
    pub title: Option<String>,
    pub url: Option<String>,
    pub date_added: Option<DateTime<Utc>>,
    pub preview_text: Option<String>,
    pub position: Option<DecodedValue>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryRecord {
    pub id: String,
    pub uuid: Option<String>,
    pub version: Option<i64>,
    pub data: Option<DecodedValue>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SafariSnapshot {
    pub format: String,
    pub exported_at: DateTime<Utc>,
    pub devices: Vec<TabDevice>,
    pub tabs: Vec<Tab>,
    pub bookmarks: Vec<Bookmark>,
    pub history: Vec<HistoryRecord>,
    pub records: BTreeMap<String, Vec<RawRecord>>,
}
