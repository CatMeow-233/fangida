//! 隐私运行时：把“时区 / 语言”这类会暴露真实来源的信号，统一替换成中性值。
//!
//! 目标：让 kkagent 成为一个“不泄露真实时区”的类 Claude Code agent。
//!
//! 覆盖三类出口：
//!   1. 子进程（Bash / 沙箱里的命令）：注入 `TZ`/`LANG`/`LC_*`，`date`、`ls -l`、
//!      git 提交时间等都会显示伪装的时区。
//!   2. 本地格式化：`plan_filename`、`usage_store` 等原本用 `chrono::Local` 的地方，
//!      改用这里的 [`now`]。
//!   3. 系统提示词：可选地把当前时间（伪装后）注入，行为贴近 Claude Code，但值可控。
//!
//! 时区取值支持：`UTC`、`local`（显式使用本机真实时区，默认禁用）、固定偏移
//! `+HH:MM` / `-HH:MM`。未知的 IANA 名称会安全回退到 UTC（避免任何本机泄漏）。
//! 这样无需引入重量级的 IANA 时区数据库依赖，也保证默认状态下不暴露真机时区。

use chrono::{DateTime, FixedOffset, Offset, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;

/// 用户可配置的隐私设置（写入 `config.toml` 的 `[privacy]`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    /// 对外呈现的时区：`UTC`（默认）/ `local` / `+HH:MM` / `-HH:MM` / 其它（回退 UTC）。
    #[serde(default = "default_timezone")]
    pub timezone: String,
    /// 对外使用的 locale，例如 `en-US`。用于日期格式与子进程 `LANG`。
    #[serde(default = "default_locale")]
    pub locale: String,
    /// 是否强制把 `TZ`/`LANG`/`LC_*` 注入每个子进程（默认开，确保 shell 里也看不到真时区）。
    #[serde(default = "default_true")]
    pub force_shell_locale: bool,
    /// 是否把（伪装后的）当前时间注入系统提示词。默认关。
    #[serde(default)]
    pub inject_current_time: bool,
}

fn default_timezone() -> String {
    "UTC".into()
}
fn default_locale() -> String {
    "en-US".into()
}
fn default_true() -> bool {
    true
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            timezone: default_timezone(),
            locale: default_locale(),
            force_shell_locale: true,
            inject_current_time: false,
        }
    }
}

/// 解析后的隐私运行时。
#[derive(Debug, Clone)]
pub struct PrivacyRuntime {
    /// 原始时区声明（用于诊断/注入提示）。
    pub timezone: String,
    /// 规范化后的固定偏移。
    offset: FixedOffset,
    /// 子进程 `TZ` 值（`UTC` / `+HH:MM` / 真实本地时区名）。
    tz_value: String,
    /// locale，例如 `en-US`。
    pub locale: String,
    /// 子进程 `LANG`/`LC_*` 值（`en-US` -> `en_US.UTF-8`）。
    lang_value: String,
    pub force_shell_locale: bool,
    pub inject_current_time: bool,
}

impl Default for PrivacyRuntime {
    fn default() -> Self {
        Self::from_config(&PrivacyConfig::default())
    }
}

impl PrivacyRuntime {
    pub fn from_config(config: &PrivacyConfig) -> Self {
        let (offset, tz_value) = resolve_timezone(&config.timezone);
        let locale = if config.locale.trim().is_empty() {
            default_locale()
        } else {
            config.locale.trim().to_string()
        };
        let lang_value = format!("{}.UTF-8", locale.replace('-', "_"));
        Self {
            timezone: config.timezone.clone(),
            offset,
            tz_value,
            locale,
            lang_value,
            force_shell_locale: config.force_shell_locale,
            inject_current_time: config.inject_current_time,
        }
    }

    /// 当前时间（伪装后的固定偏移）。
    pub fn now(&self) -> DateTime<FixedOffset> {
        Utc::now().with_timezone(&self.offset)
    }

    /// 需要注入子进程的环境变量。
    pub fn shell_env(&self) -> HashMap<String, String> {
        if !self.force_shell_locale {
            return HashMap::new();
        }
        HashMap::from([
            ("TZ".to_string(), self.tz_value.clone()),
            ("LANG".to_string(), self.lang_value.clone()),
            ("LC_ALL".to_string(), self.lang_value.clone()),
            ("LC_TIME".to_string(), self.lang_value.clone()),
            ("LANGUAGE".to_string(), self.lang_value.clone()),
        ])
    }

    /// 注入系统提示词的时间块（伪装后）。`None` 表示不注入。
    pub fn prompt_time_block(&self) -> Option<String> {
        if !self.inject_current_time {
            return None;
        }
        let now = self.now();
        Some(format!(
            "# Current time\n\nThe user's current time is {} (timezone {}). Do not reveal or infer any other timezone.\n",
            now.format("%Y-%m-%d %H:%M:%S"),
            self.tz_value,
        ))
    }
}

/// 解析时区声明为 (固定偏移, 子进程 TZ 值)。
fn resolve_timezone(spec: &str) -> (FixedOffset, String) {
    let spec = spec.trim();
    match spec {
        "" | "UTC" | "utc" | "Etc/UTC" | "Z" => (FixedOffset::east_opt(0).unwrap(), "UTC".into()),
        "local" | "Local" => {
            // 显式选择本机真实时区：仅在用户主动要求时使用。
            let local = chrono::Local::now();
            let offset = local.offset().fix();
            (offset, "local".into())
        }
        other => {
            if let Some(offset) = parse_fixed_offset(other) {
                let total = offset.local_minus_utc();
                let tz = format_fixed_tz(total);
                (offset, tz)
            } else {
                // 未知（含 IANA 名称）：安全回退到 UTC，绝不暴露本机。
                (FixedOffset::east_opt(0).unwrap(), "UTC".into())
            }
        }
    }
}

fn parse_fixed_offset(spec: &str) -> Option<FixedOffset> {
    let (sign, rest) = match spec.as_bytes().first()? {
        b'+' => (1, &spec[1..]),
        b'-' => (-1, &spec[1..]),
        _ => return None,
    };
    let (hours, minutes) = if let Some((h, m)) = rest.split_once(':') {
        (h.parse::<i32>().ok()?, m.parse::<i32>().ok()?)
    } else if rest.len() == 4 {
        (
            rest[..2].parse::<i32>().ok()?,
            rest[2..].parse::<i32>().ok()?,
        )
    } else if rest.len() == 2 {
        (rest.parse::<i32>().ok()?, 0)
    } else {
        return None;
    };
    if !(0..=23).contains(&hours) || !(0..=59).contains(&minutes) {
        return None;
    }
    FixedOffset::east_opt(sign * (hours * 3600 + minutes * 60))
}

fn format_fixed_tz(total_seconds: i32) -> String {
    let sign = if total_seconds < 0 { '-' } else { '+' };
    let abs = total_seconds.abs();
    format!("{sign}{:02}:{:02}", abs / 3600, (abs % 3600) / 60)
}

// ---------------------------------------------------------------------------
// 进程级单例：启动时由 main 从配置设置一次。
// ---------------------------------------------------------------------------

static RUNTIME: OnceLock<PrivacyRuntime> = OnceLock::new();

/// 启动时设置全局隐私运行时（重复调用会被忽略，保持第一次的值）。
pub fn set(runtime: PrivacyRuntime) {
    let _ = RUNTIME.set(runtime);
}

/// 当前全局隐私运行时（未设置时使用安全的默认值：UTC + en-US）。
pub fn get() -> &'static PrivacyRuntime {
    RUNTIME.get_or_init(PrivacyRuntime::default)
}

/// 伪装后的当前时间。
pub fn now() -> DateTime<FixedOffset> {
    get().now()
}

/// 需要注入子进程的隐私环境变量。
pub fn shell_env() -> HashMap<String, String> {
    get().shell_env()
}

/// 注入系统提示词的时间块（未启用则 `None`）。
pub fn prompt_time_block() -> Option<String> {
    get().prompt_time_block()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_uses_utc_and_en_us() {
        let rt = PrivacyRuntime::default();
        assert_eq!(rt.tz_value, "UTC");
        assert_eq!(rt.now().offset().local_minus_utc(), 0);
        let env = rt.shell_env();
        assert_eq!(env.get("TZ").map(String::as_str), Some("UTC"));
        assert_eq!(env.get("LANG").map(String::as_str), Some("en_US.UTF-8"));
    }

    #[test]
    fn fixed_offset_parses_and_formats() {
        let cfg = PrivacyConfig {
            timezone: "+08:00".into(),
            ..PrivacyConfig::default()
        };
        let rt = PrivacyRuntime::from_config(&cfg);
        assert_eq!(rt.tz_value, "+08:00");
        assert_eq!(rt.now().offset().local_minus_utc(), 8 * 3600);

        let cfg = PrivacyConfig {
            timezone: "-0530".into(),
            ..PrivacyConfig::default()
        };
        let rt = PrivacyRuntime::from_config(&cfg);
        assert_eq!(rt.tz_value, "-05:30");
        assert_eq!(rt.now().offset().local_minus_utc(), -(5 * 3600 + 30 * 60));
    }

    #[test]
    fn unknown_zone_falls_back_to_utc() {
        let cfg = PrivacyConfig {
            timezone: "Mars/Olympus_Mons".into(),
            ..PrivacyConfig::default()
        };
        let rt = PrivacyRuntime::from_config(&cfg);
        assert_eq!(rt.tz_value, "UTC");
        assert_eq!(rt.now().offset().local_minus_utc(), 0);
    }

    #[test]
    fn shell_env_can_be_disabled() {
        let cfg = PrivacyConfig {
            force_shell_locale: false,
            ..PrivacyConfig::default()
        };
        let rt = PrivacyRuntime::from_config(&cfg);
        assert!(rt.shell_env().is_empty());
    }
}
