use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::{net::SocketAddr, path::PathBuf};
use url::Url;

#[derive(Parser)]
#[command(version, about = "轻量 Gist 订阅分发与独立分享管理")]
pub struct Cli {
    #[arg(long, env = "GATEWAY_DATA_DIR", default_value = "var")]
    pub data_dir: PathBuf,
    #[command(subcommand)]
    pub command: Command,
}
#[derive(Subcommand)]
pub enum Command {
    /// 本地初始化管理员和独立加密密钥；不开放网页安装
    Init {
        #[arg(long)]
        secret_stdin: bool,
        #[arg(long, default_value = "http://127.0.0.1:4387")]
        public_url: String,
        #[arg(long)]
        dev: bool,
    },
    /// 运行服务；生产环境应通过可信反代提供 HTTPS
    Serve {
        #[arg(long, env = "GATEWAY_BIND", default_value = "127.0.0.1:4387")]
        bind: SocketAddr,
        #[arg(long, env = "GATEWAY_DEV")]
        dev: bool,
    },
}
pub fn normalize_base(input: &str, dev: bool) -> Result<String> {
    let u = Url::parse(input).context("对外地址格式不正确")?;
    let loopback = matches!(
        u.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    );
    if !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || u.path() != "/"
    {
        bail!("对外地址只能包含协议、主机和端口");
    }
    if u.scheme() != "https" && !(dev && loopback && u.scheme() == "http") {
        bail!("生产对外地址必须使用 HTTPS；本机 HTTP 需要 --dev");
    }
    if u.host_str().is_none() {
        bail!("对外地址缺少主机");
    }
    Ok(u.as_str().trim_end_matches('/').to_owned())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn base_url_is_explicit_and_safe() {
        assert_eq!(
            normalize_base("https://sub.example.com/", false).unwrap(),
            "https://sub.example.com"
        );
        assert!(normalize_base("http://example.com", true).is_err());
        assert!(normalize_base("https://u:p@example.com", false).is_err());
        assert!(normalize_base("https://example.com/a", false).is_err());
        assert!(normalize_base("http://127.0.0.1:4387", true).is_ok());
    }
}
