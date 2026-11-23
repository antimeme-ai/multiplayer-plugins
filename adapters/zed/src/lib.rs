#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

use zed_extension_api::{self as zed, ContextServerId, Project, Result};

const CONTEXT_SERVER_ID: &str = "multiplayer";
const GITHUB_REPO: &str = "antimemeai/multiplayer_outpost";
const BINARY_NAME: &str = "mp-outpost";

struct MultiplayerOutpostExtension {
    cached_binary_path: Option<String>,
}

impl MultiplayerOutpostExtension {
    fn platform_target() -> Result<&'static str> {
        let (os, arch) = zed::current_platform();
        match (os, arch) {
            (zed::Os::Mac, zed::Architecture::Aarch64) => Ok("darwin-arm64"),
            (zed::Os::Linux, zed::Architecture::X8664) => Ok("linux-x86_64"),
            (zed::Os::Linux, zed::Architecture::Aarch64) => Ok("linux-arm64"),
            _ => Err(format!(
                "unsupported platform ({os:?}, {arch:?}) for prebuilt mp-outpost; install mp-outpost on PATH"
            )),
        }
    }

    fn ensure_binary(&mut self) -> Result<String> {
        if let Some(path) = &self.cached_binary_path {
            if fs::metadata(path).map_or(false, |m| m.is_file()) {
                return Ok(path.clone());
            }
        }

        let target = Self::platform_target()?;
        let release = zed::latest_github_release(
            GITHUB_REPO,
            zed::GithubReleaseOptions {
                require_assets: true,
                pre_release: false,
            },
        )?;

        let version = release.version.trim_start_matches('v');
        let dir_name = format!("{BINARY_NAME}-v{version}-{target}");
        let asset_name = format!("{dir_name}.tar.gz");

        let asset = release
            .assets
            .iter()
            .find(|a| a.name == asset_name)
            .ok_or_else(|| {
                format!(
                    "no release asset matching '{asset_name}' in {GITHUB_REPO} {}",
                    release.version
                )
            })?;

        let version_dir = format!("mp-outpost-{}", release.version);
        let binary_path = PathBuf::from(&version_dir)
            .join(&dir_name)
            .join(BINARY_NAME);
        let binary_path_str = binary_path
            .to_str()
            .ok_or_else(|| "non-UTF-8 binary path".to_string())?
            .to_string();

        if !fs::metadata(&binary_path).map_or(false, |m| m.is_file()) {
            zed::download_file(
                &asset.download_url,
                &version_dir,
                zed::DownloadedFileType::GzipTar,
            )
            .map_err(|e| format!("failed to download {asset_name}: {e}"))?;
            zed::make_file_executable(&binary_path_str)?;
        }

        self.cached_binary_path = Some(binary_path_str.clone());
        Ok(binary_path_str)
    }
}

impl zed::Extension for MultiplayerOutpostExtension {
    fn new() -> Self {
        Self {
            cached_binary_path: None,
        }
    }

    fn context_server_command(
        &mut self,
        context_server_id: &ContextServerId,
        _project: &Project,
    ) -> Result<zed::Command> {
        if context_server_id.as_ref() != CONTEXT_SERVER_ID {
            return Err(format!(
                "unknown context server id '{}'",
                context_server_id.as_ref()
            ));
        }

        let command = self.ensure_binary()?;
        Ok(zed::Command {
            command,
            args: vec!["mcp".to_string()],
            env: Default::default(),
        })
    }
}

zed::register_extension!(MultiplayerOutpostExtension);
