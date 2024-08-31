use anyhow::Context as _;
use clap::Parser as _;
use std::io::Read as _;
use std::io::Write as _;

fn default_user() -> String {
    "root".to_string()
}

fn default_port() -> u16 {
    22
}

fn default_keysize() -> usize {
    4096
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct SshHost {
    /// Host name or IP address.
    host: String,

    /// SSH port. defaults to 22.
    #[serde(default = "default_port")]
    port: u16,

    /// SSH user. defaults to root.
    #[serde(default = "default_user")]
    user: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
enum Host {
    /// Local device that this tool is running on.
    Local,
    Ssh(SshHost),
}

impl Host {
    pub fn client(&self) -> Client {
        match &self {
            Self::Local => Client {
                // While it is ineffecient to go through this for the local
                // machine, it works very well and allows to use the same code
                // for both cases.
                args: vec!["bash".to_string(), "-c".to_string()],
            },
            Self::Ssh(host) => Client {
                args: vec![
                    "ssh".to_string(),
                    "-p".to_string(),
                    host.port.to_string(),
                    format!("{}@{}", host.user, host.host),
                ],
            },
        }
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct FileLocation {
    path: std::path::PathBuf,
    /// MODE argument for chmod.
    chmod: String,
    // OWNER:GROUP argument for chown.
    chown: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
enum Location {
    PodmanSecret(String),
    File(FileLocation),
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
enum KeyType {
    Client,
    Server,
}

impl KeyType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct Key {
    /// A unique identifier which is used for logs and filters.
    id: String,
    /// Name of a host in the host list.
    host: String,
    /// Name of the CA to use.
    ca: String,
    common_name: String,
    /// systemd service, which will be restarted after updating the key.
    service: Option<String>,
    #[serde(default)]
    additional_domains: Vec<String>,
    cert: Option<Location>,
    key: Option<Location>,
    /// cert + key in one file.
    combined: Option<Location>,
    pfx: Option<Location>,
    r#type: KeyType,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default = "default_keysize")]
    key_size: usize,
}

impl Key {
    pub fn cert_location(&self) -> anyhow::Result<&Location> {
        if let Some(cert) = &self.cert {
            Ok(cert)
        } else if let Some(combined) = &self.combined {
            Ok(combined)
        } else {
            anyhow::bail!("No certificate found");
        }
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct Config {
    #[serde(default)]
    hosts: std::collections::HashMap<String, Host>,

    #[serde(default)]
    keys: Vec<Key>,
}

#[derive(clap::Parser)]
#[command(version)]
struct Cli {
    /// Path to the config file.
    #[arg(value_name = "FILE")]
    config: std::path::PathBuf,

    /// Update expired keys.
    #[arg(short, long)]
    update: bool,

    /// Tags which will not be processed.
    #[arg(long)]
    exclude_tag: Vec<String>,

    /// Tags which will be processed.
    #[arg(long)]
    include_tag: Vec<String>,

    /// Only process this specific key.
    #[arg(long)]
    id: Option<String>,

    /// Update keys even if not needed.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PodmanSecret {
    #[serde(rename = "SecretData")]
    data: String,
}

/// Calls Into<String> on evert argument and runs the cmd through given client.
macro_rules! cmd {
    ( $client:expr, $stdin:expr $(, $arg:expr )* $(,)? ) => {
        {
            let args = vec![
                $( Into::<String>::into($arg), )*
            ];
            $client.cmd(&args, $stdin)
        }
    };
}

struct Client {
    args: Vec<String>,
}

impl Client {
    /// Generates a command to safely run a process on an SSH host.
    ///
    /// With SSH, all code is evaluated by a shell. It's always run as
    /// $SHELL -c "...". This is bad if you want to safely run a program and
    /// not have to care about whitespace and special characters like quotes.
    ///
    /// The way this function works is kinda insane, but it works reliably.
    /// By passing arguments via stdin, we don't need to do shell-specific
    /// escaping to prevent interpreting any arguments.
    ///
    /// The biggest downside is, that we are occupying stdin, so this can not
    /// be used for interactive commands, but we don't need that for this tool
    /// anyway.
    fn make_command_string(&self, stdin: &mut Vec<u8>, args: Vec<String>) -> String {
        let mut command_string = String::new();
        command_string.push_str("set -eu;");

        for (i, arg) in args.iter().enumerate() {
            let bytes = arg.as_bytes();
            command_string.push_str(&format!(
                "a{i}=$(dd bs=1 count={} 2>/dev/null);",
                bytes.len()
            ));
            stdin.extend(bytes);
        }

        for (i, _) in args.iter().enumerate() {
            command_string.push_str(&format!("\"$a{i}\" "));
        }

        command_string
    }

    fn cmd<U>(&self, args: U, stdin: Option<&[u8]>) -> duct::Expression
    where
        U: IntoIterator,
        U::Item: Into<String>,
    {
        let args: Vec<String> = args.into_iter().map(|s| s.into()).collect();

        let mut final_stdin = Vec::<u8>::new();
        let command_string = self.make_command_string(&mut final_stdin, args);

        if let Some(stdin) = stdin {
            final_stdin.extend_from_slice(stdin);
        }

        let mut args_cmd = self.args.clone();
        args_cmd.push(command_string);

        duct::cmd(&args_cmd[0], &args_cmd[1..]).stdin_bytes(final_stdin)
    }

    fn read_file(&self, path: &std::path::Path) -> anyhow::Result<Vec<u8>> {
        let mut data = Vec::new();
        cmd!(self, None, "cat", path.to_str().context("non-UTF8 path")?)
            .reader()
            .context("Failed to read file")?
            .read_to_end(&mut data)
            .map(|_| data)
            .context("Failed to read file")
    }

    fn write_file(&mut self, location: &FileLocation, data: &[u8]) -> anyhow::Result<()> {
        let mut stdin = Vec::<u8>::new();
        let path = location.path.to_str().context("Non-UTF8 path")?;
        let path_bytes = path.as_bytes();
        stdin.extend_from_slice(path_bytes);
        stdin.extend_from_slice(data);

        // We read the path from stdin so we can handle special characters.
        // It's also kinda insane, that we spawn a shell again after everything
        // we did in the cmd macro to prevent that, but this prevents having to
        // duplicate code.
        cmd!(
            self,
            Some(&stdin),
            "sh",
            "-c",
            format!(
                "set -eu; umask 0277; path=$(dd bs=1 count={} 2>/dev/null); rm -f \"$path\"; cat > \"$path\"",
                path_bytes.len()
            )
        )
        .run()
        .context("Failed to write file")?;

        cmd!(self, None, "chown", &location.chown, path)
            .run()
            .context("Failed to chmod file")?;

        cmd!(self, None, "chmod", &location.chmod, path)
            .run()
            .context("Failed to chmod file")?;

        Ok(())
    }

    fn read_podman_secret_raw(&self, name: &str) -> anyhow::Result<Vec<u8>> {
        let mut data = Vec::new();
        cmd!(
            self,
            None,
            "podman",
            "secret",
            "inspect",
            "--showsecret",
            name
        )
        .reader()
        .context("Failed to read secret")?
        .read_to_end(&mut data)
        .map(|_| data)
        .context("Failed to read secret")
    }

    fn read_podman_secret(&self, name: &str) -> anyhow::Result<PodmanSecret> {
        let raw = self.read_podman_secret_raw(name)?;
        let secrets: [PodmanSecret; 1] = serde_json::from_slice(&raw)?;
        Ok(secrets.into_iter().nth(0).unwrap())
    }

    fn write_podman_secret(&mut self, name: &str, data: &[u8]) -> anyhow::Result<()> {
        cmd!(
            self,
            Some(data),
            "podman",
            "secret",
            "create",
            "--replace",
            name,
            "-"
        )
        .run()
        .context("Failed to write podman secret")
        .map(|_| ())
    }

    fn restart_service(&mut self, name: &str) -> anyhow::Result<()> {
        cmd!(self, None, "systemctl", "restart", name)
            .run()
            .context("Failed to restart service")
            .map(|_| ())
    }

    fn read(&self, location: &Location) -> anyhow::Result<Vec<u8>> {
        match location {
            Location::PodmanSecret(name) => {
                self.read_podman_secret(name).map(|s| s.data.into_bytes())
            }
            Location::File(location) => self.read_file(&location.path),
        }
    }

    fn write(&mut self, location: &Location, data: &[u8]) -> anyhow::Result<()> {
        match location {
            Location::PodmanSecret(name) => self.write_podman_secret(name, data),
            Location::File(location) => self.write_file(location, data),
        }
    }

    fn cert_needs_refresh(&self, key: &Key) -> anyhow::Result<bool> {
        let certs = match self.read(key.cert_location()?) {
            Ok(d) => d,
            Err(e) => {
                tracing::debug!("Failed to read current certificate: {e:#?}");
                return Ok(true);
            }
        };

        for pem in x509_parser::pem::Pem::iter_from_buffer(&certs) {
            let pem = pem.context("Reading next PEM block failed")?;
            let x509 = match pem.parse_x509() {
                Ok(d) => d,
                Err(_) => continue,
            };
            let time = x509.tbs_certificate.validity.time_to_expiration();
            if let Some(time) = &time {
                tracing::info!("Will expire in {time}");
            } else {
                tracing::warn!("Expired");
            }
            return Ok(match time {
                Some(d) if d <= time::Duration::HOUR => true,
                None => true,
                _ => false,
            });
        }

        anyhow::bail!("No certificate found");
    }
}

fn process_key(cli: &Cli, config: &Config, key: &Key) -> anyhow::Result<()> {
    let host = config.hosts.get(&key.host).context("Can't find host")?;
    let mut client = host.client();
    let common_name = &key.common_name;
    let ca_name = &key.ca;
    let key_type_str = key.r#type.name();
    let id = &key.id;

    let needs_refresh = client.cert_needs_refresh(key)?;
    if !cli.force && !needs_refresh {
        tracing::debug!("No refresh needed");
        return Ok(());
    }
    if !cli.update {
        return Ok(());
    }

    let mut ext_file = tempfile::Builder::new()
        .suffix(".conf")
        .tempfile()
        .context("failed to create ext file")?;
    match key.r#type {
        KeyType::Client => write!(
            &mut ext_file,
            "\
            basicConstraints = CA:FALSE\n\
            keyUsage = nonRepudiation, digitalSignature, keyEncipherment\n\
            extendedKeyUsage = clientAuth\n\
            subjectKeyIdentifier = hash\n\
            authorityKeyIdentifier = keyid,issuer\n\
            nsCertType = client\n\
        "
        )?,
        KeyType::Server => {
            write!(
                &mut ext_file,
                "\
                basicConstraints = CA:FALSE\n\
                keyUsage = digitalSignature, keyEncipherment\n\
                extendedKeyUsage = serverAuth,clientAuth\n\
                subjectKeyIdentifier = hash\n\
                authorityKeyIdentifier = keyid,issuer\n\
                subjectAltName = @alt_names\n\
                \n\
                [alt_names]\n\
                DNS.1 = {common_name}\n\
            "
            )?;

            for (index, domain) in key.additional_domains.iter().enumerate() {
                writeln!(&mut ext_file, "DNS.{} = {}", 2 + index, domain)?;
            }
        }
    }
    let ext_file_path = ext_file.path();

    let private_key = duct::cmd!("openssl", "genrsa", "-out", "-", key.key_size.to_string())
        .read()
        .context("Failed to generate key")?;
    let csr = duct::cmd!(
        "openssl",
        "req",
        "-new",
        "-key",
        "/dev/stdin",
        "-subj",
        format!("/CN={common_name}")
    )
    .stdin_bytes(private_key.as_bytes())
    .read()
    .context("Failed to create CSR")?;

    let date = duct::cmd!("date", "+%Y%m%d-%s-%N")
        .read()
        .context("Failed to create date-string")?;
    let local_cert_path = format!("certs/{ca_name}-{key_type_str}-{id}-{date}.pem");

    let cert = duct::cmd!(
        "openssl",
        "x509",
        "-engine",
        "pkcs11",
        "-req",
        "-CA",
        format!("ca-{ca_name}.pem"),
        "-CAkey",
        format!("pkcs11:object=CA-{ca_name};type=private"),
        "-CAkeyform",
        "engine",
        "-CAcreateserial",
        "-clrext",
        "-extfile",
        ext_file_path,
        "-days",
        "365",
        "-sha512",
        "-out",
        "-"
    )
    .env("OPENSSL_CONF", "openssl.conf")
    .stdin_bytes(csr)
    .read()
    .context("Failed to sign certificate")?;

    {
        let mut f =
            std::fs::File::create(&local_cert_path).context("Failed to create local cert file")?;
        f.write_all(cert.as_bytes())
            .context("Failed to write local cert file")?;
    }

    if let Some(location) = &key.cert {
        client.write(location, cert.as_bytes())?;
    }

    if let Some(location) = &key.key {
        client.write(location, private_key.as_bytes())?;
    }

    if let Some(location) = &key.combined {
        let combined = format!("{cert}{private_key}");
        client.write(location, combined.as_bytes())?;
    }

    if let Some(location) = &key.pfx {
        let mut pfx = Vec::new();
        duct::cmd!(
            "openssl",
            "pkcs12",
            "-export",
            "-out",
            "-",
            "-inkey",
            "-in",
            private_key,
            "-certfile",
            &local_cert_path
        )
        .reader()
        .context("Failed to spawn pfx generator")?
        .read_to_end(&mut pfx)
        .context("Failed to generate pfx")?;

        client.write(location, &pfx)?;
    }

    if let Some(service) = &key.service {
        client
            .restart_service(service)
            .context("failed to restart service")?;
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();

    tracing::trace!("Hello");

    let file = std::fs::File::open(&cli.config).context("Failed to open config file")?;
    let config: Config = ron::de::from_reader(file).context("Failed to parse config file")?;

    for key in &config.keys {
        let span = tracing::span!(tracing::Level::ERROR, "key", id = key.id);
        let _enter = span.enter();

        if let Some(id) = &cli.id {
            if key.id != *id {
                tracing::debug!("Skip due to id filter");
                continue;
            }
        }

        if !cli.include_tag.is_empty() && !cli.include_tag.iter().any(|t| key.tags.contains(t)) {
            tracing::debug!("Skip due to include-tag");
            continue;
        }

        if cli.exclude_tag.iter().any(|t| key.tags.contains(t)) {
            tracing::debug!("Skip due to exclude-tag");
            continue;
        }

        if let Err(e) = process_key(&cli, &config, key) {
            tracing::error!("{e:#}");
        }
    }

    tracing::trace!("Done");

    Ok(())
}
