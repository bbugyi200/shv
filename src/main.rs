//! View your shell history with vim.

#[macro_use]
extern crate error_chain;

#[macro_use]
extern crate log;

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

mod errors {
    error_chain! {
        foreign_links {
            Io(std::io::Error);
            Var(std::env::VarError);
        }
    }
}

use crate::errors::*;

fn build_custom_log(
    _dp_shell_history: &Path,
    _fp_results: &Path,
    _daterange: (Option<&str>, Option<&str>),
    _username: Option<&str>,
    _wdir: Option<&Path>,
    _hostname: Option<&str>,
    _regexp: Option<&str>,
    _unique: bool,
) {

}

fn parse_cli_args<'a, I, T>(argv: I) -> clap::ArgMatches<'a>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    use clap::{App, Arg};

    App::new("vshlog")
        .version("0.1.0")
        .author("Bryan Bugyi <bryanbugyi34@gmail.com>")
        .about("View your shell history with vim.")
        .arg(
            Arg::with_name("daterange")
                .short("D")
                .long("daterange")
                .multiple(true)
                .takes_value(true)
                .help("Filter logs by using a daterange."),
        )
        .arg(
            Arg::with_name("hostname")
                .short("H")
                .long("hostname")
                .takes_value(true)
                .help("Filter logs by the machine's hostname."),
        )
        .arg(
            Arg::with_name("regexp")
                .short("e")
                .long("regexp")
                .takes_value(true)
                .help(
                    "Filter logs by command string using a regular expression",
                ),
        )
        .arg(Arg::with_name("unique").short("u").long("unique").help(
            "Filter out duplicate entries where two entries are \
             considered to be duplicats if their command strings are \
             the same.",
        ))
        .arg(
            Arg::with_name("username")
                .short("U")
                .long("username")
                .help("Filter logs by username."),
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .multiple(true)
                .help("Increase verbosity level."),
        )
        .arg(
            Arg::with_name("view_report")
                .long("view-report")
                .takes_value(true)
                .possible_values(&["y", "n"])
                .default_value("y")
                .help("View final report of matched shell commands."),
        )
        .arg(
            Arg::with_name("wdir")
                .short("w")
                .long("working-dir")
                .takes_value(true)
                .value_name("DIR")
                .help(
                    "Filter logs by what directory the user was in when the \
                     command was run.",
                ),
        )
        .get_matches_from(argv)
}

#[test]
fn test_parse_cli_args() {
    let mut args;

    args = parse_cli_args(vec!["vshlog", "-vv"]);
    assert_eq!(args.occurrences_of("verbose"), 2);

    args = parse_cli_args(vec!["vshlog", "-D", "BOT", "EOT"]);
    let mut values = args.values_of("daterange").unwrap();
    assert_eq!(values.next(), Some("BOT"));
    assert_eq!(values.next(), Some("EOT"));
    assert_eq!(values.next(), None);

    args = parse_cli_args(vec!["vshlog", "-e", "^pig$"]);
    assert_eq!(args.value_of("regexp").unwrap(), "^pig$");
    assert_eq!(args.value_of("view_report").unwrap(), "y");

    args = parse_cli_args(vec!["vshlog", "--view-report", "n"]);
    assert_eq!(args.value_of("view_report").unwrap(), "n");

    args = parse_cli_args(vec!["vshlog", "-w", "/home/bryan"]);
    assert_eq!(args.value_of("wdir").unwrap(), "/home/bryan");
    assert_eq!(args.value_of("regexp"), None);
}

fn main() -> Result<()> {
    let args = parse_cli_args(std::env::args());

    let log_level = match args.occurrences_of("verbose") {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };

    std::env::set_var("RUST_LOG", log_level);

    env_logger::init();
    match log_level {
        "debug" => debug!("Debug mode is enabled."),
        "trace" => trace!("Trace mode is enabled."),
        _ => (),
    }

    let fp_results = Path::new("/tmp/vshlog/vshlog.log");
    let dp_results = fp_results.parent().unwrap();

    fs::create_dir_all(dp_results)?;

    let dp_shell_history = {
        let home = std::env::var("HOME")?;
        let shell_history_dir =
            format!("{}/Dropbox/var/logs/shell-history", home);
        PathBuf::from(&shell_history_dir)
    };

    assert!(
        dp_shell_history.exists(),
        "{:?} directory does not exist!",
        dp_shell_history
    );

    let wdir = match args.value_of("wdir") {
        Some(dir) => Some(Path::new(dir)),
        None => None,
    };

    let daterange = match args.values_of("daterange") {
        Some(mut values) => {
            let start = values.next();
            let end = values.next();
            (start, end)
        }
        None => (None, None),
    };

    build_custom_log(
        &dp_shell_history,
        &fp_results,
        daterange,
        args.value_of("username"),
        wdir,
        args.value_of("hostname"),
        args.value_of("regexp"),
        args.is_present("unique"),
    );

    assert!(
        fp_results.exists(),
        "The file {:?} does not exist!",
        fp_results
    );

    if args.value_of("view_report").unwrap() == "y" {
        Command::new("vim")
            .arg("+")
            .arg(fp_results)
            .status()
            .expect("vim command failed");
    }

    fs::remove_file(fp_results)?;

    Ok(())
}
