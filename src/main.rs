//! View your shell history with vim.

#[macro_use]
extern crate error_chain;

#[macro_use]
extern crate log;


use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gethostname::gethostname;
use regex::Regex;


mod errors {
    error_chain! {
        foreign_links {
            ChronoParse(chrono::format::ParseError);
            Io(std::io::Error);
            FromUtf8(std::string::FromUtf8Error);
            ParseInt(std::num::ParseIntError);
            Regex(regex::Error);
            Var(std::env::VarError);
        }
    }
}
use crate::errors::*;

mod datetime;
mod report;


fn init_logger(verbose_count: u8) {
    let log_level = if let Ok(level) = std::env::var("RUST_LOG") {
        level
    } else {
        let cli_level = match verbose_count {
            0 => "info",
            1 => "debug",
            _ => "trace",
        };

        std::env::set_var("RUST_LOG", cli_level);
        cli_level.to_string()
    };

    env_logger::init();
    match log_level.as_ref() {
        "debug" => debug!("Debug mode is enabled."),
        "trace" => trace!("Trace mode is enabled."),
        _ => (),
    }
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
            "Filter out duplicate entries where two entries are considered to \
             be duplicats if their command strings are the same.",
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
                    "Filter logs by what directory the user was in when the  \
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
    init_logger(args.occurrences_of("verbose") as u8);

    let fp_results = Path::new("/tmp/vshlog/vshlog.log");
    let dp_results = fp_results.parent().unwrap();

    fs::create_dir_all(dp_results)?;

    let dp_shell_history = {
        let shell_history_root = std::env::var("VSHLOG_SHELL_HISTORY_ROOT")?;
        PathBuf::from(&shell_history_root)
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

    let tz = datetime::get_timezone()?;
    let parse = |dts| datetime::parse_cli_date(dts, &tz);
    let (date_start, date_end) = match args.values_of("daterange") {
        Some(mut values) => {
            let start = if let Some(dts) = values.next() {
                parse(dts)?
            } else {
                parse("BOT")?
            };

            let end = if let Some(dts) = values.next() {
                parse(dts)?
            } else {
                parse("EOT")?
            };

            (start, end)
        }
        None => (parse("BOT")?, parse("EOT")?),
    };

    let hostname = if let Some(hn) = args.value_of("hostname") {
        hn.to_string()
    } else {
        gethostname().into_string().unwrap()
    };

    let regexp_str = if let Some(re) = args.value_of("regexp") {
        re
    } else {
        ".*"
    };

    let regexp = Regex::new(regexp_str).expect("bad regular expession pattern");

    report::build(
        &dp_shell_history,
        &fp_results,
        (date_start, date_end, &tz),
        args.value_of("username"),
        wdir,
        hostname,
        regexp,
        args.is_present("unique"),
    )
    .expect("failed to build vshlog.log");

    assert!(
        fp_results.exists(),
        "The file {:?} does not exist!",
        fp_results
    );

    if args.value_of("view_report").unwrap() == "y" {
        let editor = match std::env::var("EDITOR") {
            Ok(val) => val,
            Err(_) => "vim".to_string(),
        };

        let mut base_editor_cmd = Command::new(&editor);

        let editor_cmd = if Regex::new("vim")?.is_match(&editor) {
            base_editor_cmd.arg("+")
        } else {
            &mut base_editor_cmd
        };

        editor_cmd
            .arg(fp_results)
            .status()
            .expect(&format!("{} command failed", editor));
    }

    Ok(())
}
