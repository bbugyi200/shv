//! (S)hell (H)istory (V)iewer

#[macro_use]
extern crate log;


use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{exit, Command};

use regex::Regex;


pub mod datetime;
pub mod shr;

pub mod errors {
    use std::fmt;

    #[derive(Debug)]
    pub struct ShvError {
        emsg: String,
    }

    impl From<String> for ShvError {
        fn from(emsg: String) -> Self { Self { emsg } }
    }

    impl fmt::Display for ShvError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.emsg)
        }
    }
}


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

    App::new("shv")
        .version("0.1.2")
        .author("Bryan Bugyi <bryanbugyi34@gmail.com>")
        .about("(S)hell (H)istory (V)iewer")
        // ----- ARGUMENTS
        .arg(
            Arg::with_name("regexp").takes_value(true).help(
                "Filter logs by command string using a regular expression.",
            ),
        )
        // ----- FLAGS
        .arg(
            Arg::with_name("all")
                .short("a")
                .long("all")
                .help("Report all matching commands, including duplicates."),
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .multiple(true)
                .help("Increase verbosity level."),
        )
        // ----- OPTIONS
        .arg(
            Arg::with_name("daterange")
                .short("D")
                .long("daterange")
                .takes_value(true)
                .max_values(2)
                .require_delimiter(true)
                .value_delimiter(":")
                .help(
                    "Filter logs by using a daterange of the form \
                     START[:END]. Defaults to parsing all logs. If only the \
                     START date is given, the end range is automatically set \
                     to \"EOT\". Accepts dates of the form YYYY-MM-DD, \
                     YYYY-MM, YYYY, MM-DD, MM, and the special values \"BOT\" \
                     (beginning-of-time) and \"EOT\" (end-of-time). Lastly, \
                     this option will also accept arguments of the form: \
                     \"Nd\", \"Nw\", \"Nm\" or  \"Ny\". These are interpreted \
                     as datetimes corresponding to N days/weeks/months/years \
                     ago.",
                ),
        )
        .arg(
            Arg::with_name("hostname")
                .short("H")
                .long("hostname")
                .takes_value(true)
                .help(
                    "Filter logs by the machine's hostname. If this option is \
                     not provided, logs from all known hostnames are \
                     processed.",
                ),
        )
        .arg(
            Arg::with_name("username")
                .short("u")
                .long("username")
                .takes_value(true)
                .help("Filter logs by username."),
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

    args = parse_cli_args(vec!["shv", "-vv"]);
    assert_eq!(args.occurrences_of("verbose"), 2);

    args = parse_cli_args(vec!["shv", "-D", "BOT:EOT"]);
    let mut values = args.values_of("daterange").unwrap();
    assert_eq!(values.next(), Some("BOT"));
    assert_eq!(values.next(), Some("EOT"));
    assert_eq!(values.next(), None);

    args = parse_cli_args(vec!["shv", "^pig$"]);
    assert_eq!(args.value_of("regexp").unwrap(), "^pig$");
    assert_eq!(args.value_of("view_report").unwrap(), "y");

    args = parse_cli_args(vec!["shv", "--view-report", "n"]);
    assert_eq!(args.value_of("view_report").unwrap(), "n");

    args = parse_cli_args(vec!["shv", "-w", "/home/bryan"]);
    assert_eq!(args.value_of("wdir").unwrap(), "/home/bryan");
    assert_eq!(args.value_of("regexp"), None);
}


fn run<I, T>(argv: I)
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args = parse_cli_args(argv);
    init_logger(args.occurrences_of("verbose") as u8);

    let tmp_file = tempfile::Builder::new()
        .prefix("shv-")
        .suffix(".log")
        .tempfile()
        .unwrap();
    let fp_results = tmp_file.path();

    let dp_shell_history = {
        let shell_history_root = std::env::var("SHV_SHELL_HISTORY_ROOT")
            .unwrap_or_else(|_| {
                eprintln!(
                    "shv: In order to run shv, the SHV_SHELL_HISTORY_ROOT \
                     environment variable must first be set."
                );
                exit(1);
            });

        PathBuf::from(&shell_history_root)
    };

    if !dp_shell_history.exists() {
        eprintln!(
            "shv: The {:?} directory specified by the \
             SHV_SHELL_HISTORY_ROOT environment variable does not exist.",
            dp_shell_history
        );
        exit(1);
    }

    let wdir = match args.value_of("wdir") {
        Some(dir) => Some(Path::new(dir)),
        None => None,
    };

    let tz = datetime::get_timezone();
    let parse_cli_date = |dts| {
        datetime::parse_cli_date(dts, &tz).unwrap_or_else(|e| {
            eprintln!("shv: {}", e);
            exit(1);
        })
    };
    let (date_start, date_end) = match args.values_of("daterange") {
        Some(mut values) => {
            let start = if let Some(dts) = values.next() {
                parse_cli_date(dts)
            } else {
                parse_cli_date("BOT")
            };

            let end = if let Some(dts) = values.next() {
                parse_cli_date(dts)
            } else {
                parse_cli_date("EOT")
            };

            (start, end)
        }
        None => (parse_cli_date("BOT"), parse_cli_date("EOT")),
    };

    let hostname = if let Some(hn) = args.value_of("hostname") {
        hn.to_string()
    } else {
        "ALL".to_string()
    };

    let regexp_str = if let Some(re) = args.value_of("regexp") {
        re
    } else {
        ".*"
    };

    let regexp = Regex::new(regexp_str).unwrap_or_else(|e| {
        eprintln!(
            "shv: There was a problem compiling the regular expression \
             \"{}\": {}",
            regexp_str, e
        );
        exit(1);
    });

    shr::build(
        &dp_shell_history,
        fp_results,
        (date_start, date_end, &tz),
        args.value_of("username"),
        wdir,
        &hostname,
        regexp,
        !args.is_present("all"),
    )
    .expect(
        "An unrecoverable error occurred while building the shv.log report.",
    );

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

        let editor_cmd = if Regex::new("vim").unwrap().is_match(&editor) {
            base_editor_cmd.arg("+")
        } else {
            &mut base_editor_cmd
        };

        editor_cmd.arg(fp_results).status().unwrap_or_else(|e| {
            eprintln!(
                "shv: Unable to open {:?} using the {} editor: {}",
                fp_results, editor, e
            );
            exit(1);
        });
    }
}


fn main() { run(std::env::args()) }
