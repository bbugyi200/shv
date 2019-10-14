//! View your shell history with vim.

#[macro_use]
extern crate error_chain;

#[macro_use]
extern crate log;

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use chrono::prelude::*;
use chrono::Duration;
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


fn process_logfile(
    fp_log: &Path,
    (date_start, date_end, tz): (Date<FixedOffset>, Date<FixedOffset>, &str),
    regexp: &Regex,
    username: Option<&str>,
    wdir: Option<&Path>,
    (unique, command_registry): (bool, &mut HashSet<String>),
    check_date: bool,
) -> Result<Vec<String>> {
    let f_log = fs::File::open(fp_log)?;
    let reader = std::io::BufReader::new(f_log);

    let mut matched_lines = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let v: Vec<_> = line.trim().splitn(5, ':').collect();

        if v.len() != 5 {
            warn!("Log line has bad format: {:?}", v);
            continue;
        }

        let (hostname, user, dts, wd, cmd) = (v[0], v[1], v[2], v[3], v[4]);

        let parse_log_datetime = |dts| parse_datetime(dts, "%Y%m%d%H%M%S", tz);

        let mut conditions = vec![
            username == None || username == Some(user),
            (wdir == None) || (wdir == Some(Path::new(wd))),
            regexp.is_match(cmd),
            !unique || !command_registry.contains(cmd),
        ];

        let mut maybe_dt = None;
        if check_date {
            maybe_dt = Some(parse_log_datetime(dts)?);
            let date = maybe_dt.unwrap().date();
            conditions.push((date >= date_start) && (date <= date_end));
        }

        if conditions.iter().all(|cond| *cond) {
            let dt = match maybe_dt {
                Some(datetime) => datetime,
                None => parse_log_datetime(dts)?,
            };

            let pretty_line = format!(
                "[{}] ({}@{}) {}\n\t{}\n\n",
                dt.format("%Y-%m-%d %H:%M:%S").to_string(),
                user,
                hostname,
                wd,
                cmd,
            );

            matched_lines.push(pretty_line.to_string());

            if unique {
                command_registry.insert(cmd.to_string());
            }
        }
    }

    Ok(matched_lines)
}


fn days_in_month(month: u8, year: u16) -> Duration {
    Duration::days(match month {
        2 => {
            if year % 4 == 0 {
                if year % 100 != 0 {
                    29
                } else {
                    if year % 400 == 0 {
                        29
                    } else {
                        28
                    }
                }
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    })
}


fn get_hostname_paths(dp_shell_history: &Path) -> Result<Vec<Box<PathBuf>>> {
    let mut hostname_paths = Vec::new();
    for entry in fs::read_dir(dp_shell_history)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            hostname_paths.push(Box::new(path));
        }
    }

    Ok(hostname_paths)
}

#[test]
#[ignore]
fn test_get_hostname_paths() {
    let dp_shell_history =
        Path::new("/home/bryan/Dropbox/var/logs/shell-history");
    let mut hostname_paths = get_hostname_paths(dp_shell_history).unwrap();

    assert_eq!(
        hostname_paths.pop(),
        Some(Box::new(PathBuf::from(
            "/home/bryan/Dropbox/var/logs/shell-history/aphrodite"
        )))
    );
}


fn merge_hosts(
    dp_shell_history: &Path,
    year: u16,
    month: u8,
) -> Result<PathBuf> {
    assert!(dp_shell_history.is_dir());

    let hostname_paths = get_hostname_paths(&dp_shell_history)?;
    let mut all_log_paths = Vec::new();
    for hpath in hostname_paths {
        let relative_log_path = format!("{}/{:02}.log", year, month);
        let absolute_log_path = hpath.join(relative_log_path);
        if absolute_log_path.exists() {
            all_log_paths.push(absolute_log_path);
        }
    }

    let fp_log =
        PathBuf::from(&format!("/tmp/vshlog/{}/{:02}.log", year, month));

    if all_log_paths.len() > 0 {
        let dp_parent = fp_log.parent().unwrap();
        fs::create_dir_all(dp_parent)?;

        let mut cat_cmd = Command::new("cat");
        let mut maybe_full_cat_cmd = None;
        for log_path in all_log_paths {
            maybe_full_cat_cmd = Some(cat_cmd.arg(log_path.to_str().unwrap()));
        }

        let f_log = fs::File::create(&fp_log)?;

        if let Some(full_cat_cmd) = maybe_full_cat_cmd {
            let cat_ps = full_cat_cmd.stdout(Stdio::piped()).spawn().unwrap();
            let mut sort_ps = Command::new("sort")
                .arg("-t:")
                .arg("-k")
                .arg("3n")
                .stdin(cat_ps.stdout.unwrap())
                .stdout(Stdio::from(f_log))
                .spawn()
                .unwrap();
            sort_ps.wait().unwrap();
        }
    }

    Ok(fp_log)
}


/// Creates and fills /tmp/vshlog/vshlog.log.
fn build_custom_log(
    dp_shell_history: &Path,
    fp_results: &Path,
    (date_start, date_end, tz): (Date<FixedOffset>, Date<FixedOffset>, &str),
    username: Option<&str>,
    wdir: Option<&Path>,
    hostname: String,
    regexp: Regex,
    unique: bool,
) -> Result<()> {
    fs::File::create(fp_results)?.write_all(b"# vim: filetype=vshlog\n\n")?;

    fn date_ym_value(date: Date<FixedOffset>) -> u32 {
        ((date.year() * 100) as u32) + (date.month() as u32)
    }

    let mut f_results = fs::OpenOptions::new().append(true).open(fp_results)?;

    let mut date = date_start.clone();
    let mut entry_count = 0;

    let mut command_registry = HashSet::new();
    while date_ym_value(date) <= date_ym_value(date_end) {
        let fp_log = if hostname.to_lowercase() == "all" {
            merge_hosts(
                &dp_shell_history,
                date.year() as u16,
                date.month() as u8,
            )?
        } else {
            let relative_log_path =
                format!("{}/{}/{:02}.log", hostname, date.year(), date.month());
            let absolute_log_path = dp_shell_history.join(relative_log_path);
            PathBuf::from(&absolute_log_path)
        };

        let check_date = {
            let is_start_month = (date.year() == date_start.year())
                && (date.month() == date_start.month());

            let is_end_month = (date.year() == date_end.year())
                && (date.month() == date_end.month());

            is_start_month || is_end_month
        };

        if fp_log.exists() {
            let log_lines = process_logfile(
                &fp_log,
                (date_start, date_end, tz),
                &regexp,
                username,
                wdir,
                (unique, &mut command_registry),
                check_date,
            )?;

            entry_count += log_lines.len();

            for line in log_lines {
                write!(&mut f_results, "{}", line)?;
            }
        }

        date = date + days_in_month(date.month() as u8, date.year() as u16);
    }

    write!(
        &mut f_results,
        "# Number of shell commands matched by vshlog query:  {}",
        entry_count,
    )?;

    Ok(())
}


fn get_today(tz: &str) -> Date<FixedOffset> {
    let utc_time = Utc::now();
    let tz_offset = get_timezone_offset(tz).unwrap();
    let east_tz = FixedOffset::east(tz_offset * 3600);
    utc_time.with_timezone(&east_tz).date()
}

#[test]
#[ignore]
fn test_get_today() {
    assert_eq!(get_today("-0400").year(), 2019);
    assert_eq!(get_today("-0400").month(), 10);
    assert_eq!(get_today("-0400").day(), 13);
}


fn get_timezone() -> Result<String> {
    let ps = Command::new("date")
        .arg("+%z")
        .output()
        .expect("'date' command failed");

    Ok(String::from_utf8(ps.stdout)?.trim().to_string())
}

#[test]
#[ignore]
fn test_get_timezone() {
    assert_eq!(get_timezone().unwrap(), "-0400");
}


fn get_timezone_offset(tz: &str) -> Result<i32> {
    Ok(tz.to_string().parse::<i32>()? / 100)
}

#[test]
fn test_get_timezone_offset() {
    assert_eq!(get_timezone_offset("-0400").unwrap(), -4);
}


fn parse_datetime(
    dts: &str,
    dt_fmt: &str,
    tz: &str,
) -> Result<DateTime<FixedOffset>> {
    let full_date = format!("{} {}", dts, tz);
    let datetime =
        DateTime::parse_from_str(&full_date, &format!("{} %z", dt_fmt))?;
    Ok(datetime)
}

fn parse_date(dts: &str, dt_fmt: &str, tz: &str) -> Result<Date<FixedOffset>> {
    Ok(parse_datetime(dts, dt_fmt, tz)?.date())
}

#[test]
fn test_parse_date() {
    let today = parse_date("2019-10-01 00:00:00", "%Y-%m-%d %H:%M:%S", "-0400")
        .unwrap();

    assert_eq!(today.year(), 2019);
    assert_eq!(today.month(), 10);
    assert_eq!(today.day(), 1);

    let tomorrow = today + Duration::days(1);
    assert_eq!(tomorrow.day(), 2);
}


fn parse_cli_date(date_spec: &str, tz: &str) -> Result<Date<FixedOffset>> {
    let date_spec = date_spec.to_uppercase();
    let today = get_today(tz);
    let is_match = |pttrn, expr| Regex::new(pttrn).unwrap().is_match(expr);
    let dts: std::borrow::Cow<str> = match date_spec.as_ref() {
        "BOT" => "2017-01-01".into(),
        "EOT" => return Ok(today),
        mmdd if is_match("^[0-9][0-9]?-[0-9][0-9]?$", mmdd) => {
            format!("{}-{}", today.year(), mmdd).into()
        }
        yyyymmdd
            if is_match(
                "^[2-9][0-9]{3}-[0-9][0-9]?-[0-9][0-9]?$",
                yyyymmdd,
            ) =>
        {
            yyyymmdd.into()
        }
        yyyymm if is_match("^[2-9][0-9]{3}-[0-9][0-9]?$", yyyymm) => {
            format!("{}-01", yyyymm).into()
        }
        mm if is_match("^[0-9][0-9]?$", mm) => {
            format!("{}-{}-01", today.year(), mm).into()
        }
        yyyy if is_match("^[2-9][0-9]{3}$", yyyy) => {
            format!("{}-01-01", yyyy).into()
        }
        relative_date if is_match("^[1-9][0-9]*(D|M|Y)$", relative_date) => {
            let mut n_string = relative_date.to_string();
            let ch = n_string.pop();
            let n: i64 = n_string.parse().unwrap();
            let mut rel_date = today;

            return Ok(match ch {
                Some('D') => today - Duration::days(n),
                Some('M') => {
                    for _ in 0..n {
                        rel_date = rel_date
                            - days_in_month(
                                rel_date.year() as u8,
                                rel_date.month() as u16,
                            );
                    }
                    rel_date
                }
                Some('Y') => {
                    for _ in 0..n {
                        rel_date = rel_date - Duration::days(365);
                    }
                    rel_date
                }
                _ => panic!("Error in relative_date regular expression."),
            });
        }
        _ => {
            let emsg = format!("Unsupported date format: {}", date_spec);
            return Err(emsg.into());
        }
    };
    trace!("dts = {:?}", dts);

    parse_date(&format!("{} 00:00:00", dts), "%Y-%m-%d %H:%M:%S", tz)
}

#[test]
fn test_parse_cli_date() {
    let tz = "-0400";
    let today = get_today(tz);

    let mut assert_ymd = |dts, y, m, d| {
        let date = match parse_cli_date(dts, tz) {
            Ok(d) => d,
            Err(e) => panic!("[{}]: {:?}", dts, e),
        };

        let emsg = |T, actual, expected| {
            String::from(format!(
                "{}: {}[actual({}) != expected({})]",
                dts, T, actual, expected
            ))
        };

        let year = date.year();
        assert!(year == y, emsg("Years", year, y));

        let month = date.month();
        assert!(month == m, emsg("Months", month as i32, m as i32));

        let day = date.day();
        assert!(day == d, emsg("Days", day as i32, d as i32));
    };

    assert_ymd("bot", 2017, 1, 1);
    assert_ymd("eot", today.year(), today.month(), today.day());
    assert_ymd("05-20", today.year(), 5, 20);
    assert_ymd("2019-10-15", 2019, 10, 15);
    assert_ymd("2019-10", 2019, 10, 1);
    assert_ymd("3", today.year(), 3, 1);
    assert_ymd("2017", 2017, 1, 1);

    let assert_relative = |dts| {
        let emsg = format!("RelativeDate({})", dts);
        assert!(
            if let Ok(_) = parse_cli_date(dts, tz) {
                true
            } else {
                false
            },
            emsg
        );
    };

    assert_relative("1d");
    assert_relative("15d");
    assert_relative("3m");
    assert_relative("12m");
    assert_relative("2y");
    assert_relative("10y");
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

    let tz = get_timezone()?;
    let parse = |dts| parse_cli_date(dts, &tz);
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

    build_custom_log(
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

    fs::remove_file(fp_results)?;

    Ok(())
}
