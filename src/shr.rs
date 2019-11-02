//! (S)hell (H)istory (R)eader

use std::collections::HashSet;
use std::fs;
use std::io;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use chrono::prelude::*;
use regex::Regex;

use crate::datetime;


fn process_logfile(
    fp_log: &Path,
    (date_start, date_end, tz): (Date<FixedOffset>, Date<FixedOffset>, &str),
    regexp: &Regex,
    username: Option<&str>,
    wdir: Option<&Path>,
    (unique, command_registry): (bool, &mut HashSet<String>),
    check_date: bool,
) -> Result<Vec<String>, io::Error> {
    let f_log = fs::File::open(fp_log)?;
    let reader = std::io::BufReader::new(f_log);

    let mut matched_lines = Vec::new();

    let mut i = 0; // Tracks line number.
    for line in reader.lines() {
        i += 1;

        let line = line?;
        let v: Vec<_> = line.trim().splitn(5, ':').collect();

        if v.len() != 5 {
            warn!("({:?}:{}) Log line has bad format => {:?}", fp_log, i, v);
            continue;
        }

        let (hostname, user, dts, wd, cmd) = (v[0], v[1], v[2], v[3], v[4]);

        let parse_log_datetime =
            |dts| datetime::parse_datetime(dts, "%Y%m%d%H%M%S", tz);

        let mut conditions = vec![
            username == None || username == Some(user),
            wdir == None || wdir == Some(Path::new(wd)),
            regexp.is_match(cmd),
            !unique || !command_registry.contains(cmd),
        ];

        let mut maybe_dt = None;
        if check_date {
            maybe_dt = Some(parse_log_datetime(dts).unwrap());
            let date = maybe_dt.unwrap().date();
            conditions.push(date_start <= date && date <= date_end);
        }

        if conditions.iter().all(|cond| *cond) {
            let dt = match maybe_dt {
                Some(datetime) => datetime,
                None => parse_log_datetime(dts).unwrap(),
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


fn get_hostname_paths(
    dp_shell_history: &Path,
) -> Result<Vec<Box<PathBuf>>, io::Error> {
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
    hostname_paths: &Vec<Box<PathBuf>>,
    (year, this_year): (i32, i32),
    (month, this_month): (u32, u32),
) -> Result<PathBuf, io::Error> {
    let fp_log = PathBuf::from(
        dp_shell_history.join(&format!("ALL/{}/{:02}.log", year, month)),
    );

    let is_current_log = (year == this_year) && (month == this_month);

    if fp_log.exists() && !is_current_log {
        return Ok(fp_log);
    }

    let mut all_log_paths = Vec::new();
    for hpath in hostname_paths {
        let relative_log_path = format!("{}/{:02}.log", year, month);
        let absolute_log_path = hpath.join(relative_log_path);
        if absolute_log_path.exists() {
            all_log_paths.push(absolute_log_path);
        }
    }

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


/// Creates and fills the final report file (/tmp/shv/shv.log).
pub fn build(
    dp_shell_history: &Path,
    fp_results: &Path,
    (date_start, date_end, tz): (Date<FixedOffset>, Date<FixedOffset>, &str),
    username: Option<&str>,
    wdir: Option<&Path>,
    hostname: &str,
    regexp: Regex,
    unique: bool,
) -> Result<(), io::Error> {
    fs::File::create(fp_results)?.write_all(b"# vim: filetype=shv\n\n")?;

    fn date_ym_value(date: Date<FixedOffset>) -> u32 {
        ((date.year() * 100) as u32) + (date.month() as u32)
    }

    let mut f_results = fs::OpenOptions::new().append(true).open(fp_results)?;

    let mut date = date_start.clone();
    let mut entry_count = 0;

    let hostname_paths = get_hostname_paths(&dp_shell_history)?;
    let (this_year, this_month) = {
        let today = datetime::get_today(&tz);
        (today.year(), today.month())
    };

    let mut command_registry = HashSet::new();
    while date_ym_value(date) <= date_ym_value(date_end) {
        let fp_log = if hostname.to_lowercase() == "all" {
            merge_hosts(
                dp_shell_history,
                &hostname_paths,
                (date.year(), this_year),
                (date.month(), this_month),
            )?
        } else {
            let relative_log_path =
                format!("{}/{}/{:02}.log", hostname, date.year(), date.month());
            let absolute_log_path = dp_shell_history.join(relative_log_path);
            PathBuf::from(&absolute_log_path)
        };

        if fp_log.exists() {
            let check_date = {
                let is_start_month = (date.year() == date_start.year())
                    && (date.month() == date_start.month());

                let is_end_month = (date.year() == date_end.year())
                    && (date.month() == date_end.month());

                is_start_month || is_end_month
            };

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

        date = date + datetime::days_in_month(date.month(), date.year());
    }

    write!(
        &mut f_results,
        "# Number of shell commands matched by shv query:  {}",
        entry_count,
    )?;

    Ok(())
}
