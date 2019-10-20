use chrono::prelude::*;
use chrono::Duration;

use std::process::Command;
use regex::Regex;

use crate::errors::*;


pub fn days_in_month(month: u32, year: i32) -> Duration {
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


pub fn get_today(tz: &str) -> Date<FixedOffset> {
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


pub fn get_timezone() -> Result<String> {
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


pub fn get_timezone_offset(tz: &str) -> Result<i32> {
    Ok(tz.to_string().parse::<i32>()? / 100)
}

#[test]
fn test_get_timezone_offset() {
    assert_eq!(get_timezone_offset("-0400").unwrap(), -4);
}


pub fn parse_datetime(
    dts: &str,
    dt_fmt: &str,
    tz: &str,
) -> Result<DateTime<FixedOffset>> {
    let full_date = format!("{} {}", dts, tz);
    let datetime =
        DateTime::parse_from_str(&full_date, &format!("{} %z", dt_fmt))?;
    Ok(datetime)
}

pub fn parse_date(dts: &str, dt_fmt: &str, tz: &str) -> Result<Date<FixedOffset>> {
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


pub fn parse_cli_date(date_spec: &str, tz: &str) -> Result<Date<FixedOffset>> {
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
                            - days_in_month(rel_date.month(), rel_date.year());
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

    let assert_ymd = |dts, y, m, d| {
        let date = match parse_cli_date(dts, tz) {
            Ok(d) => d,
            Err(e) => panic!("[{}]: {:?}", dts, e),
        };

        let emsg = |t, actual, expected| {
            String::from(format!(
                "{}: {}[actual({}) != expected({})]",
                dts, t, actual, expected
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
