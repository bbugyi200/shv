extern crate clap;

fn main() {
    let matches = clap::App::new("vshlog")
        .version("0.1")
        .author("Bryan Bugyi <bryanbugyi34@gmail.com>")
        .about("\nView your Shell History with Vim")
        .arg(
            clap::Arg::with_name("verbose")
            .short("v")
            .long("verbose")
            .multiple(true)
            .help("Increase verbosity level. Can be used multiple times.")
        )
        .get_matches();
}
