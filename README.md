What was that `gpg` option again? I guess I'll look it up... Again... For the thousandth time. Right? Wrong!

# (S)hell (H)istory (V)iewer
`shv` is a CLI program that sorts and filters your shell history based on properties specified via command-line options. Some of these properties include: a regular expression on the command, a date range of when the command was executed, the directory that the command was executed from, and more,

### Installation
#### From Source
Run the following commands to install `shv` from source:
```
git clone https://github.com/bbugyi200/shv
cd shv
cargo built --release
cp target/release/shv shw.sh ~/.cargo/bin/
```
Then add the following line to your `.zshrc` (or `.bashrc` if you have [bash-preexec](https://github.com/rcaloras/bash-preexec) installed):
```
preexec() { log_shell_history &> /dev/null "$1"; }
```
