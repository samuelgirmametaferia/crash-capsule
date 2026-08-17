//! Regenerates the committed specification corpus.

use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let root = cc_vectors::repository_root();
    let mut written = 0usize;

    for (path, contents) in cc_vectors::generated_files() {
        let absolute = root.join(&path);
        if let Some(parent) = absolute.parent() {
            if let Err(error) = fs::create_dir_all(parent) {
                eprintln!("cannot create {}: {error}", parent.display());
                return ExitCode::FAILURE;
            }
        }
        if fs::read(&absolute).is_ok_and(|existing| existing == contents) {
            continue;
        }
        if let Err(error) = fs::write(&absolute, &contents) {
            eprintln!("cannot write {}: {error}", absolute.display());
            return ExitCode::FAILURE;
        }
        println!("wrote {}", path.display());
        written += 1;
    }

    println!("{written} file(s) changed");
    ExitCode::SUCCESS
}
