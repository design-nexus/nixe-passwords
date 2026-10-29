//! Prints the theme the browser extension's pages get from Passwords, as JSON
//! (`browser/test/preview.mjs` shows the pages in it).

fn main() {
    println!("{}", nyx_passwords::daemon::extension_theme());
}
