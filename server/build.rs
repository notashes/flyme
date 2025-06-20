// build.rs for server
fn main() {
    #[cfg(unix)]
    {
        println!("cargo:rustc-link-lib=c");
    }
}
