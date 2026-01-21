fn main() {
    println!("cargo::rustc-check-cfg=cfg(is_nightly)");

    let is_nightly = rustc_version::version_meta()
        .map(|meta| meta.channel == rustc_version::Channel::Nightly)
        .unwrap_or(false);

    if is_nightly {
        println!("cargo:rustc-cfg=is_nightly");
    }
}
