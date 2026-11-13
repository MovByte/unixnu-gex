//! With the `webmetal` feature on wgpu-native, which WebMetal's executor
//! links dynamically, gexc finds the library where the executor's own
//! targets do: `WEBGPU_NATIVE_DIR/lib`, added to its run-time search path
//! (`third_party/WebMetal/host/build.rs` describes the variables). A build
//! script's link arguments apply only to its own package's targets, so
//! this one repeats them for gexc.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=WEBGPU_NATIVE");
    println!("cargo:rerun-if-env-changed=WEBGPU_NATIVE_DIR");
    if std::env::var_os("CARGO_FEATURE_WEBMETAL").is_none() {
        return;
    }
    if std::env::var("WEBGPU_NATIVE").as_deref() == Ok("wgpu-native") {
        if let Ok(root) = std::env::var("WEBGPU_NATIVE_DIR") {
            let lib = std::path::Path::new(&root).join("lib");
            println!("cargo:rustc-link-arg-bins=-Wl,-rpath,{}", lib.display());
        }
    }
}
