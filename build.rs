use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Determine namespace and grease settings
    let cxx_namespace = if let Ok(ns) = env::var("MLSPP_CXX_NAMESPACE") {
        ns
    } else if cfg!(feature = "libdave-compat") {
        "mlspp".to_string()
    } else {
        "mls".to_string()
    };

    let disable_grease = if let Ok(val) = env::var("MLSPP_DISABLE_GREASE") {
        val == "1"
    } else {
        cfg!(feature = "libdave-compat")
    };

    if cfg!(feature = "vendored") {
        build_vendored(&manifest_dir, &out_dir, &cxx_namespace, disable_grease);
    } else {
        // system mode: assume mlspp is installed and findable
        println!("cargo:rustc-link-lib=static=mlspp");
        println!("cargo:rustc-link-lib=static=hpke");
        println!("cargo:rustc-link-lib=static=tls_syntax");
        println!("cargo:rustc-link-lib=static=bytes");
    }

    // Link C++ standard library
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }

    // Link OpenSSL
    // openssl-sys handles the actual linking, but we need crypto for hpke
    println!("cargo:rustc-link-lib=crypto");

    // Generate bindings
    generate_bindings(&manifest_dir, &out_dir);
}

fn build_vendored(
    manifest_dir: &PathBuf,
    out_dir: &PathBuf,
    cxx_namespace: &str,
    disable_grease: bool,
) {
    let cmake_src_dir = manifest_dir.join("cmake");

    // Get OpenSSL info from openssl-sys
    let openssl_root = env::var("DEP_OPENSSL_ROOT").ok();
    let openssl_include = env::var("DEP_OPENSSL_INCLUDE")
        .ok()
        .or_else(|| openssl_root.as_ref().map(|r| format!("{}/include", r)));

    let mut cmake_config = cmake::Config::new(&cmake_src_dir);

    cmake_config
        .define("TESTING", "OFF")
        .define("MLS_CXX_NAMESPACE", cxx_namespace)
        .define("CMAKE_CXX_STANDARD", "17")
        .define("CMAKE_POSITION_INDEPENDENT_CODE", "ON");

    if disable_grease {
        cmake_config.define("DISABLE_GREASE", "ON");
    } else {
        cmake_config.define("DISABLE_GREASE", "OFF");
    }

    // Pass OpenSSL location to CMake
    if let Some(ref root) = openssl_root {
        cmake_config.define("OPENSSL_ROOT_DIR", root);
    }
    if let Some(ref inc) = openssl_include {
        cmake_config.define("OPENSSL_INCLUDE_DIR", inc);
    }

    // Suppress warnings-as-errors for vendored build
    cmake_config.define("CMAKE_CXX_FLAGS", "-Wno-error");

    let dst = cmake_config.build();

    let lib_dir = dst.join("lib");
    // Some systems use lib64
    let lib_dir = if lib_dir.exists() {
        lib_dir
    } else {
        dst.join("lib64")
    };

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=mlspp");
    println!("cargo:rustc-link-lib=static=hpke");
    println!("cargo:rustc-link-lib=static=tls_syntax");
    println!("cargo:rustc-link-lib=static=bytes");

    // Export paths for downstream crates
    let include_dir = dst.join("include");
    println!("cargo:root={}", dst.display());
    println!("cargo:include={}", include_dir.display());

    // Compile the C++ FFI wrapper
    let mlspp_include = include_dir.join("mlspp");
    let mut cc_build = cc::Build::new();
    cc_build
        .cpp(true)
        .std("c++17")
        .file(manifest_dir.join("ffi/wrapper.cpp"))
        .include(&mlspp_include)
        .include(&include_dir);

    if let Some(ref inc) = openssl_include {
        cc_build.include(inc);
    }

    // Add the cmake build directory for generated headers (namespace.h)
    let cmake_build_dir = out_dir.join("build");
    let mlspp_cmake_build = cmake_build_dir.join("mlspp");
    cc_build.include(mlspp_cmake_build.join("include"));

    // Search for generated namespace.h in build tree
    // The mlspp CMake generates it at ${CMAKE_CURRENT_BINARY_DIR}/include/namespace.h
    // With our wrapper, this ends up in the mlspp subdirectory of the build
    let build_include = mlspp_cmake_build.join("include");
    if build_include.exists() {
        cc_build.include(&build_include);
    }

    // Also add the sub-library include paths
    cc_build.include(manifest_dir.join("vendor/mlspp/include"));
    cc_build.include(manifest_dir.join("vendor/mlspp/lib/bytes/include"));
    cc_build.include(manifest_dir.join("vendor/mlspp/lib/hpke/include"));
    cc_build.include(manifest_dir.join("vendor/mlspp/lib/tls_syntax/include"));
    cc_build.include(manifest_dir.join("vendor/mlspp/third_party"));

    cc_build.warnings(false);
    cc_build.compile("mlspp_wrapper");
}

fn generate_bindings(manifest_dir: &PathBuf, out_dir: &PathBuf) {
    let wrapper_h = manifest_dir.join("ffi/wrapper.h");

    let bindings = bindgen::Builder::default()
        .header(wrapper_h.to_str().unwrap())
        .allowlist_function("mlspp_.*")
        .allowlist_type("mlspp_.*")
        .generate()
        .expect("Failed to generate bindings");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Failed to write bindings");
}
