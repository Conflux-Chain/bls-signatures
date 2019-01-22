extern crate cbindgen;

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target_path = out_path.join("../../..");

    let cfg = cbindgen::Config::from_root_or_default(std::path::Path::new(&crate_dir));

    let c = cbindgen::Builder::new()
        .with_config(cfg)
        .with_crate(crate_dir)
        .with_header(format!("/* libbls_signatures Header Version {} */", VERSION))
        .with_language(cbindgen::Language::C)
        .generate();

    // This is needed to ensure we don't panic if there are errors in the crates code
    // but rather just tell the rest of the system we can't proceed.
    match c {
        Ok(res) => {
            res.write_to_file(target_path.join("libbls_signatures.h"));
        }
        Err(err) => {
            eprintln!("unable to generate bindings: {:?}", err);
            std::process::exit(1);
        }
    }

    let mut pc_file = File::create(target_path.join("libbls_signatures.pc"))
        .expect("unable to generate .pc file: {:?}");

    write!(
        pc_file,
        "prefix=/usr/local
libdir=${{prefix}}/lib
includedir=${{prefix}}/include

Name: libbls_signatures
Version: foo
Description: bls-signatures library
Libs: -L${{libdir}} -lbls_signatures -lSystem -lresolv -lc -lm
Cflags: -I${{includedir}}
")
    .expect("unable to write to .pc file: {:?}");
}
