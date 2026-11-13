use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let proto_root = manifest_dir.join("../../proto");
    let protos = [
        proto_root.join("phoneconnect/v1/envelope.proto"),
        proto_root.join("phoneconnect/v1/session.proto"),
    ];

    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto.display());
    }
    println!("cargo:rerun-if-changed={}", proto_root.display());

    prost_build::Config::new().compile_protos(&protos, &[proto_root])?;
    Ok(())
}
