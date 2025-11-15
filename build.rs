fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(&["proto/file_transfer.proto"], &["proto"])?;

    println!("cargo:rerun-if-changed=proto/file_transfer.proto");

    Ok(())
}
