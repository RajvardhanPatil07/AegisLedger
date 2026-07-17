fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Keep protobuf generation reproducible on clean CI runners and build hosts.
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);

    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_protos(&["proto/signer.proto"], &["proto"])?;
    Ok(())
}
