fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .bytes([".apexmail.mail.v1.StoreMessageRequest.raw_message"])
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/mail.proto"], &["proto/"])?;
    Ok(())
}
