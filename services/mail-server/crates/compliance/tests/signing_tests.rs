//! Hostile-input and end-to-end tests for `compliance::signing`.
//!
//! # Fixture provenance
//!
//! * The RFC 3161 response in `FIXTURE_RESPONSE_HEX` was produced by
//!   OpenSSL 3.6 (`openssl ts -query` + `openssl ts -reply`) from a real
//!   2048-bit RSA TSA key and a self-signed certificate carrying the critical
//!   `timeStamping` extended key usage. It contains a real RSASSA-PKCS1-v1_5
//!   SHA-256 CMS signature and an ESSCertIDv2 signed attribute. Its
//!   independent verification with `openssl cms -verify` succeeds (recorded
//!   in the workstream report).
//! * The `FIXTURE_REJECTED_HEX` response is the genuine OpenSSL "rejection"
//!   reply for a SHA-1 query, with `failInfo = badAlg`.
//! * The ASiC-E `signatures.xml` fixture was produced by signing the exact
//!   `SignedInfo` octets with the same RSA key
//!   (`openssl dgst -sha256 -sign`), so the production XML-DSig verification
//!   path is exercised against a real signature, not a placeholder.
//!
//! No test here needs a database or network beyond a loopback HTTP listener.

use chrono::{DateTime, Utc};
use compliance::signing::container::{
    resolve_member_uri, verify_asic_e, AsicEvidence, ContainerMember, ASIC_E_MIMETYPE,
};
use compliance::signing::der::{self, Budget, DerError, Limits, Reader};
use compliance::signing::timestamp::{
    build_request, parse_request, timestamp_document, verify_response, HashAlgorithm,
    TimeStampClient, TimeStampError, TimeStampEvidence, TimestampVerificationRequest, OID_SHA256,
    OID_SHA512, OID_TST_INFO,
};
use compliance::signing::{CheckOutcome, CheckVerdict};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ── Fixtures ───────────────────────────────────────────────────────────────

/// The exact bytes OpenSSL hashed for the fixture query.
const FIXTURE_DOCUMENT: &[u8] =
    b"ApexMail statutory filing fixture document.\nPeriod: 2026-01-01..2026-12-31\n";

/// A genuine OpenSSL `TimeStampResp` (granted, nonce `FIXTURE_NONCE`).
const FIXTURE_RESPONSE_HEX: &str = "30820a09300302010030820a0006092a864886f70d010702a08209f1308209ed020103310f300d06096086480165030402010500308180060b2a864886f70d01\n09100104a071046f306d020101060a2b0601040183bf3001013031300d0609608648016503040201050004206ccbf31f3339b0d03d9aeb7d6321751b79320b85\n41dc53d4b4291c833b4d186f020102180f32303236303931323231313934345a300a020101800201f4810164020900d57f3edcb92f412da082071a3082038930\n820271a00302010202045a504558300d06092a864886f70d01010b0500305a310b3009060355040613024545311e301c060355040a0c15417065784d61696c20\n546573742046697874757265312b302906035504030c22417065784d61696c20546573742054534120284e4f542050524f44554354494f4e29301e170d323630\n3931323231313933375a170d3336303930393231313933375a305a310b3009060355040613024545311e301c060355040a0c15417065784d61696c2054657374\n2046697874757265312b302906035504030c22417065784d61696c20546573742054534120284e4f542050524f44554354494f4e2930820122300d06092a8648\n86f70d01010105000382010f003082010a0282010100b30a8b1ae3ecf5fb229dc9beb60b613cc02d86b4b9bc8f84d595984399dd8a1afa71521c6d91b6377537\n8ba7bf2ed6d9d543faa71f777dc3c2632c5b4c8ea7d8a7cd26f7462694d721f5aefdbe4ef31878b78bccb9aa1acd89bd73252218420ef3b6fcd27ee010864862\nedacb2dcfe35901c71060284771986f2033c40309e716ca7ad9c7efb5c494b6dfd7a012bb0210b283cccca9e3059cb1a48d03a2bb604ebfce7bd1bd24e30efb9\n9949b3966b09597e46e87483b1afb0b289a73c7bf7df4d489698ff37e223f83b046af65f51454ccdbe9f3442c4705cd5c397d9f2369fb513db37a20955e62384\n892c2bea6388d17583426fdc9284efb1c604d011df150203010001a3573055300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301606\n03551d250101ff040c300a06082b06010505070308301d0603551d0e04160414717afd522d0495d89e78f45d59795d981a0d482a300d06092a864886f70d0101\n0b0500038201010028e4f826146b6240f3f1d13ec21284e1dbe4494cf405cebb211aca3e90c864bd314ba83591120d7dba2cf3b497022b04630a1e1e58d8fdde\na0e36b47bbc91ae357cc9d5fe44e50fba8e476a9850f8017070ef10628e7fa12d41bdb03411e275055c04834419c909f1a4ee683c0e3ce96ecb5334f04398b64\n88bbead7c74771ec913e6d927e54261ebb67dc036762683a573b259643e6370f81e0e87070a556ba33e515738a8a5853840c834a4d53a2d0d40816c99a4b1ca0\n6b8ba847537481be1632fce7d5ff1ea419d8bd47e9ab779beaabb5de7068a2f869befb2f43c0f34f4ef92c385630cc655f0b5e8de49c4bd43a8585a5af92dd7e\n4b3730fb785f9b853082038930820271a00302010202045a504558300d06092a864886f70d01010b0500305a310b3009060355040613024545311e301c060355\n040a0c15417065784d61696c20546573742046697874757265312b302906035504030c22417065784d61696c20546573742054534120284e4f542050524f4455\n4354494f4e29301e170d3236303931323231313933375a170d3336303930393231313933375a305a310b3009060355040613024545311e301c060355040a0c15\n417065784d61696c20546573742046697874757265312b302906035504030c22417065784d61696c20546573742054534120284e4f542050524f44554354494f\n4e2930820122300d06092a864886f70d01010105000382010f003082010a0282010100b30a8b1ae3ecf5fb229dc9beb60b613cc02d86b4b9bc8f84d595984399\ndd8a1afa71521c6d91b63775378ba7bf2ed6d9d543faa71f777dc3c2632c5b4c8ea7d8a7cd26f7462694d721f5aefdbe4ef31878b78bccb9aa1acd89bd732522\n18420ef3b6fcd27ee010864862edacb2dcfe35901c71060284771986f2033c40309e716ca7ad9c7efb5c494b6dfd7a012bb0210b283cccca9e3059cb1a48d03a\n2bb604ebfce7bd1bd24e30efb99949b3966b09597e46e87483b1afb0b289a73c7bf7df4d489698ff37e223f83b046af65f51454ccdbe9f3442c4705cd5c397d9\nf2369fb513db37a20955e62384892c2bea6388d17583426fdc9284efb1c604d011df150203010001a3573055300c0603551d130101ff04023000300e0603551d\n0f0101ff04040302078030160603551d250101ff040c300a06082b06010505070308301d0603551d0e04160414717afd522d0495d89e78f45d59795d981a0d48\n2a300d06092a864886f70d01010b0500038201010028e4f826146b6240f3f1d13ec21284e1dbe4494cf405cebb211aca3e90c864bd314ba83591120d7dba2cf3\nb497022b04630a1e1e58d8fddea0e36b47bbc91ae357cc9d5fe44e50fba8e476a9850f8017070ef10628e7fa12d41bdb03411e275055c04834419c909f1a4ee6\n83c0e3ce96ecb5334f04398b6488bbead7c74771ec913e6d927e54261ebb67dc036762683a573b259643e6370f81e0e87070a556ba33e515738a8a5853840c83\n4a4d53a2d0d40816c99a4b1ca06b8ba847537481be1632fce7d5ff1ea419d8bd47e9ab779beaabb5de7068a2f869befb2f43c0f34f4ef92c385630cc655f0b5e\n8de49c4bd43a8585a5af92dd7e4b3730fb785f9b8531820234308202300201013062305a310b3009060355040613024545311e301c060355040a0c1541706578\n4d61696c20546573742046697874757265312b302906035504030c22417065784d61696c20546573742054534120284e4f542050524f44554354494f4e290204\n5a504558300d06096086480165030402010500a081a4301a06092a864886f70d010903310d060b2a864886f70d0109100104301c06092a864886f70d01090531\n0f170d3236303931323231313934345a302f06092a864886f70d01090431220420913999fbeb8574d89dc21976957fa88672ce1ab714601fb77fbb19ca535002\n063037060b2a864886f70d010910022f312830263024302204201d2e89363dc0ae22976e4abc010efc985b63eccac2d87c0b00ebfc46b55e0912300d06092a86\n4886f70d01010105000482010001bd2755b82cfbabbdb4d42b087a12fd3d2e74bc4cb71e8912f4eef14dd1d654bc30100171dbf89827e281e4f116113a4be7ed\nc7c29b191f988574e4a35f6adea0e8e45be8466ef73fe1001f6b0f782949d024d946fa1fabe82be84c37d30f67aad777c4b9e1f310872955b84d285c0cb742ee\nebc6f5a57196e3ba2c69d0f0ad0d51725515f74e9f8bbef774f72d160b4b56ff94630933952c4cc9e69eefeace75bcbe8efe3af97887d452c280107a5bb2b23a\nf5b0999afe42fe123a355ddf20a779fd1b700057540752675cef8e5d4460d991daaac961140cbce358bcdaad1a609748ee687e1e4346a8e0f5ab886eae761016\n24bde8637973f453bf37a86e07";

/// A genuine OpenSSL `TimeStampResp` for a SHA-1 query: status rejection with
/// `failInfo = badAlg` and no token.
const FIXTURE_REJECTED_HEX: &str = "30373035020102302c0c2a4d6573736167652064696765737420616c676f726974686d206973206e6f7420737570706f727465642e03020780";

/// The DER of the certificate OpenSSL put into the response (used to locate
/// and corrupt certificate bytes inside the fixture).
const FIXTURE_CERT_HEX: &str = "3082038930820271a00302010202045a504558300d06092a864886f70d01010b0500305a310b3009060355040613024545311e301c060355040a0c1541706578\n4d61696c20546573742046697874757265312b302906035504030c22417065784d61696c20546573742054534120284e4f542050524f44554354494f4e29301e\n170d3236303931323231313933375a170d3336303930393231313933375a305a310b3009060355040613024545311e301c060355040a0c15417065784d61696c\n20546573742046697874757265312b302906035504030c22417065784d61696c20546573742054534120284e4f542050524f44554354494f4e2930820122300d\n06092a864886f70d01010105000382010f003082010a0282010100b30a8b1ae3ecf5fb229dc9beb60b613cc02d86b4b9bc8f84d595984399dd8a1afa71521c6d\n91b63775378ba7bf2ed6d9d543faa71f777dc3c2632c5b4c8ea7d8a7cd26f7462694d721f5aefdbe4ef31878b78bccb9aa1acd89bd73252218420ef3b6fcd27e\ne010864862edacb2dcfe35901c71060284771986f2033c40309e716ca7ad9c7efb5c494b6dfd7a012bb0210b283cccca9e3059cb1a48d03a2bb604ebfce7bd1b\nd24e30efb99949b3966b09597e46e87483b1afb0b289a73c7bf7df4d489698ff37e223f83b046af65f51454ccdbe9f3442c4705cd5c397d9f2369fb513db37a2\n0955e62384892c2bea6388d17583426fdc9284efb1c604d011df150203010001a3573055300c0603551d130101ff04023000300e0603551d0f0101ff04040302\n078030160603551d250101ff040c300a06082b06010505070308301d0603551d0e04160414717afd522d0495d89e78f45d59795d981a0d482a300d06092a8648\n86f70d01010b0500038201010028e4f826146b6240f3f1d13ec21284e1dbe4494cf405cebb211aca3e90c864bd314ba83591120d7dba2cf3b497022b04630a1e\n1e58d8fddea0e36b47bbc91ae357cc9d5fe44e50fba8e476a9850f8017070ef10628e7fa12d41bdb03411e275055c04834419c909f1a4ee683c0e3ce96ecb533\n4f04398b6488bbead7c74771ec913e6d927e54261ebb67dc036762683a573b259643e6370f81e0e87070a556ba33e515738a8a5853840c834a4d53a2d0d40816\nc99a4b1ca06b8ba847537481be1632fce7d5ff1ea419d8bd47e9ab779beaabb5de7068a2f869befb2f43c0f34f4ef92c385630cc655f0b5e8de49c4bd43a8585\na5af92dd7e4b3730fb785f9b85";

/// The raw CMS signature bytes inside the fixture (used to locate and corrupt
/// the signature independently of everything else).
const FIXTURE_SIGNATURE_HEX: &str = "01bd2755b82cfbabbdb4d42b087a12fd3d2e74bc4cb71e8912f4eef14dd1d654bc30100171dbf89827e281e4f116113a4be7edc7c29b191f988574e4a35f6ade\na0e8e45be8466ef73fe1001f6b0f782949d024d946fa1fabe82be84c37d30f67aad777c4b9e1f310872955b84d285c0cb742eeebc6f5a57196e3ba2c69d0f0ad\n0d51725515f74e9f8bbef774f72d160b4b56ff94630933952c4cc9e69eefeace75bcbe8efe3af97887d452c280107a5bb2b23af5b0999afe42fe123a355ddf20\na779fd1b700057540752675cef8e5d4460d991daaac961140cbce358bcdaad1a609748ee687e1e4346a8e0f5ab886eae76101624bde8637973f453bf37a86e07";

const FIXTURE_NONCE: u64 = 0xD57F_3EDC_B92F_412D;
const FIXTURE_GEN_TIME: &str = "2026-09-12T21:19:44Z";
const FIXTURE_POLICY: &str = "1.3.6.1.4.1.57264.1.1";
const FIXTURE_SERIAL_HEX: &str = "02";
const FIXTURE_IMPRINT_HEX: &str =
    "6ccbf31f3339b0d03d9aeb7d6321751b79320b8541dc53d4b4291c833b4d186f";
const FIXTURE_CERT_SUBJECT: &str =
    "C=EE, O=ApexMail Test Fixture, CN=ApexMail Test TSA (NOT PRODUCTION)";

/// A valid ASiC-E `META-INF/signatures.xml` with a real RSA-SHA256
/// `SignatureValue` over the `SignedInfo` octets, two file references and one
/// XAdES `SignedProperties` reference.
const ASIC_SIGNATURES_XML: &str = r##"<?xml version="1.0" encoding="UTF-8"?>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="signature-1">
  <ds:SignedInfo Id="signed-info-1">
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference Id="ref-document" URI="document.txt">
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      <ds:DigestValue>bMvzHzM5sNA9mut9YyF1G3kyC4VB3FPUtCkcgztNGG8=</ds:DigestValue>
    </ds:Reference>
    <ds:Reference Id="ref-financials" URI="financials.csv">
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      <ds:DigestValue>4vHdVh+HF/ahvp6sG7uihYhE0B5T7FsGsaGzEmvGres=</ds:DigestValue>
    </ds:Reference>
    <ds:Reference Id="ref-signed-props" URI="#signed-properties-1" Type="http://uri.etsi.org/01903#SignedProperties">
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      <ds:DigestValue>FlWTO5Fx7ujbA2Ikbjv744LEBVamrM3Ngg3NCTcb9FQ=</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>ZcHWNAfvu1PTpKwws1ZVxRwiwDU4KaAQrCpfzG8D78ytDgWLR1P3Ngk6YbtzIFuRwFjNxNjTFubmzAr2Dd2WGkT3LZQiNubdW5yAkm2cpEzJUK8H2+me7q+1WCgi0MxmcqSqhBF1GM+GN4ObY3exHdKvqN7liWN3Z7M2vXdCXCy2Hg4zvn0qN29BoiBej5rQdJYMxoBkI3+9wA4sJDC0FDGJ/Aebxi1hpebOEcJ5k0ZxJHMjsjo7iOsYIN8AURHpHW5BZzD41yFiGPOyLeFqzXInxvvnosPk0iTVQdIauYCFgdRXxiTTD8609oTmZRqQVpvjy7b3GPpvoAUskcgZnA==</ds:SignatureValue>
  <ds:KeyInfo Id="key-info-1">
    <ds:X509Data>
      <ds:X509Certificate>MIIDiTCCAnGgAwIBAgIEWlBFWDANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJFRTEeMBwGA1UECgwVQXBleE1haWwgVGVzdCBGaXh0dXJlMSswKQYDVQQDDCJBcGV4TWFpbCBUZXN0IFRTQSAoTk9UIFBST0RVQ1RJT04pMB4XDTI2MDkxMjIxMTkzN1oXDTM2MDkwOTIxMTkzN1owWjELMAkGA1UEBhMCRUUxHjAcBgNVBAoMFUFwZXhNYWlsIFRlc3QgRml4dHVyZTErMCkGA1UEAwwiQXBleE1haWwgVGVzdCBUU0EgKE5PVCBQUk9EVUNUSU9OKTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALMKixrj7PX7Ip3JvrYLYTzALYa0ubyPhNWVmEOZ3Yoa+nFSHG2Rtjd1N4unvy7W2dVD+qcfd33DwmMsW0yOp9inzSb3RiaU1yH1rv2+TvMYeLeLzLmqGs2JvXMlIhhCDvO2/NJ+4BCGSGLtrLLc/jWQHHEGAoR3GYbyAzxAMJ5xbKetnH77XElLbf16ASuwIQsoPMzKnjBZyxpI0DortgTr/Oe9G9JOMO+5mUmzlmsJWX5G6HSDsa+wsomnPHv3301Ilpj/N+Ij+DsEavZfUUVMzb6fNELEcFzVw5fZ8jaftRPbN6IJVeYjhIksK+pjiNF1g0Jv3JKE77HGBNAR3xUCAwEAAaNXMFUwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYEFHF6/VItBJXYnnj0XVl5XZgaDUgqMA0GCSqGSIb3DQEBCwUAA4IBAQAo5PgmFGtiQPPx0T7CEoTh2+RJTPQFzrshGso+kMhkvTFLqDWREg19uizztJcCKwRjCh4eWNj93qDja0e7yRrjV8ydX+ROUPuo5HaphQ+AFwcO8QYo5/oS1BvbA0EeJ1BVwEg0QZyQnxpO5oPA486W7LUzTwQ5i2SIu+rXx0dx7JE+bZJ+VCYeu2fcA2diaDpXOyWWQ+Y3D4Hg6HBwpVa6M+UVc4qKWFOEDINKTVOi0NQIFsmaSxyga4uoR1N0gb4WMvzn1f8epBnYvUfpq3eb6qu13nBoovhpvvsvQ8DzT075LDhWMMxlXwtejeScS9Q6hYWlr5Ldfks3MPt4X5uF</ds:X509Certificate>
    </ds:X509Data>
  </ds:KeyInfo>
  <ds:Object Id="object-1">
    <xades:QualifyingProperties Target="#signature-1">
      <xades:SignedProperties Id="signed-properties-1">
        <xades:SignedSignatureProperties>
          <xades:SigningTime>2026-09-12T21:19:44Z</xades:SigningTime>
          <xades:SigningCertificateV2>
            <xades:Cert>
              <xades:CertDigest>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>HS6JNj3AriKXbkq8AQ78mFtj7MrC2HwLAOv8RrVeCRI=</ds:DigestValue>
              </xades:CertDigest>
              <xades:IssuerSerial>
                <ds:X509IssuerName>C=EE,O=ApexMail Test Fixture,CN=ApexMail Test TSA (NOT PRODUCTION)</ds:X509IssuerName>
                <ds:X509SerialNumber>1515210584</ds:X509SerialNumber>
              </xades:IssuerSerial>
            </xades:Cert>
          </xades:SigningCertificateV2>
        </xades:SignedSignatureProperties>
      </xades:SignedProperties>
    </xades:QualifyingProperties>
  </ds:Object>
</ds:Signature>
"##;

const ASIC_FINANCIALS: &[u8] = b"account,amount\nrevenue,1000.00\n";

fn strip_whitespace(value: &str) -> String {
    value.chars().filter(|character| !character.is_whitespace()).collect()
}

fn fixture_response() -> Vec<u8> {
    hex::decode(strip_whitespace(FIXTURE_RESPONSE_HEX)).expect("fixture hex")
}

/// Parse exactly one TLV from `bytes` (test helper).
fn parse_one(bytes: &[u8]) -> der::Tlv<'_> {
    let mut budget = Budget::default();
    let mut reader = Reader::new(bytes);
    let tlv = reader.read(&mut budget).expect("one TLV");
    assert!(reader.is_empty(), "expected exactly one TLV");
    tlv
}

fn fixture_rejected() -> Vec<u8> {
    hex::decode(strip_whitespace(FIXTURE_REJECTED_HEX)).expect("fixture hex")
}

fn fixture_cert_der() -> Vec<u8> {
    hex::decode(strip_whitespace(FIXTURE_CERT_HEX)).expect("fixture hex")
}

fn fixture_signature() -> Vec<u8> {
    hex::decode(strip_whitespace(FIXTURE_SIGNATURE_HEX)).expect("fixture hex")
}

fn fixture_now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(FIXTURE_GEN_TIME)
        .expect("fixture genTime")
        .with_timezone(&Utc)
}

fn verify_fixture(
    document: &[u8],
    nonce: u64,
    now: DateTime<Utc>,
    tolerance_secs: i64,
) -> Result<TimeStampEvidence, TimeStampError> {
    verify_response(
        &fixture_response(),
        &TimestampVerificationRequest {
            document,
            nonce,
            algorithm: HashAlgorithm::Sha256,
            tolerance_secs,
            now,
            tsa_url: Some("https://tsa.example.test/"),
        },
    )
}

fn timestamp_outcome<'a>(evidence: &'a TimeStampEvidence, id: &str) -> &'a CheckOutcome {
    &evidence
        .checks
        .iter()
        .find(|check| check.check == id)
        .unwrap_or_else(|| panic!("timestamp evidence has no check {id:?}"))
        .outcome
}

fn container_outcome<'a>(evidence: &'a AsicEvidence, id: &str) -> &'a CheckOutcome {
    &evidence
        .container_checks
        .iter()
        .find(|check| check.check == id)
        .unwrap_or_else(|| panic!("container evidence has no check {id:?}"))
        .outcome
}

fn signature_outcome<'a>(
    evidence: &'a AsicEvidence,
    signature: usize,
    id: &str,
) -> &'a CheckOutcome {
    &evidence.signatures[signature]
        .checks
        .iter()
        .find(|check| check.check == id)
        .unwrap_or_else(|| panic!("signature evidence has no check {id:?}"))
        .outcome
}

fn reference_for<'a>(
    evidence: &'a AsicEvidence,
    signature: usize,
    uri: &str,
) -> &'a compliance::signing::container::ReferenceVerdict {
    evidence.signatures[signature]
        .references
        .iter()
        .find(|reference| reference.uri == uri)
        .unwrap_or_else(|| panic!("no reference {uri:?}"))
}

fn asic_members(document: &[u8], signatures_xml: &str) -> Vec<ContainerMember> {
    vec![
        ContainerMember::new("mimetype", ASIC_E_MIMETYPE.as_bytes().to_vec()),
        ContainerMember::new("META-INF/signatures.xml", signatures_xml.as_bytes().to_vec()),
        ContainerMember::new("document.txt", document.to_vec()),
        ContainerMember::new("financials.csv", ASIC_FINANCIALS.to_vec()),
    ]
}

fn assert_fail_contains(outcome: &CheckOutcome, needle: &str) {
    match outcome {
        CheckOutcome::Fail { detail } => assert!(
            detail.contains(needle),
            "failure detail {detail:?} does not contain {needle:?}"
        ),
        other => panic!("expected Fail containing {needle:?}, got {other:?}"),
    }
}

// ── DER hardening ──────────────────────────────────────────────────────────

#[test]
fn der_reader_refuses_indefinite_length() {
    let mut budget = Budget::default();
    let input = [0x30u8, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00];
    let mut reader = Reader::new(&input);
    assert_eq!(
        reader.read(&mut budget).unwrap_err(),
        DerError::IndefiniteLength
    );
}

#[test]
fn der_reader_refuses_over_long_length() {
    let mut budget = Budget::default();
    // Length 3 encoded in two bytes with a leading zero (not minimal).
    let input = [0x30u8, 0x82, 0x00, 0x03, 0x02, 0x01, 0x01];
    let mut reader = Reader::new(&input);
    assert_eq!(
        reader.read(&mut budget).unwrap_err(),
        DerError::NonMinimalLength
    );

    // Same value encoded in one extra byte without a leading zero.
    let input = [0x30u8, 0x81, 0x02, 0x05, 0x00];
    let mut reader = Reader::new(&input);
    assert_eq!(
        reader.read(&mut budget).unwrap_err(),
        DerError::NonMinimalLength
    );
}

#[test]
fn der_reader_refuses_truncated_input() {
    let mut budget = Budget::default();
    for input in [
        vec![],
        vec![0x30u8],
        vec![0x30u8, 0x10],
        vec![0x30u8, 0x10, 0x02],
        vec![0x30u8, 0x03, 0x02, 0x01],
    ] {
        let mut reader = Reader::new(&input);
        assert!(reader.read(&mut budget).is_err(), "input {input:?} parsed");
    }
}

#[test]
fn der_reader_refuses_huge_lengths() {
    let mut budget = Budget::default();
    let input = [0x30u8, 0x84, 0xFF, 0xFF, 0xFF, 0xFF];
    let mut reader = Reader::new(&input);
    assert!(matches!(
        reader.read(&mut budget),
        Err(DerError::ElementTooLarge { .. })
    ));

    let mut budget = Budget::default();
    let input = [0x30u8, 0x89, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut reader = Reader::new(&input);
    assert_eq!(
        reader.read(&mut budget).unwrap_err(),
        DerError::LengthFieldTooLong
    );
}

#[test]
fn der_reader_refuses_high_tag_number() {
    let mut budget = Budget::default();
    let input = [0x1Fu8, 0x01, 0x00];
    let mut reader = Reader::new(&input);
    assert!(matches!(
        reader.read(&mut budget),
        Err(DerError::UnsupportedTag { .. })
    ));
}

#[test]
fn der_reader_refuses_trailing_garbage() {
    let mut budget = Budget::default();
    let input = [0x05u8, 0x00, 0x00, 0x00];
    let mut reader = Reader::new(&input);
    let tlv = reader.read(&mut budget).expect("NULL");
    assert_eq!(tlv.tag, der::TAG_NULL);
    assert_eq!(reader.finish(), Err(DerError::TrailingGarbage { remaining: 2 }));
}

#[test]
fn der_budget_refuses_deep_nesting() {
    let mut blob = der::null();
    for _ in 0..100 {
        blob = der::sequence(&[blob]);
    }
    let mut budget = Budget::default();
    let mut reader = Reader::new(&blob);
    let top = reader.read(&mut budget).expect("top-level SEQUENCE");

    fn walk(tlv: &der::Tlv<'_>, budget: &mut Budget) -> Result<(), DerError> {
        budget.descend(|budget| {
            let mut reader = tlv.reader();
            while !reader.is_empty() {
                let child = reader.read(budget)?;
                if child.constructed {
                    walk(&child, budget)?;
                }
            }
            Ok(())
        })
    }

    assert!(matches!(
        walk(&top, &mut budget),
        Err(DerError::DepthExceeded { .. })
    ));
}

#[test]
fn der_budget_refuses_element_flood() {
    let parts: Vec<Vec<u8>> = (0..64).map(|_| der::unsigned_integer(1)).collect();
    let blob = der::sequence(&parts);
    let limits = Limits {
        max_elements: 16,
        ..Limits::default()
    };
    let mut budget = Budget::new(limits);
    let mut reader = Reader::new(&blob);
    let top = reader.read(&mut budget).expect("top-level SEQUENCE");
    let mut inner = top.reader();
    let mut error = None;
    while !inner.is_empty() {
        match inner.read(&mut budget) {
            Ok(_) => {}
            Err(found) => {
                error = Some(found);
                break;
            }
        }
    }
    assert!(matches!(
        error,
        Some(DerError::ElementLimitExceeded { .. })
    ));
}

#[test]
fn der_oid_round_trips_and_rejects_nonsense() {
    for dotted in [OID_SHA256, OID_SHA512, OID_TST_INFO, "1.2.3.4.5.6.7.8"] {
        let encoded = der::oid(dotted).expect("encode");
        let tlv = parse_one(&encoded);
        assert_eq!(tlv.tag, der::TAG_OID);
        assert_eq!(der::decode_oid(&tlv).expect("decode"), dotted);
    }
    assert!(der::oid("256.1").is_err());
    assert!(der::oid("1.40").is_err());
    assert!(der::oid("1").is_err());
    assert!(der::oid("1..2").is_err());
}

#[test]
fn der_integer_and_time_decoding_is_strict() {
    // Negative INTEGERs are refused rather than reinterpreted.
    let negative = [0x02u8, 0x01, 0x80];
    let tlv = parse_one(&negative);
    assert_eq!(der::decode_u64(&tlv), Err(DerError::InvalidInteger));

    // RFC 3161 genTime must be a GeneralizedTime in a recognised shape.
    let good = der::tlv(der::TAG_GENERALIZED_TIME, b"20260912211944Z");
    let tlv = parse_one(&good);
    let parsed = der::decode_generalized_time(&tlv).expect("genTime");
    assert_eq!(parsed.to_rfc3339(), "2026-09-12T21:19:44+00:00");
    assert_eq!(parsed.timestamp(), 1_789_247_984);
    let with_fraction = der::tlv(der::TAG_GENERALIZED_TIME, b"20260912211944.500Z");
    let tlv = parse_one(&with_fraction);
    let parsed = der::decode_generalized_time(&tlv).expect("fractional genTime");
    assert_eq!(parsed.timestamp(), 1_789_247_984);
    for bad in [
        b"2026-09-12T21:19:44Z".as_slice(),
        b"20260912211944".as_slice(),
        b"20260912211944+99".as_slice(),
        b"20261312211944Z".as_slice(),
    ] {
        let encoded = der::tlv(der::TAG_GENERALIZED_TIME, bad);
        let tlv = parse_one(&encoded);
        assert!(
            der::decode_generalized_time(&tlv).is_err(),
            "accepted {bad:?}"
        );
    }
}

// ── RFC 3161: the real OpenSSL fixture ─────────────────────────────────────

#[test]
fn fixture_document_matches_embedded_imprint() {
    assert_eq!(
        hex::encode(Sha256::digest(FIXTURE_DOCUMENT)),
        FIXTURE_IMPRINT_HEX
    );
    assert_eq!(FIXTURE_DOCUMENT.len(), 75);
}

#[test]
fn open_ssl_fixture_passes_every_check_independently() {
    let evidence = verify_fixture(FIXTURE_DOCUMENT, FIXTURE_NONCE, fixture_now(), 300)
        .expect("fixture must verify");

    assert!(evidence.all_passed(), "checks: {:?}", evidence.checks);
    assert!(
        evidence.strictly_passed(),
        "every check (including optional ones) must pass: {:?}",
        evidence.checks
    );
    assert!(!evidence.has_failures());
    assert_eq!(evidence.request_nonce, FIXTURE_NONCE);
    assert_eq!(evidence.tsa_url.as_deref(), Some("https://tsa.example.test/"));
    assert_eq!(evidence.policy_oid, FIXTURE_POLICY);
    assert_eq!(evidence.serial_number_hex, FIXTURE_SERIAL_HEX);
    assert_eq!(evidence.imprint_algorithm, "sha256");
    assert_eq!(evidence.imprint_hex, FIXTURE_IMPRINT_HEX);
    assert_eq!(evidence.document_digest_hex, FIXTURE_IMPRINT_HEX);
    assert_eq!(evidence.gen_time_rfc3339.as_deref(), Some(FIXTURE_GEN_TIME));
    assert_eq!(evidence.gen_time_unix, Some(fixture_now().timestamp()));

    let certificate = evidence.signer_certificate.as_ref().expect("certificate");
    assert_eq!(certificate.subject, FIXTURE_CERT_SUBJECT);
    assert_eq!(certificate.serial_hex, "5a504558");
    assert_eq!(certificate.public_key_algorithm_oid, "1.2.840.113549.1.1.1");
    assert_eq!(certificate.sha256_fingerprint_hex.len(), 64);

    // Every expected check id is present exactly once and passes.
    for id in [
        "status_granted",
        "imprint_algorithm_expected",
        "imprint_matches_document",
        "nonce_matches_request",
        "gen_time_parses",
        "gen_time_within_tolerance",
        "signer_certificate_parses",
        "digest_algorithm_accepted",
        "signed_attrs_content_type",
        "signed_attrs_message_digest_matches_econtent",
        "ess_signing_certificate_hash_matches_certificate",
        "signer_id_matches_certificate",
        "token_signature_valid",
    ] {
        assert_eq!(timestamp_outcome(&evidence, id), &CheckOutcome::Pass, "{id}");
    }
    assert_eq!(evidence.checks.len(), 13);
    assert!(evidence.proven_properties.iter().any(|line| line.contains("nonce")));
    assert!(evidence
        .not_proven_properties
        .iter()
        .any(|line| line.contains("trusted root")));
}

#[test]
fn wrong_document_fails_only_the_imprint_check() {
    let other = b"a different filing entirely";
    let evidence = verify_fixture(other, FIXTURE_NONCE, fixture_now(), 300)
        .expect("the response parses; the failure is reported as a named check");
    assert!(!evidence.all_passed());
    let outcome = timestamp_outcome(&evidence, "imprint_matches_document");
    assert_fail_contains(outcome, "does not equal");
    // The rest of the machine is intact: the token still binds to itself.
    assert_eq!(
        timestamp_outcome(&evidence, "nonce_matches_request"),
        &CheckOutcome::Pass
    );
    assert_eq!(
        timestamp_outcome(&evidence, "token_signature_valid"),
        &CheckOutcome::Pass
    );
    assert_eq!(
        timestamp_outcome(&evidence, "signed_attrs_message_digest_matches_econtent"),
        &CheckOutcome::Pass
    );
    assert_eq!(evidence.document_digest_hex, hex::encode(Sha256::digest(other)));
}

#[test]
fn wrong_nonce_fails_only_the_nonce_check() {
    let evidence = verify_fixture(FIXTURE_DOCUMENT, 0xDEAD_BEEF_CAFE_F00D, fixture_now(), 300)
        .expect("the response parses; the failure is reported as a named check");
    assert!(!evidence.all_passed());
    assert!(evidence
        .failing_checks()
        .iter()
        .any(|check| check.check == "nonce_matches_request"));
    let outcome = timestamp_outcome(&evidence, "nonce_matches_request");
    match outcome {
        CheckOutcome::Fail { detail } => {
            assert!(detail.contains("DEADBEEFCAFEF00D"), "{detail}");
        }
        other => panic!("expected Fail, got {other:?}"),
    }
    assert_eq!(
        timestamp_outcome(&evidence, "imprint_matches_document"),
        &CheckOutcome::Pass
    );
    assert_eq!(
        timestamp_outcome(&evidence, "gen_time_within_tolerance"),
        &CheckOutcome::Pass
    );
}

#[test]
fn gen_time_outside_tolerance_fails_with_the_observed_time() {
    let far_future = fixture_now() + chrono::Duration::hours(3);
    let evidence = verify_fixture(FIXTURE_DOCUMENT, FIXTURE_NONCE, far_future, 300)
        .expect("the response parses; the failure is reported as a named check");
    assert!(!evidence.all_passed());
    let outcome = timestamp_outcome(&evidence, "gen_time_within_tolerance");
    match outcome {
        CheckOutcome::Fail { detail } => {
            assert!(detail.contains(FIXTURE_GEN_TIME), "{detail}");
            assert!(detail.contains("10800 seconds"), "{detail}");
        }
        other => panic!("expected Fail, got {other:?}"),
    }
    assert_eq!(timestamp_outcome(&evidence, "gen_time_parses"), &CheckOutcome::Pass);

    // Far past must fail just as loudly.
    let far_past = fixture_now() - chrono::Duration::days(30);
    let evidence = verify_fixture(FIXTURE_DOCUMENT, FIXTURE_NONCE, far_past, 300)
        .expect("the response parses; the failure is reported as a named check");
    assert!(!evidence.all_passed());
    assert_fail_contains(
        timestamp_outcome(&evidence, "gen_time_within_tolerance"),
        "seconds from the verification clock",
    );
}

#[test]
fn rejected_status_reports_status_string_and_fail_info() {
    let error = verify_response(
        &fixture_rejected(),
        &TimestampVerificationRequest {
            document: FIXTURE_DOCUMENT,
            nonce: FIXTURE_NONCE,
            algorithm: HashAlgorithm::Sha256,
            tolerance_secs: 300,
            now: fixture_now(),
            tsa_url: None,
        },
    )
    .expect_err("a rejection must not produce evidence");
    match error {
        TimeStampError::Rejected {
            status,
            status_name,
            status_string,
            fail_info,
        } => {
            assert_eq!(status, 2);
            assert_eq!(status_name, "rejection");
            assert!(
                status_string
                    .iter()
                    .any(|value| value.contains("Message digest algorithm is not supported")),
                "{status_string:?}"
            );
            assert_eq!(fail_info, vec!["badAlg".to_string()]);
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[test]
fn corrupted_signer_certificate_fails_only_the_certificate_checks() {
    let mut response = fixture_response();
    let cert = fixture_cert_der();
    let offset = response
        .windows(cert.len())
        .position(|window| window == cert.as_slice())
        .expect("certificate must appear verbatim in the token");
    // Flip the [0] version tag inside the certificate: x509-parser refuses it,
    // while the surrounding CMS structure still parses (the certificate is an
    // opaque SEQUENCE to the DER walker).
    assert_eq!(response[offset + 8], 0xA0);
    response[offset + 8] = 0xB0;

    let evidence = verify_response(
        &response,
        &TimestampVerificationRequest {
            document: FIXTURE_DOCUMENT,
            nonce: FIXTURE_NONCE,
            algorithm: HashAlgorithm::Sha256,
            tolerance_secs: 300,
            now: fixture_now(),
            tsa_url: None,
        },
    )
    .expect("the token still parses; the certificate failure is a named check");
    assert!(!evidence.all_passed());
    assert_fail_contains(
        timestamp_outcome(&evidence, "signer_certificate_parses"),
        "not a parseable X.509 certificate",
    );
    assert!(evidence.signer_certificate.is_none());
    // The content checks do not depend on the certificate.
    for id in [
        "imprint_matches_document",
        "nonce_matches_request",
        "gen_time_parses",
        "gen_time_within_tolerance",
        "digest_algorithm_accepted",
        "signed_attrs_message_digest_matches_econtent",
    ] {
        assert_eq!(timestamp_outcome(&evidence, id), &CheckOutcome::Pass, "{id}");
    }
    // Signature checks cannot run without a public key, and say so.
    assert!(timestamp_outcome(&evidence, "token_signature_valid").is_not_performed());
    assert!(timestamp_outcome(&evidence, "ess_signing_certificate_hash_matches_certificate")
        .is_not_performed());
}

#[test]
fn corrupted_signature_fails_only_the_signature_check() {
    let mut response = fixture_response();
    let signature = fixture_signature();
    let offset = response
        .windows(signature.len())
        .position(|window| window == signature.as_slice())
        .expect("signature must appear verbatim in the token");
    response[offset + 7] ^= 0x01;

    let evidence = verify_response(
        &response,
        &TimestampVerificationRequest {
            document: FIXTURE_DOCUMENT,
            nonce: FIXTURE_NONCE,
            algorithm: HashAlgorithm::Sha256,
            tolerance_secs: 300,
            now: fixture_now(),
            tsa_url: None,
        },
    )
    .expect("the token still parses; the signature failure is a named check");
    assert!(!evidence.all_passed());
    assert_fail_contains(
        timestamp_outcome(&evidence, "token_signature_valid"),
        "did not verify",
    );
    for id in [
        "imprint_matches_document",
        "nonce_matches_request",
        "signer_certificate_parses",
        "signed_attrs_message_digest_matches_econtent",
        "ess_signing_certificate_hash_matches_certificate",
    ] {
        assert_eq!(timestamp_outcome(&evidence, id), &CheckOutcome::Pass, "{id}");
    }
}

#[test]
fn hostile_responses_are_rejected_without_panicking() {
    let response = fixture_response();
    let request = TimestampVerificationRequest {
        document: FIXTURE_DOCUMENT,
        nonce: FIXTURE_NONCE,
        algorithm: HashAlgorithm::Sha256,
        tolerance_secs: 300,
        now: fixture_now(),
        tsa_url: None,
    };

    // Truncation at many lengths: always a typed DER error, never a panic.
    for cut in [1usize, 2, 5, 50, 500, 2000, response.len() - 1] {
        let error = verify_response(&response[..cut], &request).expect_err("truncated");
        assert!(
            matches!(error, TimeStampError::MalformedDer(_)),
            "cut {cut}: {error:?}"
        );
    }

    // Trailing garbage.
    let mut trailing = response.clone();
    trailing.extend_from_slice(&[0x00, 0x01]);
    match verify_response(&trailing, &request) {
        Err(TimeStampError::MalformedDer(DerError::TrailingGarbage { remaining: 2 })) => {}
        other => panic!("expected trailing garbage, got {other:?}"),
    }

    // A huge declared length (4-byte length of 2^32-1) must be refused before
    // any slicing or allocation.
    let mut huge = vec![0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF];
    huge.extend_from_slice(&response[5..]);
    match verify_response(&huge, &request) {
        Err(TimeStampError::MalformedDer(DerError::ElementTooLarge { .. })) => {}
        other => panic!("expected ElementTooLarge, got {other:?}"),
    }

    // Deep nesting: a structurally valid but deeply nested blob.
    let mut deep = der::sequence(&[der::tlv(der::TAG_SEQUENCE, &[0x02, 0x01, 0x00])]);
    for _ in 0..60 {
        deep = der::sequence(&[deep]);
    }
    assert!(verify_response(&deep, &request).is_err());

    // Indefinite length, over-long length, wrong top-level tag.
    for blob in [
        vec![0x30u8, 0x80, 0x00, 0x00],
        vec![0x30u8, 0x82, 0x00, 0x02, 0x05, 0x00],
        vec![0x31u8, 0x00],
    ] {
        assert!(verify_response(&blob, &request).is_err(), "{blob:?}");
    }

    // Byte-flood: every single-byte mutation must terminate (Ok or Err, but
    // never a panic).
    for index in 0..response.len() {
        let mut mutated = response.clone();
        mutated[index] = 0xFF;
        let _ = verify_response(&mutated, &request);
    }
}

#[test]
fn request_building_round_trips_for_sha256_and_sha512() {
    for algorithm in [HashAlgorithm::Sha256, HashAlgorithm::Sha512] {
        let nonce = 0x9F0E_1D2C_3B4A_5968u64;
        let der_bytes = build_request(FIXTURE_DOCUMENT, algorithm, nonce, true).expect("build");
        let parsed = parse_request(&der_bytes).expect("parse");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.imprint_algorithm_oid, algorithm.oid());
        assert_eq!(parsed.imprint, algorithm.digest(FIXTURE_DOCUMENT));
        assert_eq!(parsed.nonce, Some(nonce));
        assert!(parsed.cert_req);
        // certReq=true must be an explicit BOOLEAN TRUE in DER terms.
        assert!(der_bytes.windows(3).any(|window| window == [0x01, 0x01, 0xFF]));
    }

    // A request without certReq omits the boolean (DEFAULT FALSE).
    let der_bytes = build_request(b"x", HashAlgorithm::Sha256, 1, false).expect("build");
    let parsed = parse_request(&der_bytes).expect("parse");
    assert!(!parsed.cert_req);

    // Hostile request bytes must be refused, not panic.
    for blob in [vec![], vec![0x30, 0x01, 0x05], vec![0x30, 0x03, 0x02, 0x01, 0xFF]] {
        assert!(parse_request(&blob).is_err(), "{blob:?}");
    }
}

// ── Fail-closed configuration ──────────────────────────────────────────────

#[test]
fn no_configured_tsa_means_no_timestamp() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let error = runtime
        .block_on(timestamp_document(None, FIXTURE_DOCUMENT, HashAlgorithm::Sha256))
        .expect_err("must fail closed");
    assert!(matches!(error, TimeStampError::NotConfigured));
    // No URL, no client, no network call: the error is produced before any
    // transport object exists.
    assert!(error.to_string().contains("APEXMAIL_TSA_URL"));

    // A configured client with an unreachable endpoint produces a transport
    // error, never a fabricated token.
    let config = compliance::signing::timestamp::TsaConfig::new("http://127.0.0.1:9/tsa")
        .expect("config")
        .with_timeout_secs(1);
    let error = runtime
        .block_on(timestamp_document(Some(&config), FIXTURE_DOCUMENT, HashAlgorithm::Sha256))
        .expect_err("must fail");
    assert!(
        matches!(error, TimeStampError::Transport(_)),
        "expected Transport, got {error:?}"
    );
}

#[test]
fn invalid_tsa_urls_are_rejected_at_configuration_time() {
    for url in ["", "   ", "not a url", "ftp://tsa.example/", "http://", "https://"] {
        assert!(
            compliance::signing::timestamp::TsaConfig::new(url).is_err(),
            "accepted {url:?}"
        );
    }
    let config = compliance::signing::timestamp::TsaConfig::new(
        "https://tsa.example.test/rfc3161",
    )
    .expect("valid");
    assert!(config.describe().contains("tsa.example.test"));
    assert!(!config.describe().contains("Bearer"));
}

// ── Transport round trip against a loopback TSA ────────────────────────────

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n").map(|index| index + 4)
}

fn content_length(headers: &str) -> Option<usize> {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
}

/// A one-shot HTTP/1.1 server that answers one TSA request and reports the
/// request body it received.
async fn spawn_tsa_server<F>(make_response: F) -> (String, tokio::task::JoinHandle<Vec<u8>>)
where
    F: FnOnce(&[u8]) -> Vec<u8> + Send + 'static,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let read = socket.read(&mut chunk).await.expect("read");
            if read == 0 {
                return buffer;
            }
            buffer.extend_from_slice(&chunk[..read]);
            let Some(header_end) = find_header_end(&buffer) else {
                continue;
            };
            let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
            let Some(length) = content_length(&head) else {
                continue;
            };
            if buffer.len() < header_end + length {
                continue;
            }
            let body = buffer[header_end..header_end + length].to_vec();
            let response = make_response(&body);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            );
            socket.write_all(head.as_bytes()).await.expect("write head");
            socket.write_all(&response).await.expect("write body");
            socket.shutdown().await.ok();
            return body;
        }
    });
    (format!("http://127.0.0.1:{port}/tsa"), handle)
}

#[tokio::test]
async fn transport_rejects_a_response_for_a_foreign_nonce() {
    let (url, server) = spawn_tsa_server(|_body| fixture_response()).await;
    let config = compliance::signing::timestamp::TsaConfig::new(url)
        .expect("config")
        .with_timeout_secs(5);
    let client = TimeStampClient::new(config).expect("client");

    let error = client
        .timestamp_at(FIXTURE_DOCUMENT, HashAlgorithm::Sha256, fixture_now())
        .await
        .expect_err("the fixture nonce cannot match the freshly generated one");
    let evidence = match error {
        TimeStampError::VerificationFailed { failures, evidence } => {
            assert!(
                failures.iter().any(|check| check.check == "nonce_matches_request"),
                "{failures:?}"
            );
            evidence
        }
        other => panic!("expected VerificationFailed, got {other:?}"),
    };
    // The document and the token were still verified: only the exchange
    // binding failed.
    assert_eq!(
        timestamp_outcome(&evidence, "imprint_matches_document"),
        &CheckOutcome::Pass
    );
    assert!(
        evidence
            .tsa_url
            .as_deref()
            .unwrap_or_default()
            .starts_with("http://127.0.0.1:"),
        "{:?}",
        evidence.tsa_url
    );
    let request_body = server.await.expect("server task");
    let parsed = parse_request(&request_body).expect("server received a TimeStampReq");
    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.imprint, Sha256::digest(FIXTURE_DOCUMENT).to_vec());
    assert!(parsed.cert_req);
    assert_ne!(parsed.nonce, Some(FIXTURE_NONCE));
}

#[tokio::test]
async fn transport_accepts_a_response_with_the_matching_nonce() {
    // Patch the fixture's nonce with the one from the actual request. The
    // TSTInfo bytes change, so the signed messageDigest no longer matches the
    // eContent (re-signing is impossible without the TSA key): this proves
    // both that the transport round trip works and that the tamper check is
    // independent of the nonce check.
    let (url, server) = spawn_tsa_server(|body| {
        let parsed = parse_request(body).expect("request parses");
        let nonce = parsed.nonce.expect("nonce");
        let mut response = fixture_response();
        let old = [
            0x02, 0x09, 0x00, 0xD5, 0x7F, 0x3E, 0xDC, 0xB9, 0x2F, 0x41, 0x2D,
        ];
        let offset = response
            .windows(old.len())
            .position(|window| window == old)
            .expect("fixture nonce must appear exactly once");
        let mut new = vec![0x02, 0x09, 0x00];
        new.extend_from_slice(&nonce.to_be_bytes());
        response[offset..offset + old.len()].copy_from_slice(&new);
        response
    })
    .await;
    let config = compliance::signing::timestamp::TsaConfig::new(url)
        .expect("config")
        .with_timeout_secs(5);
    let client = TimeStampClient::new(config).expect("client");

    let error = client
        .timestamp_at(FIXTURE_DOCUMENT, HashAlgorithm::Sha256, fixture_now())
        .await
        .expect_err("tampered eContent must fail closed");
    let evidence = match error {
        TimeStampError::VerificationFailed { failures, evidence } => {
            assert!(
                failures
                    .iter()
                    .any(|check| check.check == "signed_attrs_message_digest_matches_econtent"),
                "{failures:?}"
            );
            evidence
        }
        other => panic!("expected VerificationFailed, got {other:?}"),
    };
    // The request binding succeeded; the content binding was caught.
    assert_eq!(
        timestamp_outcome(&evidence, "nonce_matches_request"),
        &CheckOutcome::Pass
    );
    assert_eq!(
        timestamp_outcome(&evidence, "imprint_matches_document"),
        &CheckOutcome::Pass
    );
    assert_eq!(
        timestamp_outcome(&evidence, "gen_time_within_tolerance"),
        &CheckOutcome::Pass
    );
    // The signature over the signed attributes is untouched.
    assert_eq!(
        timestamp_outcome(&evidence, "token_signature_valid"),
        &CheckOutcome::Pass
    );
    let request_body = server.await.expect("server task");
    let parsed = parse_request(&request_body).expect("request parses");
    assert_eq!(evidence.request_nonce, parsed.nonce.expect("nonce"));
}

// ── ASiC-E container ───────────────────────────────────────────────────────

#[test]
fn valid_asic_e_container_passes_every_check() {
    let evidence = verify_asic_e(&asic_members(FIXTURE_DOCUMENT, ASIC_SIGNATURES_XML));
    assert!(evidence.all_passed(), "{:#?}", evidence.failing_checks());
    assert!(
        evidence.strictly_passed(),
        "{:#?}",
        evidence.failing_checks()
    );
    assert_eq!(evidence.mimetype.as_deref(), Some(ASIC_E_MIMETYPE));
    assert_eq!(evidence.members.len(), 4);
    assert_eq!(evidence.signatures.len(), 1);

    for id in [
        "mimetype_member_present",
        "mimetype_exact",
        "signature_file_present",
        "all_container_files_signed",
    ] {
        assert_eq!(container_outcome(&evidence, id), &CheckOutcome::Pass, "{id}");
    }

    let signature = &evidence.signatures[0];
    assert_eq!(signature.signature_id.as_deref(), Some("signature-1"));
    assert_eq!(
        signature.signature_method.as_deref(),
        Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
    );
    for id in [
        "signed_info_present",
        "canonicalization_method_declared",
        "references_verified",
        "signer_certificate_present",
        "signer_certificate_parses",
        "signature_value_decodes",
        "signature_value_over_raw_signed_info",
        "signing_certificate_digest_matches_signer_certificate",
    ] {
        assert_eq!(
            signature_outcome(&evidence, 0, id),
            &CheckOutcome::Pass,
            "{id}"
        );
    }
    assert_eq!(signature.references.len(), 3);
    for reference in &signature.references {
        assert!(reference.ok, "{reference:?}");
        assert_eq!(reference.digest_algorithm_name.as_deref(), Some("sha256"));
    }
    // File references are required, the same-document reference is advisory
    // because this module does not canonicalize.
    assert!(reference_for(&evidence, 0, "document.txt").required);
    assert!(reference_for(&evidence, 0, "financials.csv").required);
    let signed_properties = reference_for(&evidence, 0, "#signed-properties-1");
    assert!(signed_properties.is_same_document);
    assert!(!signed_properties.required);
    // The XAdES certificate digest binds the SigningCertificateV2 to the
    // signing certificate.
    assert!(evidence.signatures[0].signer_certificate.is_some());
}

#[test]
fn corrupted_document_fails_its_reference_digest_only() {
    let mut document = FIXTURE_DOCUMENT.to_vec();
    document[0] ^= 0x40;
    let evidence = verify_asic_e(&asic_members(&document, ASIC_SIGNATURES_XML));
    assert!(!evidence.all_passed());
    let failure = reference_for(&evidence, 0, "document.txt");
    assert!(!failure.ok);
    assert!(failure.detail.contains("digest mismatch"), "{failure:?}");
    assert_ne!(
        failure.expected_digest_hex,
        failure.actual_digest_hex.clone().unwrap_or_default()
    );
    assert!(reference_for(&evidence, 0, "financials.csv").ok);
    assert!(reference_for(&evidence, 0, "#signed-properties-1").ok);
    assert_fail_contains(
        signature_outcome(&evidence, 0, "references_verified"),
        "document.txt",
    );
    // The signature itself is still valid: it covers the SignedInfo octets,
    // not the document bytes.
    assert_eq!(
        signature_outcome(&evidence, 0, "signature_value_over_raw_signed_info"),
        &CheckOutcome::Pass
    );
}

#[test]
fn corrupted_mimetype_fails_the_media_type_check() {
    let mut members = asic_members(FIXTURE_DOCUMENT, ASIC_SIGNATURES_XML);
    members[0] = ContainerMember::new("mimetype", b"application/zip".to_vec());
    let evidence = verify_asic_e(&members);
    assert!(!evidence.all_passed());
    assert_fail_contains(container_outcome(&evidence, "mimetype_exact"), "application/zip");
    // Nothing else is perturbed.
    assert_eq!(
        container_outcome(&evidence, "all_container_files_signed"),
        &CheckOutcome::Pass
    );
}

#[test]
fn trailing_newline_in_mimetype_is_rejected() {
    let mut members = asic_members(FIXTURE_DOCUMENT, ASIC_SIGNATURES_XML);
    let mut mimetype = ASIC_E_MIMETYPE.as_bytes().to_vec();
    mimetype.push(b'\n');
    members[0] = ContainerMember::new("mimetype", mimetype);
    let evidence = verify_asic_e(&members);
    assert!(!evidence.all_passed());
    assert_fail_contains(container_outcome(&evidence, "mimetype_exact"), "\\n");
}

#[test]
fn malformed_signature_xml_fails_the_parse_check() {
    let evidence = verify_asic_e(&asic_members(
        FIXTURE_DOCUMENT,
        "<ds:Signature><ds:SignedInfo></ds:Signature>",
    ));
    assert!(!evidence.all_passed());
    let outcome = evidence
        .container_checks
        .iter()
        .find(|check| check.check.starts_with("signatures_xml_parses"))
        .expect("parse check");
    assert!(outcome.outcome.is_fail(), "{outcome:?}");
    assert!(evidence.signatures.is_empty());

    // Well-formed XML that is not a signature at all fails differently.
    let evidence = verify_asic_e(&asic_members(FIXTURE_DOCUMENT, "<hello>world</hello>"));
    assert!(!evidence.all_passed());
    assert_fail_contains(
        container_outcome(&evidence, "signature_present[META-INF/signatures.xml]"),
        "no ds:Signature element",
    );
}

#[test]
fn missing_member_fails_the_reference() {
    let mut members = asic_members(FIXTURE_DOCUMENT, ASIC_SIGNATURES_XML);
    members.retain(|member| member.path != "document.txt");
    let evidence = verify_asic_e(&members);
    assert!(!evidence.all_passed());
    let failure = reference_for(&evidence, 0, "document.txt");
    assert!(!failure.ok);
    assert!(
        failure.detail.contains("no container member matches"),
        "{failure:?}"
    );
}

#[test]
fn unsigned_extra_member_fails_coverage() {
    let mut members = asic_members(FIXTURE_DOCUMENT, ASIC_SIGNATURES_XML);
    members.push(ContainerMember::new("notes.txt", b"unsigned".to_vec()));
    let evidence = verify_asic_e(&members);
    assert!(!evidence.all_passed());
    assert_fail_contains(
        container_outcome(&evidence, "all_container_files_signed"),
        "notes.txt",
    );
}

#[test]
fn tampered_signed_info_fails_the_signature_value_check() {
    // "rsa-sha256" -> "rsa-sha512" keeps the XML well-formed but changes the
    // SignedInfo octets that the signature covers.
    let tampered = ASIC_SIGNATURES_XML.replace("rsa-sha256", "rsa-sha512");
    assert_ne!(tampered, ASIC_SIGNATURES_XML);
    let evidence = verify_asic_e(&asic_members(FIXTURE_DOCUMENT, &tampered));
    assert!(!evidence.all_passed());
    assert_fail_contains(
        signature_outcome(&evidence, 0, "signature_value_over_raw_signed_info"),
        "did not verify",
    );
    // References are unaffected by the SignatureMethod change.
    assert!(reference_for(&evidence, 0, "document.txt").ok);
}

#[test]
fn external_reference_is_refused() {
    let tampered =
        ASIC_SIGNATURES_XML.replace("URI=\"document.txt\"", "URI=\"https://evil.example/doc\"");
    assert_ne!(tampered, ASIC_SIGNATURES_XML);
    let evidence = verify_asic_e(&asic_members(FIXTURE_DOCUMENT, &tampered));
    assert!(!evidence.all_passed());
    let failure = reference_for(&evidence, 0, "https://evil.example/doc");
    assert!(!failure.ok);
    assert!(failure.required);
    assert!(resolve_member_uri(&[], "https://evil.example/doc").is_none());
    assert!(resolve_member_uri(&[], "../escape.txt").is_none());
    assert!(resolve_member_uri(&[], "a%2e%2e/b").is_none());
}

#[test]
fn missing_signature_file_and_mimetype_are_reported() {
    let evidence = verify_asic_e(&[ContainerMember::new("document.txt", b"x".to_vec())]);
    assert!(!evidence.all_passed());
    assert!(container_outcome(&evidence, "mimetype_member_present").is_fail());
    assert!(container_outcome(&evidence, "signature_file_present").is_fail());
    assert!(evidence.mimetype.is_none());
}

#[test]
fn evidence_records_are_serialisable_and_carry_the_audit_lists() {
    let timestamp_evidence =
        verify_fixture(FIXTURE_DOCUMENT, FIXTURE_NONCE, fixture_now(), 300).expect("verify");
    let json = serde_json::to_value(&timestamp_evidence).expect("serialise");
    assert_eq!(json["schema_version"], json!(1));
    assert_eq!(json["request_nonce_hex"], json!("0xD57F3EDCB92F412D"));
    assert_eq!(json["policy_oid"], json!(FIXTURE_POLICY));
    assert_eq!(json["signer_certificate"]["serial_hex"], json!("5a504558"));
    assert!(json["proven_properties"].as_array().expect("proven").len() >= 5);
    assert!(json["not_proven_properties"].as_array().expect("not proven").len() >= 4);
    let decoded: TimeStampEvidence = serde_json::from_value(json).expect("round trip");
    assert_eq!(decoded, timestamp_evidence);

    let container_evidence = verify_asic_e(&asic_members(FIXTURE_DOCUMENT, ASIC_SIGNATURES_XML));
    let json = serde_json::to_value(&container_evidence).expect("serialise");
    assert_eq!(json["members"][0]["path"], json!("mimetype"));
    assert_eq!(json["signatures"][0]["references"][0]["uri"], json!("document.txt"));
    assert!(json["not_proven_properties"]
        .as_array()
        .expect("not proven")
        .iter()
        .any(|line| line.as_str().unwrap_or_default().contains("canonicalization")));
    let decoded: AsicEvidence = serde_json::from_value(json).expect("round trip");
    assert_eq!(decoded, container_evidence);
}

/// The check helpers are part of the public API surface used by callers that
/// build their own policy on top of the evidence.
#[test]
fn check_verdict_helpers_behave() {
    let pass = CheckVerdict::pass("x", true);
    let fail = CheckVerdict::fail("y", true, "boom");
    let skipped = CheckVerdict::not_performed("z", false, "unsupported");
    assert!(pass.is_pass());
    assert!(fail.outcome.is_fail());
    assert!(skipped.outcome.is_not_performed());
    // A skipped optional check does not block the baseline gate; a skipped
    // required check would.
    assert!(compliance::signing::all_passed(&[pass.clone(), skipped.clone()]));
    assert!(compliance::signing::all_passed(&[pass.clone()]));
    assert!(!compliance::signing::all_passed(&[CheckVerdict::not_performed(
        "required-skip",
        true,
        "unsupported"
    )]));
    assert!(compliance::signing::has_failures(&[pass.clone(), fail.clone()]));
    assert!(!compliance::signing::strictly_passed(&[pass.clone(), skipped.clone()]));
    assert!(compliance::signing::strictly_passed(&[pass.clone()]));
    let with_note = CheckVerdict::pass("n", true).with_note("context");
    assert_eq!(with_note.note.as_deref(), Some("context"));
    assert_eq!(
        compliance::signing::describe_failures(&[pass, fail]),
        "y failed (boom)"
    );
}
