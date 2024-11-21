use rustls_cng::store::CertStore;

const PFX: &[u8] = include_bytes!("assets/rustls-ec.p12");
const PASSWORD: &str = "changeit";

#[test]
fn test_find_by_subject_str() {
    let store = CertStore::from_pkcs12(PFX, PASSWORD).expect("Cannot open cert store");

    let context = store
        .find_by_subject_str("rustls")
        .unwrap()
        .into_iter()
        .next();
    assert!(context.is_some());
}

#[test]
fn test_find_by_subject_name() {
    let store = CertStore::from_pkcs12(PFX, PASSWORD).expect("Cannot open cert store");

    let context = store
        .find_by_subject_name("CN=rustls-ec")
        .unwrap()
        .into_iter()
        .next();
    assert!(context.is_some());
}

#[test]
fn test_find_by_issuer_str() {
    let store = CertStore::from_pkcs12(PFX, PASSWORD).expect("Cannot open cert store");

    let context = store
        .find_by_issuer_str("Inforce")
        .unwrap()
        .into_iter()
        .next();
    assert!(context.is_some());
}

#[test]
fn test_find_by_issuer_name() {
    let store = CertStore::from_pkcs12(PFX, PASSWORD).expect("Cannot open cert store");

    let context = store
        .find_by_issuer_name("O=Inforce Technologies, CN=Inforce Technologies CA")
        .unwrap()
        .into_iter()
        .next();
    assert!(context.is_some());
}

#[test]
fn test_find_by_hash() {
    let store = CertStore::from_pkcs12(PFX, PASSWORD).expect("Cannot open cert store");

    let sha1 = [
        0x66, 0xBF, 0xFD, 0xE5, 0xD2, 0x9D, 0x57, 0x97, 0x1B, 0x17, 0xBB, 0x81, 0x5D, 0x7A, 0xF8,
        0x6D, 0x61, 0x91, 0xA8, 0xA7,
    ];
    let context = store.find_by_sha1(sha1).unwrap().into_iter().next();
    assert!(context.is_some());
}

#[test]
fn test_find_all() {
    let store = CertStore::from_pkcs12(PFX, PASSWORD).expect("Cannot open cert store");

    let context = store.find_all().unwrap().into_iter().next();
    assert!(context.is_some());
}
