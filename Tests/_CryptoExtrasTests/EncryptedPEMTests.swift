
import XCTest
import _CryptoExtras

final class EncryptedPEMTests: XCTestCase {
    func testPBES2WithAES128EncryptedKeyInit() {
        let pbes2WithAES128EncryptedPrivateKey = """
        -----BEGIN ENCRYPTED PRIVATE KEY-----
        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
        -----END ENCRYPTED PRIVATE KEY-----
        """

        XCTAssertNoThrow(
            try _RSA.Signing.PrivateKey(
                encryptedPEMRepresentation: pbes2WithAES128EncryptedPrivateKey,
                encryptionPassword: "foobar"
            )
        )
        XCTAssertThrowsError(
            try _RSA.Signing.PrivateKey(
                encryptedPEMRepresentation: pbes2WithAES128EncryptedPrivateKey,
                encryptionPassword: "wrong"
            )
        )
    }
    
    func testPBES2WithTripleDESKeyEncryptedKeyInit() {
        let pbes2WithTripleDESEncryptedPrivateKey = """
        -----BEGIN ENCRYPTED PRIVATE KEY-----
        MIIFJDBWBgkqhkiG9w0BBQ0wSTAxBgkqhkiG9w0BBQwwJAQQ8HZLW3BDKXdsGjxA
        5BM8GgICCAAwDAYIKoZIhvcNAgkFADAUBggqhkiG9w0DBwQIUo0QnIb9O+wEggTI
        GqGG0X9OWxs8opGqJ6ynfJzCUy1TJh9CGJgBBVOMS8zqz7qAkBCKhT+VPCtn7W0g
        GTf+OhOkj7YnmN/GSwbih/O33NFXoVQrP+kJOTRYFne2zVQ5KvG48oN3P7T4tHMP
        zRqq7+qpz6Y0906z/6RmVZWEPryAb0xYEd2DhdX4wBMyHfTf28u10ivEsfTWa5/5
        /n4ENmwAce2MLUbvNGgtXvgbiDn5ITj17Reyal3hTzRoL3J6kLj6xFpBkaAAvvQP
        O8FGaVuvi4seeWPVAwwuksRiCwA+wPi3eyREPwG8Q4tS2IKwJqUrbPjrIhxl7HwK
        bb2iaQ+es+FZIHXHWvfWiEUyDs2OMcErlUqx8Qaf9K/3o8KFdyqZ7qOKNjK+Z0BC
        AHelXjvO62N/sNoK8318LYOkCZ1Wd820JdSTac3AVy9BGQRu7GfhcpjjNbOxsjhz
        HSnrZR8PIRNujTyLC8b2fzsTpDNLUE6KYiNzZWfUDOVMmm9xi64kwCMvsKsLd47n
        4VdaPHaqqSA3XkXIDyqAZUKo6r2CUkJH6CYKuVLl6GsA6lLFxVCHtdbQu6MopymO
        0+XkLTJrZItEB4ZIbtG88/ubnYOPqOn7Jvi7W8TEDBXw9inGO4osj7wSnWNEsTRx
        8P/uF9ygpKTANuR84welaJk6c3pxf96esfmxkp7XxGdRx9o0OWbSqB1C4LUjWmKs
        LpPF8TvnzFlZyfyW5VyzOs8/4zNO7B0S6X5Ywwytobo0G0/6/eilFIPGZfLTz7gw
        2LPMYKgi+OjE27KGUS3fSDlVkcQqrfrADchtEM6bSYHU1B0K8QE2bkRVM97DRVTv
        lngqxvr9yeE+ILCGOf/kTfqGqvoampUUUUMi8is80oSlSVApYiZ3uWJWOMsHlH7X
        H1sONAARzhbm+BQ7QRFTH41mMmHIzNSuXVYItRxbC4VkbRqMzLCfZtsCCZ7Mupo7
        a9FdDMDsLeA28EDTESzWEPREk4i0wvJ1QRLdQFJ9GL+RP/YsV1GEwRqHu9lsZCAL
        Oz83V41/NfSuTrykZFKaLA2D4DjVGbyinxxcThUL/3u3k98EjBKdfMj6wMF8hKCx
        eYvowNOJUdMG3+i7Bo5rKhKZ5mIeRP3MGvelvSQ8gXm03pM255iDV441Ir4F/mpJ
        TaMXySqhZef4Ls6tkxsq7E2mXhsPkJVy/hSmnbqZi3FltMGvkbiM3aqNJQcG67mO
        NX66Zlbb8JHi6OG8o7H3u6i3BTeyvQkPO0n+sUWrYo1vqemykDUHAdqLdSIdC4pb
        kCvRncCw729CD1B3IVkvSZ6NTqNxGCqmc1g/6bkqCaNOXXOqiT4Fzxxv+FCt2sGf
        m2G8BvdBVILRRVSGgmG7ahvIY5O+911duS6vkzoxF39VJjrYXcqzKRh71zfAM3J0
        h9GLgrI+lZ7HYCi4eDsSMOdARfL6C7beA6Jaa4snHfGNNrwCECuV0zKrB61n33nN
        wE1Nc+gPZ4rbYeYUa8EvdchNB5JdMTyKqOAHrHrM4EberwnZAZMk4Aal/PLAup5L
        mrdalZF0qlLUetwUPmAGMuW34igiV084ecKxsuZWXvKtLTHhiTN4NYBgV2rvJ2LE
        PRiLIoKv+M+qjywhjPeQbD70byOdIx5J
        -----END ENCRYPTED PRIVATE KEY-----
        """
        
        XCTAssertNoThrow(
            try _RSA.Signing.PrivateKey(
                encryptedPEMRepresentation: pbes2WithTripleDESEncryptedPrivateKey,
                encryptionPassword: "foobar"
            )
        )
        XCTAssertThrowsError(
            try _RSA.Signing.PrivateKey(
                encryptedPEMRepresentation: pbes2WithTripleDESEncryptedPrivateKey,
                encryptionPassword: "wrong"
            )
        )
    }
}
