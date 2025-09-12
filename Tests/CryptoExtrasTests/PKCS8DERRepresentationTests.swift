//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import Foundation
import XCTest

@testable import CryptoExtras

final class PKCS8DERRepresentationTests: XCTestCase {
    func test_RSA() {
        let rsaPrivateKeyPEM = """
            -----BEGIN RSA PRIVATE KEY-----
            MIIEpQIBAAKCAQEAxeBrlW1i+gXmqC/4XlTppLCXPpksZbxsc0AufsWzpcIxBAQL
            jr4LxXyOenZcyhrdXxksEsCJE/8stJuUZgiFyDMesWjoL5bYyOpWrwPyvCMNaC8F
            15cKe5n7OSVNU312X0ZSxTZAOrCEH0kGrsXoQn5JgHygVXejSPlHw8F1Pwps3pnc
            cRYE9vsHZegspUI3DaqWgmewFWz6jSMY0v1DcZv2Xw+pMLeXEpKKMf+eo90mHShh
            n8FijsI1tFuYD++LmM/e1TV1z+W2sPL2CaosBO890WeCyL/bFl4j1lmdnXdBNX+l
            ub/5HTqI7hxAm/qonzDs3iV5KK1ZWZTVsPyqtwIDAQABAoIBAQCGLBQG8HMKgXHT
            XSOWIxGCIFONmKMoIMmQpFZik3+qx7AgvvVvRqIIuNqLYzKrv+eXEiR2WqMYMhCI
            Lm5DeUftZexL84xsqGY6Zdt9NLoko8f1et0FQF9VTCWyq/5wvEPFepOpMY3/vaz4
            4bVsULmaTLNeMiMtkL/hPVZSAB2WLjI7EgOq7JamRBCMY+ivtdtqi12kO8vaA2Ns
            dSKuU+e8tvAP4o6cMvuLtcqLy2UeoZzYTI998up0tqn+mGHl0DHx6MSi/TbVv3v8
            gSQGlBvWzUx85vz+1GyjRn+o4hO/tibtP6aKfWYztIyLgkaU8JuDZzT+CwwmCnEH
            ge/JmGuRAoGBAPypZ9MuWi1Ms57nVcpHRSHUc+cO/CfoaC4kRzgh99ApDbL+rj78
            9eXkS10Z8hTLQprcznQr+WZhnhNw13PrvzaGhtOXd/xLBnWlqZ6aIGYrJgKu+JLl
            yGVBZByG70yXel8IZt9l4CYctlS4D8iYAtdR+CCn8XGrc8JILnwBbYDNAoGBAMh9
            tiC8hyIc/wBV/WcgtpY6tPkrN4uw6WREH+UkVpvNM2kMMCgn1YLHbYq1vSKN3rKZ
            L9Ep4+8umRMg5yTgq9iURMoNjq+qU8NDF0nRljmyJRvgA5Ez2iQErm3y5dYxK+8w
            BRvCkDeOiiu1Mnd9chgu0tQhpfo7o+T3XeXB5omTAoGBAKl3IqlVnKxnls6NEVC0
            Tt0q93ZR6bUGv+G6+X3f4qxe7M5S3iJnXrMMVbQjc+iYkJr4YQ0wdX5DGVimxgv9
            Ymo6/vGq1ZKF69Y7ADLd479DT6JbI2S79JZdrr0nkBfKPgzBwOY0GYzWk0Dtl8CO
            nNE5LHkSy/HW8rSr32nTN1Q9AoGAOdl8GcoMO92d/pzRN1aLGKHr4hGEP3xWe6Xk
            hhuMGfyFnwPzSULlKo0coG98GWJSJbppv7KUoEkTxh8yUsO5Eg8GIj7zMuC0tpy/
            NX+SFye96WMj5FvPz6DCK9twUfNyN9vlPXNQZZdtatsnqq65oxyvnKHw4FkhG0n8
            //SI7p0CgYEA9CoA6/3rRIVKKEOgeCQHDVKIJIauTUskwdrBHLVU7SH+cfQ6VNy6
            zp/M54MpUP5jviSL61HmRoEqqcMWLALJHyZ1yQAZXSpthyMw0ahqTUZ71j1ukIO0
            UUjK3drJJd2jGQ0LfhlDCX7VmURIqJ6kaQ0WBNAJLFhTW4AS8HGYRZk=
            -----END RSA PRIVATE KEY-----
            """

        // Same key in PKCS8 DER representation.
        let encodedPKCS8DER =
            "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDF4GuVbWL6BeaoL/heVOmksJc+mSxlvGxzQC5+xbOlwjEEBAuOvgvFfI56dlzKGt1fGSwSwIkT/yy0m5RmCIXIMx6xaOgvltjI6lavA/K8Iw1oLwXXlwp7mfs5JU1TfXZfRlLFNkA6sIQfSQauxehCfkmAfKBVd6NI+UfDwXU/CmzemdxxFgT2+wdl6CylQjcNqpaCZ7AVbPqNIxjS/UNxm/ZfD6kwt5cSkoox/56j3SYdKGGfwWKOwjW0W5gP74uYz97VNXXP5baw8vYJqiwE7z3RZ4LIv9sWXiPWWZ2dd0E1f6W5v/kdOojuHECb+qifMOzeJXkorVlZlNWw/Kq3AgMBAAECggEBAIYsFAbwcwqBcdNdI5YjEYIgU42YoyggyZCkVmKTf6rHsCC+9W9Gogi42otjMqu/55cSJHZaoxgyEIgubkN5R+1l7EvzjGyoZjpl2300uiSjx/V63QVAX1VMJbKr/nC8Q8V6k6kxjf+9rPjhtWxQuZpMs14yIy2Qv+E9VlIAHZYuMjsSA6rslqZEEIxj6K+122qLXaQ7y9oDY2x1Iq5T57y28A/ijpwy+4u1yovLZR6hnNhMj33y6nS2qf6YYeXQMfHoxKL9NtW/e/yBJAaUG9bNTHzm/P7UbKNGf6jiE7+2Ju0/pop9ZjO0jIuCRpTwm4NnNP4LDCYKcQeB78mYa5ECgYEA/Kln0y5aLUyznudVykdFIdRz5w78J+hoLiRHOCH30CkNsv6uPvz15eRLXRnyFMtCmtzOdCv5ZmGeE3DXc+u/NoaG05d3/EsGdaWpnpogZismAq74kuXIZUFkHIbvTJd6Xwhm32XgJhy2VLgPyJgC11H4IKfxcatzwkgufAFtgM0CgYEAyH22ILyHIhz/AFX9ZyC2ljq0+Ss3i7DpZEQf5SRWm80zaQwwKCfVgsdtirW9Io3espkv0Snj7y6ZEyDnJOCr2JREyg2Or6pTw0MXSdGWObIlG+ADkTPaJASubfLl1jEr7zAFG8KQN46KK7Uyd31yGC7S1CGl+juj5Pdd5cHmiZMCgYEAqXciqVWcrGeWzo0RULRO3Sr3dlHptQa/4br5fd/irF7szlLeImdeswxVtCNz6JiQmvhhDTB1fkMZWKbGC/1iajr+8arVkoXr1jsAMt3jv0NPolsjZLv0ll2uvSeQF8o+DMHA5jQZjNaTQO2XwI6c0TkseRLL8dbytKvfadM3VD0CgYA52XwZygw73Z3+nNE3VosYoeviEYQ/fFZ7peSGG4wZ/IWfA/NJQuUqjRygb3wZYlIlumm/spSgSRPGHzJSw7kSDwYiPvMy4LS2nL81f5IXJ73pYyPkW8/PoMIr23BR83I32+U9c1Bll21q2yeqrrmjHK+cofDgWSEbSfz/9IjunQKBgQD0KgDr/etEhUooQ6B4JAcNUogkhq5NSyTB2sEctVTtIf5x9DpU3LrOn8zngylQ/mO+JIvrUeZGgSqpwxYsAskfJnXJABldKm2HIzDRqGpNRnvWPW6Qg7RRSMrd2skl3aMZDQt+GUMJftWZREionqRpDRYE0AksWFNbgBLwcZhFmQ=="
        let rsaPrivateKeyPKCS8DER = Data(base64Encoded: encodedPKCS8DER)!

        // Create private keys from both representations of the same key
        let keyFromPEM = try! _RSA.Signing.PrivateKey(pemRepresentation: rsaPrivateKeyPEM)
        let keyFromDER = try! _RSA.Signing.PrivateKey(derRepresentation: rsaPrivateKeyPKCS8DER)

        XCTAssertEqual(keyFromDER.keySizeInBits, 2048)
        XCTAssertEqual(keyFromPEM.keySizeInBits, 2048)

        // The keys match
        XCTAssertEqual(keyFromPEM.derRepresentation, keyFromDER.derRepresentation)

        // Our property creates the expected representation
        XCTAssertEqual(keyFromPEM.pkcs8DERRepresentation, rsaPrivateKeyPKCS8DER)
    }

    func test_ed25519() {
        let privateKeyPEM = """
            -----BEGIN PRIVATE KEY-----
            MC4CAQAwBQYDK2VwBCIEIFSrpkDrDWBMoz/YWjFaW9t4TQaKWyalZ6TRDUS/4+LE
            -----END PRIVATE KEY-----
            """

        // Same key in PKCS8 DER representation.
        let privateKeyPKCS8DER = Data(
            base64Encoded:
                "MC4CAQAwBQYDK2VwBCIEIFSrpkDrDWBMoz/YWjFaW9t4TQaKWyalZ6TRDUS/4+LE"
        )!

        // We only need the 32 bytes of the key.
        let document = try! ASN1.PEMDocument(pemString: privateKeyPEM)
        var bytes = document.derBytes
        bytes.removeFirst(bytes.count - 32)

        let keyFromDER = try! Curve25519.Signing.PrivateKey(rawRepresentation: bytes)

        let pkcs8 = keyFromDER.pkcs8DERRepresentation

        XCTAssertEqual(pkcs8, privateKeyPKCS8DER)
    }

    func test_ed25519_rfc_example() {
        // Example key from RFC 8410, Section 10.3.
        // Create private key from bytes.
        let keyBytes = Data(
            base64Encoded:
                "1O5y2/kTWErVttjx92n4rTr+fCjL8dT74Jeoj0R1WEI="
        )!
        // Same key in PKCS8 DER representation.
        let exampleKeyPKCS8DER = Data(
            base64Encoded:
                "MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC"
        )!

        // Create key from the private key bytes and compare our exported representation.
        let exampleKey = try! Curve25519.Signing.PrivateKey(rawRepresentation: keyBytes)

        XCTAssertEqual(exampleKey.pkcs8DERRepresentation, exampleKeyPKCS8DER)
    }

    func test_x25519() {
        let privateKeyPEM = """
            -----BEGIN PRIVATE KEY-----
            MC4CAQAwBQYDK2VuBCIEIKBtrFwBvmRtGZjMyj0rXewOQclz/8cdEY981glA/w5a
            -----END PRIVATE KEY-----
            """

        // Same key in PKCS8 DER representation.
        let privateKeyPKCS8DER = Data(
            base64Encoded:
                "MC4CAQAwBQYDK2VuBCIEIKBtrFwBvmRtGZjMyj0rXewOQclz/8cdEY981glA/w5a"
        )!

        // We only need the 32 bytes of the key.
        let document = try! ASN1.PEMDocument(pemString: privateKeyPEM)
        var bytes = document.derBytes
        bytes.removeFirst(bytes.count - 32)

        // Create key from the private key bytes and compare our exported representation.
        let keyFromDER = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: bytes)

        XCTAssertEqual(keyFromDER.pkcs8DERRepresentation, privateKeyPKCS8DER)
    }

    func test_P256() {
        let privateKeyPEM = """
            -----BEGIN PRIVATE KEY-----
            MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgO6fz+J/sZqbCki3h
            chsrVb69KW8q24pLDwotAtwz/gahRANCAASkBqszxMCGrd8l+xZitPto300blCWk
            wRCdoar3UeEEfuH5LsJ3kNjN+oMZmHAmnhHE6cqLHFem/ujsGgrqJ3E8
            -----END PRIVATE KEY-----
            """
        let encodedPKCS8DER =
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgO6fz+J/sZqbCki3hchsrVb69KW8q24pLDwotAtwz/gahRANCAASkBqszxMCGrd8l+xZitPto300blCWkwRCdoar3UeEEfuH5LsJ3kNjN+oMZmHAmnhHE6cqLHFem/ujsGgrqJ3E8"
        let privateKeyPKCS8DER = Data(base64Encoded: encodedPKCS8DER)!

        // Create key from PEM and compare our exported representation.
        let keyFromPEM = try! P256.Signing.PrivateKey(pemRepresentation: privateKeyPEM)

        XCTAssertEqual(keyFromPEM.pkcs8DERRepresentation, privateKeyPKCS8DER)
    }

    func test_P384() {
        let privateKeyPEM = """
            -----BEGIN PRIVATE KEY-----
            MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDD2qUnvEDviY5Hon7fx
            rsJmgWCGQcNlU+nXEWOoFPC49kioBm1hsveCH0q3vk9GjZKhZANiAAQFzxvdG2gI
            uWZfkAeMW2BzsKGdUWwybx8MHs8fv48MCPmfvL4kIvkU9T7F7diut41ciSzILv5/
            gb45xx6+dZjlWxIopstQuBu5v/J4oa3fgN1uYQJTSsKksDi3L52TcnY=
            -----END PRIVATE KEY-----
            """

        // Same key in PKCS8 DER representation.
        let encodedPKCS8DER =
            "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDD2qUnvEDviY5Hon7fxrsJmgWCGQcNlU+nXEWOoFPC49kioBm1hsveCH0q3vk9GjZKhZANiAAQFzxvdG2gIuWZfkAeMW2BzsKGdUWwybx8MHs8fv48MCPmfvL4kIvkU9T7F7diut41ciSzILv5/gb45xx6+dZjlWxIopstQuBu5v/J4oa3fgN1uYQJTSsKksDi3L52TcnY="
        let privateKeyPKCS8DER = Data(base64Encoded: encodedPKCS8DER)!

        // Create key from PEM and compare our exported representation.
        let keyFromPEM = try! P384.Signing.PrivateKey(pemRepresentation: privateKeyPEM)

        XCTAssertEqual(keyFromPEM.pkcs8DERRepresentation, privateKeyPKCS8DER)
    }

    func test_P521() {
        let privateKeyPEM = """
            -----BEGIN PRIVATE KEY-----
            MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBcQv0MVt8xb5teBQJ
            Mqn7wnQ2GVzgL+jkMERcMaABU7+UL7uC0ff+15RKEI2RwKLVUVvp3WJigCHBDpwY
            qI9OFnyhgYkDgYYABAD7PeX+GFUa99yyhYJ4WReKq2nLUOjo+ZZ+pdepc0EaESj+
            8o2Sv4mRjIU0s3WFTNx0mh9BKiszBNRu2nq148ZfCwAcAiJu4xcwR2o+L7BqNadJ
            1hCoVItbL61BWxAMITZPegQLMV1K7SMS6NNkYBBIh10Q870tBO26VJ5wMm5K46MA
            Cg==
            -----END PRIVATE KEY-----
            """

        // Same key in PKCS8 DER representation.
        let encodedPKCS8DER =
            "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBcQv0MVt8xb5teBQJMqn7wnQ2GVzgL+jkMERcMaABU7+UL7uC0ff+15RKEI2RwKLVUVvp3WJigCHBDpwYqI9OFnyhgYkDgYYABAD7PeX+GFUa99yyhYJ4WReKq2nLUOjo+ZZ+pdepc0EaESj+8o2Sv4mRjIU0s3WFTNx0mh9BKiszBNRu2nq148ZfCwAcAiJu4xcwR2o+L7BqNadJ1hCoVItbL61BWxAMITZPegQLMV1K7SMS6NNkYBBIh10Q870tBO26VJ5wMm5K46MACg=="
        let privateKeyPKCS8DER = Data(base64Encoded: encodedPKCS8DER)

        // Create key from PEM and compare our exported representation.
        let keyFromPEM = try! P521.Signing.PrivateKey(pemRepresentation: privateKeyPEM)

        XCTAssertEqual(keyFromPEM.pkcs8DERRepresentation, privateKeyPKCS8DER)
    }
}
