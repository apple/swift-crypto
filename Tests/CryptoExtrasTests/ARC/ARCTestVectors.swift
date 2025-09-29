//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import Crypto
@testable import CryptoExtras
import XCTest

let ARCEncodedTestVector = """
[
  {
    "Credential": {
      "U": "033ee1ebbcff622bc26b10932ed1eb147226d832048fb2337dc0ad7722cb07483d",
      "U_prime": "02637fe04cc143281ee607bd8f898e670293dce44a2840b9cbb9e0d1fc7a2b29b4",
      "X1": "03c413230a9bd956718aa46138a33f774f4c708d61c1d6400d404243049d4a31dc",
      "m1": "eedfe7939e2382934ab5b0f76aae44124955d2c5ebf9b41d88786259c34692d2"
    },
    "CredentialRequest": {
      "m1": "eedfe7939e2382934ab5b0f76aae44124955d2c5ebf9b41d88786259c34692d2",
      "m1_enc": "03b8f11506a5302424143573e087fa20195cb5e893a67ef354eae3a78e263c54e4",
      "m2": "911fb315257d9ae29d47ecb48c6fa27074dee6860a0489f8db6ac9a486be6a3e",
      "m2_enc": "03f1ae4d7b78ba8030bd63859d4f4a909395c52bda34716b6620a2fdd52b336fc9",
      "proof": "0f361327abbc724ff0d37db365065bc4bd60e18125842bb4c03a7e5a632a1e95e74dcc440fcb9fb39106922e0d2544e6c82ca710abf35e8b10bf5d61296c9adb7d683eaed9a76a755b73f2b4b6e763a7c7883ce4b5c21bd02cd96b9af18cfb227f1acb4ead77c85049d291ed7841405610843f163e9cc2f6a8869111582324cd32bf13000c129d274ccf5386cb90e839916d5dff7eade18e3eabec415f613911",
      "r1": "008035081690bfde3b1e68b91443c22cc791d244340fe957d5aa44d7313740df",
      "r2": "d59c5e6ff560cc597c2b8ca25256c720bceca2ab03921492c5e9e4ad3b558002",
      "request_context": "74657374207265717565737420636f6e74657874"
    },
    "CredentialResponse": {
      "H_aux": "03d3cd09eeb8d19716586a49260c69309c495a717a36cad3381f6c02ac80b70e64",
      "U": "033ee1ebbcff622bc26b10932ed1eb147226d832048fb2337dc0ad7722cb07483d",
      "X0_aux": "02d453c121324114367906bd11ffc3b6e6a77b75382497279b1a60ab8412c1dec6",
      "X1_aux": "03b0e4b1f376c6207bf34efda46ce54b132a20b90bc28b9152f3e441fe2b508b63",
      "X2_aux": "0327369efcb7577abaeb7b56940e6e042126900bdf8bd8944c0adbb7be3ad98e2a",
      "b": "e699140babbe599f7dd8f6e3e8f615e5f201d1c2b0bc2f821f19e80a0a0e1e7b",
      "enc_U_prime": "035b8e09ce8776f1a2c7ef8610c9a6a39936c5666ab8b28d6629d3685056716482",
      "proof": "dd4596175db0b4273fcdff330370d2b5e7a4bf92bf518141f4553af37ef0e1260cb8312affc2462800adba102117448b449985d1704d8afd0df9ac708231561dca56faae325cb56b0a9e8ad07bdc6ce90f6e7430090e970a7240e289218de7a17672bea9a66187d102ffef976fb01af69d8d3aa3156a5a4223dc6d08b8ce9f1d2639a2edc7052404bf1410adf6c41465bd687e3dfa5372ea71f804b56d947bae9482e5707f42dbe35f8b0e11b4a0d27a5a01e1b9a75b66d82b7945eb0b002ee400bebcdc4c3133f804b22bd2d771762058cc35a5033365d2e15150fe46d3b0e98e18ee55f0451b0b171420f73592292e4ff50603c1f0d7769dbd090936090f63"
    },
    "Presentation1": {
      "U": "032704f22133d2ec70f9e6f4bbf64c582220b666f2e2c1d37c3f8995a2a5568c7e",
      "U_prime_commit": "03533cf1b2fd53a0716e02425eb42e4c55835aa6b2992d364cba70810d0f8aeb51",
      "a": "b78e57df8f0a95d102ff12bbb97e15ed35c23e54f9b4483d30b76772ee60d886",
      "m1_commit": "03e412408579105213ed10b6447c85bcd672ba73ecae1e21c463d0df4ef7beb814",
      "nonce": "0x0",
      "presentation_context": "746573742070726573656e746174696f6e20636f6e74657874",
      "proof": "a558da5f17c04adcb0898827aaded14be1dc612dcd12b0579c11bb387ce9ae4b7dbcb3bbe413caaaf754d99e5a342abb7e0041458d670f4b58eda37e745a675295d7a7b86248141d6547b53d793e5c77896ec4dc8dd438ab66d9c8b43ef6b060938a1ca793057b154970ebc3c7ec3a23134e0852d0041f9098ce77311e5b5eca0000000000000000000000000000000000000000000000000000000000000004",
      "r": "42252210dd60ddbbf1a57e3b144e26dd693b7644a9626a8c36896ede53d12930",
      "tag": "031a774fd87a8f18f6420bea43cf5425e7426eec8ba7b8df5c13dc05f10ec652d9",
      "z": "f5a4bbcf14e55e357df9f5ccb5ded37b2b14bc2e1a68e31f86416f0606ee75d1"
    },
    "Presentation2": {
      "U": "035fd233dee2c147155c6008ea64941b6ff7b315aced12531468f2e27bf22e3ef0",
      "U_prime_commit": "02434af337b87fd21d1e3d950aebfc8033a3d2e9dd2bb8b9e7953488078754496d",
      "a": "95bcf45150a61f5c44a6cfbf343cd9e0f593f127b6f49bec0f9b20f0550504a2",
      "m1_commit": "02a578fd3a84eb5b657367b02de39b45fd48ab7781ef8f94efe601274a5ded2a07",
      "nonce": "0x1",
      "presentation_context": "746573742070726573656e746174696f6e20636f6e74657874",
      "proof": "050965cde906fc4723333b100ce0fd9f7b026315f1db16984d4cccb2bc4aa65eb7a17f5b8dfe4f14d40006506ee5fb323e829dd4cb9dc3c455b2e04dd691600aec3cc3f1939198a80acb78b7f90b3bff769cab890f33e4d69b7c302d21ad35ec457d048d3ed7d13ee82c3c0aac2129ad0c8375cf29cd8ea3948a16b9247b1cc5faf69a3116f903b9dcccc4eff31f026041e49797b53c87eca66cfe1040187ef7",
      "r": "d7ed72750b6d366ed0febdc539b52d89434f468a578c59d7ca9015b7da240ad6",
      "tag": "03084fe6fff0ecc7c33ef5c49b492dda38083f52e9a2b70b88f3d4b4ba7b50afba",
      "z": "91eedfb168c556ff5ca3b89d047f482c9279b47f584aab6c7f895f7674251771"
    },
    "ServerKey": {
      "X0": "0232b5e93dc2ff489c20a986a84757c5cc4512f057e1ea92011a26d3ad2c56288d",
      "X1": "03c413230a9bd956718aa46138a33f774f4c708d61c1d6400d404243049d4a31dc",
      "X2": "02db00f6f8e6d235786a120017bd356fe1c9d09069d3ac9352cc9be10ef1505a55",
      "x0": "3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364",
      "x1": "f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1",
      "x2": "350e8040f828bf6ceca27405420cdf3d63cb3aef005f40ba51943c8026877963",
      "xb": "fd293126bb49a6d793cd77d7db960f5692fec3b7ec07602c60cd32aee595dffd"
    },
    "suite": "ARCV1-P256",
  },
  {
    "Credential": {
      "U": "02be890d43908e52ed43ae7bc7098f3a7694617fe44a88c33c6fa4eb9e942c0b2bb9d2fd56a44e1d6094fc7b9e8b949055",
      "U_prime": "02bec70edf38a3f5c77d5c6f39afd5f94cd266f958c804a954f6104b57a2c8310862a790cbc6b519f8db989d59aebaf081",
      "X1": "03ef0f59c9b0cc51c9e603dfcaa9a3e3719e186252b64f9ce1ebec352c5b605b805af308a9bd697df7c97b0f1147108c3a",
      "m1": "5a32aaf031be0555089356d299ce24b0eedfe7939e2382934ab5b0f76aae44124955d2c5ebf9b41d88786259c34692d2"
    },
    "CredentialRequest": {
      "m1": "5a32aaf031be0555089356d299ce24b0eedfe7939e2382934ab5b0f76aae44124955d2c5ebf9b41d88786259c34692d2",
      "m1_enc": "030a5167977e0c038a98fce96e127fc228aa58526f71a920044b74b2f22dd5839f0e1cf871e6419a1f522e94510ccf2d92",
      "m2": "ae93d3ea7e5856d5d951a0ae87f8845d767df2e97dd669c8025715e604cb1c43569792b6864f592fed3abe29b9ebc950",
      "m2_enc": "03a0fea0d3e83ee67b36cb86d8380d4b8420a75e23eb5dcb560a79e74d136cf3c382bff7576f7e50c2cd3d247b56dbf56d",
      "proof": "ec5a68b4b89b7c411d0073ec384c698016ecfeee8903b7c4cc6e63651a8544b4e06f2d61634a84304b4367bbca558609be6382768d7d070ea047831753b0c9add8db1e3bd9476d2661ac6109218cdccbe5b4250d3785b431114d9b53d66ff7cbc44a7ebbdf90dd5366187d7fbbb5d89f1e450ce8c87c75b94b726e931c81c963ba415eb0334a73b73379abdf34284410e079f18c8200b035b11ade92e8d5e381c1cd5d4db9bba5aff1fe97ce1cebf29dc9389aea13dd64fd8fb1779b6bb549af335d4b9c4603dce2a6bc5ca7b6d9c40287bf265f28c7b1d0b0e2300e5854361670617562aa405d861d9170b08bc09e90",
      "r1": "df2c61be3c0b37bc73dc89fc386c96b3008035081690bfde3b1e68b91443c22cc791d244340fe957d5aa44d7313740df",
      "r2": "10fcb00134739cc403f27a79588ca05ad59c5e6ff560cc597c2b8ca25256c720bceca2ab03921492c5e9e4ad3b558002",
      "request_context": "74657374207265717565737420636f6e74657874"
    },
    "CredentialResponse": {
      "H_aux": "03c7714830e1d72604e52fec595c7a399fe0f3276766f84425fd1f98764ac76dab631c6dfd05e0200c4ffe6d6967304882",
      "U": "02be890d43908e52ed43ae7bc7098f3a7694617fe44a88c33c6fa4eb9e942c0b2bb9d2fd56a44e1d6094fc7b9e8b949055",
      "X0_aux": "02890d3f4287e7878ce88b2bc1cc818b2c40fee0f93187af43acb479259979cef1c39d609ea69cc7d6ba1e2a55d107653f",
      "X1_aux": "0345f2be0dd21d49437a82b221f7a9f074b352e8698fe6ffa08aecad480e96e93a25b6dacd4531fc961e78cfb5503f0e69",
      "X2_aux": "020f31991b9a40be69bc06ef30c250d9353a824f4da88cc43e63bf92bc8ac8bca7e26bffed33a32cc124fd1fb6c73f8b77",
      "b": "b8b2e8c2103ad6f1970e873420d82a21e699140babbe599f7dd8f6e3e8f615e5f201d1c2b0bc2f821f19e80a0a0e1e7b",
      "enc_U_prime": "027f43377c69a2ad931cc21a9cc4d6ea85f84d517d197db721c931276a9ed543a78055ddeb9cac6be3af34c212bca5f403",
      "proof": "1d5ea5448d22de8e4cb2193693a7c50874d37af3e2879cbf4484d26dd23362e6f3765bbf894599e9551deb31e6f362693a5d799f07fbaf2376976608d73c401a20db7385c89e4cd3b805c3ea9bdf03925b04bf24021246a778282adb1d740e82163fb5037c3ad3221f55dd3ed5e3b3c6a0492827c410efde6d315e3b0b7835459292e81805bea764e372fcd77776863c630b1f1509ef52e50a1fea5dc85b48523936408852d19461a2a8410e7aa49182905a444e089f0ad6b116f065debd09798121793487d7c84d680331bacb1e8730928b897ac839b0b748cfd806833d79a3b50d736349b7bc674672de02e375ee20348f5e349e30ab03ccb0f3a530935f4fada0e63ccb52b58785ecd9483ea37cf3faf0ced66cc36ad33a80a94fa9b0041ff5be03e5fd1f74a748bd5986676390427c27696d6591ec0443fac2415e9c0a4d6197d81a242dd71c739a5f9989a51d8b245ecddb94ebb13c3da2bfc91d42ff992d4f0f1b567138ce1d1012053c4b70b10ed756e102faeb9a1d982227ab16c353"
    },
    "Presentation1": {
      "U": "03383b2ad2831739bc86c0c98119f256e54c9d89a762a9fc91b3904eb3aee7260350a19085ea093a8059369219f03da2c3",
      "U_prime_commit": "034af7c09ee5150fc914a3bb0adf17f7e90af3c4d9246ec8c511f938467174113513b7577329cecd2a7bff0b97e43a9808",
      "a": "ad00ec0f71b7a8fb7c0aef35c7243e17b78e57df8f0a95d102ff12bbb97e15ed35c23e54f9b4483d30b76772ee60d886",
      "m1_commit": "02fb95e1d8010da0c63d38ca212c1f76d768cecc8aa26ab07e77557070c8343e1da571230f071a15a03973cd57dc33ebf4",
      "nonce": "0x0",
      "presentation_context": "746573742070726573656e746174696f6e20636f6e74657874",
      "proof": "91a355f96a4917bc81aa7e5573da2a79bc9e026508e8d161cdbba91f7c3f3f4a1a313adfe78c9e0025640720b1cd973b36fce60a4f82aaedc5cefc4c32760fcec573a2609dafaddf4283949445451b614331172be50abc83c32aaf5cb10b4aee06d2d1240cc7c4fb10491a96d125571dc4317c7583ad54c0971e22cb13b2c040e1d4791dba0a25dd3d1b785e484e8a1e8f24ca91f0f6d0cddf8456a21fa42a06748fa865cd008f3fe91e40a47126a47e54a321bec5c7b73700fbcb335c8a0988000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004",
      "r": "e5cab8c896187b61abe017e57022528742252210dd60ddbbf1a57e3b144e26dd693b7644a9626a8c36896ede53d12930",
      "tag": "0247e3fd325bc774c27329a78a62f616f5e409d3a4857609cecde3251140f2bb101905c4cbe66fe06a779e44f5d9e97f08",
      "z": "f61f4c924d3ef04b31e9196935ff27c5f5a4bbcf14e55e357df9f5ccb5ded37b2b14bc2e1a68e31f86416f0606ee75d1"
    },
    "Presentation2": {
      "U": "020c627c7ced92dd621860017ed29361bb78c4a17c8f7deb79f0c49a4772389899a7e3b7b21e6a6c73abfca1332dc7df6e",
      "U_prime_commit": "023d7eb948df3f49abe39e8ef32f4bb1bcca0f13f04836efd8b7bc9bd0a73f915531ce845dc8c334d03c13647e5e4cc908",
      "a": "a8e630484ba024bf9363805bc7a45f1695bcf45150a61f5c44a6cfbf343cd9e0f593f127b6f49bec0f9b20f0550504a2",
      "m1_commit": "036eea98df5b8248262fc5b511eef49bef1c2ec2a724df3e3a811296fcf7891298d99a22f05ef0b08a2d00857117d88ac7",
      "nonce": "0x1",
      "presentation_context": "746573742070726573656e746174696f6e20636f6e74657874",
      "proof": "5547662ff1c63f14292cc998b24f0c74c20149cd89accde1c7a02485ebac2c7888fd2ffbbafd539f79c8c4677dfcf79acf12a70bd0032c89c70e0966204301699a3c50d1a778d55d812f7d4ef71d29c8b8377607d6d8d5884a31ec8386c909145ee7aa6bc17558be1e2dece1329a9473782d97a7ea5819a60d03990563dd2efccd1fd1a6d4376b2f900a4092a73266e3fec867feae45e645e368178df894c3e1353acd57f3757faabf651b2ef04b87b426c1a695bed9002a0657b3752fdeaee4aab899d00e39c0ebd6d336674db0f38b3dfeb6327653321dffc328fc088b0166cf1cddb68db353db732355034ec831dd",
      "r": "df6d39c3c0716d7cf8093073168bf967d7ed72750b6d366ed0febdc539b52d89434f468a578c59d7ca9015b7da240ad6",
      "tag": "03f9ceb1690ef6cd9c1b7d4c29dc86cf25565e4045ae431f8d28029e0405f9ac251ef5a9e873f4a038ecd5a1e43d56bf5d",
      "z": "1b8e374ed4390e5a9023b309ecb94c0791eedfb168c556ff5ca3b89d047f482c9279b47f584aab6c7f895f7674251771"
    },
    "ServerKey": {
      "X0": "02caa111a43a5909de4af5cb836897334e5a34857ffc3565223cad95a20f1f32303eb8f7594b286238f243eca1a79c60b8",
      "X1": "03ef0f59c9b0cc51c9e603dfcaa9a3e3719e186252b64f9ce1ebec352c5b605b805af308a9bd697df7c97b0f1147108c3a",
      "X2": "028a9547a39d925bdd054706aa5ff7616c28aca94c92041c678970c52ee65722f2c54d4f6cecba66abd721ecbcdb2b8a04",
      "x0": "504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364",
      "x1": "803d955f0e073a04aa5d92b3fb739f56f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1",
      "x2": "a097e722ed2427de86966910acba9f5c350e8040f828bf6ceca27405420cdf3d63cb3aef005f40ba51943c8026877963",
      "xb": "3a349db178a923aa7dff7d2d15d89756fd293126bb49a6d793cd77d7db960f5692fec3b7ec07602c60cd32aee595dffd"
    },
    "suite": "ARCV1-P384",
  }
]
"""

struct ARCCredentialTestVector: Codable {
    let U: String
    let U_prime: String
    let X1: String
    let m1: String
}

struct ARCCredentialRequestTestVector: Codable {
    let m1: String
    let m1_enc: String
    let m2: String
    let m2_enc: String
    let proof: String
    let r1: String
    let r2: String
    let request_context: String
}

struct ARCCredentialResponseTestVector: Codable {
    let H_aux: String
    let U: String
    let X0_aux: String
    let X1_aux: String
    let X2_aux: String
    let b: String
    let enc_U_prime: String
    let proof: String
}

struct ARCPresentationTestVector: Codable {
    let U: String
    let U_prime_commit: String
    let a: String
    let m1_commit: String
    let nonce: String
    let presentation_context: String
    let proof: String
    let r: String
    let tag: String
    let z: String
}

struct ARCServerTestVector: Codable {
    let x0: String
    let x1: String
    let x2: String
    let xb: String
    let X0: String
    let X1: String
    let X2: String
}

struct ARCTestVector: Codable {
    let suite: String
    let ServerKey: ARCServerTestVector
    let CredentialRequest: ARCCredentialRequestTestVector
    let CredentialResponse: ARCCredentialResponseTestVector
    let Credential: ARCCredentialTestVector
    let Presentation1: ARCPresentationTestVector
    let Presentation2: ARCPresentationTestVector
}

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
class ARCTestVectors: XCTestCase {
    func testVectors() throws {
        let data = ARCEncodedTestVector.data(using: .utf8)!
        let decoder = JSONDecoder()
        let testVectors = try decoder.decode([ARCTestVector].self, from: data)
        testVectors.forEach { validateTestVector($0) }
    }

    func validate<Curve: SupportedCurveDetailsImpl>(curveType _: Curve.Type, _ tv: ARCTestVector) throws {
        let x0 = try scalarFromString(CurveType: Curve.self, value: tv.ServerKey.x0)
        let x1 = try scalarFromString(CurveType: Curve.self, value: tv.ServerKey.x1)
        let x2 = try scalarFromString(CurveType: Curve.self, value: tv.ServerKey.x2)
        let xb = try scalarFromString(CurveType: Curve.self, value: tv.ServerKey.xb)

        // Initialize server
        let ciphersuite = ARC.Ciphersuite(HashToCurveImpl<Curve>.self)
        let server = ARC.Server(ciphersuite: ciphersuite, x0: x0, x1: x1, x2: x2, x0Blinding: xb)
        XCTAssertEqual(server.serverPublicKey.X0.oprfRepresentation.hexString, tv.ServerKey.X0)
        XCTAssertEqual(server.serverPublicKey.X1.oprfRepresentation.hexString, tv.ServerKey.X1)
        XCTAssertEqual(server.serverPublicKey.X2.oprfRepresentation.hexString, tv.ServerKey.X2)

        // Initialize precredential, make a credential request
        let requestContext = try Data(hexString: tv.CredentialRequest.request_context)
        let m1 = try scalarFromString(CurveType: Curve.self, value: tv.CredentialRequest.m1)
        let m2 = try scalarFromString(CurveType: Curve.self, value: tv.CredentialRequest.m2)
        let r1 = try scalarFromString(CurveType: Curve.self, value: tv.CredentialRequest.r1)
        let r2 = try scalarFromString(CurveType: Curve.self, value: tv.CredentialRequest.r2)
        let precredential = try ARC.Precredential(ciphersuite: ciphersuite, m1: m1, requestContext: requestContext, r1: r1, r2: r2, serverPublicKey: server.serverPublicKey)
        XCTAssertEqual(precredential.credentialRequest.m1Enc.oprfRepresentation.hexString, tv.CredentialRequest.m1_enc)
        XCTAssertEqual(precredential.credentialRequest.m2Enc.oprfRepresentation.hexString, tv.CredentialRequest.m2_enc)
        XCTAssertEqual(precredential.clientSecrets.m2.rawRepresentation.hexString, tv.CredentialRequest.m2)

        // Verify request proof, by creating a new request with the
        // tv.CredentialRequest.proof scalars and verifying it.
        let requestProof = try proofFromString(CurveType: Curve.self, value: tv.CredentialRequest.proof, scalarCount: ARC.CredentialRequest<HashToCurveImpl<Curve>>.getScalarCount())
        let newRequest = ARC.CredentialRequest(m1Enc: precredential.credentialRequest.m1Enc, m2Enc: precredential.credentialRequest.m2Enc, proof: requestProof)
        XCTAssert(try newRequest.verify(generatorG: precredential.generatorG, generatorH: precredential.generatorH, ciphersuite: ciphersuite))

        // Make a credential response, passing in randomness b
        let b = try scalarFromString(CurveType: Curve.self, value: tv.CredentialResponse.b)
        let response = try server.respond(credentialRequest: precredential.credentialRequest, b: b)
        XCTAssertEqual(response.HAux.oprfRepresentation.hexString, tv.CredentialResponse.H_aux)
        XCTAssertEqual(response.U.oprfRepresentation.hexString, tv.CredentialResponse.U)
        XCTAssertEqual(response.X0Aux.oprfRepresentation.hexString, tv.CredentialResponse.X0_aux)
        XCTAssertEqual(response.X1Aux.oprfRepresentation.hexString, tv.CredentialResponse.X1_aux)
        XCTAssertEqual(response.X2Aux.oprfRepresentation.hexString, tv.CredentialResponse.X2_aux)
        XCTAssertEqual(response.encUPrime.oprfRepresentation.hexString, tv.CredentialResponse.enc_U_prime)

        // Verify response proof, by creating a new response with the
        // tv.CredentialResponse.proof scalars and verifying it.
        let responseProof = try proofFromString(CurveType: Curve.self, value: tv.CredentialResponse.proof, scalarCount: ARC.CredentialResponse<HashToCurveImpl<Curve>>.getScalarCount())
        let newResponse = ARC.CredentialResponse(U: response.U, encUPrime: response.encUPrime, X0Aux: response.X0Aux, X1Aux: response.X1Aux, X2Aux: response.X2Aux, HAux: response.HAux, proof: responseProof)
        XCTAssert(try newResponse.verify(request: precredential.credentialRequest, serverPublicKey: server.serverPublicKey, generatorG: server.generatorG, generatorH: server.generatorH, ciphersuite: ciphersuite))

        // Make a credential from the response
        var credential = try precredential.makeCredential(credentialResponse: response)
        XCTAssertEqual(credential.U.oprfRepresentation.hexString, tv.Credential.U)
        XCTAssertEqual(credential.UPrime.oprfRepresentation.hexString, tv.Credential.U_prime)
        XCTAssertEqual(credential.X1.oprfRepresentation.hexString, tv.Credential.X1)
        XCTAssertEqual(credential.m1.rawRepresentation.hexString, tv.Credential.m1)

        // Make a first presentation from the credential, passing in randomness a, r, z
        let presentationContext1 = try Data(hexString: tv.Presentation1.presentation_context)
        let a_1 = try scalarFromString(CurveType: Curve.self, value: tv.Presentation1.a)
        let r_1 = try scalarFromString(CurveType: Curve.self, value: tv.Presentation1.r)
        let z_1 = try scalarFromString(CurveType: Curve.self, value: tv.Presentation1.z)
        let nonce_1 = Int(tv.Presentation1.nonce.replacingOccurrences(of: "0x", with: ""), radix: 16)!
        let (presentation1, nonce_1_returned) = try credential.makePresentation(presentationContext: presentationContext1, presentationLimit: 2, a: a_1, r: r_1, z: z_1, optionalNonce: nonce_1)
        XCTAssertEqual(nonce_1, nonce_1_returned)
        XCTAssertEqual(presentation1.U.oprfRepresentation.hexString, tv.Presentation1.U)
        XCTAssertEqual(presentation1.UPrimeCommit.oprfRepresentation.hexString, tv.Presentation1.U_prime_commit)
        XCTAssertEqual(presentation1.m1Commit.oprfRepresentation.hexString, tv.Presentation1.m1_commit)
        XCTAssertEqual(presentation1.tag.oprfRepresentation.hexString, tv.Presentation1.tag)

        // Verify presentation1 proof, by creating a new presentation with the
        // tv.Presentation1.proof scalars and verifying it.
        let presentation1Proof = try proofFromString(CurveType: Curve.self, value: tv.Presentation1.proof, scalarCount: ARC.Presentation<HashToCurveImpl<Curve>>.getScalarCount())
        let newPresentation1 = ARC.Presentation(U: presentation1.U, UPrimeCommit: presentation1.UPrimeCommit, m1Commit: presentation1.m1Commit, tag: presentation1.tag, proof: presentation1Proof)
        XCTAssert(try newPresentation1.verify(serverPrivateKey: server.serverPrivateKey, X1: server.serverPublicKey.X1, m2: m2, presentationContext: presentationContext1, presentationLimit: 2, nonce: nonce_1, generatorG: credential.generatorG, generatorH: credential.generatorH, ciphersuite: ciphersuite))

        // Make a second presentation from the credential, passing in randomness a, r, z
        let presentationContext2 = try Data(hexString: tv.Presentation2.presentation_context)
        let a_2 = try scalarFromString(CurveType: Curve.self, value: tv.Presentation2.a)
        let r_2 = try scalarFromString(CurveType: Curve.self, value: tv.Presentation2.r)
        let z_2 = try scalarFromString(CurveType: Curve.self, value: tv.Presentation2.z)
        let nonce_2 = Int(tv.Presentation2.nonce.replacingOccurrences(of: "0x", with: ""), radix: 16)!
        let (presentation2, nonce_2_returned) = try credential.makePresentation(presentationContext: presentationContext1, presentationLimit: 2, a: a_2, r: r_2, z: z_2, optionalNonce: nonce_2)
        XCTAssertEqual(nonce_2, nonce_2_returned)
        XCTAssertEqual(presentation2.U.oprfRepresentation.hexString, tv.Presentation2.U)
        XCTAssertEqual(presentation2.UPrimeCommit.oprfRepresentation.hexString, tv.Presentation2.U_prime_commit)
        XCTAssertEqual(presentation2.m1Commit.oprfRepresentation.hexString, tv.Presentation2.m1_commit)
        XCTAssertEqual(presentation2.tag.oprfRepresentation.hexString, tv.Presentation2.tag)

        // Verify presentation2 proof, by creating a new presentation with the
        // tv.Presentation2.proof scalars and verifying it.
        let presentation2Proof = try proofFromString(CurveType: Curve.self, value: tv.Presentation2.proof, scalarCount: ARC.Presentation<HashToCurveImpl<Curve>>.getScalarCount())
        let newPresentation2 = ARC.Presentation(U: presentation2.U, UPrimeCommit: presentation2.UPrimeCommit, m1Commit: presentation2.m1Commit, tag: presentation2.tag, proof: presentation2Proof)
        XCTAssert(try newPresentation2.verify(serverPrivateKey: server.serverPrivateKey, X1: server.serverPublicKey.X1, m2: m2, presentationContext: presentationContext2, presentationLimit: 2, nonce: nonce_2, generatorG: credential.generatorG, generatorH: credential.generatorH, ciphersuite: ciphersuite))

        // Verify both presentations
        XCTAssertTrue(try server.verify(presentation: presentation1, requestContext: requestContext, presentationContext: presentationContext1, presentationLimit: 2, nonce: nonce_1))
        XCTAssertTrue(try server.verify(presentation: presentation2, requestContext: requestContext, presentationContext: presentationContext2, presentationLimit: 2, nonce: nonce_2))
    }

    func validateTestVector(_ tv: ARCTestVector) {
        switch tv.suite {
        case "ARCV1-P256": XCTAssertNoThrow(try self.validate(curveType: P256.self, tv))
        case "ARCV1-P384": XCTAssertNoThrow(try self.validate(curveType: P384.self, tv))
        default: XCTFail("Unsupported ciphersuite:" + tv.suite)
        }
    }
}

private func scalarFromString<Curve: SupportedCurveDetailsImpl>(CurveType _: Curve.Type, value: String) throws -> GroupImpl<Curve>.Element.Scalar {
    return try GroupImpl<Curve>.Scalar(bytes: Data(hexString: value))
}

private func elementFromString<Curve: SupportedCurveDetailsImpl>(CurveType _: Curve.Type, value: String) throws -> GroupImpl<Curve>.Element {
    return try GroupImpl<Curve>.Element(oprfRepresentation: Data(hexString: value))
}

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
private func proofFromString<Curve: SupportedCurveDetailsImpl>(CurveType _: Curve.Type, value: String, scalarCount: Int) throws -> Proof<HashToCurveImpl<Curve>> {
    let scalarHexCharacterCount = Curve.orderByteCount * 2
    var startIndex = value.index(value.startIndex, offsetBy: 0)
    var endIndex = value.index(value.startIndex, offsetBy: scalarHexCharacterCount)

    // Deserialize challenge
    let challengeEnc = try Data(hexString: String(value[startIndex..<endIndex]))
    let challenge = try GroupImpl<Curve>.Scalar(bytes: challengeEnc)

    // Deserialize responses
    var responses: [GroupImpl<Curve>.Scalar] = []
    for _ in (0..<scalarCount-1) {
        startIndex = endIndex
        endIndex = value.index(startIndex, offsetBy: scalarHexCharacterCount)

        let responseEnc = try Data(hexString: String(value[startIndex..<endIndex]))
        let response = try GroupImpl<Curve>.Scalar(bytes: responseEnc)
        responses.append(response)
    }

    return Proof(challenge: challenge, responses: responses)
}
