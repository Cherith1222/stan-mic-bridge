import Foundation

// The executable and app compile this same bounded, single-request pipe contract.
enum CredentialBrokerWire {
    static let schema = 1
    static let maximumMessageBytes = 16 * 1024
    static let brokerIdentifier = "com.stan.micbridge.credentials"
    static let appIdentifier = "com.stan.micbridge"

    struct Request: Codable {
        let schema: Int
        let operation: String
        let payload: Data?
        #if BROKER_TESTING
        var testKeychain: String?
        #endif
        init(schema: Int, operation: String, payload: Data?) {
            self.schema = schema; self.operation = operation; self.payload = payload
            #if BROKER_TESTING
            self.testKeychain = nil
            #endif
        }
        private enum CodingKeys: String, CodingKey {
            case schema, operation, payload
            #if BROKER_TESTING
            case testKeychain
            #endif
        }
        init(from decoder: Decoder) throws {
            let all = try decoder.container(keyedBy: AnyKey.self)
            var allowed: Set<String> = ["schema", "operation", "payload"]
            #if BROKER_TESTING
            allowed.insert("testKeychain")
            #endif
            guard Set(all.allKeys.map(\.stringValue)).isSubset(of: allowed) else {
                throw DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "Unsupported broker request field"))
            }
            let values = try decoder.container(keyedBy: CodingKeys.self)
            schema = try values.decode(Int.self, forKey: .schema)
            operation = try values.decode(String.self, forKey: .operation)
            payload = try values.decodeIfPresent(Data.self, forKey: .payload)
            #if BROKER_TESTING
            testKeychain = try values.decodeIfPresent(String.self, forKey: .testKeychain)
            #endif
        }
        var isValid: Bool {
            guard schema == CredentialBrokerWire.schema else { return false }
            switch operation {
            case "load", "remove": return payload == nil
            case "save": return payload.flatMap(ConnectionData.decode) != nil
            default: return false
            }
        }
    }
    struct Response: Codable {
        let schema: Int
        let status: Int32
        let data: Data?
    }
    struct ConnectionData: Codable {
        let origin: String
        let token: String
        static func decode(_ data: Data) -> ConnectionData? {
            guard !data.isEmpty, data.count <= CredentialBrokerWire.maximumMessageBytes,
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  Set(object.keys) == Set(["origin", "token"]),
                  let result = try? JSONDecoder().decode(Self.self, from: data), result.isValid else { return nil }
            return result
        }
        var isValid: Bool {
            guard !origin.isEmpty, origin.utf8.count <= 2048,
                  let parts = URLComponents(string: origin), parts.scheme == "https",
                  let host = parts.host, !host.isEmpty,
                  parts.user == nil, parts.password == nil, parts.path.isEmpty,
                  parts.query == nil, parts.fragment == nil,
                  parts.port.map({ (1...65535).contains($0) }) ?? true,
                  !token.isEmpty, token.utf8.count <= 1024,
                  !token.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { return false }
            return true
        }
    }
    private struct AnyKey: CodingKey {
        let stringValue: String
        let intValue: Int? = nil
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }
}
