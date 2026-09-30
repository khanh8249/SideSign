//
//  Authentication.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import GSACryptoKit

// MARK: - Shared Types

/// Rút gọn cho `[String: any Sendable]` — dùng khắp module auth.
public typealias SendableDict = [String: any Sendable]

// MARK: - Auth Type

/// Các loại phản hồi `au` từ GrandSlam sau SRP complete.
enum GrandSlamAuthType: String {
    case trustedDeviceSecondaryAuth
    case trustedDevice
    case secondaryAuth
    case sms
    case voice
    case phone
    case repair

    var requiresTrustedDevice: Bool {
        self == .trustedDeviceSecondaryAuth || self == .trustedDevice
    }

    var requiresSecondaryAuth: Bool {
        switch self {
        case .trustedDeviceSecondaryAuth, .trustedDevice,
             .secondaryAuth, .sms, .voice, .phone:
            return true
        case .repair:
            return false
        }
    }
}

// MARK: - SRP Session Payload

/// Payload giải mã từ `spd` sau SRP complete.
private struct SRPSessionPayload {
    let dsid: String
    let idmsToken: String
    let sessionKey: Data
    let challenge: Data

    init(decrypted: SendableDict) throws {
        guard let dsid = (decrypted["adsid"] as? String)
                ?? (decrypted["dsid"] as? CustomStringConvertible)?.description
        else {
            throw ServerError.missingKey(key: "adsid", jsonPayload: prettyJSONString(from: decrypted))
        }

        guard let idms = (decrypted["GsIdmsToken"] as? String)
                ?? (decrypted["idmsToken"] as? String)
        else {
            throw ServerError.missingKey(key: "GsIdmsToken", jsonPayload: prettyJSONString(from: decrypted))
        }

        guard let sk = decrypted["sk"] as? Data else {
            throw ServerError.missingKey(key: "sk", jsonPayload: prettyJSONString(from: decrypted))
        }

        guard let c = decrypted["c"] as? Data else {
            throw ServerError.missingKey(key: "c", jsonPayload: prettyJSONString(from: decrypted))
        }

        self.dsid = dsid
        self.idmsToken = idms
        self.sessionKey = sk
        self.challenge = c
    }
}

// MARK: - Fetched Auth Token

private struct FetchedAuthToken {
    let token: String
    let creationDate: Date
    let expirationDate: Date?
    let timeToLive: TimeInterval?
}

// MARK: - Main Extension

public extension DeveloperPortal {

    // MARK: Public Entry

    func authenticate(appleID unsanitizedAppleID: String,
                      password: String,
                      anisetteData: AnisetteData,
                      xcodeVersion: String,
                      machinePassword: String? = nil,
                      accountRepairHandler: DeveloperPortal.AccountRepairHandler = DeveloperPortal.defaultAccountRepairHandler,
                      verificationHandler: DeveloperPortal.VerificationHandler? = nil) async throws -> AuthSession
    {
        let sanitizedAppleID = unsanitizedAppleID
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()

        debugLog("[SideSign] Starting authenticate for \(sanitizedAppleID)")
        let clientDictionary = makeClientDictionary(anisetteData: anisetteData)

        // Vòng lặp thay cho đệ quy — tránh stack sâu khi 2FA nhiều vòng.
        while true {
            let result = try await performSRPHandshake(
                appleID: sanitizedAppleID,
                password: password,
                anisetteData: anisetteData,
                clientDictionary: clientDictionary
            )

            let context = TwoFactorAuthContext(
                dsid: result.payload.dsid,
                idmsToken: result.payload.idmsToken,
                anisetteData: anisetteData,
                xcodeVersion: xcodeVersion
            )

            if let authType = result.authType, authType.requiresSecondaryAuth {
                try await handle2FARequest(
                    isTrustedDevice: authType.requiresTrustedDevice,
                    response: result.authResponse,
                    context: context,
                    verificationHandler: verificationHandler
                )
                debugLog("[SideSign] 2FA solved — retrying SRP handshake.")
                continue // thay vì recursion
            }

            if result.authType == .repair {
                try await handleRepair(
                    response: result.authResponse,
                    handler: accountRepairHandler
                )
            }

            // Fetch app token & account info
            let fetchedToken = try await fetchAuthToken(
                app: Constants.authApp,
                dsid: result.payload.dsid,
                idmsToken: result.payload.idmsToken,
                sessionKey: result.payload.sessionKey,
                challenge: result.payload.challenge,
                clientDictionary: clientDictionary,
                anisetteData: anisetteData
            )

            let session = Session(
                dsid: result.payload.dsid,
                authToken: fetchedToken.token,
                anisetteData: anisetteData,
                xcodeVersion: xcodeVersion,
                machinePassword: machinePassword,
                creationDate: fetchedToken.creationDate,
                expirationDate: fetchedToken.expirationDate,
                timeToLive: fetchedToken.timeToLive
            )
            let account = try await fetchAccount(session: session)
            return AuthSession(account: account, session: session)
        }
    }

    // MARK: - Client Dictionary

    private func makeClientDictionary(anisetteData: AnisetteData) -> SendableDict {
        [
            "bootstrap": true,
            "icscrec": true,
            "pbe": false,
            "prkgen": true,
            "svct": Constants.grandSlamService,
            "loc": anisetteData.locale,
            "X-Apple-Locale": anisetteData.locale,
            "X-Apple-I-MD": anisetteData.oneTimePassword,
            "X-Apple-I-MD-M": anisetteData.machineID,
            "X-Mme-Device-Id": anisetteData.deviceID,
            "X-Apple-I-MD-LU": anisetteData.localUserID,
            "X-Apple-I-MD-RINFO": anisetteData.routingInfo,
            "X-Apple-I-SRL-NO": anisetteData.serialNumber,
            "X-Apple-I-Client-Time": anisetteData.clientTime,
            "X-Apple-I-TimeZone": anisetteData.timeZone
        ]
    }

    // MARK: - SRP Handshake

    private struct SRPHandshakeResult {
        let payload: SRPSessionPayload
        let authType: GrandSlamAuthType?
        let authResponse: SendableDict
    }

    private func performSRPHandshake(appleID: String,
                                     password: String,
                                     anisetteData: AnisetteData,
                                     clientDictionary: SendableDict) async throws -> SRPHandshakeResult
    {
        // 1. SRP init
        guard let srpClient = SRPClient(),
              let publicKey = srpClient.startAuthentication()
        else {
            throw DeveloperPortalError.authenticationHandshakeFailed(
                cause: "Failed to start SRPClient / generate public key A"
            )
        }
        verboseLog("[SideSign] Public key A: \(publicKey.hexEncodedString())")

        let initResponse = try await sendAuthenticationRequest(
            parameters: [
                "A2k": publicKey,
                "cpd": clientDictionary,
                "ps": ["s2k", "s2k_fo"],
                "o": "init",
                "u": appleID
            ],
            anisetteData: anisetteData
        )

        guard let c = initResponse["c"] as? String,
              let salt = initResponse["s"] as? Data,
              let iterations = initResponse["i"] as? Int,
              let serverPublicKey = initResponse["B"] as? Data
        else {
            throw ServerError.badServerResponse(
                reason: "Auth init response missing c/s/i/B",
                jsonPayload: prettyJSONString(from: initResponse)
            )
        }

        // 2. Derive password key
        let derivedPasswordKey = try derivePasswordKey(
            password: password,
            salt: salt,
            iterations: iterations,
            useHexDigest: (initResponse["sp"] as? String) == "s2k_fo"
        )

        guard let M1 = srpClient.processChallenge(
            username: appleID,
            password: derivedPasswordKey,
            salt: salt,
            serverPublicKey: serverPublicKey
        ) else {
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "SRP challenge processing failed")
        }

        // 3. SRP complete
        let completeResponse = try await sendAuthenticationRequest(
            parameters: [
                "c": c,
                "cpd": clientDictionary,
                "M1": M1,
                "o": "complete",
                "u": appleID
            ],
            anisetteData: anisetteData
        )

        guard let spd = completeResponse["spd"] as? Data else {
            throw ServerError.missingKey(key: "spd", jsonPayload: prettyJSONString(from: completeResponse))
        }
        guard let M2 = completeResponse["M2"] as? Data else {
            throw ServerError.missingKey(key: "M2", jsonPayload: prettyJSONString(from: completeResponse))
        }
        guard srpClient.verifyServerProof(M2) else {
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Server proof (M2) mismatch")
        }
        guard let sharedSecret = srpClient.sessionKey() else {
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Missing SRP session key")
        }

        // 4. Decrypt SPD
        guard let spdKey = CryptoUtilities.hmacSHA256(key: sharedSecret, strings: ["extra data key:"]),
              let spdIV  = CryptoUtilities.hmacSHA256(key: sharedSecret, strings: ["extra data iv:"]),
              let decrypted = CryptoUtilities.aesCBCDecrypt(key: spdKey, iv: spdIV, ciphertext: spd)
        else {
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to decrypt SPD")
        }
        guard let dict = parsePlistOrJSON(decrypted) else {
            throw ServerError.invalidResponseFormat(rawPayload: prettyJSONString(from: decrypted))
        }

        // 5. Parse + detect auth type
        let payload = try SRPSessionPayload(decrypted: dict)
        let statusDict = completeResponse["Status"] as? SendableDict
        let rawAuthType = (statusDict?["au"] as? String) ?? (completeResponse["au"] as? String)
        let authType = rawAuthType.flatMap(GrandSlamAuthType.init(rawValue:))

        return SRPHandshakeResult(
            payload: payload,
            authType: authType,
            authResponse: completeResponse
        )
    }

    private func derivePasswordKey(password: String,
                                   salt: Data,
                                   iterations: Int,
                                   useHexDigest: Bool) throws -> Data
    {
        guard let passwordData = password.data(using: .utf8),
              let digest = CryptoUtilities.sha256(passwordData)
        else {
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "SHA256 failed")
        }

        let inputDigest: Data = useHexDigest
            ? Data(digest.hexEncodedString().utf8)
            : digest

        guard let derived = CryptoUtilities.pbkdf2SHA256(
            password: inputDigest,
            salt: salt,
            rounds: iterations,
            outputLength: digest.count
        ) else {
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "PBKDF2 failed")
        }
        return derived
    }

    // MARK: - Repair Flow

    private func handleRepair(response: SendableDict,
                              handler: DeveloperPortal.AccountRepairHandler) async throws
    {
        let statusDict = response["Status"] as? SendableDict
        let rawURL = (response["repairUrl"] as? String)
                  ?? (response["url"] as? String)
                  ?? (statusDict?["url"] as? String)
        let url = rawURL.flatMap(URL.init(string:)) ?? Constants.URLs.developerAccount
        let rawMessage = (statusDict?["em"] as? String)?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let message = (rawMessage?.isEmpty == false ? rawMessage : nil)
                   ?? Constants.defaultAccountRepairMessage

        debugLog("[SideSign] Account repair required: \(message) — url: \(url)")
        let decision = try await handler(url, message)

        if decision == .cancel {
            throw DeveloperPortalError.accountRepairRequired(url: url, message: message)
        }
        debugLog("[SideSign] Account repair acknowledged.")
    }

    // MARK: - App Token

    /// Layout của token Apple: `[3-byte AAD][16-byte nonce][ciphertext][16-byte tag]`
    private static let gcmAADLength = 3
    private static let gcmNonceLength = 16
    private static let gcmTagLength = 16

    private func fetchAuthToken(app: String,
                                dsid: String,
                                idmsToken: String,
                                sessionKey: Data,
                                challenge: Data,
                                clientDictionary: SendableDict,
                                anisetteData: AnisetteData) async throws -> FetchedAuthToken
    {
        guard let checksum = CryptoUtilities.hmacSHA256(
            key: sessionKey,
            strings: ["apptokens", dsid, app]
        ) else {
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "apptokens checksum failed")
        }

        let response = try await sendAuthenticationRequest(
            parameters: [
                "app": [app],
                "c": challenge,
                "checksum": checksum,
                "cpd": clientDictionary,
                "o": "apptokens",
                "t": idmsToken,
                "u": dsid
            ],
            anisetteData: anisetteData
        )

        let token = try decryptAuthToken(response: response, sessionKey: sessionKey, app: app)
        return try parseAuthTokenMetadata(token: token, app: app)
    }

    private func decryptAuthToken(response: SendableDict,
                                  sessionKey: Data,
                                  app: String) throws -> SendableDict
    {
        guard let et = response["et"] as? Data else {
            throw ServerError.missingKey(key: "et", jsonPayload: prettyJSONString(from: response))
        }

        let headerLen = Self.gcmAADLength + Self.gcmNonceLength
        let minLen = headerLen + Self.gcmTagLength
        guard et.count > minLen else {
            throw DeveloperPortalError.authenticationHandshakeFailed(
                cause: "Encrypted token too short (\(et.count) bytes)"
            )
        }

        let aad        = et.subdata(in: 0..<Self.gcmAADLength)
        let nonce      = et.subdata(in: Self.gcmAADLength..<headerLen)
        let tagStart   = et.count - Self.gcmTagLength
        let ciphertext = et.subdata(in: headerLen..<tagStart)
        let tag        = et.subdata(in: tagStart..<et.count)

        guard let plaintext = CryptoUtilities.aesGCMDecrypt(
            key: sessionKey, nonce: nonce, aad: aad, ciphertext: ciphertext, tag: tag
        ) else {
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "AES-GCM decrypt failed")
        }

        guard let dict = parsePlistOrJSON(plaintext) else {
            throw ServerError.invalidResponseFormat(rawPayload: prettyJSONString(from: plaintext))
        }
        return dict
    }

    private func parseAuthTokenMetadata(token dict: SendableDict, app: String) throws -> FetchedAuthToken {
        guard let appTokens = dict["t"] as? SendableDict,
              let tokens = appTokens[app] as? SendableDict,
              let authToken = tokens["token"] as? String
        else {
            throw ServerError.missingKey(key: "t/\(app)/token", jsonPayload: prettyJSONString(from: dict))
        }

        let now = Date()
        let (expiry, ttl) = Self.extractExpiry(from: tokens, now: now)

        let ttlDesc = ttl.map {
            "\(Int($0 / 86400))d \(Int($0.truncatingRemainder(dividingBy: 86400) / 3600))h"
        } ?? "n/a"
        debugLog("[SideSign] Got token for \(app) — TTL: \(ttlDesc)")

        return FetchedAuthToken(
            token: authToken,
            creationDate: now,
            expirationDate: expiry,
            timeToLive: ttl
        )
    }

    private static func extractExpiry(from tokens: SendableDict,
                                      now: Date) -> (Date?, TimeInterval?) {
        let iso = ISO8601DateFormatter()

        if let d = tokens["expiry"] as? Date { return (d, d.timeIntervalSince(now)) }
        if let s = tokens["expiry"] as? String, let d = iso.date(from: s) { return (d, d.timeIntervalSince(now)) }
        if let d = tokens["expiry-date"] as? Date { return (d, d.timeIntervalSince(now)) }
        if let s = tokens["expiry-date"] as? String, let d = iso.date(from: s) { return (d, d.timeIntervalSince(now)) }
        if let ttl = (tokens["ttl"] as? Double) ?? (tokens["ttl"] as? Int).map(Double.init) {
            return (now.addingTimeInterval(ttl), ttl)
        }
        return (nil, nil)
    }

    // MARK: - GrandSlam HTTP

    func sendAuthenticationRequest(parameters requestParameters: SendableDict,
                                   anisetteData: AnisetteData) async throws -> SendableDict
    {
        let body: SendableDict = [
            "Header": ["Version": Constants.grandSlamAuthHeader],
            "Request": requestParameters
        ]

        var request = URLRequest(url: Constants.URLs.grandSlamAuth)
        request.httpMethod = "POST"
        request.httpBody = try PropertyListSerialization.data(
            fromPropertyList: body, format: .xml, options: 0
        )
        request.setValue("text/x-xml-plist", forHTTPHeaderField: "Content-Type")
        request.setValue(anisetteData.clientInfo, forHTTPHeaderField: "X-MMe-Client-Info")
        request.setValue("*/*", forHTTPHeaderField: "Accept")
        request.setValue(Constants.userAgent, forHTTPHeaderField: "User-Agent")

        let (data, response) = try await session.data(for: request)
        let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0

        guard !data.isEmpty else {
            throw ServerError.badServerResponse(
                reason: "Auth endpoint returned empty (HTTP \(statusCode))",
                jsonPayload: "0 bytes"
            )
        }
        guard let parsed = parsePlistOrJSON(data) else {
            let raw = String(data: data, encoding: .utf8) ?? data.hexEncodedString()
            throw ServerError.invalidResponseFormat(rawPayload: raw)
        }

        let dict = (parsed["Response"] as? SendableDict) ?? parsed
        guard let status = dict["Status"] as? SendableDict else {
            throw ServerError.missingKey(key: "Status", jsonPayload: prettyJSONString(from: parsed))
        }

        let errorCode = status["ec"] as? Int ?? 0
        if errorCode != 0 {
            throw mapAuthError(code: errorCode, message: status["em"] as? String)
        }
        return dict
    }

    private func mapAuthError(code: Int, message: String?) -> Error {
        debugLog("[SideSign] Auth error \(code): \(message ?? "no message")")
        switch code {
        case GrandSlamAuthErrorCodes.incorrectCredentials:
            return DeveloperPortalError.incorrectCredentials(cause: message)
        case GrandSlamAuthErrorCodes.appSpecificPasswordRequired,
             GrandSlamAuthErrorCodes.appSpecificPasswordRequiredFallback:
            return DeveloperPortalError.appSpecificPasswordRequired(cause: message)
        case GrandSlamAuthErrorCodes.incorrectVerificationCode:
            return DeveloperPortalError.incorrectVerificationCode(cause: message)
        default:
            return ServerError.underlyingError(code: code, message: message ?? "Auth failed")
        }
    }

    // MARK: - Parsing Helpers

    private func parsePlistOrJSON(_ data: Data) -> SendableDict? {
        (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? SendableDict
        ?? (try? JSONSerialization.jsonObject(with: data, options: [])) as? SendableDict
    }
}

// MARK: - 2FA Context & Models

extension DeveloperPortal {

    struct TwoFactorAuthContext {
        let dsid: String
        let idmsToken: String
        let anisetteData: AnisetteData
        let xcodeVersion: String
    }

    private struct PhoneCodeResponse {
        let phoneID: String
        let activeMode: String
        let phoneNumbers: [TrustedPhoneNumber]
    }

    fileprivate enum Channel {
        case trustedDevice
        case sms(phoneID: String)
        case voice(phoneID: String)
    }

    fileprivate enum ValidationResult {
        case success
        case retry(message: String)
    }

    /// Chặn brute-force 2FA — tránh Apple lock tài khoản.
    fileprivate static let max2FARetries = 5
}

// MARK: - 2FA Flow

extension DeveloperPortal {

    func handle2FARequest(isTrustedDevice: Bool,
                          response: SendableDict,
                          context: TwoFactorAuthContext,
                          verificationHandler: VerificationHandler?) async throws
    {
        guard let verificationHandler else {
            throw DeveloperPortalError.requiresTwoFactorAuthentication
        }

        var phoneNumbers = parseTrustedPhoneNumbers(from: response)
            ?? parseTrustedPhoneNumbers(from: response["Status"] as? SendableDict)
            ?? []

        var currentRequest = TwoFactorRequest.selectDeliveryMethod(
            preferredMode: isTrustedDevice ? .trustedDevice : .sms,
            phoneNumbers: phoneNumbers
        )
        var activeChannel: Channel?
        var attempts = 0

        while attempts < Self.max2FARetries {
            debugLog("[SideSign] 2FA prompt: \(currentRequest)")

            switch try await verificationHandler(currentRequest) {
            case .requestTrustedDevice:
                try await sendTrustedDeviceCode(context: context)
                activeChannel = .trustedDevice
                currentRequest = .trustedDevice(error: nil)

            case .requestSMS(let id):
                let r = try await sendPhoneCode(mode: "sms", phoneID: id, known: phoneNumbers, context: context)
                phoneNumbers = r.phoneNumbers
                activeChannel = .sms(phoneID: r.phoneID)
                currentRequest = .sms(phoneNumbers: r.phoneNumbers, activeID: r.phoneID, error: nil)

            case .requestVoice(let id):
                let r = try await sendPhoneCode(mode: "voice", phoneID: id, known: phoneNumbers, context: context)
                phoneNumbers = r.phoneNumbers
                activeChannel = .voice(phoneID: r.phoneID)
                currentRequest = .voice(phoneNumbers: r.phoneNumbers, activeID: r.phoneID, error: nil)

            case .verificationCode(let code):
                guard let channel = activeChannel else {
                    throw DeveloperPortalError.authenticationHandshakeFailed(
                        cause: "Verification code before selecting a delivery method"
                    )
                }

                let result = try await validate(code: code, channel: channel, context: context)
                switch result {
                case .success:
                    debugLog("[SideSign] 2FA success.")
                    return
                case .retry(let msg):
                    attempts += 1
                    debugLog("[SideSign] 2FA retry (\(attempts)/\(Self.max2FARetries)): \(msg)")
                    currentRequest = makeRetryRequest(
                        channel: channel,
                        phones: phoneNumbers,
                        error: msg
                    )
                }

            case .cancel:
                throw DeveloperPortalError.userCancelled
            }
        }

        throw DeveloperPortalError.tooManyAttempts(
            cause: "Exceeded \(Self.max2FARetries) 2FA attempts"
        )
    }

    private func makeRetryRequest(channel: Channel,
                                  phones: [TrustedPhoneNumber],
                                  error: String) -> TwoFactorRequest
    {
        switch channel {
        case .trustedDevice:  return .trustedDevice(error: error)
        case .sms(let id):    return .sms(phoneNumbers: phones, activeID: id, error: error)
        case .voice(let id):  return .voice(phoneNumbers: phones, activeID: id, error: error)
        }
    }

    private func validate(code: String,
                          channel: Channel,
                          context: TwoFactorAuthContext) async throws -> ValidationResult
    {
        switch channel {
        case .trustedDevice:
            var req = make2FARequest(url: Constants.URLs.grandSlamValidate, context: context)
            req.setValue(code, forHTTPHeaderField: "security-code")
            let (data, resp) = try await session.data(for: req)
            return try parseVerifyResponse(
                data: data,
                statusCode: (resp as? HTTPURLResponse)?.safeStatusCode ?? 0,
                requirePeToken: false,
                response: resp as? HTTPURLResponse
            )

        case .sms(let phoneID):
            return try await validatePhone(code: code, phoneID: phoneID, mode: "sms", context: context)

        case .voice(let phoneID):
            return try await validatePhone(code: code, phoneID: phoneID, mode: "voice", context: context)
        }
    }

    // MARK: - Send Code

    private func sendTrustedDeviceCode(context: TwoFactorAuthContext) async throws {
        var req = make2FARequest(url: Constants.URLs.trustedDevice, context: context)
        req.httpMethod = "GET"

        let (data, resp) = try await session.data(for: req)
        let code = (resp as? HTTPURLResponse)?.safeStatusCode ?? 0
        try throwIfXMLUIErrorAlert(in: data, statusCode: code, actionName: "trustedDevice")

        guard code == HTTPStatusCodes.ok else {
            throw ServerError.badServerResponse(
                reason: "Trusted device request failed (HTTP \(code))",
                jsonPayload: prettyJSONString(from: data)
            )
        }
    }

    private func sendPhoneCode(mode: String,
                               phoneID: String?,
                               known: [TrustedPhoneNumber],
                               context: TwoFactorAuthContext) async throws -> PhoneCodeResponse
    {
        let sanitizedID: String = {
            if let id = phoneID?.trimmingCharacters(in: .whitespacesAndNewlines), !id.isEmpty {
                return id
            }
            return "1"
        }()

        var req = make2FARequest(url: Constants.URLs.phonePutURL(mode: mode), context: context)
        req.httpMethod = "POST"
        req.httpBody = try PropertyListSerialization.data(
            fromPropertyList: [
                "serverInfo": ["mode": mode, "phoneNumber.id": sanitizedID]
            ],
            format: .xml, options: 0
        )

        let (data, resp) = try await session.data(for: req)
        let statusCode = (resp as? HTTPURLResponse)?.safeStatusCode ?? 0
        try throwIfXMLUIErrorAlert(in: data, statusCode: statusCode, actionName: "sendPhoneCode")

        let dict = parsePlistOrJSON(data)
        let ec = dict?["ec"] as? Int ?? 0
        let em = (dict?["em"] as? String)
             ?? ((dict?["Status"] as? SendableDict)?["em"] as? String)

        if Self.isRateLimited(errorCode: ec, statusCode: statusCode) {
            throw DeveloperPortalError.tooManyAttempts(cause: em ?? "Rate limited")
        }
        if ec != 0 {
            throw ServerError.underlyingError(code: ec, message: em ?? "Failed to request code")
        }
        guard statusCode == HTTPStatusCodes.ok else {
            throw ServerError.badServerResponse(
                reason: em ?? HTTPStatusCodes.localizedDescription(for: statusCode),
                jsonPayload: prettyJSONString(from: data)
            )
        }

        return extractPhoneResponse(
            from: dict ?? [:],
            data: data,
            known: known,
            requestedID: phoneID,
            requestedMode: mode
        )
    }

    private func extractPhoneResponse(from dict: SendableDict,
                                      data: Data,
                                      known: [TrustedPhoneNumber],
                                      requestedID: String?,
                                      requestedMode: String) -> PhoneCodeResponse
    {
        var phones = parseTrustedPhoneNumbers(from: dict) ?? (known.isEmpty ? [] : known)

        let single       = dict["phoneNumber"] as? SendableDict
        let first        = (dict["phoneNumbers"] as? [SendableDict])?.first
        let trustedFirst = (dict["trustedPhoneNumbers"] as? [SendableDict])?.first
        let phoneDict    = single ?? first ?? trustedFirst

        let (xmlID, xmlMode) = parseXMLUIServerInfo(from: data)

        let rawID = (phoneDict?["id"] as? CustomStringConvertible)?.description
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let resolvedID = (rawID?.isEmpty == false ? rawID : nil) ?? xmlID
        let resolvedRequestedID = (requestedID?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false)
            ? requestedID : nil

        let phoneID = resolvedID ?? resolvedRequestedID ?? phones.first?.id ?? "1"
        let activeMode = (phoneDict?["mode"] as? String) ?? xmlMode ?? requestedMode

        let obfuscated = (phoneDict?["numberWithDialCode"] as? String)
                      ?? (phoneDict?["obfuscatedNumber"] as? String)
                      ?? (phoneDict?["lastTwoDigits"] as? String).map { "••\($0)" }
                      ?? parseXMLUIObfuscatedNumber(from: data)
                      ?? phones.first(where: { $0.id == phoneID })?.number
                      ?? ""

        if !obfuscated.isEmpty {
            if let idx = phones.firstIndex(where: { $0.id == phoneID }) {
                phones[idx] = TrustedPhoneNumber(id: phoneID, number: obfuscated)
            } else {
                phones.append(TrustedPhoneNumber(id: phoneID, number: obfuscated))
            }
        }

        return PhoneCodeResponse(phoneID: phoneID, activeMode: activeMode, phoneNumbers: phones)
    }

    // MARK: - Validate Code

    private func validatePhone(code: String,
                               phoneID: String,
                               mode: String,
                               context: TwoFactorAuthContext) async throws -> ValidationResult
    {
        var req = make2FARequest(url: Constants.URLs.phoneSecurityCode, context: context)
        req.httpMethod = "POST"
        req.httpBody = try PropertyListSerialization.data(
            fromPropertyList: [
                "securityCode.code": code,
                "serverInfo": ["mode": mode, "phoneNumber.id": phoneID]
            ],
            format: .xml, options: 0
        )

        let (data, resp) = try await session.data(for: req)
        return try parseVerifyResponse(
            data: data,
            statusCode: (resp as? HTTPURLResponse)?.safeStatusCode ?? 0,
            requirePeToken: true,
            response: resp as? HTTPURLResponse
        )
    }

    private func parseVerifyResponse(data: Data,
                                     statusCode: Int,
                                     requirePeToken: Bool,
                                     response: HTTPURLResponse?) throws -> ValidationResult
    {
        let dict = parsePlistOrJSON(data)
        let (title, msg) = parseXMLUIAlertMessage(from: data)
        let ec = dict?["ec"] as? Int ?? 0
        let statusDict = dict?["Status"] as? SendableDict
        let em = (dict?["em"] as? String)
             ?? (statusDict?["em"] as? String)
             ?? msg ?? title

        if Self.isRateLimited(errorCode: ec, statusCode: statusCode) {
            throw DeveloperPortalError.tooManyAttempts(cause: em ?? "Too many attempts")
        }
        if ec == GrandSlamAuthErrorCodes.incorrectVerificationCode {
            return .retry(message: em ?? "Incorrect code")
        }
        if ec != 0 {
            throw ServerError.underlyingError(code: ec, message: em ?? "2FA error")
        }
        if title != nil || msg != nil {
            throw DeveloperPortalError.invalid2FAResponse(cause: msg ?? em ?? title ?? "Verification failed")
        }
        guard statusCode == HTTPStatusCodes.ok else {
            return .retry(message: em ?? HTTPStatusCodes.localizedDescription(for: statusCode))
        }

        if requirePeToken,
           response?.value(forHTTPHeaderField: "X-Apple-PE-Token") == nil {
            return .retry(message: em ?? "Missing PE token")
        }
        return .success
    }

    private static func isRateLimited(errorCode: Int, statusCode: Int) -> Bool {
        errorCode == GrandSlamAuthErrorCodes.tooManyAttempts
            || errorCode == GrandSlamAuthErrorCodes.tooManyCodesRequested
            || errorCode == GrandSlamAuthErrorCodes.rateLimited
            || statusCode == HTTPStatusCodes.tooManyRequests
    }

    // MARK: - 2FA Request Builder

    private func make2FARequest(url: URL, context: TwoFactorAuthContext) -> URLRequest {
        let identity = "\(context.dsid):\(context.idmsToken)"
        let encoded = Data(identity.utf8).base64EncodedString()
        let a = context.anisetteData

        var req = URLRequest(url: url)
        let headers: [String: String] = [
            "Accept": "application/x-buddyml",
            "Accept-Language": "en-us",
            "Content-Type": "application/x-plist",
            "User-Agent": Constants.xcodeUserAgent,
            "X-Apple-App-Info": Constants.authApp,
            "X-Xcode-Version": context.xcodeVersion,
            "X-Apple-Identity-Token": encoded,
            "X-Apple-I-MD": a.oneTimePassword,
            "X-Apple-I-MD-M": a.machineID,
            "X-Mme-Device-Id": a.deviceID,
            "X-MMe-Client-Info": a.clientInfo,
            "X-Apple-I-MD-LU": a.localUserID,
            "X-Apple-I-MD-RINFO": a.routingInfo,
            "X-Apple-I-SRL-NO": a.serialNumber,
            "X-Apple-I-Client-Time": a.clientTime,
            "X-Apple-Locale": a.locale,
            "X-Apple-I-TimeZone": a.timeZone
        ]
        headers.forEach { req.setValue($1, forHTTPHeaderField: $0) }
        return req
    }

    // MARK: - XML-UI Parsing

    private func parseXMLUIAlertMessage(from data: Data) -> (title: String?, message: String?) {
        guard let str = String(data: data, encoding: .utf8),
              !str.contains("<pinView"),
              let range = str.range(of: #"<alert(?![^>]*\bid=)[^>]*>"#, options: .regularExpression)
        else { return (nil, nil) }

        let tag = String(str[range])
        let title = tag.firstMatch(#"(?<=title=")[^"]+"#)
        let message = tag.firstMatch(#"(?<=message=")[^"]+"#)
        return (title, message)
    }

    private func parseXMLUIServerInfo(from data: Data) -> (phoneID: String?, mode: String?) {
        guard let str = String(data: data, encoding: .utf8),
              let range = str.range(of: #"<serverInfo[^>]*>"#, options: .regularExpression)
        else { return (nil, nil) }

        let tag = String(str[range])
        let id = tag.firstMatch(#"(?<=phoneNumber\.id=")[^"]+"#)
        let mode = tag.firstMatch(#"(?<=mode=")[^"]+"#)
        return (id, mode)
    }

    private func parseXMLUIObfuscatedNumber(from data: Data) -> String? {
        guard let str = String(data: data, encoding: .utf8) else { return nil }
        let patterns = [
            #"(?:to|at)\s+([+•\d\s\(\)-]{4,25})[.\s<]"#,
            #"([+•\d\s\(\)-]*[•]+[+•\d\s\(\)-]*)"#
        ]
        for pattern in patterns {
            if let match = str.firstMatch(pattern) {
                let cleaned = match
                    .replacingOccurrences(of: "to ", with: "")
                    .replacingOccurrences(of: "at ", with: "")
                    .trimmingCharacters(in: CharacterSet(charactersIn: ". <\n\r\t"))
                if cleaned.contains("•") && cleaned.count >= 3 { return cleaned }
            }
        }
        return nil
    }

    private func throwIfXMLUIErrorAlert(in data: Data, statusCode: Int, actionName: String) throws {
        let (title, message) = parseXMLUIAlertMessage(from: data)
        guard title != nil || message != nil else { return }

        let combined = [title, message]
            .compactMap { $0?.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .joined(separator: ": ")
        debugLog("[SideSign] \(actionName) alert (HTTP \(statusCode)): \(combined)")
        throw DeveloperPortalError.invalid2FAResponse(cause: message ?? combined)
    }

    // MARK: - Phone Parsing

    private func parseTrustedPhoneNumbers(from dict: SendableDict?) -> [TrustedPhoneNumber]? {
        guard let dict else { return nil }

        let list = (dict["trustedPhoneNumbers"] as? [SendableDict])
                ?? (dict["phoneNumbers"] as? [SendableDict])
                ?? []

        var results = list.compactMap(Self.phoneNumber(from:))
        if results.isEmpty,
           let single = dict["phoneNumber"] as? SendableDict,
           let phone = Self.phoneNumber(from: single) {
            results = [phone]
        }
        return results.isEmpty ? nil : results
    }

    private static func phoneNumber(from item: SendableDict) -> TrustedPhoneNumber? {
        guard let id = (item["id"] as? CustomStringConvertible)?.description
                .trimmingCharacters(in: .whitespacesAndNewlines),
              !id.isEmpty
        else { return nil }

        let number = (item["numberWithDialCode"] as? String)
                  ?? (item["obfuscatedNumber"] as? String)
                  ?? (item["lastTwoDigits"] as? String).map { "••\($0)" }
                  ?? "Phone \(id)"
        return TrustedPhoneNumber(id: id, number: number)
    }
}

// MARK: - String Regex Helper

private extension String {
    /// Trả về match đầu tiên cho regex (không cần capture group).
    func firstMatch(_ pattern: String) -> String? {
        guard let range = range(of: pattern, options: .regularExpression) else { return nil }
        return String(self[range])
    }
}
