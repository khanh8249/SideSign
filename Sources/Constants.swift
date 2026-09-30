//
//  Constants.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

// MARK: - Protocol & Client

public enum Constants {

    // MARK: Protocol Versions
    public static let protocolVersion         = "QH65B2"
    public static let servicesProtocolVersion = "v1"
    public static let authProtocolVersion     = "A1234"
    public static let grandSlamAuthHeader     = "1.0.1"

    // MARK: Service Identity
    public static let grandSlamService = "iCloud"
    public static let clientID         = "XABBG36SBA"
    public static let appIDKey         = "ba2ec180e6ca6e6c6a542255453b24d6e6e5b2be0cc48bc1b0d8ad64cfe0228f"
    public static let authApp          = "com.apple.gs.xcode.auth"

    // MARK: User Agents
    public static let userAgent        = "AuthKit/1 (Macintosh; OS X 26.6) (com.apple.dt.Xcode/26.0)"
    public static let authKitUserAgent = "AuthKit/1 (Macintosh; OS X 26.6)"
    public static let xcodeUserAgent   = "Xcode"

    // MARK: Messages
    public static let defaultAccountRepairMessage =
        "Your Apple ID requires account verification or terms agreement.\n" +
        "Please sign in to developer.apple.com or appleid.apple.com."

    // MARK: URL Namespace
    public enum URLs {

        // MARK: Base hosts
        fileprivate static let grandSlamHost = "https://gsa.apple.com"
        fileprivate static let phoneBase     = "\(grandSlamHost)/auth/verify/phone"

        fileprivate static let servicesBase  = "https://developerservices2.apple.com/services/\(Constants.protocolVersion)"
        fileprivate static let servicesV1    = "https://developerservices2.apple.com/services/\(Constants.servicesProtocolVersion)"

        // MARK: - Auth
        public static let developerAccount = url("https://developer.apple.com/account")
        public static let grandSlamAuth    = url("\(grandSlamHost)/grandslam/GsService2")
        public static let grandSlamLookup  = url("\(grandSlamHost)/grandslam/GsService2/lookup")
        public static let grandSlamValidate = url("\(grandSlamHost)/grandslam/GsService2/validate")

        public static let trustedDevice             = url("\(grandSlamHost)/auth/verify/trusteddevice")
        public static let trustedDeviceSecurityCode = url("\(grandSlamHost)/auth/verify/trusteddevice/securitycode")

        public static let phoneSecurityCode = url("\(phoneBase)/securitycode?referrer=/auth/verify/phone/put")

        public static func phonePutURL(mode: String = "sms") -> URL {
            url("\(phoneBase)/put?mode=\(mode)")
        }

        public static let appleAuthDevices = url("https://idmsa.apple.com/appleauth/auth/devices")

        // MARK: - Developer Portal Base
        public static let developerServicesBase   = url("\(servicesBase)/")
        public static let developerServicesV1Base = url("\(servicesV1)/")
        public static let appStoreConnectBase     = url("https://appstoreconnect.apple.com/iris/\(Constants.servicesProtocolVersion)/")

        // MARK: - Developer Portal Actions
        public static let viewDeveloper = url("\(servicesBase)/viewDeveloper.action")
        public static let listTeams     = url("\(servicesBase)/listTeams.action")

        // MARK: - iOS: App IDs
        public static let listAppIDs  = url("\(servicesBase)/ios/listAppIds.action")
        public static let addAppID    = url("\(servicesBase)/ios/addAppId.action")
        public static let updateAppID = url("\(servicesBase)/ios/updateAppId.action")
        public static let deleteAppID = url("\(servicesBase)/ios/deleteAppId.action")

        // MARK: - iOS: Application Groups
        public static let listApplicationGroups  = url("\(servicesBase)/ios/listApplicationGroups.action")
        public static let addApplicationGroup    = url("\(servicesBase)/ios/addApplicationGroup.action")
        public static let updateApplicationGroup = url("\(servicesBase)/ios/updateApplicationGroup.action")
        public static let assignApplicationGroup = url("\(servicesBase)/ios/assignApplicationGroupToAppId.action")
        public static let deleteApplicationGroup = url("\(servicesBase)/ios/deleteApplicationGroup.action")

        // MARK: - iOS: Devices
        public static let listDevices    = url("\(servicesBase)/ios/listDevices.action")
        public static let addDevice      = url("\(servicesBase)/ios/addDevice.action")
        public static let updateDevice   = url("\(servicesBase)/ios/updateDevice.action")
        public static let disableDevice  = url("\(servicesBase)/ios/disableDevice.action")
        public static let deleteDevice   = url("\(servicesBase)/ios/deleteDevice.action")

        // MARK: - iOS: Certificates
        public static let listCertificates = url("\(servicesBase)/ios/listAllDevelopmentCerts.action")
        public static let submitCSR        = url("\(servicesBase)/ios/submitDevelopmentCSR.action")

        // MARK: - iOS: Provisioning Profiles
        public static let listProvisioningProfiles          = url("\(servicesBase)/ios/listProvisioningProfiles.action")
        public static let downloadProvisioningProfile       = url("\(servicesBase)/ios/downloadTeamProvisioningProfile.action")
        public static let downloadManualProvisioningProfile = url("\(servicesBase)/ios/downloadProvisioningProfile.action")
        public static let createProvisioningProfile         = url("\(servicesBase)/ios/createProvisioningProfile.action")
        public static let regenProvisioningProfile          = url("\(servicesBase)/ios/regenProvisioningProfile.action")
        public static let deleteProvisioningProfile         = url("\(servicesBase)/ios/deleteProvisioningProfile.action")

        // MARK: - Anisette
        public static let v3ClientInfo          = "v3/client_info"
        public static let v3GetHeaders          = "v3/get_headers"
        public static let v3ProvisioningSession = "v3/provisioning_session"

        // MARK: - Helpers

        /// Tạo URL từ chuỗi tĩnh (internal). Chỉ dùng cho literal biên dịch được.
        /// - Note: Static và force-unwrap an toàn vì mọi literal đều đã được kiểm tra.
        private static func url(_ string: String) -> URL {
            guard let url = URL(string: string) else {
                preconditionFailure("Invalid URL literal: \(string)")
            }
            return url
        }
    }

    // MARK: - Secondary Auth
    public enum SecondaryAuthType: String, Sendable, CaseIterable {
        case secondaryAuth
        case sms
        case voice
        case phone
    }

    // MARK: - Session Storage
    public enum Session {
        public static let magicSS01: [UInt8] = Array("SS01".utf8) // auto
        public static let magicSS02: [UInt8] = Array("SS02".utf8) // pass

        public static let saltLength     = 16
        public static let nonceLength    = 12
        public static let tagLength      = 16
        public static let pbkdf2Rounds   = 100_000
        public static let keyOutputLength = 32

        public static let defaultDirName    = "sidesign"
        public static let defaultConfigDir  = ".config"
        public static let sessionSubdirectory = "session"
        public static let defaultFileName   = "session.dat"
        public static let filePrefix        = "session_"
        public static let fileExtension     = ".dat"

        public static let machineSeedInfo   = "SideSign.AES-GCM.SessionStorageKey"
        public static let machineSeedDomain = "SideSign.Session.MachineSeed.v1"
        public static let fallbackSeed      = "SideSignFallbackSeed"

        public static let envXDGConfig = "XDG_CONFIG_HOME"
        public static let envAppData   = "APPDATA"
        public static let envHome      = "HOME"
        public static let envUser      = "USER"
        public static let envUsername  = "USERNAME"
    }

    // MARK: - Device Data
    public enum DeviceData {
        public static let magicADID: [UInt8] = Array("ADI1".utf8)
        public static let defaultFileName    = "machine.dat"
        public static let filePrefix         = "machine_"
        public static let fileExtension      = ".dat"
    }

    // MARK: - Anisette Paths
    public enum Anisette {
        public static let defaultBaseDirName     = ".sidesign"
        public static let localLibsSubdirectory  = "local-libs"
        public static let remoteLibsSubdirectory = "remote-libs"
        public static let provisioningSubdirectory = "provisioning"

        public static let cachingPollingDelayNanoseconds: UInt64 = 200_000_000
        public static let remoteCacheDuration: TimeInterval      = 30.0
        public static let serverValidationTimeout: TimeInterval  = 3.0
    }
}

// MARK: - Error Codes

public enum GrandSlamAuthErrorCodes {
    public static let incorrectCredentials                = -22406
    public static let appSpecificPasswordRequired         = -20101
    public static let appSpecificPasswordRequiredFallback = -20209
    public static let incorrectVerificationCode           = -21669
    public static let tooManyCodesRequested               = -20102
    public static let tooManyAttempts                     = -21668
    public static let rateLimited                         = -22411
    public static let serverError                         = -22416
}

public enum DeveloperPortalResultCodes {
    public static let success                             = 0
    public static let serviceMappingUnavailable           = 1003
    public static let invalidCertificateRequest           = 3250
    public static let appGroupDoesNotExist                = 35
    public static let deviceAlreadyRegistered             = 35
    public static let maximumCertificatesReached          = 35
    public static let maximumCertificatesReachedAlternate = 7460
    public static let bundleIdentifierUnavailable         = 35
    public static let maximumAppIDLimitReached            = 37
    public static let appIDDoesNotExist                   = 9115
    public static let appIDDoesNotExistAlternate          = 8201
}

// MARK: - HTTP

public enum HTTPStatusCodes {
    public static let ok                  = 200
    public static let noContent           = 204
    public static let badRequest          = 400
    public static let unauthorized        = 401
    public static let forbidden           = 403
    public static let notFound            = 404
    public static let tooManyRequests     = 429
    public static let internalServerError = 500
    public static let badGateway          = 502
    public static let serviceUnavailable  = 503
    public static let gatewayTimeout      = 504

    public static func localizedDescription(for statusCode: Int) -> String {
        switch statusCode {
        case badRequest:          "The server rejected the request parameters."
        case unauthorized:        "Your sign-in session expired or is unauthorized."
        case forbidden:           "Access to this Apple Developer service was denied."
        case notFound:            "The requested Apple service endpoint could not be found."
        case tooManyRequests:     "Too many requests sent to Apple. Please wait a few moments and try again."
        case internalServerError: "Apple's authentication servers encountered an internal error."
        case badGateway:          "Apple's servers received an invalid gateway response."
        case serviceUnavailable:  "Apple Developer Portal is temporarily unavailable or undergoing maintenance."
        case gatewayTimeout:      "Apple's servers took too long to respond (connection timed out)."
        default:                  "Apple service returned an unexpected error (HTTP \(statusCode))."
        }
    }
}

// MARK: - Device Family

public enum UIDeviceFamilyCodes {
    public static let iPhone     = 1
    public static let iPad       = 2
    public static let appleTV    = 3
    public static let appleWatch = 4
    public static let mac        = 6
    public static let visionPro  = 7
}
