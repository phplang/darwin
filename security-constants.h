/* https://developer.apple.com/documentation/security/keychain_services/keychains/1536090-seckeychainstatus_values */
PHP_DARWIN_LONG(kSecUnlockStateStatus)
PHP_DARWIN_LONG(kSecReadPermStatus)
PHP_DARWIN_LONG(kSecWritePermStatus)

/* https://developer.apple.com/documentation/security/1542001-security_framework_result_codes */
/* System Result Codes */
PHP_DARWIN_LONG(errSecSuccess)
PHP_DARWIN_LONG(errSecUnimplemented)
PHP_DARWIN_LONG(errSecDskFull)
PHP_DARWIN_LONG(errSecDiskFull)
PHP_DARWIN_LONG(errSecIO)
PHP_DARWIN_LONG(errSecOpWr)
PHP_DARWIN_LONG(errSecParam)
PHP_DARWIN_LONG(errSecWrPerm)
PHP_DARWIN_LONG(errSecAllocate)
PHP_DARWIN_LONG(errSecUserCanceled)
PHP_DARWIN_LONG(errSecBadReq)
/* Internal Error Result Codes */
PHP_DARWIN_LONG(errSecInternalComponent)
PHP_DARWIN_LONG(errSecCoreFoundationUnknown)
PHP_DARWIN_LONG(errSecInternalError)
/* Keychain Result Codes */
PHP_DARWIN_LONG(errSecNotAvailable)
PHP_DARWIN_LONG(errSecReadOnly)
PHP_DARWIN_LONG(errSecAuthFailed)
PHP_DARWIN_LONG(errSecNoSuchKeychain)
PHP_DARWIN_LONG(errSecInvalidKeychain)
PHP_DARWIN_LONG(errSecDuplicateKeychain)
PHP_DARWIN_LONG(errSecDuplicateCallback)
PHP_DARWIN_LONG(errSecInvalidCallback)
PHP_DARWIN_LONG(errSecDuplicateItem)
PHP_DARWIN_LONG(errSecItemNotFound)
PHP_DARWIN_LONG(errSecBufferTooSmall)
PHP_DARWIN_LONG(errSecDataTooLarge)
PHP_DARWIN_LONG(errSecNoSuchAttr)
PHP_DARWIN_LONG(errSecInvalidItemRef)
PHP_DARWIN_LONG(errSecInvalidSearchRef)
PHP_DARWIN_LONG(errSecNoSuchClass)
PHP_DARWIN_LONG(errSecNoDefaultKeychain)
PHP_DARWIN_LONG(errSecInteractionNotAllowed)
PHP_DARWIN_LONG(errSecReadOnlyAttr)
PHP_DARWIN_LONG(errSecWrongSecVersion)
PHP_DARWIN_LONG(errSecKeySizeNotAllowed)
PHP_DARWIN_LONG(errSecNoStorageModule)
PHP_DARWIN_LONG(errSecNoCertificateModule)
PHP_DARWIN_LONG(errSecNoPolicyModule)
PHP_DARWIN_LONG(errSecInteractionRequired)
PHP_DARWIN_LONG(errSecDataNotAvailable)
PHP_DARWIN_LONG(errSecDataNotModifiable)
PHP_DARWIN_LONG(errSecCreateChainFailed)
PHP_DARWIN_LONG(errSecInvalidPrefsDomain)
PHP_DARWIN_LONG(errSecInDarkWake)
/* Certificate Result Codes */
PHP_DARWIN_LONG(errSecUnknownCriticalExtensionFlag)
PHP_DARWIN_LONG(errSecCertificateCannotOperate)
PHP_DARWIN_LONG(errSecCertificateExpired)
PHP_DARWIN_LONG(errSecCertificateNotValidYet)
PHP_DARWIN_LONG(errSecCertificateRevoked)
PHP_DARWIN_LONG(errSecCertificateSuspended)
PHP_DARWIN_LONG(errSecInvalidCertAuthority)
PHP_DARWIN_LONG(errSecInvalidCertificateGroup)
PHP_DARWIN_LONG(errSecInvalidCertificateRef)
/* ACL Result Codes */
PHP_DARWIN_LONG(errSecACLAddFailed)
PHP_DARWIN_LONG(errSecACLChangeFailed)
PHP_DARWIN_LONG(errSecACLDeleteFailed)
PHP_DARWIN_LONG(errSecACLNotSimple)
PHP_DARWIN_LONG(errSecACLReplaceFailed)
PHP_DARWIN_LONG(errSecAppleAddAppACLSubject)
PHP_DARWIN_LONG(errSecInvalidBaseACLs)
PHP_DARWIN_LONG(errSecInvalidACL)
/* CRL Result Codes */
PHP_DARWIN_LONG(errSecCRLExpired)
PHP_DARWIN_LONG(errSecCRLNotValidYet)
PHP_DARWIN_LONG(errSecCRLNotFound)
PHP_DARWIN_LONG(errSecCRLServerDown)
PHP_DARWIN_LONG(errSecCRLBadURI)
PHP_DARWIN_LONG(errSecCRLNotTrusted)
PHP_DARWIN_LONG(errSecUnknownCertExtension)
PHP_DARWIN_LONG(errSecUnknownCRLExtension)
PHP_DARWIN_LONG(errSecCRLPolicyFailed)
PHP_DARWIN_LONG(errSecCRLAlreadySigned)
PHP_DARWIN_LONG(errSecIDPFailure)
PHP_DARWIN_LONG(errSecInvalidCRLEncoding)
PHP_DARWIN_LONG(errSecInvalidCRLType)
PHP_DARWIN_LONG(errSecInvalidCRL)
PHP_DARWIN_LONG(errSecInvalidCRLGroup)
PHP_DARWIN_LONG(errSecInvalidCRLIndex)
PHP_DARWIN_LONG(errSecInvaldCRLAuthority)
/* SMIME Result Codes */
PHP_DARWIN_LONG(errSecSMIMEEmailAddressesNotFound)
PHP_DARWIN_LONG(errSecSMIMEBadExtendedKeyUsage)
PHP_DARWIN_LONG(errSecSMIMEBadKeyUsage)
PHP_DARWIN_LONG(errSecSMIMEKeyUsageNotCritical)
PHP_DARWIN_LONG(errSecSMIMENoEmailAddress)
PHP_DARWIN_LONG(errSecSMIMESubjAltNameNotCritical)
PHP_DARWIN_LONG(errSecSSLBadExtendedKeyUsage)
/* OCSP Result Codes */
PHP_DARWIN_LONG(errSecOCSPBadResponse)
PHP_DARWIN_LONG(errSecOCSPBadRequest)
PHP_DARWIN_LONG(errSecOCSPUnavailable)
PHP_DARWIN_LONG(errSecOCSPStatusUnrecognized)
PHP_DARWIN_LONG(errSecEndOfData)
PHP_DARWIN_LONG(errSecIncompleteCertRevocationCheck)
PHP_DARWIN_LONG(errSecNetworkFailure)
PHP_DARWIN_LONG(errSecOCSPNotTrustedToAnchor)
PHP_DARWIN_LONG(errSecRecordModified)
PHP_DARWIN_LONG(errSecOCSPSignatureError)
PHP_DARWIN_LONG(errSecOCSPNoSigner)
PHP_DARWIN_LONG(errSecOCSPResponderMalformedReq)
PHP_DARWIN_LONG(errSecOCSPResponderInternalError)
PHP_DARWIN_LONG(errSecOCSPResponderTryLater)
PHP_DARWIN_LONG(errSecOCSPResponderSignatureRequired)
PHP_DARWIN_LONG(errSecOCSPResponderUnauthorized)
PHP_DARWIN_LONG(errSecOCSPResponseNonceMismatch)
/* Code Signing Result Codes */
PHP_DARWIN_LONG(errSecCodeSigningBadCertChainLength)
PHP_DARWIN_LONG(errSecCodeSigningNoBasicConstraints)
PHP_DARWIN_LONG(errSecCodeSigningBadPathLengthConstraint)
PHP_DARWIN_LONG(errSecCodeSigningNoExtendedKeyUsage)
PHP_DARWIN_LONG(errSecCodeSigningDevelopment)
PHP_DARWIN_LONG(errSecResourceSignBadCertChainLength)
PHP_DARWIN_LONG(errSecResourceSignBadExtKeyUsage)
PHP_DARWIN_LONG(errSecTrustSettingDeny)
PHP_DARWIN_LONG(errSecInvalidSubjectName)
PHP_DARWIN_LONG(errSecUnknownQualifiedCertStatement)
/* Mobile Me Result Codes */
PHP_DARWIN_LONG(errSecMobileMeRequestQueued)
PHP_DARWIN_LONG(errSecMobileMeRequestRedirected)
PHP_DARWIN_LONG(errSecMobileMeServerError)
PHP_DARWIN_LONG(errSecMobileMeServerNotAvailable)
PHP_DARWIN_LONG(errSecMobileMeServerAlreadyExists)
PHP_DARWIN_LONG(errSecMobileMeServerServiceErr)
PHP_DARWIN_LONG(errSecMobileMeRequestAlreadyPending)
PHP_DARWIN_LONG(errSecMobileMeNoRequestPending)
PHP_DARWIN_LONG(errSecMobileMeCSRVerifyFailure)
PHP_DARWIN_LONG(errSecMobileMeFailedConsistencyCheck)
/* Cryptographic Key Result Codes */
PHP_DARWIN_LONG(errSecKeyUsageIncorrect)
PHP_DARWIN_LONG(errSecKeyBlobTypeIncorrect)
PHP_DARWIN_LONG(errSecKeyHeaderInconsistent)
PHP_DARWIN_LONG(errSecKeyIsSensitive)
PHP_DARWIN_LONG(errSecUnsupportedKeyFormat)
PHP_DARWIN_LONG(errSecUnsupportedKeySize)
PHP_DARWIN_LONG(errSecInvalidKeyUsageMask)
PHP_DARWIN_LONG(errSecUnsupportedKeyUsageMask)
PHP_DARWIN_LONG(errSecInvalidKeyAttributeMask)
PHP_DARWIN_LONG(errSecUnsupportedKeyAttributeMask)
PHP_DARWIN_LONG(errSecInvalidKeyLabel)
PHP_DARWIN_LONG(errSecUnsupportedKeyLabel)
PHP_DARWIN_LONG(errSecInvalidKeyFormat)
PHP_DARWIN_LONG(errSecInvalidKeyBlob)
PHP_DARWIN_LONG(errSecInvalidKeyHierarchy)
PHP_DARWIN_LONG(errSecInvalidKeyRef)
PHP_DARWIN_LONG(errSecInvalidKeyUsageForPolicy)
/* Invalid Attribute Result Codes */
PHP_DARWIN_LONG(errSecInvalidAttributeKey)
PHP_DARWIN_LONG(errSecInvalidAttributeInitVector)
PHP_DARWIN_LONG(errSecInvalidAttributeSalt)
PHP_DARWIN_LONG(errSecInvalidAttributePadding)
PHP_DARWIN_LONG(errSecInvalidAttributeRandom)
PHP_DARWIN_LONG(errSecInvalidAttributeSeed)
PHP_DARWIN_LONG(errSecInvalidAttributePassphrase)
PHP_DARWIN_LONG(errSecInvalidAttributeKeyLength)
PHP_DARWIN_LONG(errSecInvalidAttributeBlockSize)
PHP_DARWIN_LONG(errSecInvalidAttributeOutputSize)
PHP_DARWIN_LONG(errSecInvalidAttributeRounds)
PHP_DARWIN_LONG(errSecInvalidAlgorithmParms)
PHP_DARWIN_LONG(errSecInvalidAttributeLabel)
PHP_DARWIN_LONG(errSecInvalidAttributeKeyType)
PHP_DARWIN_LONG(errSecInvalidAttributeMode)
PHP_DARWIN_LONG(errSecInvalidAttributeEffectiveBits)
PHP_DARWIN_LONG(errSecInvalidAttributeStartDate)
PHP_DARWIN_LONG(errSecInvalidAttributeEndDate)
PHP_DARWIN_LONG(errSecInvalidAttributeVersion)
PHP_DARWIN_LONG(errSecInvalidAttributePrime)
PHP_DARWIN_LONG(errSecInvalidAttributeBase)
PHP_DARWIN_LONG(errSecInvalidAttributeSubprime)
PHP_DARWIN_LONG(errSecInvalidAttributeIterationCount)
PHP_DARWIN_LONG(errSecInvalidAttributeDLDBHandle)
PHP_DARWIN_LONG(errSecInvalidAttributeAccessCredentials)
PHP_DARWIN_LONG(errSecInvalidAttributePublicKeyFormat)
PHP_DARWIN_LONG(errSecInvalidAttributePrivateKeyFormat)
PHP_DARWIN_LONG(errSecInvalidAttributeSymmetricKeyFormat)
PHP_DARWIN_LONG(errSecInvalidAttributeWrappedKeyFormat)
/* Missing Attribute Result Codes */
PHP_DARWIN_LONG(errSecMissingAttributeKey)
PHP_DARWIN_LONG(errSecMissingAttributeInitVector)
PHP_DARWIN_LONG(errSecMissingAttributeSalt)
PHP_DARWIN_LONG(errSecMissingAttributePadding)
PHP_DARWIN_LONG(errSecMissingAttributeRandom)
PHP_DARWIN_LONG(errSecMissingAttributeSeed)
PHP_DARWIN_LONG(errSecMissingAttributePassphrase)
PHP_DARWIN_LONG(errSecMissingAttributeKeyLength)
PHP_DARWIN_LONG(errSecMissingAttributeBlockSize)
PHP_DARWIN_LONG(errSecMissingAttributeOutputSize)
PHP_DARWIN_LONG(errSecMissingAttributeRounds)
PHP_DARWIN_LONG(errSecMissingAlgorithmParms)
PHP_DARWIN_LONG(errSecMissingAttributeLabel)
PHP_DARWIN_LONG(errSecMissingAttributeKeyType)
PHP_DARWIN_LONG(errSecMissingAttributeMode)
PHP_DARWIN_LONG(errSecMissingAttributeEffectiveBits)
PHP_DARWIN_LONG(errSecMissingAttributeStartDate)
PHP_DARWIN_LONG(errSecMissingAttributeEndDate)
PHP_DARWIN_LONG(errSecMissingAttributeVersion)
PHP_DARWIN_LONG(errSecMissingAttributePrime)
PHP_DARWIN_LONG(errSecMissingAttributeBase)
PHP_DARWIN_LONG(errSecMissingAttributeSubprime)
PHP_DARWIN_LONG(errSecMissingAttributeIterationCount)
PHP_DARWIN_LONG(errSecMissingAttributeDLDBHandle)
PHP_DARWIN_LONG(errSecMissingAttributeAccessCredentials)
PHP_DARWIN_LONG(errSecMissingAttributePublicKeyFormat)
PHP_DARWIN_LONG(errSecMissingAttributePrivateKeyFormat)
PHP_DARWIN_LONG(errSecMissingAttributeSymmetricKeyFormat)
PHP_DARWIN_LONG(errSecMissingAttributeWrappedKeyFormat)
/* Timestamp Result Codes */
PHP_DARWIN_LONG(errSecTimestampMissing)
PHP_DARWIN_LONG(errSecTimestampInvalid)
PHP_DARWIN_LONG(errSecTimestampNotTrusted)
PHP_DARWIN_LONG(errSecTimestampServiceNotAvailable)
PHP_DARWIN_LONG(errSecTimestampBadAlg)
PHP_DARWIN_LONG(errSecTimestampBadRequest)
PHP_DARWIN_LONG(errSecTimestampBadDataFormat)
PHP_DARWIN_LONG(errSecTimestampTimeNotAvailable)
PHP_DARWIN_LONG(errSecTimestampUnacceptedPolicy)
PHP_DARWIN_LONG(errSecTimestampUnacceptedExtension)
PHP_DARWIN_LONG(errSecTimestampAddInfoNotAvailable)
PHP_DARWIN_LONG(errSecTimestampSystemFailure)
PHP_DARWIN_LONG(errSecSigningTimeMissing)
PHP_DARWIN_LONG(errSecTimestampRejection)
PHP_DARWIN_LONG(errSecTimestampWaiting)
PHP_DARWIN_LONG(errSecTimestampRevocationWarning)
PHP_DARWIN_LONG(errSecTimestampRevocationNotification)
/* Other Result Codes */
PHP_DARWIN_LONG(errSecAddinLoadFailed)
PHP_DARWIN_LONG(errSecAddinUnloadFailed)
PHP_DARWIN_LONG(errSecAlgorithmMismatch)
PHP_DARWIN_LONG(errSecAlreadyLoggedIn)
PHP_DARWIN_LONG(errSecAppleInvalidKeyEndDate)
PHP_DARWIN_LONG(errSecAppleInvalidKeyStartDate)
PHP_DARWIN_LONG(errSecApplePublicKeyIncomplete)
PHP_DARWIN_LONG(errSecAppleSSLv2Rollback)
PHP_DARWIN_LONG(errSecAppleSignatureMismatch)
PHP_DARWIN_LONG(errSecAttachHandleBusy)
PHP_DARWIN_LONG(errSecAttributeNotInContext)
PHP_DARWIN_LONG(errSecBlockSizeMismatch)
PHP_DARWIN_LONG(errSecCallbackFailed)
PHP_DARWIN_LONG(errSecConversionError)
PHP_DARWIN_LONG(errSecDatabaseLocked)
PHP_DARWIN_LONG(errSecDatastoreIsOpen)
PHP_DARWIN_LONG(errSecDecode)
PHP_DARWIN_LONG(errSecDeviceError)
PHP_DARWIN_LONG(errSecDeviceFailed)
PHP_DARWIN_LONG(errSecDeviceReset)
PHP_DARWIN_LONG(errSecDeviceVerifyFailed)
PHP_DARWIN_LONG(errSecEMMLoadFailed)
PHP_DARWIN_LONG(errSecEMMUnloadFailed)
PHP_DARWIN_LONG(errSecEventNotificationCallbackNotFound)
PHP_DARWIN_LONG(errSecExtendedKeyUsageNotCritical)
PHP_DARWIN_LONG(errSecFieldSpecifiedMultiple)
PHP_DARWIN_LONG(errSecFileTooBig)
PHP_DARWIN_LONG(errSecFunctionFailed)
PHP_DARWIN_LONG(errSecFunctionIntegrityFail)
PHP_DARWIN_LONG(errSecHostNameMismatch)
PHP_DARWIN_LONG(errSecIncompatibleDatabaseBlob)
PHP_DARWIN_LONG(errSecIncompatibleFieldFormat)
PHP_DARWIN_LONG(errSecIncompatibleKeyBlob)
PHP_DARWIN_LONG(errSecIncompatibleVersion)
PHP_DARWIN_LONG(errSecInputLengthError)
PHP_DARWIN_LONG(errSecInsufficientClientID)
PHP_DARWIN_LONG(errSecInsufficientCredentials)
PHP_DARWIN_LONG(errSecInvalidAccessCredentials)
PHP_DARWIN_LONG(errSecInvalidAccessRequest)
PHP_DARWIN_LONG(errSecInvalidAction)
PHP_DARWIN_LONG(errSecInvalidAddinFunctionTable)
PHP_DARWIN_LONG(errSecInvalidAlgorithm)
PHP_DARWIN_LONG(errSecInvalidAuthority)
PHP_DARWIN_LONG(errSecInvalidAuthorityKeyID)
PHP_DARWIN_LONG(errSecInvalidBundleInfo)
PHP_DARWIN_LONG(errSecInvalidContext)
PHP_DARWIN_LONG(errSecInvalidDBList)
PHP_DARWIN_LONG(errSecInvalidDBLocation)
PHP_DARWIN_LONG(errSecInvalidData)
PHP_DARWIN_LONG(errSecInvalidDatabaseBlob)
PHP_DARWIN_LONG(errSecInvalidDigestAlgorithm)
PHP_DARWIN_LONG(errSecInvalidEncoding)
PHP_DARWIN_LONG(errSecInvalidExtendedKeyUsage)
PHP_DARWIN_LONG(errSecInvalidFormType)
PHP_DARWIN_LONG(errSecInvalidGUID)
PHP_DARWIN_LONG(errSecInvalidHandle)
PHP_DARWIN_LONG(errSecInvalidHandleUsage)
PHP_DARWIN_LONG(errSecInvalidID)
PHP_DARWIN_LONG(errSecInvalidIDLinkage)
PHP_DARWIN_LONG(errSecInvalidIdentifier)
PHP_DARWIN_LONG(errSecInvalidIndex)
PHP_DARWIN_LONG(errSecInvalidIndexInfo)
PHP_DARWIN_LONG(errSecInvalidInputVector)
PHP_DARWIN_LONG(errSecInvalidLoginName)
PHP_DARWIN_LONG(errSecInvalidModifyMode)
PHP_DARWIN_LONG(errSecInvalidName)
PHP_DARWIN_LONG(errSecInvalidNetworkAddress)
PHP_DARWIN_LONG(errSecInvalidNewOwner)
PHP_DARWIN_LONG(errSecInvalidNumberOfFields)
PHP_DARWIN_LONG(errSecInvalidOutputVector)
PHP_DARWIN_LONG(errSecInvalidOwnerEdit)
PHP_DARWIN_LONG(errSecInvalidPVC)
PHP_DARWIN_LONG(errSecInvalidParsingModule)
PHP_DARWIN_LONG(errSecInvalidPassthroughID)
PHP_DARWIN_LONG(errSecInvalidPasswordRef)
PHP_DARWIN_LONG(errSecInvalidPointer)
PHP_DARWIN_LONG(errSecInvalidPolicyIdentifiers)
PHP_DARWIN_LONG(errSecInvalidQuery)
PHP_DARWIN_LONG(errSecInvalidReason)
PHP_DARWIN_LONG(errSecInvalidRecord)
PHP_DARWIN_LONG(errSecInvalidRequestInputs)
PHP_DARWIN_LONG(errSecInvalidRequestor)
PHP_DARWIN_LONG(errSecInvalidResponseVector)
PHP_DARWIN_LONG(errSecInvalidRoot)
PHP_DARWIN_LONG(errSecInvalidSampleValue)
PHP_DARWIN_LONG(errSecInvalidScope)
PHP_DARWIN_LONG(errSecInvalidServiceMask)
PHP_DARWIN_LONG(errSecInvalidSignature)
PHP_DARWIN_LONG(errSecInvalidStopOnPolicy)
PHP_DARWIN_LONG(errSecInvalidSubServiceID)
PHP_DARWIN_LONG(errSecInvalidSubjectKeyID)
PHP_DARWIN_LONG(errSecInvalidTimeString)
PHP_DARWIN_LONG(errSecInvalidTrustSetting)
PHP_DARWIN_LONG(errSecInvalidTrustSettings)
PHP_DARWIN_LONG(errSecInvalidTuple)
PHP_DARWIN_LONG(errSecInvalidTupleCredendtials)
PHP_DARWIN_LONG(errSecInvalidTupleGroup)
PHP_DARWIN_LONG(errSecInvalidValidityPeriod)
PHP_DARWIN_LONG(errSecInvalidValue)
PHP_DARWIN_LONG(errSecLibraryReferenceNotFound)
PHP_DARWIN_LONG(errSecMDSError)
PHP_DARWIN_LONG(errSecMemoryError)
PHP_DARWIN_LONG(errSecMissingRequiredExtension)
PHP_DARWIN_LONG(errSecMissingValue)
PHP_DARWIN_LONG(errSecModuleManagerInitializeFailed)
PHP_DARWIN_LONG(errSecModuleManagerNotFound)
PHP_DARWIN_LONG(errSecModuleManifestVerifyFailed)
PHP_DARWIN_LONG(errSecModuleNotLoaded)
PHP_DARWIN_LONG(errSecMultiplePrivKeys)
PHP_DARWIN_LONG(errSecMultipleValuesUnsupported)
PHP_DARWIN_LONG(errSecNoAccessForItem)
PHP_DARWIN_LONG(errSecNoBasicConstraints)
PHP_DARWIN_LONG(errSecNoBasicConstraintsCA)
PHP_DARWIN_LONG(errSecNoDefaultAuthority)
PHP_DARWIN_LONG(errSecNoFieldValues)
PHP_DARWIN_LONG(errSecNoTrustSettings)
PHP_DARWIN_LONG(errSecNotInitialized)
PHP_DARWIN_LONG(errSecNotLoggedIn)
PHP_DARWIN_LONG(errSecNotSigner)
PHP_DARWIN_LONG(errSecNotTrusted)
PHP_DARWIN_LONG(errSecOutputLengthError)
PHP_DARWIN_LONG(errSecPVCAlreadyConfigured)
PHP_DARWIN_LONG(errSecPVCReferentNotFound)
PHP_DARWIN_LONG(errSecPassphraseRequired)
PHP_DARWIN_LONG(errSecPathLengthConstraintExceeded)
PHP_DARWIN_LONG(errSecPkcs12VerifyFailure)
PHP_DARWIN_LONG(errSecPolicyNotFound)
PHP_DARWIN_LONG(errSecPrivilegeNotGranted)
PHP_DARWIN_LONG(errSecPrivilegeNotSupported)
PHP_DARWIN_LONG(errSecPublicKeyInconsistent)
PHP_DARWIN_LONG(errSecQuerySizeUnknown)
PHP_DARWIN_LONG(errSecQuotaExceeded)
PHP_DARWIN_LONG(errSecRejectedForm)
PHP_DARWIN_LONG(errSecRequestDescriptor)
PHP_DARWIN_LONG(errSecRequestLost)
PHP_DARWIN_LONG(errSecRequestRejected)
PHP_DARWIN_LONG(errSecSelfCheckFailed)
PHP_DARWIN_LONG(errSecServiceNotAvailable)
PHP_DARWIN_LONG(errSecStagedOperationInProgress)
PHP_DARWIN_LONG(errSecStagedOperationNotStarted)
PHP_DARWIN_LONG(errSecTagNotFound)
PHP_DARWIN_LONG(errSecTrustNotAvailable)
PHP_DARWIN_LONG(errSecUnknownFormat)
PHP_DARWIN_LONG(errSecUnknownTag)
PHP_DARWIN_LONG(errSecUnsupportedAddressType)
PHP_DARWIN_LONG(errSecUnsupportedFieldFormat)
PHP_DARWIN_LONG(errSecUnsupportedFormat)
PHP_DARWIN_LONG(errSecUnsupportedIndexInfo)
PHP_DARWIN_LONG(errSecUnsupportedLocality)
PHP_DARWIN_LONG(errSecUnsupportedNumAttributes)
PHP_DARWIN_LONG(errSecUnsupportedNumIndexes)
PHP_DARWIN_LONG(errSecUnsupportedNumRecordTypes)
PHP_DARWIN_LONG(errSecUnsupportedNumSelectionPreds)
PHP_DARWIN_LONG(errSecUnsupportedOperator)
PHP_DARWIN_LONG(errSecUnsupportedQueryLimits)
PHP_DARWIN_LONG(errSecUnsupportedService)
PHP_DARWIN_LONG(errSecUnsupportedVectorOfBuffers)
PHP_DARWIN_LONG(errSecVerificationFailure)
PHP_DARWIN_LONG(errSecVerifyActionFailed)
PHP_DARWIN_LONG(errSecVerifyFailed)

/* Certificate OIDs from: https://developer.apple.com/documentation/security/certificate_key_and_trust_services/certificates/certificate_oids */
PHP_DARWIN_STR(kSecOIDADC_CERT_POLICY)
PHP_DARWIN_STR(kSecOIDAPPLE_CERT_POLICY)
PHP_DARWIN_STR(kSecOIDAPPLE_EKU_CODE_SIGNING)
PHP_DARWIN_STR(kSecOIDAPPLE_EKU_CODE_SIGNING_DEV)
PHP_DARWIN_STR(kSecOIDAPPLE_EKU_ICHAT_ENCRYPTION)
PHP_DARWIN_STR(kSecOIDAPPLE_EKU_ICHAT_SIGNING)
PHP_DARWIN_STR(kSecOIDAPPLE_EKU_RESOURCE_SIGNING)
PHP_DARWIN_STR(kSecOIDAPPLE_EKU_SYSTEM_IDENTITY)
PHP_DARWIN_STR(kSecOIDAPPLE_EXTENSION)
PHP_DARWIN_STR(kSecOIDAPPLE_EXTENSION_ADC_APPLE_SIGNING)
PHP_DARWIN_STR(kSecOIDAPPLE_EXTENSION_ADC_DEV_SIGNING)
PHP_DARWIN_STR(kSecOIDAPPLE_EXTENSION_APPLE_SIGNING)
PHP_DARWIN_STR(kSecOIDAPPLE_EXTENSION_CODE_SIGNING)
PHP_DARWIN_STR(kSecOIDAuthorityInfoAccess)
PHP_DARWIN_STR(kSecOIDAuthorityKeyIdentifier)
PHP_DARWIN_STR(kSecOIDBasicConstraints)
PHP_DARWIN_STR(kSecOIDBiometricInfo)
PHP_DARWIN_STR(kSecOIDCSSMKeyStruct)
PHP_DARWIN_STR(kSecOIDCertIssuer)
PHP_DARWIN_STR(kSecOIDCertificatePolicies)
PHP_DARWIN_STR(kSecOIDClientAuth)
PHP_DARWIN_STR(kSecOIDCollectiveStateProvinceName)
PHP_DARWIN_STR(kSecOIDCollectiveStreetAddress)
PHP_DARWIN_STR(kSecOIDCommonName)
PHP_DARWIN_STR(kSecOIDCountryName)
PHP_DARWIN_STR(kSecOIDCrlDistributionPoints)
PHP_DARWIN_STR(kSecOIDCrlNumber)
PHP_DARWIN_STR(kSecOIDCrlReason)
PHP_DARWIN_STR(kSecOIDDOTMAC_CERT_EMAIL_ENCRYPT)
PHP_DARWIN_STR(kSecOIDDOTMAC_CERT_EMAIL_SIGN)
PHP_DARWIN_STR(kSecOIDDOTMAC_CERT_EXTENSION)
PHP_DARWIN_STR(kSecOIDDOTMAC_CERT_IDENTITY)
PHP_DARWIN_STR(kSecOIDDOTMAC_CERT_POLICY)
PHP_DARWIN_STR(kSecOIDDeltaCrlIndicator)
PHP_DARWIN_STR(kSecOIDDescription)
PHP_DARWIN_STR(kSecOIDEKU_IPSec)
PHP_DARWIN_STR(kSecOIDEmailAddress)
PHP_DARWIN_STR(kSecOIDEmailProtection)
PHP_DARWIN_STR(kSecOIDExtendedKeyUsage)
PHP_DARWIN_STR(kSecOIDExtendedKeyUsageAny)
PHP_DARWIN_STR(kSecOIDExtendedUseCodeSigning)
PHP_DARWIN_STR(kSecOIDGivenName)
PHP_DARWIN_STR(kSecOIDHoldInstructionCode)
PHP_DARWIN_STR(kSecOIDInvalidityDate)
PHP_DARWIN_STR(kSecOIDIssuerAltName)
PHP_DARWIN_STR(kSecOIDIssuingDistributionPoint)
PHP_DARWIN_STR(kSecOIDIssuingDistributionPoints)
PHP_DARWIN_STR(kSecOIDKERBv5_PKINIT_KP_CLIENT_AUTH)
PHP_DARWIN_STR(kSecOIDKERBv5_PKINIT_KP_KDC)
PHP_DARWIN_STR(kSecOIDKeyUsage)
PHP_DARWIN_STR(kSecOIDLocalityName)
PHP_DARWIN_STR(kSecOIDMS_NTPrincipalName)
PHP_DARWIN_STR(kSecOIDMicrosoftSGC)
PHP_DARWIN_STR(kSecOIDNameConstraints)
PHP_DARWIN_STR(kSecOIDNetscapeCertSequence)
PHP_DARWIN_STR(kSecOIDNetscapeCertType)
PHP_DARWIN_STR(kSecOIDNetscapeSGC)
PHP_DARWIN_STR(kSecOIDOCSPSigning)
PHP_DARWIN_STR(kSecOIDOrganizationName)
PHP_DARWIN_STR(kSecOIDOrganizationalUnitName)
PHP_DARWIN_STR(kSecOIDPolicyConstraints)
PHP_DARWIN_STR(kSecOIDPolicyMappings)
PHP_DARWIN_STR(kSecOIDPrivateKeyUsagePeriod)
PHP_DARWIN_STR(kSecOIDQC_Statements)
PHP_DARWIN_STR(kSecOIDSRVName)
PHP_DARWIN_STR(kSecOIDSerialNumber)
PHP_DARWIN_STR(kSecOIDServerAuth)
PHP_DARWIN_STR(kSecOIDStateProvinceName)
PHP_DARWIN_STR(kSecOIDStreetAddress)
PHP_DARWIN_STR(kSecOIDSubjectAltName)
PHP_DARWIN_STR(kSecOIDSubjectDirectoryAttributes)
PHP_DARWIN_STR(kSecOIDSubjectEmailAddress)
PHP_DARWIN_STR(kSecOIDSubjectInfoAccess)
PHP_DARWIN_STR(kSecOIDSubjectKeyIdentifier)
PHP_DARWIN_STR(kSecOIDSubjectPicture)
PHP_DARWIN_STR(kSecOIDSubjectSignatureBitmap)
PHP_DARWIN_STR(kSecOIDSurname)
PHP_DARWIN_STR(kSecOIDTimeStamping)
PHP_DARWIN_STR(kSecOIDTitle)
PHP_DARWIN_STR(kSecOIDUseExemptions)
PHP_DARWIN_STR(kSecOIDX509V1CertificateIssuerUniqueId)
PHP_DARWIN_STR(kSecOIDX509V1CertificateSubjectUniqueId)
PHP_DARWIN_STR(kSecOIDX509V1IssuerName)
PHP_DARWIN_STR(kSecOIDX509V1IssuerNameCStruct)
PHP_DARWIN_STR(kSecOIDX509V1IssuerNameLDAP)
PHP_DARWIN_STR(kSecOIDX509V1IssuerNameStd)
PHP_DARWIN_STR(kSecOIDX509V1SerialNumber)
PHP_DARWIN_STR(kSecOIDX509V1Signature)
PHP_DARWIN_STR(kSecOIDX509V1SignatureAlgorithm)
PHP_DARWIN_STR(kSecOIDX509V1SignatureAlgorithmParameters)
PHP_DARWIN_STR(kSecOIDX509V1SignatureAlgorithmTBS)
PHP_DARWIN_STR(kSecOIDX509V1SignatureCStruct)
PHP_DARWIN_STR(kSecOIDX509V1SignatureStruct)
PHP_DARWIN_STR(kSecOIDX509V1SubjectName)
PHP_DARWIN_STR(kSecOIDX509V1SubjectNameCStruct)
PHP_DARWIN_STR(kSecOIDX509V1SubjectNameLDAP)
PHP_DARWIN_STR(kSecOIDX509V1SubjectNameStd)
PHP_DARWIN_STR(kSecOIDX509V1SubjectPublicKey)
PHP_DARWIN_STR(kSecOIDX509V1SubjectPublicKeyAlgorithm)
PHP_DARWIN_STR(kSecOIDX509V1SubjectPublicKeyAlgorithmParameters)
PHP_DARWIN_STR(kSecOIDX509V1SubjectPublicKeyCStruct)
PHP_DARWIN_STR(kSecOIDX509V1ValidityNotAfter)
PHP_DARWIN_STR(kSecOIDX509V1ValidityNotBefore)
PHP_DARWIN_STR(kSecOIDX509V1Version)
PHP_DARWIN_STR(kSecOIDX509V3Certificate)
PHP_DARWIN_STR(kSecOIDX509V3CertificateCStruct)
PHP_DARWIN_STR(kSecOIDX509V3CertificateExtensionCStruct)
PHP_DARWIN_STR(kSecOIDX509V3CertificateExtensionCritical)
PHP_DARWIN_STR(kSecOIDX509V3CertificateExtensionId)
PHP_DARWIN_STR(kSecOIDX509V3CertificateExtensionStruct)
PHP_DARWIN_STR(kSecOIDX509V3CertificateExtensionType)
PHP_DARWIN_STR(kSecOIDX509V3CertificateExtensionValue)
PHP_DARWIN_STR(kSecOIDX509V3CertificateExtensionsCStruct)
PHP_DARWIN_STR(kSecOIDX509V3CertificateExtensionsStruct)
PHP_DARWIN_STR(kSecOIDX509V3CertificateNumberOfExtensions)
PHP_DARWIN_STR(kSecOIDX509V3SignedCertificate)
PHP_DARWIN_STR(kSecOIDX509V3SignedCertificateCStruct)

/* Search Attributes - https://developer.apple.com/documentation/security/keychain_services/keychain_items/search_attribute_keys_and_values */
PHP_DARWIN_STR(kSecMatchPolicy)
PHP_DARWIN_STR(kSecMatchItemList)
PHP_DARWIN_STR(kSecMatchSearchList)
PHP_DARWIN_STR(kSecMatchIssuers)
PHP_DARWIN_STR(kSecMatchEmailAddressIfPresent)
PHP_DARWIN_STR(kSecMatchSubjectContains)
PHP_DARWIN_STR(kSecMatchSubjectStartsWith)
PHP_DARWIN_STR(kSecMatchSubjectEndsWith)
PHP_DARWIN_STR(kSecMatchSubjectWholeString)
PHP_DARWIN_STR(kSecMatchCaseInsensitive)
PHP_DARWIN_STR(kSecMatchDiacriticInsensitive)
PHP_DARWIN_STR(kSecMatchWidthInsensitive)
PHP_DARWIN_STR(kSecMatchTrustedOnly)
PHP_DARWIN_STR(kSecMatchValidOnDate)
PHP_DARWIN_STR(kSecMatchLimit)
PHP_DARWIN_STR(kSecMatchLimitOne)
PHP_DARWIN_STR(kSecMatchLimitAll)
PHP_DARWIN_STR(kSecUseItemList)
PHP_DARWIN_ATTR(kSecUseKeychain, SecKeychain)
PHP_DARWIN_STR(kSecUseOperationPrompt)
PHP_DARWIN_STR(kSecUseAuthenticationUI)
PHP_DARWIN_STR(kSecUseAuthenticationContext)
PHP_DARWIN_STR(kSecUseAuthenticationUIAllow)
PHP_DARWIN_STR(kSecUseAuthenticationUIFail)
PHP_DARWIN_STR(kSecUseAuthenticationUISkip)

/* Item Attributes - https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_attribute_keys_and_values */
// Keys
PHP_DARWIN_STR(kSecAttrAccess) // SecAccess
PHP_DARWIN_STR(kSecAttrAccessControl) // SecAccessControl
PHP_DARWIN_STR(kSecAttrAccessible) // CFType
PHP_DARWIN_ATTR(kSecAttrAccessGroup, CFString)
PHP_DARWIN_ATTR(kSecAttrSynchronizable, CFString)
PHP_DARWIN_ATTR(kSecAttrCreationDate, CFDate)
PHP_DARWIN_ATTR(kSecAttrModificationDate, CFDate)
PHP_DARWIN_ATTR(kSecAttrDescription, CFString)
PHP_DARWIN_ATTR(kSecAttrComment, CFString)
PHP_DARWIN_ATTR(kSecAttrCreator, CFNumber)
PHP_DARWIN_ATTR(kSecAttrType, CFString)
PHP_DARWIN_ATTR(kSecAttrLabel, CFString)
PHP_DARWIN_ATTR(kSecAttrIsInvisible, CFBoolean)
PHP_DARWIN_ATTR(kSecAttrIsNegative, CFBoolean)
PHP_DARWIN_ATTR(kSecAttrSyncViewHint, CFString)
PHP_DARWIN_ATTR(kSecAttrAccount, CFString)
PHP_DARWIN_ATTR(kSecAttrService, CFString)
PHP_DARWIN_ATTR(kSecAttrGeneric, CFData)
PHP_DARWIN_ATTR(kSecAttrSecurityDomain, CFString)
PHP_DARWIN_ATTR(kSecAttrServer, CFString)
PHP_DARWIN_ATTR(kSecAttrProtocol, CFNumber)
PHP_DARWIN_ATTR(kSecAttrAuthenticationType, CFNumber)
PHP_DARWIN_ATTR(kSecAttrPort, CFNumber)
PHP_DARWIN_ATTR(kSecAttrPath, CFString)
PHP_DARWIN_ATTR(kSecAttrSubject, CFData)
PHP_DARWIN_ATTR(kSecAttrIssuer, CFData)
PHP_DARWIN_ATTR(kSecAttrSerialNumber, CFData)
PHP_DARWIN_ATTR(kSecAttrSubjectKeyID, CFData)
PHP_DARWIN_ATTR(kSecAttrPublicKeyHash, CFData)
PHP_DARWIN_ATTR(kSecAttrCertificateType, CFNumber)
PHP_DARWIN_ATTR(kSecAttrCertificateEncoding, CFNumber)
PHP_DARWIN_STR(kSecAttrKeyClass) // CFType
PHP_DARWIN_ATTR(kSecAttrApplicationLabel, CFString)
PHP_DARWIN_ATTR(kSecAttrApplicationTag, CFData)
PHP_DARWIN_ATTR(kSecAttrKeyType, CFString)
PHP_DARWIN_ATTR(kSecAttrPRF, CFString)
PHP_DARWIN_ATTR(kSecAttrSalt, CFData)
PHP_DARWIN_ATTR(kSecAttrRounds, CFNumber)
PHP_DARWIN_ATTR(kSecAttrKeySizeInBits, CFNumber)
PHP_DARWIN_ATTR(kSecAttrEffectiveKeySize, CFNumber)
PHP_DARWIN_ATTR(kSecAttrTokenID, CFString)
PHP_DARWIN_ATTR(kSecAttrIsPermanent, CFBoolean)
PHP_DARWIN_ATTR(kSecAttrIsSensitive, CFBoolean)
PHP_DARWIN_ATTR(kSecAttrIsExtractable, CFBoolean)
PHP_DARWIN_ATTR(kSecAttrCanEncrypt, CFBoolean)
PHP_DARWIN_ATTR(kSecAttrCanDecrypt, CFBoolean)
PHP_DARWIN_ATTR(kSecAttrCanDerive, CFBoolean)
PHP_DARWIN_ATTR(kSecAttrCanSign, CFBoolean)
PHP_DARWIN_ATTR(kSecAttrCanVerify, CFBoolean)
PHP_DARWIN_ATTR(kSecAttrCanWrap, CFBoolean)
PHP_DARWIN_ATTR(kSecAttrCanUnwrap, CFBoolean)

// Values
PHP_DARWIN_STR(kSecAttrProtocolFTP)
PHP_DARWIN_STR(kSecAttrProtocolFTPAccount)
PHP_DARWIN_STR(kSecAttrProtocolHTTP)
PHP_DARWIN_STR(kSecAttrProtocolIRC)
PHP_DARWIN_STR(kSecAttrProtocolNNTP)
PHP_DARWIN_STR(kSecAttrProtocolPOP3)
PHP_DARWIN_STR(kSecAttrProtocolSMTP)
PHP_DARWIN_STR(kSecAttrProtocolSOCKS)
PHP_DARWIN_STR(kSecAttrProtocolIMAP)
PHP_DARWIN_STR(kSecAttrProtocolLDAP)
PHP_DARWIN_STR(kSecAttrProtocolAppleTalk)
PHP_DARWIN_STR(kSecAttrProtocolAFP)
PHP_DARWIN_STR(kSecAttrProtocolTelnet)
PHP_DARWIN_STR(kSecAttrProtocolSSH)
PHP_DARWIN_STR(kSecAttrProtocolFTPS)
PHP_DARWIN_STR(kSecAttrProtocolHTTPS)
PHP_DARWIN_STR(kSecAttrProtocolHTTPProxy)
PHP_DARWIN_STR(kSecAttrProtocolHTTPSProxy)
PHP_DARWIN_STR(kSecAttrProtocolFTPProxy)
PHP_DARWIN_STR(kSecAttrProtocolSMB)
PHP_DARWIN_STR(kSecAttrProtocolRTSP)
PHP_DARWIN_STR(kSecAttrProtocolRTSPProxy)
PHP_DARWIN_STR(kSecAttrProtocolDAAP)
PHP_DARWIN_STR(kSecAttrProtocolEPPC)
PHP_DARWIN_STR(kSecAttrProtocolIPP)
PHP_DARWIN_STR(kSecAttrProtocolNNTPS)
PHP_DARWIN_STR(kSecAttrProtocolLDAPS)
PHP_DARWIN_STR(kSecAttrProtocolTelnetS)
PHP_DARWIN_STR(kSecAttrProtocolIMAPS)
PHP_DARWIN_STR(kSecAttrProtocolIRCS)
PHP_DARWIN_STR(kSecAttrProtocolPOP3S)
PHP_DARWIN_STR(kSecAttrAuthenticationTypeNTLM)
PHP_DARWIN_STR(kSecAttrAuthenticationTypeMSN)
PHP_DARWIN_STR(kSecAttrAuthenticationTypeDPA)
PHP_DARWIN_STR(kSecAttrAuthenticationTypeRPA)
PHP_DARWIN_STR(kSecAttrAuthenticationTypeHTTPBasic)
PHP_DARWIN_STR(kSecAttrAuthenticationTypeHTTPDigest)
PHP_DARWIN_STR(kSecAttrAuthenticationTypeHTMLForm)
PHP_DARWIN_STR(kSecAttrAuthenticationTypeDefault)
PHP_DARWIN_STR(kSecAttrKeyClassPublic)
PHP_DARWIN_STR(kSecAttrKeyClassPrivate)
PHP_DARWIN_STR(kSecAttrKeyClassSymmetric)
PHP_DARWIN_STR(kSecAttrKeyTypeRSA)
PHP_DARWIN_STR(kSecAttrKeyTypeDSA)
PHP_DARWIN_STR(kSecAttrKeyTypeAES)
PHP_DARWIN_STR(kSecAttrKeyTypeDES)
PHP_DARWIN_STR(kSecAttrKeyType3DES)
PHP_DARWIN_STR(kSecAttrKeyTypeRC4)
PHP_DARWIN_STR(kSecAttrKeyTypeRC2)
PHP_DARWIN_STR(kSecAttrKeyTypeCAST)
PHP_DARWIN_STR(kSecAttrKeyTypeECDSA)
PHP_DARWIN_STR(kSecAttrKeyTypeEC)
PHP_DARWIN_STR(kSecAttrKeyTypeECSECPrimeRandom)
PHP_DARWIN_STR(kSecAttrSynchronizableAny)
PHP_DARWIN_STR(kSecAttrTokenIDSecureEnclave)
PHP_DARWIN_STR(kSecAttrAccessibleAfterFirstUnlock)
PHP_DARWIN_STR(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
PHP_DARWIN_STR(kSecAttrAccessibleAlways)
PHP_DARWIN_STR(kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly)
PHP_DARWIN_STR(kSecAttrAccessibleAlwaysThisDeviceOnly)
PHP_DARWIN_STR(kSecAttrAccessibleWhenUnlocked)
PHP_DARWIN_STR(kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
PHP_DARWIN_STR(kSecAttrPRFHmacAlgSHA1)
PHP_DARWIN_STR(kSecAttrPRFHmacAlgSHA224)
PHP_DARWIN_STR(kSecAttrPRFHmacAlgSHA256)
PHP_DARWIN_STR(kSecAttrPRFHmacAlgSHA384)
PHP_DARWIN_STR(kSecAttrPRFHmacAlgSHA512)
PHP_DARWIN_STR(kSecAttrAccessGroupToken)

/* Additional Key Generation Attributes not listed above - https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/key_generation_attributes */
PHP_DARWIN_STR(kSecPrivateKeyAttrs)
PHP_DARWIN_STR(kSecPublicKeyAttrs)

/* https://developer.apple.com/documentation/security/security_transforms/transform_attributes */
PHP_DARWIN_STR(kSecEncodeLineLengthAttribute)
PHP_DARWIN_STR(kSecEncodeTypeAttribute)
PHP_DARWIN_STR(kSecDecodeTypeAttribute)
PHP_DARWIN_STR(kSecCompressionRatio)
PHP_DARWIN_STR(kSecDigestTypeAttribute)
PHP_DARWIN_STR(kSecDigestLengthAttribute)
PHP_DARWIN_STR(kSecDigestHMACKeyAttribute)
PHP_DARWIN_STR(kSecInputIsAttributeName)
PHP_DARWIN_STR(kSecEncryptionMode)
PHP_DARWIN_STR(kSecEncryptKey)
PHP_DARWIN_STR(kSecIVKey)
PHP_DARWIN_STR(kSecPaddingKey)
PHP_DARWIN_STR(kSecOAEPEncodingParametersAttributeName)
PHP_DARWIN_STR(kSecTransformInputAttributeName)
PHP_DARWIN_STR(kSecTransformOutputAttributeName)
PHP_DARWIN_STR(kSecTransformDebugAttributeName)
PHP_DARWIN_STR(kSecKeyAttributeName)
PHP_DARWIN_STR(kSecSignatureAttributeName)
PHP_DARWIN_STR(kSecTransformAbortAttributeName)
PHP_DARWIN_STR(kSecTransformTransformName)
PHP_DARWIN_STR(kSecBase32Encoding)
PHP_DARWIN_STR(kSecBase64Encoding)
PHP_DARWIN_STR(kSecZLibEncoding)
PHP_DARWIN_STR(kSecDigestMD2)
PHP_DARWIN_STR(kSecDigestMD4)
PHP_DARWIN_STR(kSecDigestMD5)
PHP_DARWIN_STR(kSecDigestSHA1)
PHP_DARWIN_STR(kSecDigestSHA2)
PHP_DARWIN_STR(kSecDigestHMACMD5)
PHP_DARWIN_STR(kSecDigestHMACSHA1)
PHP_DARWIN_STR(kSecDigestHMACSHA2)
PHP_DARWIN_STR(kSecLineLength64)
PHP_DARWIN_STR(kSecLineLength76)
PHP_DARWIN_STR(kSecInputIsDigest)
PHP_DARWIN_STR(kSecInputIsPlainText)
PHP_DARWIN_STR(kSecInputIsRaw)
PHP_DARWIN_STR(kSecPaddingNoneKey)
PHP_DARWIN_STR(kSecPaddingOAEPKey)
PHP_DARWIN_STR(kSecPaddingPKCS1Key)
PHP_DARWIN_STR(kSecPaddingPKCS5Key)
PHP_DARWIN_STR(kSecPaddingPKCS7Key)
PHP_DARWIN_STR(kSecModeNoneKey)
PHP_DARWIN_STR(kSecModeCBCKey)
PHP_DARWIN_STR(kSecModeCFBKey)
PHP_DARWIN_STR(kSecModeECBKey)
PHP_DARWIN_STR(kSecModeOFBKey)

/* SecKeySizes - https://developer.apple.com/documentation/security/seckeysizes */
PHP_DARWIN_LONG(kSecDefaultKeySize)
PHP_DARWIN_LONG(kSec3DES192)
PHP_DARWIN_LONG(kSecAES128)
PHP_DARWIN_LONG(kSecAES192)
PHP_DARWIN_LONG(kSecAES256)
PHP_DARWIN_LONG(kSecp192r1)
PHP_DARWIN_LONG(kSecp256r1)
PHP_DARWIN_LONG(kSecp384r1)
PHP_DARWIN_LONG(kSecp521r1)
PHP_DARWIN_LONG(kSecRSAMin)
PHP_DARWIN_LONG(kSecRSAMax)
