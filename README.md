The API outline below is provisional and may change over time
as I learn more about how the Security framework is put together.

This extension is a LONG WAY from complete.

# PHP Extension for Darwin CoreFoundation and Security frameworks

As a rule, I've tried to avoid building too much magic on top of the underlying APIs,
but a few key affordances are made:

  * Procedural APIs using opaque pointer types are replaced with OOP instance methods and static factory methods.
    * Method names are often shortened to fit an OOP style API.
  * Basic Core Foundation types are represented as PHP natives:
    * CFBoolean: bool
    * CFNumber: int/float
    * CFString/CFData: string (CFString is UTF-8 text, CFData is binary)
    * CFDate: DateTime
  * CFError is promoted to an exception class and thrown, rather than returned.

## Classes

```php
abstract final class Darwin\Security {
  // Various constants, see security-constants.h for full list
}
```

[CFError](https://developer.apple.com/documentation/corefoundation/cferror-ru8)
```php
final class Darwin\CFError extends \Exception {
  static public function getDomain(): ?string;
  static public function getUserInfo(): array;
  static public function getFailureReason(): ?string;
  static public function getRecoverySuggestion(): ?string;
}
```

[SecKeychain](https://developer.apple.com/documentation/security/seckeychain)
```php
abstract final class Darwin\SecKeychain {
  /**
   * Create a new keychain.
   *
   * If $password is NULL, the user will be interactively prompted to
   * provide a password by the operating system.
   */
  static public function Create(string $name, ?string $password = NULL): SecKeychain;

  /**
   * Open an existing keychain.
   */
  static public function Open(string $name): SecKeyChain;

  /**
   * Lock the keychain.
   */
  public function lock(): this;

  /**
   * Unlock the keychain.
   *
   * If keychain is currently locked, and $password is NULL,
   * the user will be interactively prompted to provide a password
   * by the operating systen.
   * If the keychain is already unlocked, no additional action is taken.
   */
  public function unlock(?string $password = NULL): this;

  /**
   * Get the current keychain API version.
   */
  static public function getVersion(): int;
}
```

[SecCertificate](https://developer.apple.com/documentation/security/seccertificate)
```php
final class Darwin\SecCertificate {
  /**
   * Instantiate a SecCertificate using raw DER encoded data.
   */
  static public function CreateFromDER(string $derdata): SecCertificate;

  /**
   * General introspection functions, refer to the link for SecCertificate above for details.
   */
  public function getDER(): string;
  public function getSubjectSummary(): string;
  public function getCommonName(): string;
  public function getEmailAddresses(): array<string>;
  public function getShortDescription(): string;
  public function getLongDescription(): string;
  public function getNormalizedIssuerSequence(): string; // OSX >= 10.12.4
  public function getNormalizedSubjectSequence(): string; // OSX >= 10.12.4
  public function getPublicKey(): SecKey;
  public function getSerialNumberData(): string;

  /**
   * Provide a dump of all data related to the certificate.
   * Keys at various points in this nested structure will
   * be a mix of human readable strings and OIDs.
   * Refer to Darwin\Security::kSecOIDXXXXX for OID values.
   */
  public function getValues(): array;
}
```

[SecKey](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys)
```php
final class Darwin\SecKey {
  /**
   * Create a new, random symmetric key.
   */
  static public function GenerateSymmetric(array $params): SecKey;

  /**
   * Derive a symmetric key based on a password.
   */
  static public function DeriveFromPassword(string $password, array $params): SecKey;

  /**
   * Create a new, random asymmetric key.
   */
  static public function CreateRandomKey(array $params): SecKey;

  /**
   * Returns the block size for this key.
   */
  public function getBlockSize(): int;

  /**
   * When called on an asymmetric key, returns the public portion.
   */
  public function getPublicKey(): ?SecKey;

  /**
   * Wraps a symmetric key in this key.
   */
  public function wrapSymmetric(SecKey $keyToWrap, array $params): string;

  /**
   * Unwraps a previously wrapped symmetric key.
   */
  public function unwrapSymmetric(string $wrappedKey, array $params): SecKey;
}
```

[SecTransform](https://developer.apple.com/documentation/security/security_transforms)
```php
final class Darwin\SecTransform {
  /**
   * Instantiate Transforms for various purposes...
   */
  static public SignTransformCreate(SecKey $key): SecTransform;
  static public VerifyTransformCreate(SecKey $key, string $sig): SecTransform;
  static public EncryptTransformCreate(SecKey $key): SecTransform;
  static public DecryptTransformCreate(SecKey $key): SecTransform;

  /**
   * Set attribute on the transform.
   * Incorrect typing will result in an exception from the Transform API
   * either upon setting, or upon execution.
   */
  public function setBooleanAttribute(string $key, bool $val): this;
  public function setIntAttribute(string $key, int $val): this;
  public function setFloatAttribute(string $key, float $val): this;
  public function setStringAttribute(string $key, string $val): this;
  public function setDataAttribute(string $key, string $val): this;

  /**
   * Get attribute from the transform.
   */
  public function getAttribute(string $key): mixed;

  /**
   * Execute the transform, returning the result.
   */
  public function execute(): mixed;
}
```
