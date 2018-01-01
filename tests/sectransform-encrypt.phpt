--TEST--
Basic encryption
--FILE--
<?php

use Darwin\SecKey;
use Darwin\SecTransform;
use Darwin\Security as S;

$key = SecKey::GenerateSymmetric([
  S::kSecAttrKeyType => S::kSecAttrKeyTypeAES,
  S::kSecAttrKeySizeInBits => 256,
  S::kSecAttrCanEncrypt => true,
  S::kSecAttrCanDecrypt => true,
]);

$data = "Lorem ipsum dolor";
$iv = random_bytes(64);

$cipher = SecTransform::EncryptTransformCreate($key)
  ->setStringAttribute(S::kSecEncryptionMode, S::kSecModeECBKey)
  ->setStringAttribute(S::kSecPaddingKey, S::kSecPaddingPKCS7Key)
  ->setDataAttribute(S::kSecIVKey, $iv)
  ->execute($data);
var_dump(bin2hex($cipher));

$plain = SecTransform::DecryptTransformCreate($key)
  ->setStringAttribute(S::kSecEncryptionMode, S::kSecModeECBKey)
  ->setStringAttribute(S::kSecPaddingKey, S::kSecPaddingPKCS7Key)
  ->setDataAttribute(S::kSecIVKey, $iv)
  ->execute($cipher);
var_dump($plain);
--EXPECTF--
string(64) "%s"
string(17) "Lorem ipsum dolor"
