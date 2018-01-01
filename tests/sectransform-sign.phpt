--TEST--
Basic signing
--FILE--
<?php

use Darwin\SecKey;
use Darwin\SecTransform;
use Darwin\Security as S;

$key = SecKey::CreateRandomKey([
  S::kSecAttrKeyType => S::kSecAttrKeyTypeRSA,
  S::kSecAttrKeySizeInBits => 1024,
]);

$data = "Lorem ipsum dolor";

$sig = SecTransform::SignTransformCreate($key)->execute($data);
var_dump(bin2hex($sig));

$verify = SecTransform::VerifyTransformCreate($key, $sig)->execute($data);
var_dump($verify);
--EXPECTF--
string(256) "%s"
bool(true)
