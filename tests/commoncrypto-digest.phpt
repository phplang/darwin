--TEST--
Basic digest/hashing
--FILE--
<?php

use Darwin\CommonCrypto as CC;

$data = "Lorem ipsum dolor";
$key = "secret";

foreach ([1, 224, 256, 384, 512] as $size) {
  echo "** SHA{$size}\n";
  $hash = "sha{$size}";
  $hmac = "sha{$size}_hmac";
  var_dump(bin2hex(CC::$hash($data)));
  var_dump(bin2hex(CC::$hmac($data, $key)));
}

--EXPECT--
** SHA1
string(40) "45f75b844be4d17b3394c6701768daf39419c99b"
string(40) "471b0bcdad8c0aff4d9e8581df7b39471ee8f027"
** SHA224
string(56) "07074717f4afab60b623f08bf960e6cc191bbcf136d4d5121e73b064"
string(56) "410ca2ddb06838218ceed01cef3eb0e328e705e522a2e68c3c8b1b6c"
** SHA256
string(64) "9b3e1beb7053e0f900a674dd1c99aca3355e1275e1b03d3cb1bc977f5154e196"
string(64) "1c7b9f3960ea22cd08b701a7da3cb41c860ad2eea953d177ac0eb60b586b5e1c"
** SHA384
string(96) "6b04298e4d74c56566977673b706705315b34b65ba6fcc751080c6445285b036d0cddac7d58866cd3efcca0ae1e8da5c"
string(96) "913d0477db571ec2814008edaadf18fd007374fdc2da3e33665a404273df56231bcc620bac9cf563c2cb12189549b089"
** SHA512
string(128) "a7bb7001b36994d6b67b8db50cbddac23b96d0cb3c29e277976c12a84cfcd993b5bf3168d53a3a2d61b5ef5d22b11d2cec78e601497088ba27323634aebe4116"
string(128) "26999ecef45b3abb370785bb7ddf85343d675a52f8850f4562b71e7551a18009add18ca956ef88a629bd793b044e47ad8c511d68493b55300e4c98f864f2e36d"
