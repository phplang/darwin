--TEST--
Calling SecKey::CreateRandomKey with no params produces exception
--FILE--
<?php

use Darwin\SecKey;

try {
  $key = SecKey::CreateRandomKey([]);
} catch (\Darwin\Exception $e) {
  echo "Caught: ", $e->getMessage(), "\n";
}
--EXPECT--
Caught: Missing required elements in parameters array: type, bsiz
