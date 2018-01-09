--TEST--
Create a new keychain, unlock it, then fail to unlock it. Reopen it.
--FILE--
<?php

use Darwin\SecKeychain;
use Darwin\Security as S;
use Darwin\SecurityException As SecEx;

$file = tempnam(sys_get_temp_dir(), "php-darwin-test-");
unlink($file);

$keychain = SecKeychain::Create($file, 'secret')->unlock('secret')->lock();

try {
  $keychain->unlock('derp');
} catch (SecEx $e) {
  echo "Caught: ", $e->getMessage(), "\n";
}

unset($keychain);

$keychain = SecKeychain::Open($file)->unlock('secret');
echo "Unlocked\n";

unlink($file);
--EXPECT--
Caught: Unable to unlock keychain: The user name or passphrase you entered is not correct.
Unlocked

