--TEST--
Create an item in a keychain, and fetch it back out.
--FILE--
<?php

use Darwin\SecCertificate;
use Darwin\SecKey;
use Darwin\SecKeychain;
use Darwin\SecKeychainItem;
use Darwin\Security as S;
use Darwin\SecurityException As SecEx;

$file = tempnam(sys_get_temp_dir(), "php-darwin-test-");
unlink($file);

$keychain = SecKeychain::Create($file, 'secret')->unlock('secret');
$cert = SecCertificate::CreateFromDER(file_get_contents(__DIR__.'/certificate.der'));
$params = [
  [
    S::kSecClass => S::kSecClassGenericPassword,
    S::kSecAttrService => '/tests/seckeychainitem-create.phpt:genp',
    S::kSecValueData => 'private',
    S::kSecAttrLabel => "Test Generic Passsword storage",
    S::kSecAttrDescription => "Nobody had better steal this!",
  ],[
    S::kSecClass => S::kSecClassInternetPassword,
    S::kSecAttrServer => 'example.org',
    S::kSecAttrPort => 80,
    S::kSecAttrPath => '/tests/seckeychainitem-create.phpt',
    S::kSecAttrAccount => 'jdoe',
    S::kSecValueData => '1234',
    S::kSecAttrLabel => "Test Internet Password storage",
    S::kSecAttrDescription => "That's the password on my luggage!",
  ],[
    S::kSecClass => S::kSecClassCertificate,
    S::kSecValueRef => $cert,
    S::kSecAttrSubject => $cert->getCommonName(),
    S::kSecAttrLabel => "Test Certificate storage",
    S::kSecAttrDescription => "Certified certificate",
  ],
];

foreach ($params as $param) {
  $param[S::kSecUseKeychain] = $keychain;
  SecKeychainItem::Create($param);
}

$display = [
  S::kSecAttrService => 'Service',
  S::kSecAttrLabel => 'Label',
  S::kSecAttrDescription => 'Description',
  S::kSecAttrServer => 'Server',
  S::kSecAttrPort => 'Port',
  S::kSecAttrAccount => 'Account',
];

$returnData = [
  // Passwords are simple strings, other types are objects
  S::kSecClassGenericPassword => true,
  S::kSecClassInternetPassword => true,
];

foreach ($params as $idx => $param) {
  echo "** {$param[S::kSecClass]}:{$idx}\n";
  $query = [
    S::kSecMatchSearchList => [$keychain],
    S::kSecClass => $param[S::kSecClass],
    S::kSecMatchLimit => S::kSecMatchLimitOne,
    S::kSecReturnAttributes => true,
  ];
  $attrs = SecKeychainItem::Find($query);
  foreach ($display as $key => $label) {
    if (isset($attrs[$key])) echo $label, ": ", $attrs[$key], "\n";
  }

  $query[S::kSecReturnAttributes] = false;
  $retType = ($returnData[$param[S::kSecClass]] ?? false) ? S::kSecReturnData : S::kSecReturnRef;
  $query[$retType] = true;
  var_dump(SecKeychainItem::Find($query));
}

unset($keychain);
unlink($file);
--EXPECTF--
** genp:0
Service: /tests/seckeychainitem-create.phpt:genp
Label: Test Generic Passsword storage
Description: Nobody had better steal this!
string(7) "private"
** inet:1
Label: Test Internet Password storage
Description: That's the password on my luggage!
Server: example.org
Port: 80
Account: jdoe
string(4) "1234"
** cert:2
Label: Henrique do N. Angelo
object(Darwin\SecCertificate)#%s (0) {
}
