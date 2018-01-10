--TEST--
Read a DER encoded certificate
--FILE--
<?php

use Darwin\SecCertificate;

// Certificate borrowed from php-src/ext/openssl/tests/cert.crt
$data = file_get_contents(__DIR__ . '/certificate.der');
$cert = SecCertificate::CreateFromDER($data);

echo "Common Name: ", $cert->getCommonName(), "\n";
echo "Email addresses: ", implode(',', $cert->getEmailAddresses()), "\n";
echo "Public Key Blocksize: ", $cert->getPublicKey()->getBlockSize(), "\n";

function redact_bin_data($v) {
  switch ($v['type'] ?? null) {
    case 'data':
      $v['value'] = 'BINARY DATA';
      break;
    case 'array':
    case 'section':
      if (is_array($v['value'] ?? null)) {
        $v['value'] = array_map('redact_bin_data', $v['value']);
      }
      break;
  }
  return $v;
}
$values = array_map('redact_bin_data', $cert->getValues());

var_dump($values);
--EXPECT--
Common Name: Henrique do N. Angelo
Email addresses: hnangelo@php.net
Public Key Blocksize: 128
array(17) {
  ["2.5.4.3"]=>
  array(4) {
    ["label"]=>
    string(2) "CN"
    ["value"]=>
    array(1) {
      [0]=>
      string(21) "Henrique do N. Angelo"
    }
    ["localized label"]=>
    string(2) "CN"
    ["type"]=>
    string(5) "array"
  }
  ["2.16.840.1.113741.2.1.1.1.5"]=>
  array(4) {
    ["label"]=>
    string(11) "Issuer Name"
    ["value"]=>
    array(5) {
      [0]=>
      array(4) {
        ["label"]=>
        string(7) "2.5.4.6"
        ["value"]=>
        string(2) "BR"
        ["localized label"]=>
        string(7) "2.5.4.6"
        ["type"]=>
        string(6) "string"
      }
      [1]=>
      array(4) {
        ["label"]=>
        string(7) "2.5.4.8"
        ["value"]=>
        string(17) "Rio Grande do Sul"
        ["localized label"]=>
        string(7) "2.5.4.8"
        ["type"]=>
        string(6) "string"
      }
      [2]=>
      array(4) {
        ["label"]=>
        string(7) "2.5.4.7"
        ["value"]=>
        string(12) "Porto Alegre"
        ["localized label"]=>
        string(7) "2.5.4.7"
        ["type"]=>
        string(6) "string"
      }
      [3]=>
      array(4) {
        ["label"]=>
        string(7) "2.5.4.3"
        ["value"]=>
        string(21) "Henrique do N. Angelo"
        ["localized label"]=>
        string(7) "2.5.4.3"
        ["type"]=>
        string(6) "string"
      }
      [4]=>
      array(4) {
        ["label"]=>
        string(20) "1.2.840.113549.1.9.1"
        ["value"]=>
        string(16) "hnangelo@php.net"
        ["localized label"]=>
        string(20) "1.2.840.113549.1.9.1"
        ["type"]=>
        string(6) "string"
      }
    }
    ["localized label"]=>
    string(11) "Issuer Name"
    ["type"]=>
    string(7) "section"
  }
  ["2.16.840.1.113741.2.1.1.1.10"]=>
  array(4) {
    ["label"]=>
    string(15) "Public Key Data"
    ["value"]=>
    string(11) "BINARY DATA"
    ["localized label"]=>
    string(15) "Public Key Data"
    ["type"]=>
    string(4) "data"
  }
  ["2.5.29.19"]=>
  array(4) {
    ["label"]=>
    string(9) "2.5.29.19"
    ["value"]=>
    array(2) {
      [0]=>
      array(4) {
        ["label"]=>
        string(8) "Critical"
        ["value"]=>
        string(2) "No"
        ["localized label"]=>
        string(8) "Critical"
        ["type"]=>
        string(6) "string"
      }
      [1]=>
      array(4) {
        ["label"]=>
        string(21) "Certificate Authority"
        ["value"]=>
        string(3) "Yes"
        ["localized label"]=>
        string(21) "Certificate Authority"
        ["type"]=>
        string(6) "string"
      }
    }
    ["localized label"]=>
    string(9) "2.5.29.19"
    ["type"]=>
    string(7) "section"
  }
  ["2.16.840.1.113741.2.1.1.1.3"]=>
  array(4) {
    ["label"]=>
    string(13) "Serial Number"
    ["value"]=>
    string(26) "00 AE C5 56 CC 72 37 50 A2"
    ["localized label"]=>
    string(13) "Serial Number"
    ["type"]=>
    string(6) "string"
  }
  ["Expired"]=>
  array(4) {
    ["label"]=>
    string(7) "Expired"
    ["value"]=>
    object(DateTime)#2 (3) {
      ["date"]=>
      string(26) "2008-07-30 10:28:43.000000"
      ["timezone_type"]=>
      int(1)
      ["timezone"]=>
      string(6) "+00:00"
    }
    ["localized label"]=>
    string(7) "Expired"
    ["type"]=>
    string(4) "date"
  }
  ["2.5.29.35"]=>
  array(4) {
    ["label"]=>
    string(9) "2.5.29.35"
    ["value"]=>
    array(4) {
      [0]=>
      array(4) {
        ["label"]=>
        string(8) "Critical"
        ["value"]=>
        string(2) "No"
        ["localized label"]=>
        string(8) "Critical"
        ["type"]=>
        string(6) "string"
      }
      [1]=>
      array(4) {
        ["label"]=>
        string(14) "Key Identifier"
        ["value"]=>
        string(11) "BINARY DATA"
        ["localized label"]=>
        string(14) "Key Identifier"
        ["type"]=>
        string(4) "data"
      }
      [2]=>
      array(4) {
        ["label"]=>
        string(14) "Directory Name"
        ["value"]=>
        array(5) {
          [0]=>
          array(4) {
            ["label"]=>
            string(7) "2.5.4.6"
            ["value"]=>
            string(2) "BR"
            ["localized label"]=>
            string(7) "2.5.4.6"
            ["type"]=>
            string(6) "string"
          }
          [1]=>
          array(4) {
            ["label"]=>
            string(7) "2.5.4.8"
            ["value"]=>
            string(17) "Rio Grande do Sul"
            ["localized label"]=>
            string(7) "2.5.4.8"
            ["type"]=>
            string(6) "string"
          }
          [2]=>
          array(4) {
            ["label"]=>
            string(7) "2.5.4.7"
            ["value"]=>
            string(12) "Porto Alegre"
            ["localized label"]=>
            string(7) "2.5.4.7"
            ["type"]=>
            string(6) "string"
          }
          [3]=>
          array(4) {
            ["label"]=>
            string(7) "2.5.4.3"
            ["value"]=>
            string(21) "Henrique do N. Angelo"
            ["localized label"]=>
            string(7) "2.5.4.3"
            ["type"]=>
            string(6) "string"
          }
          [4]=>
          array(4) {
            ["label"]=>
            string(20) "1.2.840.113549.1.9.1"
            ["value"]=>
            string(16) "hnangelo@php.net"
            ["localized label"]=>
            string(20) "1.2.840.113549.1.9.1"
            ["type"]=>
            string(6) "string"
          }
        }
        ["localized label"]=>
        string(14) "Directory Name"
        ["type"]=>
        string(7) "section"
      }
      [3]=>
      array(4) {
        ["label"]=>
        string(35) "Authority Certificate Serial Number"
        ["value"]=>
        string(26) "00 AE C5 56 CC 72 37 50 A2"
        ["localized label"]=>
        string(35) "Authority Certificate Serial Number"
        ["type"]=>
        string(6) "string"
      }
    }
    ["localized label"]=>
    string(9) "2.5.29.35"
    ["type"]=>
    string(7) "section"
  }
  ["2.16.840.1.113741.2.1.3.2.2"]=>
  array(4) {
    ["label"]=>
    string(9) "Signature"
    ["value"]=>
    string(11) "BINARY DATA"
    ["localized label"]=>
    string(9) "Signature"
    ["type"]=>
    string(4) "data"
  }
  ["2.16.840.1.113741.2.1.1.1.8"]=>
  array(4) {
    ["label"]=>
    string(12) "Subject Name"
    ["value"]=>
    array(5) {
      [0]=>
      array(4) {
        ["label"]=>
        string(7) "2.5.4.6"
        ["value"]=>
        string(2) "BR"
        ["localized label"]=>
        string(7) "2.5.4.6"
        ["type"]=>
        string(6) "string"
      }
      [1]=>
      array(4) {
        ["label"]=>
        string(7) "2.5.4.8"
        ["value"]=>
        string(17) "Rio Grande do Sul"
        ["localized label"]=>
        string(7) "2.5.4.8"
        ["type"]=>
        string(6) "string"
      }
      [2]=>
      array(4) {
        ["label"]=>
        string(7) "2.5.4.7"
        ["value"]=>
        string(12) "Porto Alegre"
        ["localized label"]=>
        string(7) "2.5.4.7"
        ["type"]=>
        string(6) "string"
      }
      [3]=>
      array(4) {
        ["label"]=>
        string(7) "2.5.4.3"
        ["value"]=>
        string(21) "Henrique do N. Angelo"
        ["localized label"]=>
        string(7) "2.5.4.3"
        ["type"]=>
        string(6) "string"
      }
      [4]=>
      array(4) {
        ["label"]=>
        string(20) "1.2.840.113549.1.9.1"
        ["value"]=>
        string(16) "hnangelo@php.net"
        ["localized label"]=>
        string(20) "1.2.840.113549.1.9.1"
        ["type"]=>
        string(6) "string"
      }
    }
    ["localized label"]=>
    string(12) "Subject Name"
    ["type"]=>
    string(7) "section"
  }
  ["1.2.840.113549.1.9.1"]=>
  array(3) {
    ["type"]=>
    string(5) "array"
    ["label"]=>
    string(3) "DNS"
    ["localized label"]=>
    string(3) "DNS"
  }
  ["2.16.840.1.113741.2.1.1.1.6"]=>
  array(4) {
    ["label"]=>
    string(16) "Not Valid Before"
    ["value"]=>
    float(236514523)
    ["localized label"]=>
    string(16) "Not Valid Before"
    ["type"]=>
    string(6) "number"
  }
  ["2.5.29.14"]=>
  array(4) {
    ["label"]=>
    string(9) "2.5.29.14"
    ["value"]=>
    array(2) {
      [0]=>
      array(4) {
        ["label"]=>
        string(8) "Critical"
        ["value"]=>
        string(2) "No"
        ["localized label"]=>
        string(8) "Critical"
        ["type"]=>
        string(6) "string"
      }
      [1]=>
      array(4) {
        ["label"]=>
        string(14) "Key Identifier"
        ["value"]=>
        string(11) "BINARY DATA"
        ["localized label"]=>
        string(14) "Key Identifier"
        ["type"]=>
        string(4) "data"
      }
    }
    ["localized label"]=>
    string(9) "2.5.29.14"
    ["type"]=>
    string(7) "section"
  }
  ["2.16.840.1.113741.2.1.1.1.2"]=>
  array(4) {
    ["label"]=>
    string(7) "Version"
    ["value"]=>
    string(1) "3"
    ["localized label"]=>
    string(7) "Version"
    ["type"]=>
    string(6) "string"
  }
  ["2.16.840.1.113741.2.1.1.1.9"]=>
  array(4) {
    ["label"]=>
    string(20) "Public Key Algorithm"
    ["value"]=>
    array(2) {
      [0]=>
      array(4) {
        ["label"]=>
        string(9) "Algorithm"
        ["value"]=>
        string(20) "1.2.840.113549.1.1.1"
        ["localized label"]=>
        string(9) "Algorithm"
        ["type"]=>
        string(6) "string"
      }
      [1]=>
      array(4) {
        ["label"]=>
        string(10) "Parameters"
        ["value"]=>
        string(4) "none"
        ["localized label"]=>
        string(10) "Parameters"
        ["type"]=>
        string(6) "string"
      }
    }
    ["localized label"]=>
    string(20) "Public Key Algorithm"
    ["type"]=>
    string(7) "section"
  }
  ["2.5.29.15"]=>
  array(4) {
    ["label"]=>
    string(9) "Key Usage"
    ["value"]=>
    int(0)
    ["localized label"]=>
    string(9) "Key Usage"
    ["type"]=>
    string(6) "number"
  }
  ["2.16.840.1.113741.2.1.3.2.1"]=>
  array(4) {
    ["label"]=>
    string(19) "Signature Algorithm"
    ["value"]=>
    array(2) {
      [0]=>
      array(4) {
        ["label"]=>
        string(9) "Algorithm"
        ["value"]=>
        string(20) "1.2.840.113549.1.1.5"
        ["localized label"]=>
        string(9) "Algorithm"
        ["type"]=>
        string(6) "string"
      }
      [1]=>
      array(4) {
        ["label"]=>
        string(10) "Parameters"
        ["value"]=>
        string(4) "none"
        ["localized label"]=>
        string(10) "Parameters"
        ["type"]=>
        string(6) "string"
      }
    }
    ["localized label"]=>
    string(19) "Signature Algorithm"
    ["type"]=>
    string(7) "section"
  }
  ["2.16.840.1.113741.2.1.1.1.7"]=>
  array(4) {
    ["label"]=>
    string(15) "Not Valid After"
    ["value"]=>
    float(239106523)
    ["localized label"]=>
    string(15) "Not Valid After"
    ["type"]=>
    string(6) "number"
  }
}
