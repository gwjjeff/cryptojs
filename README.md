cryptojs
--------

This fork clarifies some behavior which is slightly
counterintuitive based on the [CryptoJS
documentation](http://code.google.com/p/crypto-js/), and modifies
some confusing behavior.

### install

```
npm install cryptojs
# For tests you need Mocha and Should
npm install mocha
npm install should
```

### Differences from CryptoJS

#### Block Cipher Return Values

CryptoJS returns a CipherParams object as the result of
encryption. This library handles things somewhat differently.

If the `asBytes` option is set to true, an array of byte values
is returned. Otherwise a Base64 encoded string is returned. 

If no `iv` option is provided, the generated IV is prepended to
the result (which is either a byte array or a string depending on
the `asBytes` parameter).

#### In-place Encryption

By default the result returned is a copy of the input bytes.
However, if the `in_place` option is set to true and the
message is passed as a byte array, the message will be encrypted
in place (i.e. the array the message points to will be replaced).

```coffee
Crypto = (require 'cryptojs').Crypto
key = '12345678'
us = 'Hello, 世界!'

mode = new Crypto.mode.ECB Crypto.pad.pkcs7

ub = Crypto.charenc.UTF8.stringToBytes us
eb = Crypto.DES.encrypt ub, key, {asBytes: true, mode: mode, in_place: true}  # << This will set 'ub' equal to 'eb'
```

### usage (example with [coffee-script](http://coffeescript.org/))

```coffee
Crypto = (require 'cryptojs').Crypto
key = '12345678'
us = 'Hello, 世界!'

mode = new Crypto.mode.ECB Crypto.pad.pkcs7

ub = Crypto.charenc.UTF8.stringToBytes us
eb = Crypto.DES.encrypt ub, key, {asBytes: true, mode: mode}
ehs= Crypto.util.bytesToHex eb

eb2= Crypto.util.hexToBytes ehs
ub2= Crypto.DES.decrypt eb2, key, {asBytes: true, mode: mode}
us2= Crypto.charenc.UTF8.bytesToString ub2
# should be same as the var 'us'
console .log us2
```

### Acks 
* with little modification, converted from googlecode project [crypto-js](http://code.google.com/p/crypto-js/), and keep the source code structure of the origin project on googlecode
* source code worked in both browser engines and node scripts. see also: [https://github.com/gwjjeff/crypto-js-npm-conv](https://github.com/gwjjeff/crypto-js-npm-conv)
* inspiration comes from [ezcrypto](https://github.com/ElmerZhang/ezcrypto), but my tests cannot pass with his version ( ECB/pkcs7 mode ), so I made it myself
