Crypto = (require '../cryptojs').Crypto
should = require 'should'

key = '12345678'
us = 'Hello, 世界!'
us_bytes = [72,101,108,108,111,44,32,228,184,150,231,149,140,33]
ehs = "4d6add118ed63ed4799d3719976fa7cb"


describe 'charenc', ->
  it 'should convert UTF to bytes', ->
    ub = Crypto.charenc.UTF8.stringToBytes us
    ub.should.eql us_bytes

  it 'should convert bytes to UTF8',->
    utf = Crypto.charenc.UTF8.bytesToString us_bytes
    utf.should.eql us

describe 'util',->
  ascii = 'james'
  ascii_b = Crypto.charenc.UTF8.stringToBytes ascii
  b64 = 'amFtZXM='
  describe 'base64',->
    it "should encode '#{ascii_b}' to '#{b64}'", ->
      eb64 = Crypto.util.bytesToBase64 ascii_b
      eb64.should.eql b64

    it "should decode '#{b64}' to '#{ascii_b}'", ->
      asc = Crypto.util.base64ToBytes b64
      asc.should.eql ascii_b

describe 'Cipher', ->
  mode = new Crypto.mode.ECB Crypto.pad.pkcs7
  describe 'encrypt', ->
    for [crypt_name,crypt_fn] in [["DES", Crypto.DES], ["AES",Crypto.AES]]
      do (crypt_name,crypt_fn)->
        describe "#{crypt_name} with options provided", ->
          enc_b = null
          it 'should return a byte string with asBytes=true', ->
            eb = crypt_fn.encrypt us_bytes, key, {asBytes: true, mode: mode}
            eb.should.be.an.instanceOf Array
            enc_b = eb

          it 'should return a base64 string if asBytes not given', ->
            eb64 = crypt_fn.encrypt us_bytes, key, {mode: mode}
            eb64.should.be.a 'string'
            eb = null
            (()->
              eb = Crypto.util.base64ToBytes(eb64)
            ).should.not.throw()
            eb.should.eql enc_b

          it 'should not overwrite input byte array as a side effect',->
            tmp = us_bytes
            eb = crypt_fn.encrypt tmp, key, {asBytes: true, mode: mode}
            eb.should.not.eql tmp

          it 'should overwrite the input byte array if in_place is given', ->
            tmp = us_bytes.slice()
            eb = crypt_fn.encrypt tmp, key, {asBytes: true, mode: mode, in_place: true}
            eb.should.eql tmp

      describe "#{crypt_name} without options", ->
        it 'should default to OFB mode with a generated iv', ->
          es = crypt_fn.encrypt us_bytes, key

          db = crypt_fn.decrypt Crypto.util.base64ToBytes(es), key, {asBytes: true}
          db.should.eql us_bytes
