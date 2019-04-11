require "test_helper"
include GostKuznyechik

# GOST Р 34.13-2015 Kuznyechik ECB test data
kSelfTestGostKMasterKeyData = [ 
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
].pack('C*').freeze

kSelfTestGostKPlainText = [ 
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 
	0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a,
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 
	0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00,
  0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 
	0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00, 0x11
].pack('C*').freeze

kSelfTestGostKEcbEncText = [
  0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30, 
	0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd,
  0xb4, 0x29, 0x91, 0x2c, 0x6e, 0x00, 0x32, 0xf9, 
	0x28, 0x54, 0x52, 0xd7, 0x67, 0x18, 0xd0, 0x8b,
  0xf0, 0xca, 0x33, 0x54, 0x9d, 0x24, 0x7c, 0xee, 
	0xf3, 0xf5, 0xa5, 0x31, 0x3b, 0xd4, 0xb1, 0x57,
  0xd0, 0xb0, 0x9c, 0xcd, 0xe8, 0x30, 0xb9, 0xeb, 
	0x3a, 0x02, 0xc4, 0xc5, 0xaa, 0x8a, 0xda, 0x98
].pack('C*').freeze

class GostKuznyechikTest < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil ::GostKuznyechik::VERSION
  end

  def test_ecb_standard
    key = kSelfTestGostKMasterKeyData
    plainText = kSelfTestGostKPlainText
    encryptedTest = kSelfTestGostKEcbEncText

    encryptedText = KuznyechikEcb.new(key).encrypt(plainText)
    assert encryptedText == encryptedTest 
    decryptedText = KuznyechikEcb.new(key).decrypt(encryptedTest)
    assert decryptedText == plainText 
  end
end
