require "test_helper"
include GostKuznyechik

BlockSize = Kuznyechik::BlockLengthInBytes

# GOST R 34.13-2015 Kuznyechik test data
SelfTestGostKMasterKeyData = [ 
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
].pack('C*').freeze

SelfTestGostKPlainText = [ 
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 
	0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a,
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 
	0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00,
  0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 
	0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00, 0x11
].pack('C*').freeze

# ECB
SelfTestGostKEcbEncText = [
  0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30, 
	0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd,
  0xb4, 0x29, 0x91, 0x2c, 0x6e, 0x00, 0x32, 0xf9, 
	0x28, 0x54, 0x52, 0xd7, 0x67, 0x18, 0xd0, 0x8b,
  0xf0, 0xca, 0x33, 0x54, 0x9d, 0x24, 0x7c, 0xee, 
	0xf3, 0xf5, 0xa5, 0x31, 0x3b, 0xd4, 0xb1, 0x57,
  0xd0, 0xb0, 0x9c, 0xcd, 0xe8, 0x30, 0xb9, 0xeb, 
	0x3a, 0x02, 0xc4, 0xc5, 0xaa, 0x8a, 0xda, 0x98
].pack('C*').freeze

# OMAC
SelfTestGostKMacValue = [
  0x33, 0x6f, 0x4d, 0x29, 0x60, 0x59, 0xfb, 0xe3
].pack('C*').freeze

# CTR
SelfTestGostKCtrSV = [
  0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 
	0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12
].pack('C*').freeze

SelfTestGostKCtrEncText = [
  0xf1, 0x95, 0xd8, 0xbe, 0xc1, 0x0e, 0xd1, 0xdb, 
	0xd5, 0x7b, 0x5f, 0xa2, 0x40, 0xbd, 0xa1, 0xb8,
  0x85, 0xee, 0xe7, 0x33, 0xf6, 0xa1, 0x3e, 0x5d, 
	0xf3, 0x3c, 0xe4, 0xb3, 0x3c, 0x45, 0xde, 0xe4,
  0xa5, 0xea, 0xe8, 0x8b, 0xe6, 0x35, 0x6e, 0xd3, 
	0xd5, 0xe8, 0x77, 0xf1, 0x35, 0x64, 0xa3, 0xa5,
  0xcb, 0x91, 0xfa, 0xb1, 0xf2, 0x0c, 0xba, 0xb6, 
	0xd1, 0xc6, 0xd1, 0x58, 0x20, 0xbd, 0xba, 0x73
].pack('C*').freeze

# OFB
SelfTestGostKOfbSV = [
  0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 
	0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12,
  0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 
	0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19
].pack('C*').freeze

SelfTestGostKOfbEncText = [
  0x81, 0x80, 0x0a, 0x59, 0xb1, 0x84, 0x2b, 0x24, 
	0xff, 0x1f, 0x79, 0x5e, 0x89, 0x7a, 0xbd, 0x95,
  0xed, 0x5b, 0x47, 0xa7, 0x04, 0x8c, 0xfa, 0xb4, 
	0x8f, 0xb5, 0x21, 0x36, 0x9d, 0x93, 0x26, 0xbf,
  0x66, 0xa2, 0x57, 0xac, 0x3c, 0xa0, 0xb8, 0xb1, 
	0xc8, 0x0f, 0xe7, 0xfc, 0x10, 0x28, 0x8a, 0x13,
  0x20, 0x3e, 0xbb, 0xc0, 0x66, 0x13, 0x86, 0x60, 
	0xa0, 0x29, 0x22, 0x43, 0xf6, 0x90, 0x31, 0x50
].pack('C*').freeze

# CFB 
SelfTestGostKCfbSV = [
  0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 
	0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12,
  0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 
	0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19
].pack('C*').freeze

SelfTestGostKCfbEncText = [
  0x81, 0x80, 0x0a, 0x59, 0xb1, 0x84, 0x2b, 0x24, 
	0xff, 0x1f, 0x79, 0x5e, 0x89, 0x7a, 0xbd, 0x95,
  0xed, 0x5b, 0x47, 0xa7, 0x04, 0x8c, 0xfa, 0xb4, 
	0x8f, 0xb5, 0x21, 0x36, 0x9d, 0x93, 0x26, 0xbf,
  0x79, 0xf2, 0xa8, 0xeb, 0x5c, 0xc6, 0x8d, 0x38, 
	0x84, 0x2d, 0x26, 0x4e, 0x97, 0xa2, 0x38, 0xb5,
  0x4f, 0xfe, 0xbe, 0xcd, 0x4e, 0x92, 0x2d, 0xe6, 
	0xc7, 0x5b, 0xd9, 0xdd, 0x44, 0xfb, 0xf4, 0xd1
].pack('C*').freeze

# CBC
SelfTestGostKCbcSV = [
  0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 
	0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12,
  0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 
	0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19
].pack('C*').freeze

SelfTestGostKCbcEncText = [
  0x68, 0x99, 0x72, 0xd4, 0xa0, 0x85, 0xfa, 0x4d, 
	0x90, 0xe5, 0x2e, 0x3d, 0x6d, 0x7d, 0xcc, 0x27,
  0x28, 0x26, 0xe6, 0x61, 0xb4, 0x78, 0xec, 0xa6, 
	0xaf, 0x1e, 0x8e, 0x44, 0x8d, 0x5e, 0xa5, 0xac,
  0xfe, 0x7b, 0xab, 0xf1, 0xe9, 0x19, 0x99, 0xe8, 
	0x56, 0x40, 0xe8, 0xb0, 0xf4, 0x9d, 0x90, 0xd0,
  0x16, 0x76, 0x88, 0x06, 0x5a, 0x89, 0x5c, 0x63, 
	0x1a, 0x2d, 0x9a, 0x15, 0x60, 0xb6, 0x39, 0x70
].pack('C*').freeze

# CTR-ACPKM
SelfTestGostKCtrAcpkmGamma_s = BlockSize
SelfTestGostKCtrAcpkmSection_N = BlockSize * 2
SelfTestGostKCtrAcpkmIV = [
		0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCE, 0xF0
].pack('C*').freeze
SelfTestGostKCtrAcpkmPlainText = [
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 
		0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A, 
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 
		0x99, 0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A, 0x00, 
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 
		0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A, 0x00, 0x11, 
		0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 
		0xBB, 0xCC, 0xEE, 0xFF, 0x0A, 0x00, 0x11, 0x22, 
		0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 
		0xCC, 0xEE, 0xFF, 0x0A, 0x00, 0x11, 0x22, 0x33, 
		0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 
		0xEE, 0xFF, 0x0A, 0x00, 0x11, 0x22, 0x33, 0x44
].pack('C*').freeze    
SelfTestGostKCtrAcpkmEncText = [
		0xF1, 0x95, 0xD8, 0xBE, 0xC1, 0x0E, 0xD1, 0xDB, 
		0xD5, 0x7B, 0x5F, 0xA2, 0x40, 0xBD, 0xA1, 0xB8,
		0x85, 0xEE, 0xE7, 0x33, 0xF6, 0xA1, 0x3E, 0x5D, 
		0xF3, 0x3C, 0xE4, 0xB3, 0x3C, 0x45, 0xDE, 0xE4,
		0x4B, 0xCE, 0xEB, 0x8F, 0x64, 0x6F, 0x4C, 0x55, 
		0x00, 0x17, 0x06, 0x27, 0x5E, 0x85, 0xE8, 0x00,
		0x58, 0x7C, 0x4D, 0xF5, 0x68, 0xD0, 0x94, 0x39, 
		0x3E, 0x48, 0x34, 0xAF, 0xD0, 0x80, 0x50, 0x46,
		0xCF, 0x30, 0xF5, 0x76, 0x86, 0xAE, 0xEC, 0xE1, 
		0x1C, 0xFC, 0x6C, 0x31, 0x6B, 0x8A, 0x89, 0x6E,
		0xDF, 0xFD, 0x07, 0xEC, 0x81, 0x36, 0x36, 0x46, 
		0x0C, 0x4F, 0x3B, 0x74, 0x34, 0x23, 0x16, 0x3E,
		0x64, 0x09, 0xA9, 0xC2, 0x82, 0xFA, 0xC8, 0xD4, 
		0x69, 0xD2, 0x21, 0xE7, 0xFB, 0xD6, 0xDE, 0x5D
].pack('C*').freeze    

# OMAC-ACPKM
SelfTestGostKCtrAcpkmMac_s = BlockSize
SelfTestGostKCtrAcpkmMac_N = BlockSize * 2
SelfTestGostKCtrAcpkmMac_T = SelfTestGostKCtrAcpkmMac_N * 3

SelfTestGostKCtrAcpkmMac_M = [
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 
	0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 
].pack('C*').freeze
SelfTestGostKCtrAcpkmMac_mac_M = [
	0xB5, 0x36, 0x7F, 0x47, 0xB6, 0x2B, 0x99, 0x5E, 
	0xEB, 0x2A, 0x64, 0x8C, 0x58, 0x43, 0x14, 0x5E
].pack('C*').freeze

SelfTestGostKCtrAcpkmMac_data_TC26_M_5 = [
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 
	0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
	0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A, 
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 
	0x99, 0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A, 0x00, 
	0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 
	0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A, 0x00, 0x11, 
	0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 
	0xBB, 0xCC, 0xEE, 0xFF, 0x0A, 0x00, 0x11, 0x22
].pack('C*').freeze
SelfTestGostKCtrAcpkmMac_mac_TC26_M_5 = [
	0xfb, 0xb8, 0xdc, 0xee, 0x45, 0xbe, 0xa6, 0x7c,
	0x35, 0xf5, 0x8c, 0x57, 0x00, 0x89, 0x8e, 0x5d
].pack('C*').freeze

# TC 26 KExp15/KImp15 test data
TC26_K = [ 
	0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
	0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 
	0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF 
].pack('C*').freeze
TC26_Kmac = [
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F 
].pack('C*').freeze
TC26_Kenc = [ 
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 
	0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 
	0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
].pack('C*').freeze
TC26_IV_K = [
	0x09, 0x09, 0x47, 0x2D, 0xD9, 0xF2, 0x6B, 0xE8
].pack('C*').freeze
TC26_Kexp_K = [
	0xE3, 0x61, 0x84, 0xE8, 0x4E, 0x8D, 0x73, 0x6F, 
	0xF3, 0x6C, 0xC2, 0xE5, 0xAE, 0x06, 0x5D, 0xC6, 
	0x56, 0xB2, 0x3C, 0x20, 0xF5, 0x49, 0xB0, 0x2F, 
	0xDF, 0xF8, 0x8E, 0x1F, 0x3F, 0x30, 0xD8, 0xC2, 
	0x9A, 0x53, 0xF3, 0xCA, 0x55, 0x4D, 0xBA, 0xD8, 
	0x0D, 0xE1, 0x52, 0xB9, 0xA4, 0x62, 0x5B, 0x32
].pack('C*').freeze

class GostKuznyechikTest < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil ::GostKuznyechik::VERSION
  end

  def test_ecb_standard
    key = SelfTestGostKMasterKeyData
    plain_text = SelfTestGostKPlainText
    encrypted_test = SelfTestGostKEcbEncText

    encrypted_text = KuznyechikEcb.new(key).encrypt(plain_text)
    assert encrypted_text == encrypted_test 
    
    decrypted_text = KuznyechikEcb.new(key).decrypt(encrypted_test)
    assert decrypted_text == plain_text 
  end

  def test_omac_standard
    key = SelfTestGostKMasterKeyData
    plain_text = SelfTestGostKPlainText
    mac_test = SelfTestGostKMacValue

    mac = KuznyechikOmac.new(key, mac_test.length).update(plain_text).final
    assert mac == mac_test 
  end
  
  def test_ctr_standard
    key = SelfTestGostKMasterKeyData
    iv = SelfTestGostKCtrSV
    plain_text = SelfTestGostKPlainText
    encrypted_test = SelfTestGostKCtrEncText
    text_len = plain_text.length

    encrypted_text = KuznyechikCtr.new(key, iv, BlockSize).encrypt(plain_text)
    assert encrypted_text == encrypted_test
    
    ctx = KuznyechikCtr.new(key, iv, BlockSize)
    decrypted_text = ctx.decrypt(encrypted_test[0...text_len/3]) +
      ctx.decrypt(encrypted_test[text_len/3..-1])
    assert decrypted_text == plain_text 
  end

  def test_ofb_standard
    key = SelfTestGostKMasterKeyData
    iv = SelfTestGostKOfbSV
    s = BlockSize
    plain_text = SelfTestGostKPlainText
    encrypted_test = SelfTestGostKOfbEncText
    text_len = plain_text.length
    
    encrypted_text = KuznyechikOfb.new(key, iv, s).encrypt(plain_text)
    assert encrypted_text == encrypted_test
    
    ctx = KuznyechikOfb.new(key, iv, s)
    decrypted_text = ctx.decrypt(encrypted_test[0...text_len/3]) +
      ctx.decrypt(encrypted_test[text_len/3..-1])
    assert decrypted_text == plain_text
  end

  def test_cfb_standard
    key = SelfTestGostKMasterKeyData
    iv = SelfTestGostKCfbSV
    s = BlockSize
    plain_text = SelfTestGostKPlainText
    encrypted_test = SelfTestGostKCfbEncText
    text_len = plain_text.length
    
    encrypted_text = KuznyechikCfb.new(key, iv, s).encrypt(plain_text)
    assert encrypted_text == encrypted_test
    
    ctx = KuznyechikCfb.new(key, iv, s)
    decrypted_text = ctx.decrypt(encrypted_test[0...text_len/3]) +
      ctx.decrypt(encrypted_test[text_len/3..-1])
    assert decrypted_text == plain_text
  end

  def test_cbc_standard
    key = SelfTestGostKMasterKeyData
    iv = SelfTestGostKCbcSV
    plain_text = SelfTestGostKPlainText
    encrypted_test = SelfTestGostKCbcEncText

    encrypted_text = KuznyechikCbc.new(key, iv).encrypt(plain_text)
    assert encrypted_text == encrypted_test
    
    decrypted_text = KuznyechikCbc.new(key, iv).decrypt(encrypted_test)
    assert decrypted_text == plain_text    
  end
  
  def test_ctr_acpkm
    s = SelfTestGostKCtrAcpkmGamma_s
    n = SelfTestGostKCtrAcpkmSection_N
    key = SelfTestGostKMasterKeyData
    iv = SelfTestGostKCtrAcpkmIV
    plain_text = SelfTestGostKCtrAcpkmPlainText
    encrypted_test = SelfTestGostKCtrAcpkmEncText
    text_len = plain_text.length
    
    encrypted_text = KuznyechikCtrAcpkm.new(key, iv, s, n).encrypt(plain_text)
    assert encrypted_text == encrypted_test
    
    ctx = KuznyechikCtrAcpkm.new(key, iv, s, n)
    decrypted_text = ctx.decrypt(encrypted_test[0...text_len/3]) +
      ctx.decrypt(encrypted_test[text_len/3..-1])
    assert decrypted_text == plain_text     
  end

  def test_omac_acpkm
    key = SelfTestGostKMasterKeyData
    s = SelfTestGostKCtrAcpkmMac_s
    n = SelfTestGostKCtrAcpkmMac_N
    t = SelfTestGostKCtrAcpkmMac_T
    
    plain_text = SelfTestGostKCtrAcpkmMac_M
    mac_test = SelfTestGostKCtrAcpkmMac_mac_M    
    mac = KuznyechikOmacAcpkm.new(key, n, t, s).update(plain_text).final
    assert mac == mac_test 
    
    plain_text = SelfTestGostKCtrAcpkmMac_data_TC26_M_5
    text_len = plain_text.length
    mac_test = SelfTestGostKCtrAcpkmMac_mac_TC26_M_5    
    mac = KuznyechikOmacAcpkm.new(key, n, t, s).update(plain_text[0...text_len/3]).update(plain_text[text_len/3..-1]).final
    assert mac == mac_test 
  end
  
  def test_key_export_import
    key = TC26_K
    key_mac = TC26_Kmac
    key_enc = TC26_Kenc
    iv = TC26_IV_K
    key_exp_test = TC26_Kexp_K

    key_exp = KuznyechikKeyExpImp::export(key, key_mac, key_enc, iv)
    assert key_exp == key_exp_test

    imp_key = KuznyechikKeyExpImp::import(key_exp_test, key_mac, key_enc, iv)
    assert imp_key == key  
  end

end
