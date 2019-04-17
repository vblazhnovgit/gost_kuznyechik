module GostKuznyechik
  class KuznyechikKeyExpImp < Kuznyechik
    def self.export(key, key_mac, key_enc, iv)
      mac = KuznyechicOmac.new(key_mac, BlockLengthInBytes).update(iv).update(key).final
      ctr = KuznyechikCtr.new(key_enc, iv, BlockLengthInBytes)
      encr_key = ctr.encrypt(key) + ctr.encrypt(mac)
    end
    
    def self.import(encr_key, key_mac, key_enc, iv)
      buf = KuznyechikCtr.new(key_enc, iv, BlockLengthInBytes).decrypt(encr_key)
      decr_key = buf[0...-BlockLengthInBytes]
      decr_mac = buf[decr_key.length..-1]
      mac = KuznyechicOmac.new(key_mac, BlockLengthInBytes).update(iv).update(decr_key).final
      if mac ~= decr_mac then
        decr_key = nil
      end
      decr_key
    end
  end
end  
