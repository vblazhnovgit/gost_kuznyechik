module GostKuznyechik
  class KuznyechikEcb < Kuznyechik
    # key = 32-byte string
    def initialize(key)
      @key = key.dup.force_encoding('BINARY')
      # @inkey => [4] uint_64, native-endian
      @inkey = self.class.keyToNumbers(@key)

      # @keys => [10*2] uint_64, native-endian
      @encrypt_keys = self.class.expandEncryptKeys(@inkey)
      @decrypt_keys = self.class.expandDecryptKeys(@inkey)
      return self
    end
    
    # returns encrypted text string
    def encrypt(plain_text)
      len = plain_text.length
      if (len == 0) || (len % BlockLengthInBytes > 0) then
        puts "(plain_text.length == 0) || (plain_text.length % BlockLengthInBytes > 0)"
        return nil
      end
      blocks = plain_text.scan(/.{16}/m)
      encrypted_blocks = []
      blocks.each do |block|
        encryptedBlock = self.class.encryptBlock(block, @encrypt_keys)
        encrypted_blocks << encryptedBlock
      end
      output = encrypted_blocks.join
      return output
    end
    
    # returns decrypted text string
    def decrypt(encrypted_text)
      len = encrypted_text.length
      if (len == 0) || (len % BlockLengthInBytes > 0) then
        puts "(encrypted_text.length == 0) || (encrypted_text.length % BlockLengthInBytes > 0)"
        return nil
      end
      blocks = encrypted_text.scan(/.{16}/m)
      decrypted_blocks = []
      blocks.each do |block|
        decryptedBlock = self.class.decryptBlock(block, @decrypt_keys)
        decrypted_blocks << decryptedBlock
      end
      output = decrypted_blocks.join
      return output
    end

  end
end