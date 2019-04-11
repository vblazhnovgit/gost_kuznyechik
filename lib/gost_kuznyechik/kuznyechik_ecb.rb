module GostKuznyechik
  class KuznyechikEcb < Kuznyechik
    # key = 32-byte string
    def initialize(key)
      @key = key.dup.force_encoding('BINARY')
      # @inkey => [4] uint_64, native-endian
      @inkey = self.keyToNumbers(@key)

      # @keys => [10*2] uint_64, native-endian
      @encrypt_keys = self.expandEncryptKeys(@inkey)
      @decrypt_keys = self.expandDecryptKeys(@inkey)
=begin    
      puts "@encrypt_keys:"
      (0...@encrypt_keys.length).step(2) do |i|
        printf("0x%X, 0x%X\n", @keys[i], @keys[i+1])
      end
      puts "@decrypt_keys:"
      (0...@decrypt_keys.length).step(2) do |i|
        printf("0x%X, 0x%X\n", @keys[i], @keys[i+1])
      end
=end    
      return self
    end
    
    # returns encrypted text string
    def encrypt(plain_text)
      len = plain_text.length
      if (len == 0) || (len % BlockLengthInBytes > 0) then
        puts "(plain_text.length == 0) || (plain_text.length % BlockLengthInBytes > 0)"
        return nil
      end
=begin    
      puts "encrypt #{len} bytes"
      puts "plain_text: #{plain_text.unpack('H*')[0]}"
=end    
      blocks = plain_text.scan(/.{16}/m)
=begin    
      puts "encrypt: #{blocks.length} blocks"
      blocks.each {|block| puts block.unpack('H*')[0]}
=end    
      encrypted_blocks = []
      blocks.each do |block|
        encryptedBlock = self.encryptBlock(block, @encrypt_keys)
  #        puts "encryptedBlock: #{encryptedBlock.unpack('H*')[0]}"
        encrypted_blocks << encryptedBlock
  #        puts "encrypted_blocks.length = #{encrypted_blocks.length}"
      end
      output = encrypted_blocks.join
  #    puts "output: #{output.unpack('H*')[0]}"
      return output
    end
    
    # returns decrypted text string
    def decrypt(encrypted_text)
      len = encrypted_text.length
      if (len == 0) || (len % BlockLengthInBytes > 0) then
        puts "(encrypted_text.length == 0) || (encrypted_text.length % BlockLengthInBytes > 0)"
        return nil
      end
=begin    
      puts "decrypt #{len} bytes"
      puts "encrypted_text: #{encrypted_text.unpack('H*')[0]}"
=end    
      blocks = encrypted_text.scan(/.{16}/m)
=begin    
      puts "decrypt: #{blocks.length} blocks"
      blocks.each {|block| puts block.unpack('H*')[0]}
=end    
      decrypted_blocks = []
      blocks.each do |block|
        decryptedBlock = self.decryptBlock(block, @decrypt_keys)
  #        puts "decryptedBlock: #{decryptedBlock.unpack('H*')[0]}"
        decrypted_blocks << decryptedBlock
  #        puts "decrypted_blocks.length = #{decrypted_blocks.length}"
      end
      output = decrypted_blocks.join
  #    puts "output: #{output.unpack('H*')[0]}"
      return output
    end

  end
end