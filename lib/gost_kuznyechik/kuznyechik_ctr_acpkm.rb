module GostKuznyechik
  class KuznyechikCtrAcpkm < Kuznyechik
    def initialize(key, iv, gamma_s, section_N)
      @key = key.dup.force_encoding('BINARY')
      # @inkey => [4] uint_64, native-endian
      @inkey = self.class.keyToNumbers(@key)     
      @keys = self.class.expandEncryptKeys(@inkey)
      @iv = iv.dup.force_encoding('BINARY')
      @gamma_s = gamma_s
      @section_N = section_N
      @gamma_bytes = 0
      @section_bytes = 0
      @block_bytes = 0
      @bytes_count = 0
      if @iv.length < BlockLengthInBytes/2 then
        @iv += 0.chr * (BlockLengthInBytes/2 - @iv.length)
      end
      @counter = @iv[0...(BlockLengthInBytes/2)] 
      @counter += 0.chr * (BlockLengthInBytes/2) 
      @gamma = self.class.encryptBlock(@counter, @keys)
      self.class.incrementModulo(@counter, BlockLengthInBytes)
    end
    
    def encrypt(indata)
      data_len = indata.length
      if data_len > 0 then
        outdata = self.class.zeroBytes(data_len)
        (0...data_len).each do |i|
          if @section_bytes == @section_N then
            acpkmCtrKey
            @keys = self.class.expandEncryptKeys(@inkey)
            @gamma = self.class.encryptBlock(@counter, @keys)
            self.class.incrementModulo(@counter, BlockLengthInBytes)
            @section_bytes = 0
            @block_bytes = 0
            @gamma_bytes = 0         
          else
            if @gamma_bytes == @gamma_s then
              @gamma = self.class.encryptBlock(@counter, @keys)
              self.class.incrementModulo(@counter, BlockLengthInBytes)
              @gamma_bytes = 0
            end
            if @block_bytes == BlockLengthInBytes then
              @block_bytes = 0
            end        
          end                
          outdata[i] = (indata[i].ord ^ @gamma[@gamma_bytes].ord).chr
          @gamma_bytes += 1
          @block_bytes += 1
          @section_bytes += 1
          @bytes_count += 1
        end
        return outdata
      else
        return ''
      end
    end
    
    def decrypt(indata)
      encrypt(indata)
    end
    
    protected
    
    W5 = [
      0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
      0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f
    ].pack('C*').freeze  
    W6 = [
      0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
      0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    ].pack('C*').freeze
    
    def acpkmCtrKey
      @key = self.class.encryptBlock(W5, @keys) + self.class.encryptBlock(W6, @keys)
      # Recalculate @inkey array in base object
      @inkey = self.class.keyToNumbers(@key)
    end
    
  end
end
