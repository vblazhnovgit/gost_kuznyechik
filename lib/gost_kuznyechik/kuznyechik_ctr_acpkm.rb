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
    
    def crypt(indata)
      data_len = indata.length
      if data_len > 0 then
        outdata = (0.chr * data_len).force_encoding('BINARY')
        (0...data_len).each do |i|
          if @section_bytes == @section_N then
            @inkey = self.class.acpkmCtrKey(@keys)
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
    
  end
end
