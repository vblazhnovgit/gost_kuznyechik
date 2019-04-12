module GostKuznyechik
  class KuznyechikCtr < Kuznyechik
    def initialize(key, iv, gamma_s)
      @key = key.dup.force_encoding('BINARY')
      # @inkey => [4] uint_64, native-endian
      @inkey = self.class.keyToNumbers(@key)
      
      @keys = self.class.expandEncryptKeys(@inkey)
      @gamma_s = gamma_s
      @iv = iv.dup.force_encoding('BINARY')
      @prev_len = 0
      @bytes_count = 0
      @tmp_block = self.class.zeroBlock
      if @iv.length < BlockLengthInBytes/2 then
        @iv += self.class.zeroBytes(BlockLengthInBytes/2 - @iv.length)
      end
      @counter = @iv[0...(BlockLengthInBytes/2)] 
      @counter += self.class.zeroBytes(BlockLengthInBytes/2) 
    end
    
    def crypt(indata)
      data_len = indata.length
      outdata = self.class.zeroBytes(data_len)
      data_index = 0
      if @prev_len > 0 then
        if data_len < (@gamma_s - @prev_len) then
          (0...data_len).each do |j|
            outdata[j] = (indata[j].ord ^ @tmp_block[j + @prev_len].ord).chr
          end
          @prev_len += data_len
          @bytes_count += data_len
          return outdata        
        else
          (0...(@gamma_s - @prev_len)).each do |j|
            outdata[j] = (indata[j].ord ^ @tmp_block[j + @prev_len].ord).chr
          end
          data_index += @gamma_s - @prev_len
          @bytes_count += @gamma_s - @prev_len
          data_len -= @gamma_s - @prev_len
          self.class.incrementModulo(@counter, BlockLengthInBytes)
          @prev_len = 0      
        end
      end
      (0...(data_len / @gamma_s)).each do |i|
        @tmp_block = self.class.encryptBlock(@counter, @keys)
        (0...@gamma_s).each do |j|
          outdata[data_index + j] = (indata[data_index + j].ord ^ @tmp_block[j].ord).chr
        end
        data_index += @gamma_s
        @bytes_count += @gamma_s
        data_len -= @gamma_s
        self.class.incrementModulo(@counter, BlockLengthInBytes)
        @prev_len = 0
      end     
      if data_len > 0 then
        @tmp_block = self.class.encryptBlock(@counter, @keys)
        (0...data_len).each do |j|
          outdata[data_index + j] = (indata[data_index + j].ord ^ @tmp_block[j].ord).chr
        end
        @bytes_count += data_len
        @prev_len = data_len
      end
      return outdata
    end   
    
  end
end

