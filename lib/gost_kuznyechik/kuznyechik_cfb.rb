module GostKuznyechik
  class KuznyechikCfb < Kuznyechik
    def initialize(key, iv, gamma_s)
      @key = key.dup.force_encoding('BINARY')
      # @inkey => [4] uint_64, native-endian
      @inkey = self.class.keyToNumbers(@key)
      @gamma_s = gamma_s
      @ctxR = iv.dup.force_encoding('BINARY')
      # keys and gamma initialization
      @keys = self.class.expandEncryptKeys(@inkey)
      tmp_block = @ctxR[0...BlockLengthInBytes]
      @gamma_block = self.class.encryptBlock(tmp_block, @keys)
      @incomplete_block = ''
      @incomplete_block_len = 0
    end
    
    def encrypt(data)
      data_len = data.length
      outdata = ''
      if @incomplete_block_len > 0 then      
        # use old @gamma_block
        if data_len < @gamma_s - @incomplete_block_len then
          # incomplete block yet
          outdata = data.dup
          (0...data_len).each do |j|
            outdata[j] = (@gamma_block[@incomplete_block_len-1 + j].ord ^ outdata[j].ord).chr
          end
          @incomplete_block_len += data_len
          @incomplete_block += outdata
          return outdata
        else
          outdata = data[0...(@gamma_s - @incomplete_block_len)]
          (0...outdata.length).each do |j|
            outdata[j] = (@gamma_block[@incomplete_block_len-1 + j].ord ^ outdata[j].ord).chr
          end
          # complete block
          @incomplete_block += outdata
          @ctxR = @ctxR[@gamma_s..-1] + @incomplete_block
          tmp_block = @ctxR[0...BlockLengthInBytes]
          @gamma_block = self.class.encryptBlock(tmp_block, @keys)
          @incomplete_block = ''
          @incomplete_block_len = 0
        end
      end
      
      left_data_len = data_len-@incomplete_block_len
      (0...(left_data_len / @gamma_s)).each do |i|
        encr_data = data[(@incomplete_block_len+(i * @gamma_s))...(@incomplete_block_len+((i+1) * @gamma_s))]
        (0...@gamma_s).each do |j|
          encr_data[j] = (@gamma_block[j].ord ^ encr_data[j].ord).chr
        end
        outdata += encr_data
        # complete block        
        @ctxR = @ctxR[@gamma_s..-1] + encr_data
        tmp_block = @ctxR[0...BlockLengthInBytes]
        @gamma_block = self.class.encryptBlock(tmp_block, @keys)
        left_data_len -= @gamma_s
      end

      if left_data_len > 0 then
        # incomplete block start
        encr_data = data[-left_data_len..-1]
        (0...left_data_len).each do |j|
          encr_data[j] = (@gamma_block[j].ord ^ encr_data[j].ord).chr
        end
        outdata += encr_data
        @incomplete_block_len = left_data_len
        @incomplete_block = encr_data
      end
      outdata
    end
    
    
    def decrypt(data)
      data_len = data.length
      outdata = ''
      if @incomplete_block_len > 0 then      
        # use old @gamma_block
        if data_len < @gamma_s - @incomplete_block_len then
          # incomplete block yet
          outdata = data.dup
          (0...data_len).each do |j|
            outdata[j] = (@gamma_block[@incomplete_block_len-1 + j].ord ^ outdata[j].ord).chr
          end
          @incomplete_block_len += data_len
          @incomplete_block += data.dup
          return outdata
        else
          outdata = data[0...(@gamma_s - @incomplete_block_len)]
          (0...outdata.length).each do |j|
            outdata[j] = (@gamma_block[@incomplete_block_len-1 + j].ord ^ outdata[j].ord).chr
          end
          # complete block
          @incomplete_block += data[0...(@gamma_s - @incomplete_block_len)]
          @ctxR = @ctxR[@gamma_s..-1] + @incomplete_block
          tmp_block = @ctxR[0...BlockLengthInBytes]
          @gamma_block = self.class.encryptBlock(tmp_block, @keys)
          @incomplete_block = ''
          @incomplete_block_len = 0
        end
      end
      
      left_data_len = data_len-@incomplete_block_len
      (0...(left_data_len / @gamma_s)).each do |i|
        encr_data = data[(@incomplete_block_len+(i * @gamma_s))...(@incomplete_block_len+((i+1) * @gamma_s))]
        (0...@gamma_s).each do |j|
          encr_data[j] = (@gamma_block[j].ord ^ encr_data[j].ord).chr
        end
        outdata += encr_data
        # complete block        
        @ctxR = @ctxR[@gamma_s..-1] + data[(@incomplete_block_len+(i * @gamma_s))...(@incomplete_block_len+((i+1) * @gamma_s))]
        tmp_block = @ctxR[0...BlockLengthInBytes]
        @gamma_block = self.class.encryptBlock(tmp_block, @keys)
        left_data_len -= @gamma_s
      end

      if left_data_len > 0 then
        # incomplete block start
        encr_data = data[-left_data_len..-1]
        (0...left_data_len).each do |j|
          encr_data[j] = (@gamma_block[j].ord ^ encr_data[j].ord).chr
        end
        outdata += encr_data
        @incomplete_block_len = left_data_len
        @incomplete_block = data[-left_data_len..-1]
      end
      outdata
    end
    
  end
end  
