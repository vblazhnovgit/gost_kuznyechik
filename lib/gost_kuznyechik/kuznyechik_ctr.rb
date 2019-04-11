module GostKuznyechik
  class KuznyechikCtr < Kuznyechik
    def initialize(key, iv, gamma_s)
      @key = key.dup.force_encoding('BINARY')
      # @inkey => [4] uint_64, native-endian
      @inkey = keyToNumbers(@key)
      
      @keys = expandEncryptKeys(@inkey)
      @gamma_s = gamma_s
      @iv = iv.dup.force_encoding('BINARY')
      @prev_len = 0
      @bytes_count = 0
      @tmp_block = (0.chr * BlockLengthInBytes).force_encoding('BINARY')
      if @iv.length < BlockLengthInBytes/2 then
        @iv += 0.chr * (BlockLengthInBytes/2 - @iv.length)
      end
      @counter = @iv[0...(BlockLengthInBytes/2)] 
      @counter += 0.chr * (BlockLengthInBytes/2) 
    end
    
    def crypt(indata)
      data_len = indata.length
      outdata = (0.chr * data_len).force_encoding('BINARY')
      data_index = 0
      if @prev_len > 0 then
        if data_len < (@gamma_s - @prev_len) then
          (0...data_len).each do |j|
            outdata[j] = (indata[j].ord ^ @tmp_block[j + @prev_len].ord).chr
          end
  #        puts 'outdata:'
  #        printBytes(outdata)      
          @prev_len += data_len
          @bytes_count += data_len
          # @counter не изменяется
          return outdata        
        else
          (0...(@gamma_s - @prev_len)).each do |j|
            outdata[j] = (indata[j].ord ^ @tmp_block[j + @prev_len].ord).chr
          end
          data_index += @gamma_s - @prev_len
          @bytes_count += @gamma_s - @prev_len
          data_len -= @gamma_s - @prev_len
          incrementModulo(@counter, BlockLengthInBytes)
  #        puts '@counter:'
  #        printBytes(@counter)
          @prev_len = 0      
        end
      end
      (0...(data_len / @gamma_s)).each do |i|
  #      puts '@counter:'
  #      printBytes(@counter)
        @tmp_block = encryptBlock(@counter, @keys)
  #      puts '@tmp_block:'
  #      printBytes(@tmp_block)
        (0...@gamma_s).each do |j|
          outdata[data_index + j] = (indata[data_index + j].ord ^ @tmp_block[j].ord).chr
        end
  #      puts 'outdata:'
  #      printBytes(outdata)      
        data_index += @gamma_s
        @bytes_count += @gamma_s
        data_len -= @gamma_s
        incrementModulo(@counter, BlockLengthInBytes)
  #      puts 'Incremented @counter:'
  #      printBytes(@counter)
        @prev_len = 0
  #      binding.pry
      end
      
      if data_len > 0 then
  #      binding.pry
        @tmp_block = encryptBlock(@counter, @keys)
  #      puts '@tmp_block:'
  #      printBytes(@tmp_block)
        (0...data_len).each do |j|
          outdata[data_index + j] = (indata[data_index + j].ord ^ @tmp_block[j].ord).chr
        end
  #      puts 'outdata:'
  #      printBytes(outdata)      
        @bytes_count += data_len
        @prev_len = data_len
      end
  #    binding.pry
      return outdata
    end   
    
  end
end

