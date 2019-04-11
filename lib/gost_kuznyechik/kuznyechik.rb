module GostKuznyechik
  # Base abstract class
  class Kuznyechik
    # class constants
    BlockLengthInBytes = 16
    WorkspaceOfScheduleRoundKeys = 32
    NumberOfRounds = 10
    NumberOfRoundsInKeySchedule = 8
    KeyLengthInBytes = 32
    # 's' stands for native-endian byte order but 'n' stands for network (big-endian) byte order
    BigEndian = [1].pack('s') == [1].pack('n')
    
=begin    
    # key = 32-byte string
    def initialize(key)
      @key = key.dup.force_encoding('BINARY')
      # @inkey => [4] uint_64, native-endian
      @inkey = keyToNumbers(@key)
      puts "@inkey:"
      @inkey.each do |n|
        printf("0x%X, ", n)
      end
      puts ''

      return self
    end
=end   
     
    protected
    
    def self.printBytes(bytes, line_size = 16)
      bytes.unpack('H*')[0].scan(/.{1,#{line_size}}/).each{|s| puts(s)}
    end  
    
    # n - 64-bit number
    def self.funcS(n)
      uint64ToUint8(n).unpack('C*').map{|b| PiTable[b]}.pack('C*').unpack('Q*')[0]
    end
    
    def self.funcInvS(n)
      uint64ToUint8(n).unpack('C*').map{|b| InvPiTable[b]}.pack('C*').unpack('Q*')[0]
    end

    def self.keyToNumbers(key)
      inkey = key.scan(/.{8}/m).map{|k| k.unpack('Q*')[0]}
    end
    
    def self.expandEncryptKeys(inkey)  
      roundKeys = inkey.dup
      constantIndex = 0
  #    puts 'expandEncryptKeys'
      (2...NumberOfRounds).step(2) do |iNextKey|
        roundKeys += roundKeys[-4..-1]
        (0...NumberOfRoundsInKeySchedule).each do |iFeistel|
          # Функции funcF нужно передать две соседние пары чисел,
          # но для этого достаточно передать только roundKeys и iNextKey * 2.
          funcF(constantIndex, roundKeys, iNextKey * 2)      
          constantIndex += 1
        end
      end
      roundKeys
    end
    
    def self.expandDecryptKeys(inkey)
  #    puts 'expandDecryptKeys'
      roundKeys = expandEncryptKeys(inkey)
      cache = [0, 0]
  #    puts 'Rounds 1..8'
      (1..8).each do |i|
        cache[0] = roundKeys[2 * i]
        cache[1] = roundKeys[2 * i + 1]
  #      printf("Round %d: 0x%X, 0x%X\n", i, cache[0], cache[1])
        cache[0] = funcS(cache[0])
        cache[1] = funcS(cache[1])
  #      printf("funcS: 0x%X, 0x%X\n", cache[0], cache[1])
        pair = funcInvLS(cache)
        roundKeys[2 * i] = pair[0]
        roundKeys[2 * i + 1] = pair[1]     
  #      printf("funcInvLS: 0x%X, 0x%X\n", roundKeys[2 * i], roundKeys[2 * i + 1])
      end
      roundKeys
    end
    
    def self.funcF(constantIndex, roundKeys, index)
  #    printf("funcF: constantIndex: %d, index: %d\n", constantIndex, index)
      temp1 = []
      temp1 << (roundKeys[index] ^ RoundConstLeft[constantIndex]);
      temp1 << (roundKeys[index+1] ^ RoundConstRight[constantIndex]);
  #    printf("temp1: 0x%X, 0x%X\n", temp1[0], temp1[1])
      
      temp2 = funcLS(temp1)
  #    printf("temp2: 0x%X, 0x%X\n", temp2[0], temp2[1])

      roundKeys[index+2] ^= temp2[0];
      roundKeys[index+3] ^= temp2[1];

      swapBlocks(roundKeys, index);    
  #    printf("roundKeys[%d..%d]: 0x%X, 0x%X, 0x%X, 0x%X\n",
  #      index, index+3,
  #      roundKeys[index], roundKeys[index+1], roundKeys[index+2], roundKeys[index+3])
    end
    
    def self.funcLS(input)
      # Числа массива input нужно выгрузить в массив байтов в порядке little-endian,
      # потому что таблицы предрассчитаны для такого порядка байтов.
      na = []
      ns = uint64ToUint8BE(input[0]).reverse
      na += ns.unpack('C*')
      ns = uint64ToUint8BE(input[1]).reverse
      na += ns.unpack('C*')
  #    puts 'na:'
  #    na.each{|b| printf('%.2X', b)}
  #    puts ''
      left = 0
      right = 0
      na.each_with_index do |v, i|
        left ^= PrecLSTableLeft[i][v]
        right ^= PrecLSTableRight[i][v]
      end
      return [left, right]
    end
    
    def self.funcInvLS(input)
      # Числа массива input нужно выгрузить в массив байтов в порядке little-endian,
      # потому что таблицы предрассчитаны для такого порядка байтов.
      na = []
      ns = uint64ToUint8BE(input[0]).reverse
      na += ns.unpack('C*')
      ns = uint64ToUint8BE(input[1]).reverse
      na += ns.unpack('C*')
  #    puts 'na:'
  #    na.each{|b| printf('%.2X', b)}
  #    puts ''
      left = 0
      right = 0
      na.each_with_index do |v, i|
        left ^= PrecInvLSTableLeft[i][v]
        right ^= PrecInvLSTableRight[i][v]
      end
      return [left, right]
    end
    
    # roundKeys - array of 64-bit numbers
    # index - points to left[0] number
    # index+2 - points to right[0] number
    # swaps left[0..1] block with right[0..1] block 
    def self.swapBlocks(roundKeys, index)
      roundKeys[index] ^= roundKeys[index+2]
      roundKeys[index+1] ^= roundKeys[index+3]

      roundKeys[index+2] ^= roundKeys[index]
      roundKeys[index+3] ^= roundKeys[index+1]

      roundKeys[index] ^= roundKeys[index+2]
      roundKeys[index+1] ^= roundKeys[index+3]
    end

    # Unload 64-bit number to 8-byte string
    # (big-endian, adding leading zeroes)
    def self.uint64ToUint8BE(n)
      str = n.to_s(16) # big-endian
      len = str.length
      # add leading zeroes
      str.insert(0, '0'*(16 - len)) if len < 16
      # To byte string
      bytes = [str].pack('H*')
    end 
    
    # Unload 64-bit number to 8-byte string
    # (native-endian, adding leading zeroes)
    def self.uint64ToUint8(n)
      bytes = uint64ToUint8BE(n)    
      bytes.reverse! unless BigEndian   
      return bytes
    end
    
    # Unpacks 8-byte string to 64-bit number 
    # (native-endian)
    def self.uint8ToUint64(bytes)
      bytes.unpack('Q*')[0]
    end
    
    # block - 16-byte String
    def self.encryptBlock(block, keys)
  #    puts "encryptBlock: input block = #{block.unpack('H*')[0]}"
      pair = block.scan(/.{8}/m)
      data = []
      # Format 'Q*' unpacks byte string using native byte order
      data << pair[0].unpack('Q*')[0]
      data << pair[1].unpack('Q*')[0]
      
      cache = [0, 0]
      (0...(NumberOfRounds - 1)).each do |round|
          cache[0] = data[0] ^ keys[2 * round]
          cache[1] = data[1] ^ keys[2 * round + 1]
          data = funcLS(cache)
      end
      
      data[0] ^= keys[2 * (NumberOfRounds - 1)]
      data[1] ^= keys[2 * (NumberOfRounds - 1) + 1];
      
      output = uint64ToUint8(data[0]) + uint64ToUint8(data[1])
  #    puts "encryptBlock: output block = #{output.unpack('H*')[0]}"  
      output
    end
    
    def self.decryptBlock(block, keys)
  #    puts "decryptBlock: input block = #{block.unpack('H*')[0]}"
      pair = block.scan(/.{8}/m)
      data = []
      # Format 'Q*' unpacks byte string using native byte order
      data << pair[0].unpack('Q*')[0]
      data << pair[1].unpack('Q*')[0]
      round = NumberOfRounds - 1
      # round == 9
      data[0] ^= keys[2 * round]
      data[1] ^= keys[2 * round + 1] 
      round -= 1
      # round == 8
      data[0] = funcS(data[0])
      data[1] = funcS(data[1])    
      cache = funcInvLS(data)
      data = funcInvLS(cache)
      cache[0] = data[0] ^ keys[2 * round]
      cache[1] = data[1] ^ keys[2 * round + 1]
      round -= 1
      # round = 7    
      (NumberOfRounds - 3).downto(1) do |i|
          data = funcInvLS(cache)
          cache[0] = data[0] ^ keys[2 * round]
          cache[1] = data[1] ^ keys[2 * round + 1]
          round -= 1
      end
      # round == 0
      cache[0] = funcInvS(cache[0])
      cache[1] = funcInvS(cache[1])
      data[0] = cache[0] ^ keys[2 * round]
      data[1] = cache[1] ^ keys[2 * round + 1]
      
      output = uint64ToUint8(data[0]) + uint64ToUint8(data[1])
  #    puts "decryptBlock: output block = #{output.unpack('H*')[0]}"  
      output
    end
    
    # Increment CTR counter
    def self.incrementModulo(counter, size)
      lastIndex = size - 1
      (0...size).each do |i|
        if counter[lastIndex - i].ord > 0xfe then  
          counter[lastIndex - i] = (counter[lastIndex - i].ord - 0xff).chr  
        else 
          counter[lastIndex - i] = (counter[lastIndex - i].ord + 1).chr 
          break 
        end  
      end
      counter
    end

    W5 = [
      0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
      0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f
    ].pack('C*').freeze  
    W6 = [
      0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
      0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    ].pack('C*').freeze
    
    def self.acpkmCtrKey(keys)
      key = encryptBlock(W5, keys) + encryptBlock(W6, keys)
      # Recalculate @inkey array in base object
      inkey = keyToNumbers(key)
    end

    # block - byte string  
    def self.shiftLeftOne(block)
      (0...(BlockLengthInBytes-1)).each do |i|
        ri1 = block[i+1].ord
        ri = block[i].ord << 1
        ri &= 0xfe
        ri |= (ri1 >> 7) & 0x1
        block[i] = ri.chr
      end
      ri = block[BlockLengthInBytes-1].ord << 1
      block[BlockLengthInBytes-1] = (ri & 0xfe).chr
      return block
    end
    
    def self.padd(incomplete_block)
      padding_len = BlockLengthInBytes - (incomplete_block.length % BlockLengthInBytes)
      padded_block = incomplete_block.dup
      padded_block += 0x80.chr
      padding_len += 1

      if padding_len < BlockLengthInBytes then
        padded_block += 0.chr * (BlockLengthInBytes - padding_len)
      end

      return padded_block
    end
    
  end
end