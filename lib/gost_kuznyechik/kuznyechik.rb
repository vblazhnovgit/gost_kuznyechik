module GostKuznyechik
  # Base abstract class
  class Kuznyechik
    # class constants
    BlockLengthInBytes = 16
    WorkspaceOfScheduleRoundKeys = 32
    NumberOfRounds = 10
    NumberOfRoundsInKeySchedule = 8
    KeyLengthInBytes = 32
    MaxIvLength = BlockLengthInBytes*16

    # 's' stands for native-endian byte order but 'n' stands for network (big-endian) byte order
    BigEndian = [1].pack('s') == [1].pack('n')
       
    protected
    
    def self.printBytes(bytes, line_size = 16)
      bytes.unpack('H*')[0].scan(/.{1,#{line_size}}/).each{|s| puts(s)}
    end  
    
    def self.zeroBytes(n)
      ("\x00"*n).force_encoding('BINARY')
    end

    def self.zeroBlock
      ("\x00"*BlockLengthInBytes).force_encoding('BINARY')
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
      (2...NumberOfRounds).step(2) do |iNextKey|
        roundKeys += roundKeys[-4..-1]
        (0...NumberOfRoundsInKeySchedule).each do |iFeistel|
          funcF(constantIndex, roundKeys, iNextKey * 2)      
          constantIndex += 1
        end
      end
      roundKeys
    end
    
    def self.expandDecryptKeys(inkey)
      roundKeys = expandEncryptKeys(inkey)
      cache = [0, 0]
      (1..8).each do |i|
        cache[0] = roundKeys[2 * i]
        cache[1] = roundKeys[2 * i + 1]
        cache[0] = funcS(cache[0])
        cache[1] = funcS(cache[1])
        pair = funcInvLS(cache)
        roundKeys[2 * i] = pair[0]
        roundKeys[2 * i + 1] = pair[1]     
      end
      roundKeys
    end
    
    def self.funcF(constantIndex, roundKeys, index)
      temp1 = []
      temp1 << (roundKeys[index] ^ RoundConstLeft[constantIndex]);
      temp1 << (roundKeys[index+1] ^ RoundConstRight[constantIndex]);     
      temp2 = funcLS(temp1)
      roundKeys[index+2] ^= temp2[0];
      roundKeys[index+3] ^= temp2[1];
      swapBlocks(roundKeys, index);    
    end
    
    def self.funcLS(input)
      # To little-endian
      na = []
      ns = uint64ToUint8BE(input[0]).reverse
      na += ns.unpack('C*')
      ns = uint64ToUint8BE(input[1]).reverse
      na += ns.unpack('C*')
      left = 0
      right = 0
      na.each_with_index do |v, i|
        left ^= PrecLSTableLeft[i][v]
        right ^= PrecLSTableRight[i][v]
      end
      [left, right]
    end
    
    def self.funcInvLS(input)
      # To little-endian
      na = []
      ns = uint64ToUint8BE(input[0]).reverse
      na += ns.unpack('C*')
      ns = uint64ToUint8BE(input[1]).reverse
      na += ns.unpack('C*')
      left = 0
      right = 0
      na.each_with_index do |v, i|
        left ^= PrecInvLSTableLeft[i][v]
        right ^= PrecInvLSTableRight[i][v]
      end
      [left, right]
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
      bytes
    end
    
    # Unpacks 8-byte string to 64-bit number 
    # (native-endian)
    def self.uint8ToUint64(bytes)
      bytes.unpack('Q*')[0]
    end
    
    # block - 16-byte String
    def self.encryptBlock(block, keys)
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
      output
    end
    
    def self.decryptBlock(block, keys)
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
      block
    end
    
    def self.padd(incomplete_block)
      padding_len = BlockLengthInBytes - (incomplete_block.length % BlockLengthInBytes)
      padded_block = incomplete_block.dup
      padded_block += 0x80.chr
      padding_len -= 1
      if padding_len > 0 then
        padded_block += 0.chr * padding_len
      end
      padded_block
    end
      
  end
end