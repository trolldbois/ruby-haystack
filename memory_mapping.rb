# memorymapping.rb

module Haystack

  def Haystack.formatAddress(addr)
    "0x%08x"%addr
  end
  
  class MemoryMapping
    def initialize(start, stop, permissions='rwx-', offset=0x0, major_device=0x0, minor_device=0x0, inode=0x0, pathname='MEMORYDUMP')
      @start=start
      @stop=stop
      @permissions=permissions
      @offset=offset
      @major_device=major_device
      @minor_device=minor_device
      @inode=inode
      @pathname=pathname
    end

    def size
      @stop-@start
    end
    
    def contains( vaddr )
      @start <= vaddr and vaddr <= @stop
    end

    def to_s
      "#{Haystack.formatAddress(@start)}-#{Haystack.formatAddress(@stop)} => #{@pathname} (#{@permissions})"
    end

    #def display(port=$>)
    #  port.write "#{@start}-#{@stop} #{@pathname} (#{@permissions})"
    #end
  end

  class LocalMemoryMapping < MemoryMapping
    def initialize(memoryPointer, start, stop, permissions='rwx-', offset=0x0, major_device=0x0, minor_device=0x0, inode=0x0, pathname='MEMORYDUMP')
      super(start, stop, permissions, offset, major_device, minor_device, inode, pathname)
      @memoryPointer=memoryPointer
      @_address = @memoryPointer.address
    end
   
    def vtop(vaddr)
      return vaddr - @start #+ @_address, memorypointer rox 
    end
    
    def readWord(vaddr )
      #"""Address have to be aligned!"""
      laddr = self.vtop( vaddr )
      word = (@memoryPointer+vaddr).read_uint # is uint same as word ?
      return word
    end

    def readBytes(vaddr, size)
      #laddr = self.vtop(vaddr)
      #data = b''.join([ struct.pack('B',x) for x in @_local_mmap[laddr:laddr+size] ])
      data = self.readArray( vaddr, FFI::TypeDefs[:uchar], size).pack('C*')
      return data
    end
    
    def readStruct(vaddr, struct)
      laddr = self.vtop(vaddr)
      #car = Example::Car.new( ptr , :autorelease => false)
      struct = struct.new( @memoryPointer+laddr ) #, :autorelease => false) # true
      return struct
    end
    
    def readArray(vaddr, basetype, count)
      laddr = self.vtop(vaddr)
      ##NiceFFI fromArray. mais est-ce que [type] c'est pareil que type[]
      #if basetype.class == FFI::Type::Builtin
      #  #0 # can't do basic type array puts "%s"%basetype.public_methods
        #return FFI::MemoryPointer.new(basetype, count)
      #  (@memoryPointer+laddr).read_array_of_int(count)
      #else
      #  (@memoryPointer+laddr).read_array_of_type(basetype, {}, count)
      #  array = count.times.collect do |i|
      #    basetype.new(@memoryPointer.address +laddr+ (i*basetype.size))
      #  end
      #end
      array = (@memoryPointer+laddr).read_array_of_type(basetype, :read_uchar, count)
      return array
    end
    ########################3 TODO NEED to define a BultinType to read_method translation table.
    #########################   and use array Struct building for others.
    
    def getByteBuffer
      if @_bytebuffer.nil
        @_bytebuffer = self.readBytes( @start , self.size)
      end
      return @_bytebuffer
    end

    def initByteBuffer(data=nil)
      @_bytebuffer = data
    end
    
    def LocalMemoryMapping.fromPointer(memoryMapping, content_pointer)
      return self.new( content_pointer, memoryMapping.start, memoryMapping.stop, 
              memoryMapping.permissions, memoryMapping.offset, memoryMapping.major_device, memoryMapping.minor_device,
              memoryMapping.inode, memoryMapping.pathname)
    end
    
  end

end

