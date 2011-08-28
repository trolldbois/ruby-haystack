#!/usr/bin/env ruby
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+ruby@gmail.com
#

require 'utils'
require 'dbg'

module Haystack

  class MemoryMapping
    include Logging
    attr_reader :start, :stop, :permissions, :offset, :major_device, :minor_device, :inode, :pathname
  
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
    
    def include?( vaddr )
      if vaddr.nil? 
        return false
      end
      @start <= vaddr and vaddr <= @stop
    end

    def to_s
      "#{formatAddress(@start)}-#{formatAddress(@stop)} => #{@pathname} (#{@permissions})"
    end

    #def display(port=$>)
    #  port.write "#{@start}-#{@stop} #{@pathname} (#{@permissions})"
    #end
    def readCString(address, max_size, chunk_length=256)
      ''' identic to process.readCString '''
      string = ''
      size = 0
      truncated = false
      while true
        done = false
        data = self.readBytes(address, chunk_length)
        if data.include?("\0")
          done = true
          data = data[0..(data.index("\0"))]
        end
        if max_size <= size+chunk_length
          data = data[0..(max_size-size)]
          string << data
          truncated = true
          break
        end
        string << data
        if done
          break
        end
        size += chunk_length
        address += chunk_length
      end
      return [string, truncated]
    end
  end

=begin
    Process memory mapping (metadata about the mapping).

    Attributes:
     - _process: weak reference to the process
     - _local_mmap: the LocalMemoryMapping is mmap() has been called
     _ _base: the current MemoryMapping reader ( process or local_mmap )

    Operations:
     - "mmap" mmap the MemoryMap to local address space
     - "readWord()": read a memory word, from local mmap-ed memory if mmap-ed
     - "readBytes()": read some bytes, from local mmap-ed memory if mmap-ed
     - "readStruct()": read a structure, from local mmap-ed memory if mmap-ed
     - "readArray()": read an array, from local mmap-ed memory if mmap-ed
       useful in list contexts
=end
  class ProcessMemoryMapping < MemoryMapping
    def initialize (process, start, stop, permissions, offset, major_device, minor_device, inode, pathname)
      super( start, stop, permissions, offset, major_device, minor_device, inode, pathname)
      @_process = process
      @_local_mmap = nil
      @_local_mmap_content = nil
      # read from process by default
      @_base = @_process
    end
    
    def readWord(address)
      word = @_base.readWord(address)
      return word
    end

    def readBytes(address, size)
      data = @_base.readBytes(address, size)
      return data
    end

    def readStruct( address, struct)
      struct = @_base.readStruct(address, struct)
      return struct
    end

    def readArray( address, basetype, count)
      array = @_base.readArray(address, basetype, count)
      return array
    end

    def isMmaped?
      not @_local_mmap.nil?
    end
      
    # ''' mmap-ed access gives a 20% perf increase on by tests '''
    def mmap
      if not self.isMmaped?
        @_local_mmap_content = @_process.readArray(@start, FFI::Type::UCHAR, self.size ) # keep ref
        #@_local_mmap = @_process().read(@start, @end - @start)
        @_local_mmap = LocalMemoryMapping.fromPointer( self, @_local_mmap_content )
        @_base = @_local_mmap
      end
      return @_local_mmap
    end

    def unmmap
      @_base = @_process
      @_local_mmap = nil
      @_local_mmap_content = nil
    end
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
      begin
        struct = struct.new( @memoryPointer+laddr )#, :autorelease => false) # true
      rescue NoMethodError
        log.error('No initialize on that Struct. probably a Typed POinter huh... %s'%struct)
        return nil
      end
      return struct
    end
    
    def readArray(vaddr, basetype, count)
      laddr = self.vtop(vaddr)
      ##NiceFFI fromArray. mais est-ce que [type] c'est pareil que type[]
      #if basetype.class == FFI::Type::Builtin is_kind_of
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
    
    def pointer
      return @memoryPointer
    end
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


  PROC_MAP_REGEX = Regexp.new('([0-9a-f]+)-([0-9a-f]+) (.{4}) ([0-9a-f]+) ([0-9a-f]{2}):([0-9a-f]{2}) ([0-9]+) (?: +(.*))?')

=begin
    Read all memory mappings of the specified process.

    Return a list of MemoryMapping objects, or empty list if it's not possible
    to read the mappings.

    May raise a ProcessError.
=end
  def readProcessMappings(process)
    maps = []
    mapsfile = openProc(process.pid)
    mapsfile.each do |line|
      match = line.match PROC_MAP_REGEX
      if match.nil?
        raise ProcessError(process, "Unable to parse memoy mapping: %r" % line)
      end
      map = ProcessMemoryMapping.new(
        process,
        match[ 1].to_i( 16),
        match[ 2].to_i(16),
        match[ 3], # perms
        match[ 4].to_i(16),
        match[ 5].to_i(16),
        match[ 6].to_i(16),
        match[ 7], #inode
        match[ 8]) # pathname
      maps << map
    end
    return maps
  end


end

