#!/usr/bin/ruby

require 'rubygems'
require 'nice-ffi'


# get a pointer
#
#  objptr = FFI::MemoryPointer.new :pointer
#  nfound = MyLibrary.find_first_match("jimbo", objptr)
#  objptr = objptr.get_pointer(0)
#  result = calculate_something_else(11.2, objptr)

module Model
  extend FFI::Library
  ffi_lib FFI::Library::LIBC
  attach_function 'puts', [ :string ], :int
  attach_function 'memcpy', [:pointer, :pointer, :int ], :int

  def Model.bytes2array(bytes)
    #   not using  #buf = FFI::MemoryPointer.from_string(bytes) terminal \0 is added
    buf = FFI::MemoryPointer.new(FFI::TypeDefs[:uchar], bytes.size)
    (0..bytes.size-1).each do |offset|
      buf.put_uchar(offset, bytes[offset])
    end
    return buf
  end

  def Model.array2bytes(array, type)
    buf = String('')
    (0..array.size-1).each do |offset|
      buf << array.get_uchar(offset)
    end
    return buf
  end
  
  class LoadableMembers < NiceFFI::Struct
    def initialize(modulename, classname)
      @head=''
      @members=[]
      @head = "
  module #{modulename}
    class #{classname}
  "
      @tail = "\nend"
    end

    def add(members)
      if members.class != Array
        #raise fcsk TypeError
        throw TypeError.new
      end
      #members.each do |
    end
  end
end



