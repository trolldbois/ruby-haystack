#!/usr/bin/ruby

require 'rubygems'
require 'nice-ffi'

require 'utils'

# get a pointer
#
#  objptr = FFI::MemoryPointer.new :pointer
#  nfound = MyLibrary.find_first_match("jimbo", objptr)
#  objptr = objptr.get_pointer(0)
#  result = calculate_something_else(11.2, objptr)

module LoadableMembers
  include Logging
    
  def loadMembers(mappings, depth)
    log.info('loadmembers')
  end
end

module NiceFFI
  class Struct
    include LoadableMembers
  end
end

