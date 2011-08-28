#!/usr/bin/env ruby
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+ruby@gmail.com
#

require 'rubygems'
require 'nice-ffi'

require 'model'

#--- example of a generated struct
module Example
  #extend NiceFFI::Library
  # Use our CString
  #CString = :pointer
  #string = :CString
  
  
  class DNA < NiceFFI::Struct
    layout :id,  :uint,
           :c, :uchar,
           :f, :float
  end

  class Brand < NiceFFI::Struct
    layout :brandmagic, :uint,
           :brandname,  :string # string           
  end

  class Brand__Ptr < NiceFFI::TypedPointer
    extend FFI::DataConverter
    native_type FFI::Type::POINTER
    class << self
    attr_accessor :nestedtype
    end
    self.nestedtype = Brand

    def self.from_native(val, ctx)
      puts val.size
      return FFI::Pointer.new(val)
      puts val
      puts self.nestedtype

      nested = self.new self.nestedtype
      ret = nested.wrap(val)
      puts ret
      
      return ret
    end
  end

  FFI.typedef(Brand__Ptr, :bpointer)

  class Car < NiceFFI::Struct
    layout :magic1, :uint,
           :name,  :string,
           :color,  :uint,
           :a1,  :uint,
           :a2,  :uint,
           :a3,  :uint,
           :a4,  :uint,
           :a5,  :uint,
           :name2, [:uchar , 255],
           :brand, Example::Brand
           #:p_brand, :bpointer
  end
  #:char_array 
end
#--- end of generated strucs

#--- add-on contraints
require 'model'

module Example

  MAGIC=0xff112233
end

module Haystack
  Example::DNA.expectedValues = { 
        :id => [Example::MAGIC] ,
        }

  Example::Brand.expectedValues = { 
        :brandname => [NotNull],
        :brandmagic => [Example::MAGIC],
        }
  Example::Car.expectedValues = { 
        :color => [RangeValue.new(10,13)] ,
        :a1 => [1],
        :a2 => [2],
        :a3 => [3],
        :a4 => [4],
        :a5 => [5]
        }
end


