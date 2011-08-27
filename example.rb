#!/usr/bin/env ruby
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+ruby@gmail.com
#

require 'rubygems'
require 'nice-ffi'

#--- example of a generated struct
module Example

  class DNA < NiceFFI::Struct
    layout :id,  :int,
           :c, :char,
           :f, :float
  end

  class Brand < NiceFFI::Struct
    layout :name,  :string,
           :magic, :int
  end

  class Car < NiceFFI::Struct
    layout :name,  :string,
           :color,  :int,
           :a1,  :int,
           :a2,  :int,
           :a3,  :int,
           :a4,  :int,
           :a5,  :int,
           :name2, [:char , 255],
           :brand, Example::Brand
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

  Example::Car.expectedValues = { 
        :color => [RangeValue.new(0,3)] ,
        :a1 => [0],
        :a2 => [1],
        :a3 => [2],
        :a4 => [3],
        :a5 => [4],
        :brand => [NotNull]
        }
end


