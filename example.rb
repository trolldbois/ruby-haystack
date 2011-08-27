#!/usr/bin/env ruby
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+ruby@gmail.com
#

require 'rubygems'
require 'nice-ffi'

module Example

  class DNA < NiceFFI::Struct
    layout :id,  :int
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
           :name2, :string,
           :brand, Example::Brand
  end
  #:char_array 
end
