#!/usr/bin/env ruby
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+ruby@gmail.com
#

require 'rubygems'
require 'nice-ffi'

require 'example'
require 'model'
require 'memory_mapping'

include Haystack


def test_utils_types(car)
  puts isBasicType(car.color) == true
  puts isBasicType(car.name2) == false
end
def test_expectedValues
  structType.expectedValues={1=>1}
  Example::Car.expectedValues={2=>2}
  puts structType.expectedValues
  puts Example::Car.expectedValues
end

def test_fields
  Example::Car.fields.each do |x,y| 
  puts "%s -> %s"% [x.inspect, y.inspect]
  end
end

def test_mmap
  #try to map Car
  #(0..memoryMap)ptr = memoryMap
  #car = Example::Car.new( ptr , :autorelease => false)
  puts mmap
  data = mmap.readBytes(start, mmap.size)
  out=filename+'out'
  File.new(out,'w').write(data)
end




filename = 'example.heap'
start=0x09e26000
stop=0x09e47000
#filename = '/etc/passwd'
f=File.new(filename,'r')
puts 'file size : %d' % f.lstat.size?

#load it in memory
memoryMap_content = bytes2array( IO.read(filename) )
#data=Model.array2bytes( memoryMap , :uchar)

memoryMap = Haystack::LocalMemoryMapping.new(memoryMap_content, start, stop, 'rwx-', 0x0,0x0,0x0,0x0, '[heap]')

#structType = Example::DNA
structType = Example::Car
car = structType.new(memoryMap.pointer) 
#test_utils_types (car)

require 'finder'
finder = Haystack::StructFinder.new([memoryMap])
res = finder.find_struct(structType, 0, 10 )

puts "found #{res.size} results"

# check for introspection
instance,offset = res[0]

puts structType.expectedValues



