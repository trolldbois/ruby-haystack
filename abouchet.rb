#!/usr/bin/ruby

require 'rubygems'
require 'nice-ffi'

require 'example'
require 'model'
require 'memory_mapping'

filename = 'example.heap'
start=0x09e26000
stop=0x09e47000
#filename = '/etc/passwd'
f=File.new(filename,'r')
puts 'file size :' 
puts f.lstat.size?

#load it in memory
memoryMap_content=Model.bytes2array( IO.read(filename) )
#data=Model.array2bytes( memoryMap , :uchar)

memoryMap = Haystack::LocalMemoryMapping.new(memoryMap_content, start, stop, 'rwx-', 0x0,0x0,0x0,0x0, '[heap]')

require 'finder'
structType = Example::Car
finder = Haystack::StructFinder.new([memoryMap])
finder.find_struct(structType, 0, 10 )















def test_mmap
  #try to map Car
  #(0..memoryMap)ptr = memoryMap
  #car = Example::Car.new( ptr , :autorelease => false)
  puts mmap
  data = mmap.readBytes(start, mmap.size)
  out=filename+'out'
  File.new(out,'w').write(data)
end

