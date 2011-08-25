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
memoryMap=Model.bytes2array( IO.read(filename) )
#data=Model.array2bytes( memoryMap , :uchar)

mmap = Haystack::LocalMemoryMapping.new(memoryMap, start, stop, '-rwx', 0x0,0x0,0x0,0x0, '[heap]')
puts mmap
#try to map Car
#(0..memoryMap)ptr = memoryMap
#car = Example::Car.new( ptr , :autorelease => false)

data = mmap.readBytes(start, mmap.size)
out=filename+'out'
File.new(out,'w').write(data)


