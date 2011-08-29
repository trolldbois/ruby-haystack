#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+ruby@gmail.com
#
# http://libarchive-rs.rubyforge.org/


require 'haystack/memory_mapping'
require 'haystack/utils'

require 'zip/zip'


#
# ./lib/metasm/metasm/os/windows.rb MEMORY_BASIC_INFORMATION has not pathname
# we need to get it from process_file_map
# metasm defines a Windows.Process
#				elsif WinAPI.ntqueryvirtualmemory(handle, info.baseaddress, WinAPI::MEMORYMAPFILENAME, path, path.length, 0) == 0
#					us = WinAPI.decode_c_struct('UNICODE_STRING', path)
#
#
#
# 			info = WinAPI.alloc_c_struct("MEMORY_BASIC_INFORMATION#{addrsz}") that seems nice...
#				list << [info.baseaddress, info.regionsize, prot, cmt]
# cmt holds the pathname
#
# modules/post/windows/gather/memory_grep is just what we need.


module Haystack

  #  ''' Dumps a process memory maps to a tgz '''
  class MemoryDumper
    include Logging
  
    def initialize
      @mappings = []
    end
        
    def addMemory(data, start, stop, pathname)
      map = LocalMemoryMapping.new(data, start, stop, 'rwx-', 0x0, 0x0, 0x0, 0x0, pathname)
      @mappings << map
      return
    end

    def addMemoryMap(map)
      @mappings << map
      return
    end
      
    def dumpMemfile( outFilename )
      # the mappings file
      index = ''
      
      Zip::ZipFile.open(outFilename, Zip::ZipFile::CREATE) {
       |zipfile|
        # add mappings
        @mappings.each do |m|
          #log.debug("Dumping #{m}")
          # dump files to tempdir
          mname = "%s-%s" % [formatAddress(m.start), formatAddress(m.stop)]
          # we are dumping the memorymap content
          #log.debug('Dumping the memorymap content')
          zipfile.get_output_stream(mname) { |f| f.puts m.readBytes(m.start, m.size) }
          # save md
          #log.debug('Dumping the memorymap metadata')
          index << "#{mname},@{pathname}\n"
        end
        # write md
        zipfile.get_output_stream("mappings") { |f| f.puts index }
      }

      return 
    end
  end

end
