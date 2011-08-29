#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+ruby@gmail.com
#
# http://libarchive-rs.rubyforge.org/


require 'memory_mapping'
require 'utils'

require 'zip/zip'


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
