# finder.rb

require 'time'

require 'logger'
require 'utils'

log = Logger.new(STDOUT)

module Haystack
  
  class StructFinder
    #Generic structure finder.
    #Will search a structure defined by it's pointer and other constraints.
    #Address space is defined by  mappings.
    #Target memory perimeter is defined by targetMappings.
    #targetMappings is included in mappings.
    #
    #@param mappings: address space
    #@param targetMappings: search perimeter. If nil, all mappings are used in the search perimeter.
    def initialize( mappings, targetMappings=nil, updateCb=nil)
      @mappings = mappings
      @targetMappings = targetMappings
      if @targetMappings.nil?
        @targetMappings = @mappings
      end
      log.debug('StructFinder on %d memorymappings. Search Perimeter on %d mappings.'%[@mappings.size, @targetMappings.size] )
      return
    end
    
    def find_struct(structType, hintOffset=0, maxNum = 10, maxDepth=10 )
      #""" Iterate on all targetMappings to find a structure. """
      log.warning("Restricting search to %d memory mapping."%(@targetMappings.size ))
      outputs=[]
      @targetMappings.each do |m|
        ##debug, most structures are on head
        log.info("Looking at %s (%d bytes)"%[m, m.size])
        if not Haystack.hasValidPermissions(m)
          log.warning("Invalid permission for memory %s"%m)
          next
        else
          log.debug("%s,%s"%[ m,m[:permissions] ])
        end
        log.debug('look for %s'%structType)
        outputs.extend(self.find_struct_in( m, structType, hintOffset, maxNum, maxDepth))
        # check out
        if outputs.size >= maxNum
          log.debug('Found enough instance. returning results.')
          break
        end
      end
      # if we mmap, we could yield
      return outputs
    end

    #  Looks for structType instances in memory, using :
    #    hints from structType (default values, and such)
    #    guessing validation with instance(structType)().isValid()
    #    and confirming with instance(structType)().loadMembers()
    #  
    #  returns POINTERS to structType instances.
    def find_struct_in(memoryMap, structType, hintOffset=0, maxNum=10, maxDepth=99 )
      # update process mappings
      log.debug("scanning 0x%lx --> 0x%lx %s"%[memoryMap[:start],memoryMap[:stop],memoryMap[:pathname]] )

      # where do we look  
      start = memoryMap[:start]
      stop = memoryMap[:stop]
      plen = FFI::Type::POINTER.size
      structlen = structType.size
      #ret vals
      outputs=[]
      # alignement
      if memoryMap.include?(hintOffset ) # absolute offset
        align = hintOffset%plen
        start = hintOffset-align
      elsif (hintOffset != 0 and (hintOffset  < stop-start) ) # relative offset
        align = hintOffset%plen
        start = start + (hintOffset-align)
      end
      # parse for structType on each aligned word
      log.debug("checking 0x%lx-0x%lx by increment of %d"%[start, (stop-structlen), plen])
      instance=nil
      t0=Time.new
      p=0
      # xrange sucks. long int not ok
      (start..(stop-structlen) ).step(plen) do |offset|
        if (offset % (1024 << 6 )) == 0 #
          p2 = offset-start
          log.debug('processed %d bytes  - %02.02f test/sec'%[p2, (p2-p)/(plen*(Time.new-t0)) ] )
          t0 = Time.new
          p = p2
        end
        instance, validated = self.loadAt( memoryMap, offset, structType, maxDepth) 
        if validated
          log.debug( "found instance @ 0x%lx"%(offset) )
          # do stuff with it.
          outputs << [instance, offset]
        end
        if output.size >= maxNum
          log.debug('Found enough instance. returning results. find_struct_in')
          break
        end
      end
      return outputs
    end

      
    #  loads a haystack ctypes structure from a specific offset. 
    #    return (instance,validated) with instance being the haystack ctypes structure instance and validated a boolean True/False.
    def loadAt( memoryMap, offset, structType, depth=99 )
      log.debug("Loading %s from 0x%lx "%[structType,offset])
      
      instance = memoryMap.readStruct(offset,structType)
      
      # check if data matches
      if ( instance.loadMembers(@mappings, depth) )
        log.info( "found instance %s @ 0x%lx"%[structType,offset] )
        # do stuff with it.
        validated=True
      else
        log.debug("Address not validated")
        validated=False
      end
      return instance,validated
    end

  end
  
  #structure finder with a update callback to be more verbose.
  #Will search a structure defined by it's pointer and other constraints.
  #Address space is defined by  mappings.
  #Target memory perimeter is defined by targetMappings.
  #targetMappings is included in mappings.
  #
  #@param mappings: address space
  #@param targetMappings: search perimeter. If nil, all mappings are used in the search perimeter.
  #@param updateCb: callback func. for periodic status update
  class VerboseStructFinder < StructFinder
    def initialize(mappings, targetMappings=nil, &block)
      super(mappings, targetMappings)
      @updateCb = block
      self._updateCb_init()
    end
    
    def _updateCb_init()
      # approximation
      @_update_nb_steps = 0
      @targetMappings.each do |m| # get total number of words.
        @_update_nb_steps += ((m[:stop]-m[:start])/4)
      end
      @_update_i = 0
    end

    def loadAt(memoryMap, offset, structType, depth=99 )
      @_update_i += 1
      self.updateCb(@_update_i)
      super().loadAt(memoryMap, offset, structType, depth )
    end

  end

end

