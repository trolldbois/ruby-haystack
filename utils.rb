# utils.rb

module Haystack

  def Haystack.formatAddress(addr)
    "0x%08x"%addr
  end
  

  def Haystack.hasValidPermissions(memmap)
    #''' memmap must be 'rw..' or shared '...s' '''
    perms = memmap.permissions
    return ((perms[0].chr == 'r' and perms[1].chr == 'w') or (perms[3].chr == 's') )
  end


  def Haystack.bytes2array(bytes)
    #   not using  #buf = FFI::MemoryPointer.from_string(bytes) terminal \0 is added
    buf = FFI::MemoryPointer.new(FFI::TypeDefs[:uchar], bytes.size)
    (0..bytes.size-1).each do |offset|
      buf.put_uchar(offset, bytes[offset])
    end
    return buf
  end

  def Haystack.array2bytes(array, type)
    buf = String('')
    (0..array.size-1).each do |offset|
      buf << array.get_uchar(offset)
    end
    return buf
  end
  

end

module Logging
  def log
    @logger ||= Logging.logger_for(self.class.name)
  end

  # Use a hash class-ivar to cache a unique Logger per class:
  @loggers = {}

  class << self
    def logger_for(classname)
      @loggers[classname] ||= configure_logger_for(classname)
    end

    def configure_logger_for(classname)
      logger = Logger.new(STDOUT)
      logger.progname = classname
      logger
    end
    
  end

end

class Logger    
  def warning x
    warn x
  end
end
