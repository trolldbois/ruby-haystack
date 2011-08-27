#!/usr/bin/env ruby
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+ruby@gmail.com
#

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
  

=begin
    @param obj: the obj to evaluate.
    @param mappings: the memory mappings in a list.
    @param structType: the object's type, so the size could be taken in consideration.
    
    Returns False if the object address is NULL.
    Returns False if the object address is not in a mapping.
    Returns False if the object overflows the mapping.
    
    Returns the mapping in which the object stands otherwise.
=end
  def is_valid_address(obj, mappings, structType=nil)
    # check for null pointers
    addr = getaddress(obj)
    if addr == 0
      return false
    end
    return is_valid_address_value(addr, mappings, structType)
  end

=begin
    @param addr: the address to evaluate.
    @param mappings: the memory mappings in a list.
    @param structType: the object's type, so the size could be taken in consideration.
    
    Returns False if the object address is NULL.
    Returns False if the object address is not in a mapping.
    Returns False if the object overflows the mapping.
    
    Returns the mapping in which the address stands otherwise.
=end
  def is_valid_address_value(addr, mappings, structType=nil)
    for m in mappings
      if m.include?(add)
        # check if end of struct is ALSO in m
        if (not structType.nil?)
          s = structType.size
          if not m.include?(addr+s)
            return false
          end
        end
        return m
      end
    end
    return false
  end

=begin
    Costly , checks if obj is mapped to local memory space.

    Returns the memory mapping if found.
      False, otherwise.
=end
  def is_address_local(obj, structType=nil)
    addr = getaddress(obj)
    if addr == 0
      return false
    end
    process = Struct.new(:pid)
    p = process.new(os.getpid())
    mappings = readProcessMappings(p) # memory_mapping
    return is_valid_address(obj,mappings, structType)
  end

=begin
    Returns the address of the struct pointed by the obj, or null if invalid.

    @param obj: a pointer.
=end
  def getaddress(obj)
    # check for null pointers
    if bool(obj)
      if not obj.respond_to?(:contents)  ## TODO
        return 0
      end
      return obj.address
    else
      return 0  
    end
  end

=begin
    Returns the instance of typ(), in which the member "membername' is really.
    
    @param memberadd: the address of membername.
    @param typ: the type of the containing structure.
    @param membername: the membername.
    
    Stolen from linux kernel headers.
           const typeof( ((typ *)0)->member ) *__mptr = (ptr);    
          (type *)( (char *)__mptr - offsetof(type,member) );}) 
=end
  def container_of(memberaddr, typ, membername)
    return typ.new( memberaddr - offset_of(membername) )
  end

=begin
    Returns the offset of a member in a structure.
    
    @param typ: the structure type.
    @param membername: the membername in that structure.
=end
  def offsetof(typ, membername)
    return typ.offset_of(membername)
  end

  bytestr_fmt={
    'c_bool'=> '?',
    'c_char'=> 'c',
    'c_byte'=> 'b',
    'c_ubyte'=> 'B',
    'c_short'=> 'h',
    'c_ushort'=> 'H',
    'c_int'=> 'i', #c_int is c_long
    'c_uint'=> 'I',
    'int'=> 'i', 
    'c_long'=> 'l', #c_int is c_long
    'c_ulong'=> 'L',
    'long'=> 'q', 
    'c_longlong'=> 'q',
    'c_ulonglong'=> 'Q',
    'c_float'=> 'f', ## and double float ?
    'c_char_p'=> 's',
    'c_void_p'=> 'P',
    'c_void'=> 'P', ## void in array is void_p ##DEBUG
    }
=begin
#    ''' Convert an array of typ() to a byte string.'''
  def array2bytes_(array, typ)
    arrayLen = len(array)
    if arrayLen == 0
      return ''
    end
    if bytestr_fmt.include?(typ)
      log.warning('Unknown ctypes to pack: %s %s'%[typ,array])
      return nil
    end
    if typ  == 'c_void'
      return '' # void array cant be extracted
    end
    fmt=bytestr_fmt[typ]
    sb=''
    try # TODO
      for el in array:
        sb+=pack(fmt, el)
    except Exception ,e:
      log.warning('%s %s'%(fmt,el))
      #raise e
    return sb

  def array2bytes(array):
    ''' Convert an array of undetermined Basic Ctypes class to a byte string, 
    by guessing it's type from it's class name.
    
    This is a bad example of introspection.
    '''
    if not isBasicTypeArrayType(array):
      return b'NOT-AN-BasicType-ARRAY'
    # BEURK
    log.info(type(array).__name__.split('_'))
    typ='_'.join(type(array).__name__.split('_')[:2])
    return array2bytes_(array,typ)

  def bytes2array(bytes, typ):
    ''' Converts a bytestring in a ctypes array of typ() elements.'''
    typLen=ctypes.sizeof(typ)
    if len(bytes)%typLen != 0:
      raise ValueError('thoses bytes are not an array of %s'%(typ))
    arrayLen=len(bytes)/typLen
    array=(typ*arrayLen)()
    if arrayLen == 0:
      return array
    if typ.__name__ not in bytestr_fmt:
      log.warning('Unknown ctypes to pack: %s'%(typ))
      return None
    fmt=bytestr_fmt[typ.__name__]
    sb=b''
    import struct
    try:
      for i in range(0,arrayLen):
        array[i]=unpack(fmt, bytes[typLen*i:typLen*(i+1)])[0]
    except struct.error,e:
      log.error('format:%s typLen*i:typLen*(i+1) = %d:%d'%(fmt, typLen*i,typLen*(i+1)))
      raise e
    return array


  def pointer2bytes(attr,nbElement):
    ''' 
    Returns an array from a ctypes POINTER, geiven the number of elements.
    
    @param attr: the structure member.
    @param nbElement: the number of element in the array.
    '''
    # attr is a pointer and we want to read elementSize of type(attr.contents))
    if not is_address_local(attr):
      return 'POINTER NOT LOCAL'
    firstElementAddr=getaddress(attr)
    array=(type(attr.contents)*nbElement).from_address(firstElementAddr)
    # we have an array type starting at attr.contents[0]
    return array2bytes(array)

  def isCTypes(obj):
    ''' Checks if an object is a ctypes type object'''
    return  (type(obj).__module__ in ['ctypes','_ctypes']) 
      
  def isBasicType(obj):
    ''' Checks if an object is a ctypes basic type, or a python basic type.'''
    return not isPointerType(obj) and not isFunctionType(obj) and (type(obj).__module__ in ['ctypes','_ctypes','__builtin__']) 

  def isStructType(obj):
    ''' Checks if an object is a ctypes Structure.'''
    return isinstance(obj, ctypes.Structure)

  __ptrt = type(ctypes.POINTER(ctypes.c_int))
  def isPointerType(obj):
    ''' Checks if an object is a ctypes pointer.'''
    return __ptrt == type(type(obj)) or isFunctionType(obj)

  def isBasicTypeArrayType(obj):
    ''' Checks if an object is a array of basic types.
    It checks the type of the first element.
    The array should not be null :).
    '''
    if isArrayType(obj):
      if len(obj) == 0:
        return False # no len is no BasicType
      if isPointerType(obj[0]):
        return False
      if isBasicType(obj[0]):
        return True
    return False

  __arrayt = type(ctypes.c_int*1)
  def isArrayType(obj):
    ''' Checks if an object is a ctype array.'''
    return __arrayt == type(type(obj))

  __cfuncptrt = type(type(ctypes.memmove))
  def isFunctionType(obj):
    ''' Checks if an object is a function pointer.'''
    return __cfuncptrt == type(type(obj))

  def isCStringPointer(obj):
    ''' Checks if an object is our CString.'''
    return obj.__class__.__name__ == 'CString'

  def isUnionType(obj):
    ''' Checks if an object is a Union type.'''
    return isinstance(obj,ctypes.Union) and not isCStringPointer(obj)
  end

=begin
    Constraint class for the Haystack model.
    If this constraints is applied on a Structure member, 
    the member will be ignored by the validation engine.
=end
  class IgnoreMember
    def include?(obj)
      return true
    end
  end
=begin
    Constraint class for the Haystack model.
    If this constraints is applied on a Structure member, 
    the member has to be between 'low' and 'high' values to be
    considered as Valid.
=end
  class RangeValue
    def initialize(low,high)
      @low=low
      @high=high
    end
    def include?(obj)
      return ((@low <= obj) and (obj <= @high ))
    end
    def ==(obj)
      return ((@low <= obj) and (obj <= @high ))
    end
  end
=begin
    Constraint class for the Haystack model.
    If this constraints is applied on a Structure member, 
    the member should not be null to be considered valid by the validation engine.
=end
  class NotNull
    def self.include?(obj)
      return bool(obj)
    end
    def self.==(obj)
      return bool(obj)
    end
  end
=begin
  Constraint class for the Haystack model.
  If this constraints is applied on a Structure member, 
  the member should not be null to be considered valid by the validation engine.
=end





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
