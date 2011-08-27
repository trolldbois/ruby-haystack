# utils.rb

module Haystack

  def Haystack.formatAddress(addr)
    "0x%08x"%addr
  end
  

  def Haystack.hasValidPermissions(memmap)
    #''' memmap must be 'rw..' or shared '...s' '''
    perms = memmap[:permissions]
    return ((perms[0].chr == 'r' and perms[1].chr == 'w') or (perms[3].chr == 's') )
  end
  
end

