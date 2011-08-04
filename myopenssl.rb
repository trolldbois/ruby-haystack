
require 'ffi'

module Myopenssl
  extend FFI::Library
  ffi_lib 'Myopenssl'

 #include <openssl/ossl_typ.h>

 #include <openssl/safestack.h>
 #include <openssl/asn1t.h>
 #include <openssl/asn1.h>

 #include <openssl/evp.h>
 #include <openssl/aes.h>
 #include <openssl/rc4.h>
 #include <openssl/blowfish.h>
 #include <openssl/des.h>
 #include <openssl/cast.h>

 #include <openssl/hmac.h>

 #include <openssl/dsa.h>
 #include <openssl/rsa.h>

// not tested
 #include <openssl/engine.h>
 #include <openssl/crypto.h>
  attach_function :CRYPTO_EX_new, [ :pointer, :pointer, :pointer, :int, :long, :pointer ], :int
  attach_function :CRYPTO_EX_free, [ :pointer, :pointer, :pointer, :int, :long, :pointer ], :void
  attach_function :CRYPTO_EX_dup, [ :pointer, :pointer, :pointer, :int, :long, :pointer ], :int
  class StackSt < FFI::Struct
    layout(
           :num, :int,
           :data, :pointer,
           :sorted, :int,
           :num_alloc, :int,
           :comp, callback([ :pointer, :pointer ], :int)
    )
    def comp=(cb)
      @comp = cb
      self[:comp] = @comp
    end
    def comp
      @comp
    end

  end
  attach_function :sk_num, [ :pointer ], :int
  attach_function :sk_value, [ :pointer, :int ], :string
  attach_function :sk_set, [ :pointer, :int, :string ], :string
  attach_function :sk_new, [ callback([ :pointer, :pointer ], :int) ], :pointer
  attach_function :sk_new_null, [  ], :pointer
  attach_function :sk_free, [ :pointer ], :void
  attach_function :sk_pop_free, [ :pointer, callback([ :pointer ], :void) ], :void
  attach_function :sk_insert, [ :pointer, :string, :int ], :int
  attach_function :sk_delete, [ :pointer, :int ], :string
  attach_function :sk_delete_ptr, [ :pointer, :string ], :string
  attach_function :sk_find, [ :pointer, :string ], :int
  attach_function :sk_find_ex, [ :pointer, :string ], :int
  attach_function :sk_push, [ :pointer, :string ], :int
  attach_function :sk_unshift, [ :pointer, :string ], :int
  attach_function :sk_shift, [ :pointer ], :string
  attach_function :sk_pop, [ :pointer ], :string
  attach_function :sk_zero, [ :pointer ], :void
  attach_function :sk_set_cmp_func, [ :pointer, callback([ :pointer, :pointer ], :int) ], :pointer
  attach_function :sk_dup, [ :pointer ], :pointer
  attach_function :sk_sort, [ :pointer ], :void
  attach_function :sk_is_sorted, [ :pointer ], :int
  NULL = 0
  _TIME_H = 1
  _FEATURES_H = 1
  __USE_ANSI = 1
  _BSD_SOURCE = 1
  _SVID_SOURCE = 1
  _POSIX_SOURCE = 1
  _POSIX_C_SOURCE = 200809
  __USE_POSIX_IMPLICITLY = 1
  __USE_POSIX = 1
  __USE_POSIX2 = 1
  __USE_POSIX199309 = 1
  __USE_POSIX199506 = 1
  __USE_XOPEN2K = 1
  __USE_ISOC95 = 1
  __USE_ISOC99 = 1
  __USE_XOPEN2K8 = 1
  _ATFILE_SOURCE = 1
  __USE_MISC = 1
  __USE_BSD = 1
  __USE_SVID = 1
  __USE_ATFILE = 1
  __USE_FORTIFY_LEVEL = 0
  __STDC_IEC_559__ = 1
  __STDC_IEC_559_COMPLEX__ = 1
  __STDC_ISO_10646__ = 200009
  __GNU_LIBRARY__ = 6
  __GLIBC__ = 2
  __GLIBC_MINOR__ = 13
  _SYS_CDEFS_H = 1
  __WORDSIZE = 32
  _BITS_TIME_H = 1
  CLOCKS_PER_SEC = 1000000l
  CLOCK_REALTIME = 0
  CLOCK_MONOTONIC = 1
  CLOCK_PROCESS_CPUTIME_ID = 2
  CLOCK_THREAD_CPUTIME_ID = 3
  CLOCK_MONOTONIC_RAW = 4
  CLOCK_REALTIME_COARSE = 5
  CLOCK_MONOTONIC_COARSE = 6
  TIMER_ABSTIME = 1
  __clock_t_defined = 1
  _BITS_TYPES_H = 1
  class quadT < FFI::Struct
    layout(
           :__val, [:long, 2]
    )
  end
  class uQuadT < FFI::Struct
    layout(
           :__val, [:ulong, 2]
    )
  end
  _BITS_TYPESIZES_H = 1
  __FD_SETSIZE = 1024
  class fsidT < FFI::Struct
    layout(
           :__val, [:int, 2]
    )
  end
  __time_t_defined = 1
  __clockid_t_defined = 1
  __timer_t_defined = 1
  __timespec_defined = 1
  class Timespec < FFI::Struct
    layout(
           :tv_sec, :long,
           :tv_nsec, :long
    )
  end
  class Tm < FFI::Struct
    layout(
           :tm_sec, :int,
           :tm_min, :int,
           :tm_hour, :int,
           :tm_mday, :int,
           :tm_mon, :int,
           :tm_year, :int,
           :tm_wday, :int,
           :tm_yday, :int,
           :tm_isdst, :int,
           :tm_gmtoff, :long,
           :tm_zone, :pointer
    )
    def tm_zone=(str)
      @tm_zone = FFI::MemoryPointer.from_string(str)
      self[:tm_zone] = @tm_zone
    end
    def tm_zone
      @tm_zone.get_string(0)
    end

  end
  class Itimerspec < FFI::Struct
    layout(
           :it_interval, Timespec,
           :it_value, Timespec
    )
  end
  attach_function :clock, [  ], :long
  attach_function :time, [ :pointer ], :long
  attach_function :difftime, [ :long, :long ], :double
  attach_function :mktime, [ :pointer ], :long
  attach_function :strftime, [ :string, :uint, :string, :pointer ], :uint
  _XLOCALE_H = 1
  class localeStruct < FFI::Struct
    layout(
           :__locales, [:pointer, 13],
           :__ctype_b, :pointer,
           :__ctype_tolower, :pointer,
           :__ctype_toupper, :pointer,
           :__names, [:string, 13]
    )
  end
  attach_function :strftime_l, [ :string, :uint, :string, :pointer, :pointer ], :uint
  attach_function :gmtime, [ :pointer ], :pointer
  attach_function :localtime, [ :pointer ], :pointer
  attach_function :gmtime_r, [ :pointer, :pointer ], :pointer
  attach_function :localtime_r, [ :pointer, :pointer ], :pointer
  attach_function :asctime, [ :pointer ], :string
  attach_function :ctime, [ :pointer ], :string
  attach_function :asctime_r, [ :pointer, :string ], :string
  attach_function :ctime_r, [ :pointer, :string ], :string
  attach_function :tzset, [  ], :void
  attach_function :stime, [ :pointer ], :int
  attach_function :timegm, [ :pointer ], :long
  attach_function :timelocal, [ :pointer ], :long
  attach_function :dysize, [ :int ], :int
  attach_function :nanosleep, [ :pointer, :pointer ], :int
  attach_function :clock_getres, [ :int, :pointer ], :int
  attach_function :clock_gettime, [ :int, :pointer ], :int
  attach_function :clock_settime, [ :int, :pointer ], :int
  attach_function :clock_nanosleep, [ :int, :int, :pointer, :pointer ], :int
  attach_function :clock_getcpuclockid, [ :int, :pointer ], :int
  attach_function :timer_create, [ :int, :pointer, :pointer ], :int
  attach_function :timer_delete, [ :pointer ], :int
  attach_function :timer_settime, [ :pointer, :int, :pointer, :pointer ], :int
  attach_function :timer_gettime, [ :pointer, :pointer ], :int
  attach_function :timer_getoverrun, [ :pointer ], :int
  _STDIO_H = 1
  __FILE_defined = 1
  ____FILE_defined = 1
  _G_config_h = 1
  __mbstate_t_defined = 1
  class mbstateTValue < FFI::Union
    layout(
           :__wch, :uint,
           :__wchb, [:char, 4]
    )
  end
# FIXME: Nested structures are not correctly supported at the moment.
# Please check the order of the declarations in the structure below.
#   class mbstateT < FFI::Struct
#     layout(
#            :__count, :int,
#            :__value, mbstateTValue
#     )
#   end
  class GFposT < FFI::Struct
    layout(
           :__pos, :long,
           :__state, mbstateT
    )
  end
  class GFpos64T < FFI::Struct
    layout(
           :__pos, quadT,
           :__state, mbstateT
    )
  end
  _G_HAVE_BOOL = 1
  _G_HAVE_ATEXIT = 1
  _G_HAVE_SYS_CDEFS = 1
  _G_HAVE_SYS_WAIT = 1
  _G_NEED_STDARG_H = 1
  _G_HAVE_PRINTF_FP = 1
  _G_HAVE_MMAP = 1
  _G_HAVE_MREMAP = 1
  _G_HAVE_LONG_DOUBLE_IO = 1
  _G_HAVE_IO_FILE_OPEN = 1
  _G_HAVE_IO_GETLINE_INFO = 1
  _G_IO_IO_FILE_VERSION = 0x20001
  _G_HAVE_ST_BLKSIZE = 0
  _G_BUFSIZ = 8192
  _G_NAMES_HAVE_UNDERSCORE = 0
  _G_VTABLE_LABEL_HAS_LENGTH = 1
  _G_USING_THUNKS = 1
  _G_VTABLE_LABEL_PREFIX = __vt_
  _IO_HAVE_SYS_WAIT = 1
  _IO_HAVE_ST_BLKSIZE = 0
  _IO_BUFSIZ = 8192
  _TR1_STDARG_H = 1
  _GLIBCXX_TR1_CSTDARG = 1
  _IO_UNIFIED_JUMPTABLES = 1
  EOF = (-1)
  _IOS_INPUT = 1
  _IOS_OUTPUT = 2
  _IOS_ATEND = 4
  _IOS_APPEND = 8
  _IOS_TRUNC = 16
  _IOS_NOCREATE = 32
  _IOS_NOREPLACE = 64
  _IOS_BIN = 128
  _IO_MAGIC = 0xFBAD0000
  _OLD_STDIO_MAGIC = 0xFABC0000
  _IO_MAGIC_MASK = 0xFFFF0000
  _IO_USER_BUF = 1
  _IO_UNBUFFERED = 2
  _IO_NO_READS = 4
  _IO_NO_WRITES = 8
  _IO_EOF_SEEN = 0x10
  _IO_ERR_SEEN = 0x20
  _IO_DELETE_DONT_CLOSE = 0x40
  _IO_LINKED = 0x80
  _IO_IN_BACKUP = 0x100
  _IO_LINE_BUF = 0x200
  _IO_TIED_PUT_GET = 0x400
  _IO_CURRENTLY_PUTTING = 0x800
  _IO_IS_APPENDING = 0x1000
  _IO_IS_FILEBUF = 0x2000
  _IO_BAD_SEEN = 0x4000
  _IO_USER_LOCK = 0x8000
  _IO_FLAGS2_MMAP = 1
  _IO_FLAGS2_NOTCANCEL = 2
  _IO_FLAGS2_USER_WBUF = 8
  _IO_SKIPWS = 01
  _IO_LEFT = 02
  _IO_RIGHT = 04
  _IO_INTERNAL = 010
  _IO_DEC = 020
  _IO_OCT = 040
  _IO_HEX = 0100
  _IO_SHOWBASE = 0200
  _IO_SHOWPOINT = 0400
  _IO_UPPERCASE = 01000
  _IO_SHOWPOS = 02000
  _IO_SCIENTIFIC = 04000
  _IO_FIXED = 010000
  _IO_UNITBUF = 020000
  _IO_STDIO = 040000
  _IO_DONT_CLOSE = 0100000
  _IO_BOOLALPHA = 0200000
  class IOMarker < FFI::Struct
    layout(
           :_next, :pointer,
           :_sbuf, :pointer,
           :_pos, :int
    )
  end
  __codecvt_ok = 0
  __codecvt_partial = 1
  __codecvt_error = 2
  __codecvt_noconv = 3

  class IOFILE < FFI::Struct
    layout(
           :_flags, :int,
           :_IO_read_ptr, :pointer,
           :_IO_read_end, :pointer,
           :_IO_read_base, :pointer,
           :_IO_write_base, :pointer,
           :_IO_write_ptr, :pointer,
           :_IO_write_end, :pointer,
           :_IO_buf_base, :pointer,
           :_IO_buf_end, :pointer,
           :_IO_save_base, :pointer,
           :_IO_backup_base, :pointer,
           :_IO_save_end, :pointer,
           :_markers, :pointer,
           :_chain, :pointer,
           :_fileno, :int,
           :_flags2, :int,
           :_old_offset, :long,
           :_cur_column, :ushort,
           :_vtable_offset, :char,
           :_shortbuf, [:char, 1],
           :_lock, :pointer,
           :_offset, quadT,
           :__pad1, :pointer,
           :__pad2, :pointer,
           :__pad3, :pointer,
           :__pad4, :pointer,
           :__pad5, :uint,
           :_mode, :int,
           :_unused2, a(15*sizeof(int)-4*sizeof(void *)-sizeof(size_t)).char
    )
    def _IO_read_ptr=(str)
      @_IO_read_ptr = FFI::MemoryPointer.from_string(str)
      self[:_IO_read_ptr] = @_IO_read_ptr
    end
    def _IO_read_ptr
      @_IO_read_ptr.get_string(0)
    end
    def _IO_read_end=(str)
      @_IO_read_end = FFI::MemoryPointer.from_string(str)
      self[:_IO_read_end] = @_IO_read_end
    end
    def _IO_read_end
      @_IO_read_end.get_string(0)
    end
    def _IO_read_base=(str)
      @_IO_read_base = FFI::MemoryPointer.from_string(str)
      self[:_IO_read_base] = @_IO_read_base
    end
    def _IO_read_base
      @_IO_read_base.get_string(0)
    end
    def _IO_write_base=(str)
      @_IO_write_base = FFI::MemoryPointer.from_string(str)
      self[:_IO_write_base] = @_IO_write_base
    end
    def _IO_write_base
      @_IO_write_base.get_string(0)
    end
    def _IO_write_ptr=(str)
      @_IO_write_ptr = FFI::MemoryPointer.from_string(str)
      self[:_IO_write_ptr] = @_IO_write_ptr
    end
    def _IO_write_ptr
      @_IO_write_ptr.get_string(0)
    end
    def _IO_write_end=(str)
      @_IO_write_end = FFI::MemoryPointer.from_string(str)
      self[:_IO_write_end] = @_IO_write_end
    end
    def _IO_write_end
      @_IO_write_end.get_string(0)
    end
    def _IO_buf_base=(str)
      @_IO_buf_base = FFI::MemoryPointer.from_string(str)
      self[:_IO_buf_base] = @_IO_buf_base
    end
    def _IO_buf_base
      @_IO_buf_base.get_string(0)
    end
    def _IO_buf_end=(str)
      @_IO_buf_end = FFI::MemoryPointer.from_string(str)
      self[:_IO_buf_end] = @_IO_buf_end
    end
    def _IO_buf_end
      @_IO_buf_end.get_string(0)
    end
    def _IO_save_base=(str)
      @_IO_save_base = FFI::MemoryPointer.from_string(str)
      self[:_IO_save_base] = @_IO_save_base
    end
    def _IO_save_base
      @_IO_save_base.get_string(0)
    end
    def _IO_backup_base=(str)
      @_IO_backup_base = FFI::MemoryPointer.from_string(str)
      self[:_IO_backup_base] = @_IO_backup_base
    end
    def _IO_backup_base
      @_IO_backup_base.get_string(0)
    end
    def _IO_save_end=(str)
      @_IO_save_end = FFI::MemoryPointer.from_string(str)
      self[:_IO_save_end] = @_IO_save_end
    end
    def _IO_save_end
      @_IO_save_end.get_string(0)
    end

  end
  attach_function :__io_read_fn, [ :pointer, :string, :uint ], :int
  attach_function :__io_write_fn, [ :pointer, :string, :uint ], :int
  attach_function :__io_seek_fn, [ :pointer, :pointer, :int ], :int
  attach_function :__io_close_fn, [ :pointer ], :int
  attach_function :__underflow, [ :pointer ], :int
  attach_function :__uflow, [ :pointer ], :int
  attach_function :__overflow, [ :pointer, :int ], :int
  attach_function :_IO_getc, [ :pointer ], :int
  attach_function :_IO_putc, [ :int, :pointer ], :int
  attach_function :_IO_feof, [ :pointer ], :int
  attach_function :_IO_ferror, [ :pointer ], :int
  attach_function :_IO_peekc_locked, [ :pointer ], :int
  attach_function :_IO_flockfile, [ :pointer ], :void
  attach_function :_IO_funlockfile, [ :pointer ], :void
  attach_function :_IO_ftrylockfile, [ :pointer ], :int
  attach_function :_IO_vfscanf, [ :pointer, :string, __gnuc_va_list, :pointer ], :int
  attach_function :_IO_vfprintf, [ :pointer, :string, __gnuc_va_list ], :int
  attach_function :_IO_padn, [ :pointer, :int, :int ], :int
  attach_function :_IO_sgetn, [ :pointer, :pointer, :uint ], :uint
  attach_function :_IO_seekoff, [ :pointer, quadT, :int, :int ], quadT
  attach_function :_IO_seekpos, [ :pointer, quadT, :int ], quadT
  attach_function :_IO_free_backup_area, [ :pointer ], :void
  _IOFBF = 0
  _IOLBF = 1
  _IONBF = 2
  BUFSIZ = 8192
  SEEK_SET = 0
  SEEK_CUR = 1
  SEEK_END = 2
  P_tmpdir = /tmp
  L_tmpnam = 20
  TMP_MAX = 238328
  FILENAME_MAX = 4096
  L_ctermid = 9
  FOPEN_MAX = 16
  attach_function :remove, [ :string ], :int
  attach_function :rename, [ :string, :string ], :int
  attach_function :renameat, [ :int, :string, :int, :string ], :int
  attach_function :tmpfile, [  ], :pointer
  attach_function :tmpnam, [ :string ], :string
  attach_function :tmpnam_r, [ :string ], :string
  attach_function :tempnam, [ :string, :string ], :string
  attach_function :fclose, [ :pointer ], :int
  attach_function :fflush, [ :pointer ], :int
  attach_function :fflush_unlocked, [ :pointer ], :int
  attach_function :fopen, [ :string, :string ], :pointer
  attach_function :freopen, [ :string, :string, :pointer ], :pointer
  attach_function :fdopen, [ :int, :string ], :pointer
  attach_function :fmemopen, [ :pointer, :uint, :string ], :pointer
  attach_function :open_memstream, [ :pointer, :pointer ], :pointer
  attach_function :setbuf, [ :pointer, :string ], :void
  attach_function :setvbuf, [ :pointer, :string, :int, :uint ], :int
  attach_function :setbuffer, [ :pointer, :string, :uint ], :void
  attach_function :setlinebuf, [ :pointer ], :void
  attach_function :fprintf, [ :pointer, :string, :varargs ], :int
  attach_function :printf, [ :string, :varargs ], :int
  attach_function :sprintf, [ :string, :string, :varargs ], :int
  attach_function :vfprintf, [ :pointer, :string, __gnuc_va_list ], :int
  attach_function :vprintf, [ :string, __gnuc_va_list ], :int
  attach_function :vsprintf, [ :string, :string, __gnuc_va_list ], :int
  attach_function :snprintf, [ :string, :uint, :string, :varargs ], :int
  attach_function :vsnprintf, [ :string, :uint, :string, __gnuc_va_list ], :int
  attach_function :vdprintf, [ :int, :string, __gnuc_va_list ], :int
  attach_function :dprintf, [ :int, :string, :varargs ], :int
  attach_function :fscanf, [ :pointer, :string, :varargs ], :int
  attach_function :scanf, [ :string, :varargs ], :int
  attach_function :sscanf, [ :string, :string, :varargs ], :int
  attach_function :__isoc99_fscanf, [ :pointer, :string, :varargs ], :int
  attach_function :__isoc99_scanf, [ :string, :varargs ], :int
  attach_function :__isoc99_sscanf, [ :string, :string, :varargs ], :int
  attach_function :vfscanf, [ :pointer, :string, __gnuc_va_list ], :int
  attach_function :vscanf, [ :string, __gnuc_va_list ], :int
  attach_function :vsscanf, [ :string, :string, __gnuc_va_list ], :int
  attach_function :__isoc99_vfscanf, [ :pointer, :string, __gnuc_va_list ], :int
  attach_function :__isoc99_vscanf, [ :string, __gnuc_va_list ], :int
  attach_function :__isoc99_vsscanf, [ :string, :string, __gnuc_va_list ], :int
  attach_function :fgetc, [ :pointer ], :int
  attach_function :getc, [ :pointer ], :int
  attach_function :getchar, [  ], :int
  attach_function :getc_unlocked, [ :pointer ], :int
  attach_function :getchar_unlocked, [  ], :int
  attach_function :fgetc_unlocked, [ :pointer ], :int
  attach_function :fputc, [ :int, :pointer ], :int
  attach_function :putc, [ :int, :pointer ], :int
  attach_function :putchar, [ :int ], :int
  attach_function :fputc_unlocked, [ :int, :pointer ], :int
  attach_function :putc_unlocked, [ :int, :pointer ], :int
  attach_function :putchar_unlocked, [ :int ], :int
  attach_function :getw, [ :pointer ], :int
  attach_function :putw, [ :int, :pointer ], :int
  attach_function :fgets, [ :string, :int, :pointer ], :string
  attach_function :gets, [ :string ], :string
  attach_function :__getdelim, [ :pointer, :pointer, :int, :pointer ], :int
  attach_function :getdelim, [ :pointer, :pointer, :int, :pointer ], :int
  attach_function :getline, [ :pointer, :pointer, :pointer ], :int
  attach_function :fputs, [ :string, :pointer ], :int
  attach_function :puts, [ :string ], :int
  attach_function :ungetc, [ :int, :pointer ], :int
  attach_function :fread, [ :pointer, :uint, :uint, :pointer ], :uint
  attach_function :fwrite, [ :pointer, :uint, :uint, :pointer ], :uint
  attach_function :fread_unlocked, [ :pointer, :uint, :uint, :pointer ], :uint
  attach_function :fwrite_unlocked, [ :pointer, :uint, :uint, :pointer ], :uint
  attach_function :fseek, [ :pointer, :long, :int ], :int
  attach_function :ftell, [ :pointer ], :long
  attach_function :rewind, [ :pointer ], :void
  attach_function :fseeko, [ :pointer, :long, :int ], :int
  attach_function :ftello, [ :pointer ], :long
  attach_function :fgetpos, [ :pointer, :pointer ], :int
  attach_function :fsetpos, [ :pointer, :pointer ], :int
  attach_function :clearerr, [ :pointer ], :void
  attach_function :feof, [ :pointer ], :int
  attach_function :ferror, [ :pointer ], :int
  attach_function :clearerr_unlocked, [ :pointer ], :void
  attach_function :feof_unlocked, [ :pointer ], :int
  attach_function :ferror_unlocked, [ :pointer ], :int
  attach_function :perror, [ :string ], :void
  attach_function :fileno, [ :pointer ], :int
  attach_function :fileno_unlocked, [ :pointer ], :int
  attach_function :popen, [ :string, :string ], :pointer
  attach_function :pclose, [ :pointer ], :int
  attach_function :ctermid, [ :string ], :string
  attach_function :flockfile, [ :pointer ], :void
  attach_function :ftrylockfile, [ :pointer ], :int
  attach_function :funlockfile, [ :pointer ], :void
  _STDLIB_H = 1
  WNOHANG = 1
  WUNTRACED = 2
  WSTOPPED = 2
  WEXITED = 4
  WCONTINUED = 8
  WNOWAIT = 0x01000000
  __WNOTHREAD = 0x20000000
  __WALL = 0x40000000
  __WCLONE = 0x80000000
  __W_CONTINUED = 0xffff
  __WCOREFLAG = 0x80
  _ENDIAN_H = 1
  __LITTLE_ENDIAN = 1234
  __BIG_ENDIAN = 4321
  __PDP_ENDIAN = 3412
  __BYTE_ORDER = 1234
  __FLOAT_WORD_ORDER = 1234
  LITTLE_ENDIAN = 1234
  BIG_ENDIAN = 4321
  PDP_ENDIAN = 3412
  BYTE_ORDER = 1234
  _BITS_BYTESWAP_H = 1
  class WaitWaitTerminated < FFI::Struct
    layout(
           :__w_termsig, :uint,
           :__w_coredump, :uint,
           :__w_retcode, :uint
    )
  end
  class WaitWaitStopped < FFI::Struct
    layout(
           :__w_stopval, :uint,
           :__w_stopsig, :uint
    )
  end
# FIXME: Nested structures are not correctly supported at the moment.
# Please check the order of the declarations in the structure below.
#   class Wait < FFI::Union
#     layout(
#            :w_status, :int,
#            :__wait_stopped, WaitWaitStopped,
#            :__wait_terminated, WaitWaitTerminated
#     )
#   end
  class DivT < FFI::Struct
    layout(
           :quot, :int,
           :rem, :int
    )
  end
  class LdivT < FFI::Struct
    layout(
           :quot, :long,
           :rem, :long
    )
  end
  __ldiv_t_defined = 1
  class LldivT < FFI::Struct
    layout(
           :quot, :long_long,
           :rem, :long_long
    )
  end
  __lldiv_t_defined = 1
  RAND_MAX = 2147483647
  EXIT_FAILURE = 1
  EXIT_SUCCESS = 0
  attach_function :__ctype_get_mb_cur_max, [  ], :uint
  attach_function :atof, [ :string ], :double
  attach_function :atoi, [ :string ], :int
  attach_function :atol, [ :string ], :long
  attach_function :atoll, [ :string ], :long_long
  attach_function :strtod, [ :string, :pointer ], :double
  attach_function :strtof, [ :string, :pointer ], :float
  attach_function :strtold, [ :string, :pointer ], long double
  attach_function :strtol, [ :string, :pointer, :int ], :long
  attach_function :strtoul, [ :string, :pointer, :int ], :ulong
  attach_function :strtoll, [ :string, :pointer, :int ], :long_long
  attach_function :strtoull, [ :string, :pointer, :int ], :ulong_long
  attach_function :l64a, [ :long ], :string
  attach_function :a64l, [ :string ], :long
  _SYS_TYPES_H = 1
  __BIT_TYPES_DEFINED__ = 1
  _SYS_SELECT_H = 1
  _SIGSET_H_types = 1
  class sigsetT < FFI::Struct
    layout(
           :__val, a((1024/(8*sizeof(unsigned long)))).unsigned long
    )
  end
  class FdSet < FFI::Struct
    layout(
           :__fds_bits, a(1024/(8*(int) sizeof(__fd_mask))).__fd_mask
    )
  end
  FD_SETSIZE = 1024
  attach_function :select, [ :int, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :pselect, [ :int, :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  _SYS_SYSMACROS_H = 1
  _BITS_PTHREADTYPES_H = 1
  __SIZEOF_PTHREAD_ATTR_T = 36
  __SIZEOF_PTHREAD_MUTEX_T = 24
  __SIZEOF_PTHREAD_MUTEXATTR_T = 4
  __SIZEOF_PTHREAD_COND_T = 48
  __SIZEOF_PTHREAD_CONDATTR_T = 4
  __SIZEOF_PTHREAD_RWLOCK_T = 32
  __SIZEOF_PTHREAD_RWLOCKATTR_T = 8
  __SIZEOF_PTHREAD_BARRIER_T = 20
  __SIZEOF_PTHREAD_BARRIERATTR_T = 4
  class PthreadAttrT < FFI::Union
    layout(
           :__size, [:char, 36],
           :__align, :long
    )
  end
  class pthreadInternalSlist < FFI::Struct
    layout(
           :__next, :pointer
    )
  end
  class PthreadMutexTData < FFI::Struct
    layout(
           :__lock, :int,
           :__count, :uint,
           :__owner, :int,
           :__kind, :int,
           :__nusers, :uint
    )
  end
# FIXME: Nested structures are not correctly supported at the moment.
# Please check the order of the declarations in the structure below.
#   class PthreadMutexT < FFI::Union
#     layout(
#            :__size, [:char, 24],
#            :__align, :long,
#            :__data, PthreadMutexTData
#     )
#   end
  class PthreadMutexattrT < FFI::Union
    layout(
           :__size, [:char, 4],
           :__align, :int
    )
  end
  class PthreadCondTData < FFI::Struct
    layout(
           :__lock, :int,
           :__futex, :uint,
           :__total_seq, :ulong_long,
           :__wakeup_seq, :ulong_long,
           :__woken_seq, :ulong_long,
           :__mutex, :pointer,
           :__nwaiters, :uint,
           :__broadcast_seq, :uint
    )
  end
# FIXME: Nested structures are not correctly supported at the moment.
# Please check the order of the declarations in the structure below.
#   class PthreadCondT < FFI::Union
#     layout(
#            :__size, [:char, 48],
#            :__align, :long_long,
#            :__data, PthreadCondTData
#     )
#   end
  class PthreadCondattrT < FFI::Union
    layout(
           :__size, [:char, 4],
           :__align, :int
    )
  end
  class PthreadRwlockTData < FFI::Struct
    layout(
           :__lock, :int,
           :__nr_readers, :uint,
           :__readers_wakeup, :uint,
           :__writer_wakeup, :uint,
           :__nr_readers_queued, :uint,
           :__nr_writers_queued, :uint,
           :__flags, :uchar,
           :__shared, :uchar,
           :__pad1, :uchar,
           :__pad2, :uchar,
           :__writer, :int
    )
  end
# FIXME: Nested structures are not correctly supported at the moment.
# Please check the order of the declarations in the structure below.
#   class PthreadRwlockT < FFI::Union
#     layout(
#            :__size, [:char, 32],
#            :__align, :long,
#            :__data, PthreadRwlockTData
#     )
#   end
  class PthreadRwlockattrT < FFI::Union
    layout(
           :__size, [:char, 8],
           :__align, :long
    )
  end
  class PthreadBarrierT < FFI::Union
    layout(
           :__size, [:char, 20],
           :__align, :long
    )
  end
  class PthreadBarrierattrT < FFI::Union
    layout(
           :__size, [:char, 4],
           :__align, :int
    )
  end
  attach_function :random, [  ], :long
  attach_function :srandom, [ :uint ], :void
  attach_function :initstate, [ :uint, :string, :uint ], :string
  attach_function :setstate, [ :string ], :string
  class RandomData < FFI::Struct
    layout(
           :fptr, :pointer,
           :rptr, :pointer,
           :state, :pointer,
           :rand_type, :int,
           :rand_deg, :int,
           :rand_sep, :int,
           :end_ptr, :pointer
    )
  end
  attach_function :random_r, [ :pointer, :pointer ], :int
  attach_function :srandom_r, [ :uint, :pointer ], :int
  attach_function :initstate_r, [ :uint, :string, :uint, :pointer ], :int
  attach_function :setstate_r, [ :string, :pointer ], :int
  attach_function :rand, [  ], :int
  attach_function :srand, [ :uint ], :void
  attach_function :rand_r, [ :pointer ], :int
  attach_function :drand48, [  ], :double
  attach_function :erand48, [ [:ushort, 3] ], :double
  attach_function :lrand48, [  ], :long
  attach_function :nrand48, [ [:ushort, 3] ], :long
  attach_function :mrand48, [  ], :long
  attach_function :jrand48, [ [:ushort, 3] ], :long
  attach_function :srand48, [ :long ], :void
  attach_function :seed48, [ [:ushort, 3] ], :pointer
  attach_function :lcong48, [ [:ushort, 7] ], :void
  class Drand48Data < FFI::Struct
    layout(
           :__x, [:ushort, 3],
           :__old_x, [:ushort, 3],
           :__c, :ushort,
           :__init, :ushort,
           :__a, :ulong_long
    )
  end
  attach_function :drand48_r, [ :pointer, :pointer ], :int
  attach_function :erand48_r, [ [:ushort, 3], :pointer, :pointer ], :int
  attach_function :lrand48_r, [ :pointer, :pointer ], :int
  attach_function :nrand48_r, [ [:ushort, 3], :pointer, :pointer ], :int
  attach_function :mrand48_r, [ :pointer, :pointer ], :int
  attach_function :jrand48_r, [ [:ushort, 3], :pointer, :pointer ], :int
  attach_function :srand48_r, [ :long, :pointer ], :int
  attach_function :seed48_r, [ [:ushort, 3], :pointer ], :int
  attach_function :lcong48_r, [ [:ushort, 7], :pointer ], :int
  attach_function :malloc, [ :uint ], :pointer
  attach_function :calloc, [ :uint, :uint ], :pointer
  attach_function :realloc, [ :pointer, :uint ], :pointer
  attach_function :free, [ :pointer ], :void
  attach_function :cfree, [ :pointer ], :void
  _ALLOCA_H = 1
  attach_function :alloca, [ :uint ], :pointer
  attach_function :valloc, [ :uint ], :pointer
  attach_function :posix_memalign, [ :pointer, :uint, :uint ], :int
  attach_function :abort, [  ], :void
  attach_function :atexit, [ callback([  ], :void) ], :int
  attach_function :on_exit, [ callback([ :int, :pointer ], :void), :pointer ], :int
  attach_function :exit, [ :int ], :void
  attach_function :_Exit, [ :int ], :void
  attach_function :getenv, [ :string ], :string
  attach_function :__secure_getenv, [ :string ], :string
  attach_function :putenv, [ :string ], :int
  attach_function :setenv, [ :string, :string, :int ], :int
  attach_function :unsetenv, [ :string ], :int
  attach_function :clearenv, [  ], :int
  attach_function :mktemp, [ :string ], :string
  attach_function :mkstemp, [ :string ], :int
  attach_function :mkstemps, [ :string, :int ], :int
  attach_function :mkdtemp, [ :string ], :string
  attach_function :system, [ :string ], :int
  attach_function :realpath, [ :string, :string ], :string
  callback(:__compar_fn_t, [ :pointer, :pointer ], :int)
  attach_function :bsearch, [ :pointer, :pointer, :uint, :uint, :__compar_fn_t ], :pointer
  attach_function :qsort, [ :pointer, :uint, :uint, :__compar_fn_t ], :void
  attach_function :abs, [ :int ], :int
  attach_function :labs, [ :long ], :long
  attach_function :llabs, [ :long_long ], :long_long
  attach_function :div, [ :int, :int ], DivT
  attach_function :ldiv, [ :long, :long ], LdivT
  attach_function :lldiv, [ :long_long, :long_long ], LldivT
  attach_function :ecvt, [ :double, :int, :pointer, :pointer ], :string
  attach_function :fcvt, [ :double, :int, :pointer, :pointer ], :string
  attach_function :gcvt, [ :double, :int, :string ], :string
  attach_function :qecvt, [ long double, :int, :pointer, :pointer ], :string
  attach_function :qfcvt, [ long double, :int, :pointer, :pointer ], :string
  attach_function :qgcvt, [ long double, :int, :string ], :string
  attach_function :ecvt_r, [ :double, :int, :pointer, :pointer, :string, :uint ], :int
  attach_function :fcvt_r, [ :double, :int, :pointer, :pointer, :string, :uint ], :int
  attach_function :qecvt_r, [ long double, :int, :pointer, :pointer, :string, :uint ], :int
  attach_function :qfcvt_r, [ long double, :int, :pointer, :pointer, :string, :uint ], :int
  attach_function :mblen, [ :string, :uint ], :int
  attach_function :mbtowc, [ :pointer, :string, :uint ], :int
  attach_function :wctomb, [ :string, wchar_t ], :int
  attach_function :mbstowcs, [ :pointer, :string, :uint ], :uint
  attach_function :wcstombs, [ :string, :pointer, :uint ], :uint
  attach_function :rpmatch, [ :string ], :int
  attach_function :getsubopt, [ :pointer, :pointer, :pointer ], :pointer
  attach_function :getloadavg, [ a().double, :int ], :int
  OPENSSL_VERSION_NUMBER = 0x009080ffL
  OPENSSL_VERSION_TEXT = OpenSSL 0.9.8o 01 Jun 2010
  OPENSSL_VERSION_PTEXT =  part of OpenSSL 0.9.8o 01 Jun 2010
  SHLIB_VERSION_HISTORY = 
  SHLIB_VERSION_NUMBER = 0.9.8
  SSLEAY_VERSION_NUMBER = 0x009080ffL
  SSLEAY_VERSION = 0
  SSLEAY_CFLAGS = 2
  SSLEAY_BUILT_ON = 3
  SSLEAY_PLATFORM = 4
  SSLEAY_DIR = 5
  class OpensslItemSt < FFI::Struct
    layout(
           :code, :int,
           :value, :pointer,
           :value_size, :uint,
           :value_length, :pointer
    )
  end
  CRYPTO_LOCK_ERR = 1
  CRYPTO_LOCK_EX_DATA = 2
  CRYPTO_LOCK_X509 = 3
  CRYPTO_LOCK_X509_INFO = 4
  CRYPTO_LOCK_X509_PKEY = 5
  CRYPTO_LOCK_X509_CRL = 6
  CRYPTO_LOCK_X509_REQ = 7
  CRYPTO_LOCK_DSA = 8
  CRYPTO_LOCK_RSA = 9
  CRYPTO_LOCK_EVP_PKEY = 10
  CRYPTO_LOCK_X509_STORE = 11
  CRYPTO_LOCK_SSL_CTX = 12
  CRYPTO_LOCK_SSL_CERT = 13
  CRYPTO_LOCK_SSL_SESSION = 14
  CRYPTO_LOCK_SSL_SESS_CERT = 15
  CRYPTO_LOCK_SSL = 16
  CRYPTO_LOCK_SSL_METHOD = 17
  CRYPTO_LOCK_RAND = 18
  CRYPTO_LOCK_RAND2 = 19
  CRYPTO_LOCK_MALLOC = 20
  CRYPTO_LOCK_BIO = 21
  CRYPTO_LOCK_GETHOSTBYNAME = 22
  CRYPTO_LOCK_GETSERVBYNAME = 23
  CRYPTO_LOCK_READDIR = 24
  CRYPTO_LOCK_RSA_BLINDING = 25
  CRYPTO_LOCK_DH = 26
  CRYPTO_LOCK_MALLOC2 = 27
  CRYPTO_LOCK_DSO = 28
  CRYPTO_LOCK_DYNLOCK = 29
  CRYPTO_LOCK_ENGINE = 30
  CRYPTO_LOCK_UI = 31
  CRYPTO_LOCK_ECDSA = 32
  CRYPTO_LOCK_EC = 33
  CRYPTO_LOCK_ECDH = 34
  CRYPTO_LOCK_BN = 35
  CRYPTO_LOCK_EC_PRE_COMP = 36
  CRYPTO_LOCK_STORE = 37
  CRYPTO_LOCK_COMP = 38
  CRYPTO_NUM_LOCKS = 39
  CRYPTO_LOCK = 1
  CRYPTO_UNLOCK = 2
  CRYPTO_READ = 4
  CRYPTO_WRITE = 8
  class CRYPTODynlock < FFI::Struct
    layout(
           :references, :int,
           :data, :pointer
    )
  end
  CRYPTO_MEM_CHECK_OFF = 0x0
  CRYPTO_MEM_CHECK_ON = 0x1
  CRYPTO_MEM_CHECK_ENABLE = 0x2
  CRYPTO_MEM_CHECK_DISABLE = 0x3
  V_CRYPTO_MDEBUG_TIME = 0x1
  V_CRYPTO_MDEBUG_THREAD = 0x2
  V_CRYPTO_MDEBUG_ALL = (0x1|0x2)
  class CryptoExDataSt < FFI::Struct
    layout(
           :sk, :pointer,
           :dummy, :int
    )
  end
  class CryptoExDataFuncSt < FFI::Struct
    layout(
           :argl, :long,
           :argp, :pointer,
           :new_func, :pointer,
           :free_func, :pointer,
           :dup_func, :pointer
    )
  end
  CRYPTO_EX_INDEX_BIO = 0
  CRYPTO_EX_INDEX_SSL = 1
  CRYPTO_EX_INDEX_SSL_CTX = 2
  CRYPTO_EX_INDEX_SSL_SESSION = 3
  CRYPTO_EX_INDEX_X509_STORE = 4
  CRYPTO_EX_INDEX_X509_STORE_CTX = 5
  CRYPTO_EX_INDEX_RSA = 6
  CRYPTO_EX_INDEX_DSA = 7
  CRYPTO_EX_INDEX_DH = 8
  CRYPTO_EX_INDEX_ENGINE = 9
  CRYPTO_EX_INDEX_X509 = 10
  CRYPTO_EX_INDEX_UI = 11
  CRYPTO_EX_INDEX_ECDSA = 12
  CRYPTO_EX_INDEX_ECDH = 13
  CRYPTO_EX_INDEX_COMP = 14
  CRYPTO_EX_INDEX_STORE = 15
  CRYPTO_EX_INDEX_USER = 100
  attach_function :CRYPTO_malloc_debug_init, [  ], :void
  attach_function :CRYPTO_mem_ctrl, [ :int ], :int
  attach_function :CRYPTO_is_mem_check_on, [  ], :int
  attach_function :SSLeay_version, [ :int ], :string
  attach_function :SSLeay, [  ], :ulong
  attach_function :OPENSSL_issetugid, [  ], :int
  attach_function :CRYPTO_get_ex_data_implementation, [  ], :pointer
  attach_function :CRYPTO_set_ex_data_implementation, [ :pointer ], :int
  attach_function :CRYPTO_ex_data_new_class, [  ], :int
  attach_function :CRYPTO_get_ex_new_index, [ :int, :long, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :CRYPTO_new_ex_data, [ :int, :pointer, :pointer ], :int
  attach_function :CRYPTO_dup_ex_data, [ :int, :pointer, :pointer ], :int
  attach_function :CRYPTO_free_ex_data, [ :int, :pointer, :pointer ], :void
  attach_function :CRYPTO_set_ex_data, [ :pointer, :int, :pointer ], :int
  attach_function :CRYPTO_get_ex_data, [ :pointer, :int ], :pointer
  attach_function :CRYPTO_cleanup_all_ex_data, [  ], :void
  attach_function :CRYPTO_get_new_lockid, [ :string ], :int
  attach_function :CRYPTO_num_locks, [  ], :int
  attach_function :CRYPTO_lock, [ :int, :int, :string, :int ], :void
  attach_function :CRYPTO_set_locking_callback, [ callback([ :int, :int, :string, :int ], :void) ], :void
  attach_function :CRYPTO_get_locking_callback, [  ], :pointer
  attach_function :CRYPTO_set_add_lock_callback, [ callback([ :pointer, :int, :int, :string, :int ], :int) ], :void
  attach_function :CRYPTO_get_add_lock_callback, [  ], :pointer
  attach_function :CRYPTO_set_id_callback, [ callback([  ], :ulong) ], :void
  attach_function :CRYPTO_get_id_callback, [  ], :pointer
  attach_function :CRYPTO_thread_id, [  ], :ulong
  attach_function :CRYPTO_get_lock_name, [ :int ], :string
  attach_function :CRYPTO_add_lock, [ :pointer, :int, :int, :string, :int ], :int
  attach_function :int_CRYPTO_set_do_dynlock_callback, [ callback([ :int, :int, :string, :int ], :void) ], :void
  attach_function :CRYPTO_get_new_dynlockid, [  ], :int
  attach_function :CRYPTO_destroy_dynlockid, [ :int ], :void
  attach_function :CRYPTO_get_dynlock_value, [ :int ], :pointer
  attach_function :CRYPTO_set_dynlock_create_callback, [ callback([ :string, :int ], :pointer) ], :pointer
  attach_function :CRYPTO_set_dynlock_lock_callback, [ callback([ :int, :pointer, :string, :int ], :void) ], :void
  attach_function :CRYPTO_set_dynlock_destroy_callback, [ callback([ :pointer, :string, :int ], :void) ], :void
  attach_function :CRYPTO_get_dynlock_create_callback, [  ], :pointer
  attach_function :CRYPTO_get_dynlock_lock_callback, [  ], :pointer
  attach_function :CRYPTO_get_dynlock_destroy_callback, [  ], :pointer
  attach_function :CRYPTO_set_mem_functions, [ callback([ :uint ], :pointer), callback([ :pointer, :uint ], :pointer), callback([ :pointer ], :void) ], :pointer
  attach_function :CRYPTO_set_locked_mem_functions, [ callback([ :uint ], :pointer), callback([ :pointer ], :void) ], :pointer
  attach_function :CRYPTO_set_mem_ex_functions, [ callback([ :uint, :string, :int ], :pointer), callback([ :pointer, :uint, :string, :int ], :pointer), callback([ :pointer ], :void) ], :pointer
  attach_function :CRYPTO_set_locked_mem_ex_functions, [ callback([ :uint, :string, :int ], :pointer), callback([ :pointer ], :void) ], :pointer
  attach_function :CRYPTO_set_mem_debug_functions, [ callback([ :pointer, :int, :string, :int, :int ], :void), callback([ :pointer, :pointer, :int, :string, :int, :int ], :void), callback([ :pointer, :int ], :void), callback([ :long ], :void), callback([  ], :long) ], :int
  attach_function :CRYPTO_set_mem_info_functions, [ callback([ :string, :string, :int ], :int), callback([  ], :int), callback([  ], :int) ], :void
  attach_function :CRYPTO_get_mem_functions, [ :pointer, :pointer, :pointer ], :pointer
  attach_function :CRYPTO_get_locked_mem_functions, [ :pointer, :pointer ], :pointer
  attach_function :CRYPTO_get_mem_ex_functions, [ :pointer, :pointer, :pointer ], :pointer
  attach_function :CRYPTO_get_locked_mem_ex_functions, [ :pointer, :pointer ], :pointer
  attach_function :CRYPTO_get_mem_debug_functions, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :void
  attach_function :CRYPTO_malloc_locked, [ :int, :string, :int ], :pointer
  attach_function :CRYPTO_free_locked, [ :pointer ], :void
  attach_function :CRYPTO_malloc, [ :int, :string, :int ], :pointer
  attach_function :CRYPTO_strdup, [ :string, :string, :int ], :string
  attach_function :CRYPTO_free, [ :pointer ], :void
  attach_function :CRYPTO_realloc, [ :pointer, :int, :string, :int ], :pointer
  attach_function :CRYPTO_realloc_clean, [ :pointer, :int, :int, :string, :int ], :pointer
  attach_function :CRYPTO_remalloc, [ :pointer, :int, :string, :int ], :pointer
  attach_function :OPENSSL_cleanse, [ :pointer, :uint ], :void
  attach_function :CRYPTO_set_mem_debug_options, [ :long ], :void
  attach_function :CRYPTO_get_mem_debug_options, [  ], :long
  attach_function :CRYPTO_push_info_, [ :string, :string, :int ], :int
  attach_function :CRYPTO_pop_info, [  ], :int
  attach_function :CRYPTO_remove_all_info, [  ], :int
  attach_function :CRYPTO_dbg_malloc, [ :pointer, :int, :string, :int, :int ], :void
  attach_function :CRYPTO_dbg_realloc, [ :pointer, :pointer, :int, :string, :int, :int ], :void
  attach_function :CRYPTO_dbg_free, [ :pointer, :int ], :void
  attach_function :CRYPTO_dbg_set_options, [ :long ], :void
  attach_function :CRYPTO_dbg_get_options, [  ], :long
  attach_function :CRYPTO_dbg_push_info, [ :string, :string, :int ], :int
  attach_function :CRYPTO_dbg_pop_info, [  ], :int
  attach_function :CRYPTO_dbg_remove_all_info, [  ], :int
  attach_function :CRYPTO_mem_leaks_fp, [ :pointer ], :void
  attach_function :CRYPTO_mem_leaks, [ :pointer ], :void
  attach_function :CRYPTO_MEM_LEAK_CB, [ :ulong, :string, :int, :int, :pointer ], :pointer
  attach_function :CRYPTO_mem_leaks_cb, [ :pointer ], :void
  attach_function :OpenSSLDie, [ :string, :int, :string ], :void
  attach_function :OPENSSL_ia32cap_loc, [  ], :pointer
  attach_function :OPENSSL_isservice, [  ], :int
  attach_function :ERR_load_CRYPTO_strings, [  ], :void
  OPENSSL_HAVE_INIT = 1
  attach_function :OPENSSL_init, [  ], :void
  CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX = 100
  CRYPTO_F_CRYPTO_GET_NEW_DYNLOCKID = 103
  CRYPTO_F_CRYPTO_GET_NEW_LOCKID = 101
  CRYPTO_F_CRYPTO_SET_EX_DATA = 102
  CRYPTO_F_DEF_ADD_INDEX = 104
  CRYPTO_F_DEF_GET_CLASS = 105
  CRYPTO_F_INT_DUP_EX_DATA = 106
  CRYPTO_F_INT_FREE_EX_DATA = 107
  CRYPTO_F_INT_NEW_EX_DATA = 108
  CRYPTO_R_NO_DYNLOCK_CREATE_CALLBACK = 100
  BIO_TYPE_NONE = 0
  BIO_TYPE_MEM = (1|0x0400)
  BIO_TYPE_FILE = (2|0x0400)
  BIO_TYPE_FD = (4|0x0400|0x0100)
  BIO_TYPE_SOCKET = (5|0x0400|0x0100)
  BIO_TYPE_NULL = (6|0x0400)
  BIO_TYPE_SSL = (7|0x0200)
  BIO_TYPE_MD = (8|0x0200)
  BIO_TYPE_BUFFER = (9|0x0200)
  BIO_TYPE_CIPHER = (10|0x0200)
  BIO_TYPE_BASE64 = (11|0x0200)
  BIO_TYPE_CONNECT = (12|0x0400|0x0100)
  BIO_TYPE_ACCEPT = (13|0x0400|0x0100)
  BIO_TYPE_PROXY_CLIENT = (14|0x0200)
  BIO_TYPE_PROXY_SERVER = (15|0x0200)
  BIO_TYPE_NBIO_TEST = (16|0x0200)
  BIO_TYPE_NULL_FILTER = (17|0x0200)
  BIO_TYPE_BER = (18|0x0200)
  BIO_TYPE_BIO = (19|0x0400)
  BIO_TYPE_LINEBUFFER = (20|0x0200)
  BIO_TYPE_DGRAM = (21|0x0400|0x0100)
  BIO_TYPE_COMP = (23|0x0200)
  BIO_TYPE_DESCRIPTOR = 0x0100
  BIO_TYPE_FILTER = 0x0200
  BIO_TYPE_SOURCE_SINK = 0x0400
  BIO_NOCLOSE = 0x00
  BIO_CLOSE = 0x01
  BIO_CTRL_RESET = 1
  BIO_CTRL_EOF = 2
  BIO_CTRL_INFO = 3
  BIO_CTRL_SET = 4
  BIO_CTRL_GET = 5
  BIO_CTRL_PUSH = 6
  BIO_CTRL_POP = 7
  BIO_CTRL_GET_CLOSE = 8
  BIO_CTRL_SET_CLOSE = 9
  BIO_CTRL_PENDING = 10
  BIO_CTRL_FLUSH = 11
  BIO_CTRL_DUP = 12
  BIO_CTRL_WPENDING = 13
  BIO_CTRL_SET_CALLBACK = 14
  BIO_CTRL_GET_CALLBACK = 15
  BIO_CTRL_SET_FILENAME = 30
  BIO_CTRL_DGRAM_CONNECT = 31
  BIO_CTRL_DGRAM_SET_CONNECTED = 32
  BIO_CTRL_DGRAM_SET_RECV_TIMEOUT = 33
  BIO_CTRL_DGRAM_GET_RECV_TIMEOUT = 34
  BIO_CTRL_DGRAM_SET_SEND_TIMEOUT = 35
  BIO_CTRL_DGRAM_GET_SEND_TIMEOUT = 36
  BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP = 37
  BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP = 38
  BIO_CTRL_DGRAM_MTU_DISCOVER = 39
  BIO_CTRL_DGRAM_QUERY_MTU = 40
  BIO_CTRL_DGRAM_GET_MTU = 41
  BIO_CTRL_DGRAM_SET_MTU = 42
  BIO_CTRL_DGRAM_MTU_EXCEEDED = 43
  BIO_CTRL_DGRAM_GET_PEER = 46
  BIO_CTRL_DGRAM_SET_PEER = 44
  BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT = 45
  BIO_FP_READ = 0x02
  BIO_FP_WRITE = 0x04
  BIO_FP_APPEND = 0x08
  BIO_FP_TEXT = 0x10
  BIO_FLAGS_READ = 0x01
  BIO_FLAGS_WRITE = 0x02
  BIO_FLAGS_IO_SPECIAL = 0x04
  BIO_FLAGS_RWS = (0x01|0x02|0x04)
  BIO_FLAGS_SHOULD_RETRY = 0x08
  BIO_FLAGS_UPLINK = 0
  BIO_GHBN_CTRL_HITS = 1
  BIO_GHBN_CTRL_MISSES = 2
  BIO_GHBN_CTRL_CACHE_SIZE = 3
  BIO_GHBN_CTRL_GET_ENTRY = 4
  BIO_GHBN_CTRL_FLUSH = 5
  BIO_FLAGS_BASE64_NO_NL = 0x100
  BIO_FLAGS_MEM_RDONLY = 0x200
  attach_function :BIO_set_flags, [ :pointer, :int ], :void
  attach_function :BIO_test_flags, [ :pointer, :int ], :int
  attach_function :BIO_clear_flags, [ :pointer, :int ], :void
  BIO_RR_SSL_X509_LOOKUP = 0x01
  BIO_RR_CONNECT = 0x02
  BIO_RR_ACCEPT = 0x03
  BIO_CB_FREE = 0x01
  BIO_CB_READ = 0x02
  BIO_CB_WRITE = 0x03
  BIO_CB_PUTS = 0x04
  BIO_CB_GETS = 0x05
  BIO_CB_CTRL = 0x06
  BIO_CB_RETURN = 0x80
  attach_function :BIO_get_callback, [ :pointer ], :pointer
  attach_function :BIO_set_callback, [ :pointer, callback([ :pointer, :int, :string, :int, :long, :long ], :long) ], :void
  attach_function :BIO_get_callback_arg, [ :pointer ], :string
  attach_function :BIO_set_callback_arg, [ :pointer, :string ], :void
  attach_function :BIO_method_name, [ :pointer ], :string
  attach_function :BIO_method_type, [ :pointer ], :int
  attach_function :bio_info_cb, [ :pointer, :int, :string, :int, :long, :long ], :void
  class BioMethodSt < FFI::Struct
    layout(
           :type, :int,
           :name, :pointer,
           :bwrite, callback([ :pointer, :string, :int ], :int),
           :bread, callback([ :pointer, :string, :int ], :int),
           :bputs, callback([ :pointer, :string ], :int),
           :bgets, callback([ :pointer, :string, :int ], :int),
           :ctrl, callback([ :pointer, :int, :long, :pointer ], :long),
           :create, callback([ :pointer ], :int),
           :destroy, callback([ :pointer ], :int),
           :callback_ctrl, callback([ :pointer, :int, :pointer ], :long)
    )
    def name=(str)
      @name = FFI::MemoryPointer.from_string(str)
      self[:name] = @name
    end
    def name
      @name.get_string(0)
    end
    def bwrite=(cb)
      @bwrite = cb
      self[:bwrite] = @bwrite
    end
    def bwrite
      @bwrite
    end
    def bread=(cb)
      @bread = cb
      self[:bread] = @bread
    end
    def bread
      @bread
    end
    def bputs=(cb)
      @bputs = cb
      self[:bputs] = @bputs
    end
    def bputs
      @bputs
    end
    def bgets=(cb)
      @bgets = cb
      self[:bgets] = @bgets
    end
    def bgets
      @bgets
    end
    def ctrl=(cb)
      @ctrl = cb
      self[:ctrl] = @ctrl
    end
    def ctrl
      @ctrl
    end
    def create=(cb)
      @create = cb
      self[:create] = @create
    end
    def create
      @create
    end
    def destroy=(cb)
      @destroy = cb
      self[:destroy] = @destroy
    end
    def destroy
      @destroy
    end
    def callback_ctrl=(cb)
      @callback_ctrl = cb
      self[:callback_ctrl] = @callback_ctrl
    end
    def callback_ctrl
      @callback_ctrl
    end

  end
  class BioSt < FFI::Struct
    layout(
           :method, :pointer,
           :callback, callback([ :pointer, :int, :string, :int, :long, :long ], :long),
           :cb_arg, :pointer,
           :init, :int,
           :shutdown, :int,
           :flags, :int,
           :retry_reason, :int,
           :num, :int,
           :ptr, :pointer,
           :next_bio, :pointer,
           :prev_bio, :pointer,
           :references, :int,
           :num_read, :ulong,
           :num_write, :ulong,
           :ex_data, CryptoExDataSt
    )
    def callback=(cb)
      @callback = cb
      self[:callback] = @callback
    end
    def callback
      @callback
    end
    def cb_arg=(str)
      @cb_arg = FFI::MemoryPointer.from_string(str)
      self[:cb_arg] = @cb_arg
    end
    def cb_arg
      @cb_arg.get_string(0)
    end

  end
  class BioFBufferCtxStruct < FFI::Struct
    layout(
           :ibuf_size, :int,
           :obuf_size, :int,
           :ibuf, :pointer,
           :ibuf_len, :int,
           :ibuf_off, :int,
           :obuf, :pointer,
           :obuf_len, :int,
           :obuf_off, :int
    )
    def ibuf=(str)
      @ibuf = FFI::MemoryPointer.from_string(str)
      self[:ibuf] = @ibuf
    end
    def ibuf
      @ibuf.get_string(0)
    end
    def obuf=(str)
      @obuf = FFI::MemoryPointer.from_string(str)
      self[:obuf] = @obuf
    end
    def obuf
      @obuf.get_string(0)
    end

  end
  BIO_CONN_S_BEFORE = 1
  BIO_CONN_S_GET_IP = 2
  BIO_CONN_S_GET_PORT = 3
  BIO_CONN_S_CREATE_SOCKET = 4
  BIO_CONN_S_CONNECT = 5
  BIO_CONN_S_OK = 6
  BIO_CONN_S_BLOCKED_CONNECT = 7
  BIO_CONN_S_NBIO = 8
  BIO_C_SET_CONNECT = 100
  BIO_C_DO_STATE_MACHINE = 101
  BIO_C_SET_NBIO = 102
  BIO_C_SET_PROXY_PARAM = 103
  BIO_C_SET_FD = 104
  BIO_C_GET_FD = 105
  BIO_C_SET_FILE_PTR = 106
  BIO_C_GET_FILE_PTR = 107
  BIO_C_SET_FILENAME = 108
  BIO_C_SET_SSL = 109
  BIO_C_GET_SSL = 110
  BIO_C_SET_MD = 111
  BIO_C_GET_MD = 112
  BIO_C_GET_CIPHER_STATUS = 113
  BIO_C_SET_BUF_MEM = 114
  BIO_C_GET_BUF_MEM_PTR = 115
  BIO_C_GET_BUFF_NUM_LINES = 116
  BIO_C_SET_BUFF_SIZE = 117
  BIO_C_SET_ACCEPT = 118
  BIO_C_SSL_MODE = 119
  BIO_C_GET_MD_CTX = 120
  BIO_C_GET_PROXY_PARAM = 121
  BIO_C_SET_BUFF_READ_DATA = 122
  BIO_C_GET_CONNECT = 123
  BIO_C_GET_ACCEPT = 124
  BIO_C_SET_SSL_RENEGOTIATE_BYTES = 125
  BIO_C_GET_SSL_NUM_RENEGOTIATES = 126
  BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT = 127
  BIO_C_FILE_SEEK = 128
  BIO_C_GET_CIPHER_CTX = 129
  BIO_C_SET_BUF_MEM_EOF_RETURN = 130
  BIO_C_SET_BIND_MODE = 131
  BIO_C_GET_BIND_MODE = 132
  BIO_C_FILE_TELL = 133
  BIO_C_GET_SOCKS = 134
  BIO_C_SET_SOCKS = 135
  BIO_C_SET_WRITE_BUF_SIZE = 136
  BIO_C_GET_WRITE_BUF_SIZE = 137
  BIO_C_MAKE_BIO_PAIR = 138
  BIO_C_DESTROY_BIO_PAIR = 139
  BIO_C_GET_WRITE_GUARANTEE = 140
  BIO_C_GET_READ_REQUEST = 141
  BIO_C_SHUTDOWN_WR = 142
  BIO_C_NREAD0 = 143
  BIO_C_NREAD = 144
  BIO_C_NWRITE0 = 145
  BIO_C_NWRITE = 146
  BIO_C_RESET_READ_REQUEST = 147
  BIO_C_SET_MD_CTX = 148
  BIO_BIND_NORMAL = 0
  BIO_BIND_REUSEADDR_IF_UNUSED = 1
  BIO_BIND_REUSEADDR = 2
  attach_function :BIO_ctrl_pending, [ :pointer ], :uint
  attach_function :BIO_ctrl_wpending, [ :pointer ], :uint
  attach_function :BIO_ctrl_get_write_guarantee, [ :pointer ], :uint
  attach_function :BIO_ctrl_get_read_request, [ :pointer ], :uint
  attach_function :BIO_ctrl_reset_read_request, [ :pointer ], :int
  attach_function :BIO_set_ex_data, [ :pointer, :int, :pointer ], :int
  attach_function :BIO_get_ex_data, [ :pointer, :int ], :pointer
  attach_function :BIO_get_ex_new_index, [ :long, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BIO_number_read, [ :pointer ], :ulong
  attach_function :BIO_number_written, [ :pointer ], :ulong
  attach_function :BIO_s_file, [  ], :pointer
  attach_function :BIO_new_file, [ :string, :string ], :pointer
  attach_function :BIO_new_fp, [ :pointer, :int ], :pointer
  attach_function :BIO_new, [ :pointer ], :pointer
  attach_function :BIO_set, [ :pointer, :pointer ], :int
  attach_function :BIO_free, [ :pointer ], :int
  attach_function :BIO_vfree, [ :pointer ], :void
  attach_function :BIO_read, [ :pointer, :pointer, :int ], :int
  attach_function :BIO_gets, [ :pointer, :string, :int ], :int
  attach_function :BIO_write, [ :pointer, :pointer, :int ], :int
  attach_function :BIO_puts, [ :pointer, :string ], :int
  attach_function :BIO_indent, [ :pointer, :int, :int ], :int
  attach_function :BIO_ctrl, [ :pointer, :int, :long, :pointer ], :long
  attach_function :BIO_callback_ctrl, [ :pointer, :int, callback([ :pointer, :int, :string, :int, :long, :long ], :void) ], :long
  attach_function :BIO_ptr_ctrl, [ :pointer, :int, :long ], :string
  attach_function :BIO_int_ctrl, [ :pointer, :int, :long, :int ], :long
  attach_function :BIO_push, [ :pointer, :pointer ], :pointer
  attach_function :BIO_pop, [ :pointer ], :pointer
  attach_function :BIO_free_all, [ :pointer ], :void
  attach_function :BIO_find_type, [ :pointer, :int ], :pointer
  attach_function :BIO_next, [ :pointer ], :pointer
  attach_function :BIO_get_retry_BIO, [ :pointer, :pointer ], :pointer
  attach_function :BIO_get_retry_reason, [ :pointer ], :int
  attach_function :BIO_dup_chain, [ :pointer ], :pointer
  attach_function :BIO_nread0, [ :pointer, :pointer ], :int
  attach_function :BIO_nread, [ :pointer, :pointer, :int ], :int
  attach_function :BIO_nwrite0, [ :pointer, :pointer ], :int
  attach_function :BIO_nwrite, [ :pointer, :pointer, :int ], :int
  attach_function :BIO_debug_callback, [ :pointer, :int, :string, :int, :long, :long ], :long
  attach_function :BIO_s_mem, [  ], :pointer
  attach_function :BIO_new_mem_buf, [ :pointer, :int ], :pointer
  attach_function :BIO_s_socket, [  ], :pointer
  attach_function :BIO_s_connect, [  ], :pointer
  attach_function :BIO_s_accept, [  ], :pointer
  attach_function :BIO_s_fd, [  ], :pointer
  attach_function :BIO_s_log, [  ], :pointer
  attach_function :BIO_s_bio, [  ], :pointer
  attach_function :BIO_s_null, [  ], :pointer
  attach_function :BIO_f_null, [  ], :pointer
  attach_function :BIO_f_buffer, [  ], :pointer
  attach_function :BIO_f_nbio_test, [  ], :pointer
  attach_function :BIO_s_datagram, [  ], :pointer
  attach_function :BIO_sock_should_retry, [ :int ], :int
  attach_function :BIO_sock_non_fatal_error, [ :int ], :int
  attach_function :BIO_dgram_non_fatal_error, [ :int ], :int
  attach_function :BIO_fd_should_retry, [ :int ], :int
  attach_function :BIO_fd_non_fatal_error, [ :int ], :int
  attach_function :BIO_dump_cb, [ callback([ :pointer, :uint, :pointer ], :int), :pointer, :string, :int ], :int
  attach_function :BIO_dump_indent_cb, [ callback([ :pointer, :uint, :pointer ], :int), :pointer, :string, :int, :int ], :int
  attach_function :BIO_dump, [ :pointer, :string, :int ], :int
  attach_function :BIO_dump_indent, [ :pointer, :string, :int, :int ], :int
  attach_function :BIO_dump_fp, [ :pointer, :string, :int ], :int
  attach_function :BIO_dump_indent_fp, [ :pointer, :string, :int, :int ], :int
  attach_function :BIO_gethostbyname, [ :string ], :pointer
  attach_function :BIO_sock_error, [ :int ], :int
  attach_function :BIO_socket_ioctl, [ :int, :long, :pointer ], :int
  attach_function :BIO_socket_nbio, [ :int, :int ], :int
  attach_function :BIO_get_port, [ :string, :pointer ], :int
  attach_function :BIO_get_host_ip, [ :string, :pointer ], :int
  attach_function :BIO_get_accept_socket, [ :string, :int ], :int
  attach_function :BIO_accept, [ :int, :pointer ], :int
  attach_function :BIO_sock_init, [  ], :int
  attach_function :BIO_sock_cleanup, [  ], :void
  attach_function :BIO_set_tcp_ndelay, [ :int, :int ], :int
  attach_function :BIO_new_socket, [ :int, :int ], :pointer
  attach_function :BIO_new_dgram, [ :int, :int ], :pointer
  attach_function :BIO_new_fd, [ :int, :int ], :pointer
  attach_function :BIO_new_connect, [ :string ], :pointer
  attach_function :BIO_new_accept, [ :string ], :pointer
  attach_function :BIO_new_bio_pair, [ :pointer, :uint, :pointer, :uint ], :int
  attach_function :BIO_copy_next_retry, [ :pointer ], :void
  attach_function :BIO_printf, [ :pointer, :string, :varargs ], :int
  attach_function :BIO_vprintf, [ :pointer, :string, va_list ], :int
  attach_function :BIO_snprintf, [ :string, :uint, :string, :varargs ], :int
  attach_function :BIO_vsnprintf, [ :string, :uint, :string, va_list ], :int
  attach_function :ERR_load_BIO_strings, [  ], :void
  BIO_F_ACPT_STATE = 100
  BIO_F_BIO_ACCEPT = 101
  BIO_F_BIO_BER_GET_HEADER = 102
  BIO_F_BIO_CALLBACK_CTRL = 131
  BIO_F_BIO_CTRL = 103
  BIO_F_BIO_GETHOSTBYNAME = 120
  BIO_F_BIO_GETS = 104
  BIO_F_BIO_GET_ACCEPT_SOCKET = 105
  BIO_F_BIO_GET_HOST_IP = 106
  BIO_F_BIO_GET_PORT = 107
  BIO_F_BIO_MAKE_PAIR = 121
  BIO_F_BIO_NEW = 108
  BIO_F_BIO_NEW_FILE = 109
  BIO_F_BIO_NEW_MEM_BUF = 126
  BIO_F_BIO_NREAD = 123
  BIO_F_BIO_NREAD0 = 124
  BIO_F_BIO_NWRITE = 125
  BIO_F_BIO_NWRITE0 = 122
  BIO_F_BIO_PUTS = 110
  BIO_F_BIO_READ = 111
  BIO_F_BIO_SOCK_INIT = 112
  BIO_F_BIO_WRITE = 113
  BIO_F_BUFFER_CTRL = 114
  BIO_F_CONN_CTRL = 127
  BIO_F_CONN_STATE = 115
  BIO_F_FILE_CTRL = 116
  BIO_F_FILE_READ = 130
  BIO_F_LINEBUFFER_CTRL = 129
  BIO_F_MEM_READ = 128
  BIO_F_MEM_WRITE = 117
  BIO_F_SSL_NEW = 118
  BIO_F_WSASTARTUP = 119
  BIO_R_ACCEPT_ERROR = 100
  BIO_R_BAD_FOPEN_MODE = 101
  BIO_R_BAD_HOSTNAME_LOOKUP = 102
  BIO_R_BROKEN_PIPE = 124
  BIO_R_CONNECT_ERROR = 103
  BIO_R_EOF_ON_MEMORY_BIO = 127
  BIO_R_ERROR_SETTING_NBIO = 104
  BIO_R_ERROR_SETTING_NBIO_ON_ACCEPTED_SOCKET = 105
  BIO_R_ERROR_SETTING_NBIO_ON_ACCEPT_SOCKET = 106
  BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET = 107
  BIO_R_INVALID_ARGUMENT = 125
  BIO_R_INVALID_IP_ADDRESS = 108
  BIO_R_IN_USE = 123
  BIO_R_KEEPALIVE = 109
  BIO_R_NBIO_CONNECT_ERROR = 110
  BIO_R_NO_ACCEPT_PORT_SPECIFIED = 111
  BIO_R_NO_HOSTNAME_SPECIFIED = 112
  BIO_R_NO_PORT_DEFINED = 113
  BIO_R_NO_PORT_SPECIFIED = 114
  BIO_R_NO_SUCH_FILE = 128
  BIO_R_NULL_PARAMETER = 115
  BIO_R_TAG_MISMATCH = 116
  BIO_R_UNABLE_TO_BIND_SOCKET = 117
  BIO_R_UNABLE_TO_CREATE_SOCKET = 118
  BIO_R_UNABLE_TO_LISTEN_SOCKET = 119
  BIO_R_UNINITIALIZED = 120
  BIO_R_UNSUPPORTED_METHOD = 121
  BIO_R_WRITE_TO_READ_ONLY_BIO = 126
  BIO_R_WSASTARTUP = 122
  BN_DEFAULT_BITS = 1280
  BN_FLG_MALLOCED = 0x01
  BN_FLG_STATIC_DATA = 0x02
  BN_FLG_CONSTTIME = 0x04
  BN_FLG_EXP_CONSTTIME = 0x04
  BN_FLG_FREE = 0x8000
  class BignumSt < FFI::Struct
    layout(
           :d, :pointer,
           :top, :int,
           :dmax, :int,
           :neg, :int,
           :flags, :int
    )
  end
  class BnMontCtxSt < FFI::Struct
    layout(
           :ri, :int,
           :RR, BignumSt,
           :N, BignumSt,
           :Ni, BignumSt,
           :n0, BN_ULONG,
           :flags, :int
    )
  end
  class BnRecpCtxSt < FFI::Struct
    layout(
           :N, BignumSt,
           :Nr, BignumSt,
           :num_bits, :int,
           :shift, :int,
           :flags, :int
    )
  end
  class BnGencbStCb < FFI::Union
    layout(
           :cb_1, callback([ :int, :int, :pointer ], :void),
           :cb_2, callback([ :int, :int, :pointer ], :int)
    )
    def cb_1=(cb)
      @cb_1 = cb
      self[:cb_1] = @cb_1
    end
    def cb_1
      @cb_1
    end
    def cb_2=(cb)
      @cb_2 = cb
      self[:cb_2] = @cb_2
    end
    def cb_2
      @cb_2
    end

  end
# FIXME: Nested structures are not correctly supported at the moment.
# Please check the order of the declarations in the structure below.
#   class BnGencbSt < FFI::Struct
#     layout(
#            :ver, :uint,
#            :arg, :pointer,
#            :cb, BnGencbStCb
#     )
#   end
  attach_function :BN_GENCB_call, [ :pointer, :int, :int ], :int
  BN_prime_checks = 0
  attach_function :BN_value_one, [  ], :pointer
  attach_function :BN_options, [  ], :string
  attach_function :BN_CTX_new, [  ], :pointer
  attach_function :BN_CTX_init, [ :pointer ], :void
  attach_function :BN_CTX_free, [ :pointer ], :void
  attach_function :BN_CTX_start, [ :pointer ], :void
  attach_function :BN_CTX_get, [ :pointer ], :pointer
  attach_function :BN_CTX_end, [ :pointer ], :void
  attach_function :BN_rand, [ :pointer, :int, :int, :int ], :int
  attach_function :BN_pseudo_rand, [ :pointer, :int, :int, :int ], :int
  attach_function :BN_rand_range, [ :pointer, :pointer ], :int
  attach_function :BN_pseudo_rand_range, [ :pointer, :pointer ], :int
  attach_function :BN_num_bits, [ :pointer ], :int
  attach_function :BN_num_bits_word, [ BN_ULONG ], :int
  attach_function :BN_new, [  ], :pointer
  attach_function :BN_init, [ :pointer ], :void
  attach_function :BN_clear_free, [ :pointer ], :void
  attach_function :BN_copy, [ :pointer, :pointer ], :pointer
  attach_function :BN_swap, [ :pointer, :pointer ], :void
  attach_function :BN_bin2bn, [ :pointer, :int, :pointer ], :pointer
  attach_function :BN_bn2bin, [ :pointer, :pointer ], :int
  attach_function :BN_mpi2bn, [ :pointer, :int, :pointer ], :pointer
  attach_function :BN_bn2mpi, [ :pointer, :pointer ], :int
  attach_function :BN_sub, [ :pointer, :pointer, :pointer ], :int
  attach_function :BN_usub, [ :pointer, :pointer, :pointer ], :int
  attach_function :BN_uadd, [ :pointer, :pointer, :pointer ], :int
  attach_function :BN_add, [ :pointer, :pointer, :pointer ], :int
  attach_function :BN_mul, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_sqr, [ :pointer, :pointer, :pointer ], :int
  attach_function :BN_set_negative, [ :pointer, :int ], :void
  attach_function :BN_div, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_nnmod, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_mod_add, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_mod_add_quick, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_mod_sub, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_mod_sub_quick, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_mod_mul, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_mod_sqr, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_mod_lshift1, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_mod_lshift1_quick, [ :pointer, :pointer, :pointer ], :int
  attach_function :BN_mod_lshift, [ :pointer, :pointer, :int, :pointer, :pointer ], :int
  attach_function :BN_mod_lshift_quick, [ :pointer, :pointer, :int, :pointer ], :int
  attach_function :BN_mod_word, [ :pointer, BN_ULONG ], BN_ULONG
  attach_function :BN_div_word, [ :pointer, BN_ULONG ], BN_ULONG
  attach_function :BN_mul_word, [ :pointer, BN_ULONG ], :int
  attach_function :BN_add_word, [ :pointer, BN_ULONG ], :int
  attach_function :BN_sub_word, [ :pointer, BN_ULONG ], :int
  attach_function :BN_set_word, [ :pointer, BN_ULONG ], :int
  attach_function :BN_get_word, [ :pointer ], BN_ULONG
  attach_function :BN_cmp, [ :pointer, :pointer ], :int
  attach_function :BN_free, [ :pointer ], :void
  attach_function :BN_is_bit_set, [ :pointer, :int ], :int
  attach_function :BN_lshift, [ :pointer, :pointer, :int ], :int
  attach_function :BN_lshift1, [ :pointer, :pointer ], :int
  attach_function :BN_exp, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_mod_exp, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_mod_exp_mont, [ :pointer, :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_mod_exp_mont_consttime, [ :pointer, :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_mod_exp_mont_word, [ :pointer, BN_ULONG, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_mod_exp2_mont, [ :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_mod_exp_simple, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_mask_bits, [ :pointer, :int ], :int
  attach_function :BN_print_fp, [ :pointer, :pointer ], :int
  attach_function :BN_print, [ :pointer, :pointer ], :int
  attach_function :BN_reciprocal, [ :pointer, :pointer, :int, :pointer ], :int
  attach_function :BN_rshift, [ :pointer, :pointer, :int ], :int
  attach_function :BN_rshift1, [ :pointer, :pointer ], :int
  attach_function :BN_clear, [ :pointer ], :void
  attach_function :BN_dup, [ :pointer ], :pointer
  attach_function :BN_ucmp, [ :pointer, :pointer ], :int
  attach_function :BN_set_bit, [ :pointer, :int ], :int
  attach_function :BN_clear_bit, [ :pointer, :int ], :int
  attach_function :BN_bn2hex, [ :pointer ], :string
  attach_function :BN_bn2dec, [ :pointer ], :string
  attach_function :BN_hex2bn, [ :pointer, :string ], :int
  attach_function :BN_dec2bn, [ :pointer, :string ], :int
  attach_function :BN_gcd, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_kronecker, [ :pointer, :pointer, :pointer ], :int
  attach_function :BN_mod_inverse, [ :pointer, :pointer, :pointer, :pointer ], :pointer
  attach_function :BN_mod_sqrt, [ :pointer, :pointer, :pointer, :pointer ], :pointer
  attach_function :BN_generate_prime, [ :pointer, :int, :int, :pointer, :pointer, callback([ :int, :int, :pointer ], :void), :pointer ], :pointer
  attach_function :BN_is_prime, [ :pointer, :int, callback([ :int, :int, :pointer ], :void), :pointer, :pointer ], :int
  attach_function :BN_is_prime_fasttest, [ :pointer, :int, callback([ :int, :int, :pointer ], :void), :pointer, :pointer, :int ], :int
  attach_function :BN_generate_prime_ex, [ :pointer, :int, :int, :pointer, :pointer, :pointer ], :int
  attach_function :BN_is_prime_ex, [ :pointer, :int, :pointer, :pointer ], :int
  attach_function :BN_is_prime_fasttest_ex, [ :pointer, :int, :pointer, :int, :pointer ], :int
  attach_function :BN_X931_generate_Xpq, [ :pointer, :pointer, :int, :pointer ], :int
  attach_function :BN_X931_derive_prime_ex, [ :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_X931_generate_prime_ex, [ :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_MONT_CTX_new, [  ], :pointer
  attach_function :BN_MONT_CTX_init, [ :pointer ], :void
  attach_function :BN_mod_mul_montgomery, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_from_montgomery, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_MONT_CTX_free, [ :pointer ], :void
  attach_function :BN_MONT_CTX_set, [ :pointer, :pointer, :pointer ], :int
  attach_function :BN_MONT_CTX_copy, [ :pointer, :pointer ], :pointer
  attach_function :BN_MONT_CTX_set_locked, [ :pointer, :int, :pointer, :pointer ], :pointer
  BN_BLINDING_NO_UPDATE = 0x00000001
  BN_BLINDING_NO_RECREATE = 0x00000002
  attach_function :BN_BLINDING_new, [ :pointer, :pointer, :pointer ], :pointer
  attach_function :BN_BLINDING_free, [ :pointer ], :void
  attach_function :BN_BLINDING_update, [ :pointer, :pointer ], :int
  attach_function :BN_BLINDING_convert, [ :pointer, :pointer, :pointer ], :int
  attach_function :BN_BLINDING_invert, [ :pointer, :pointer, :pointer ], :int
  attach_function :BN_BLINDING_convert_ex, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_BLINDING_invert_ex, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_BLINDING_get_thread_id, [ :pointer ], :ulong
  attach_function :BN_BLINDING_set_thread_id, [ :pointer, :ulong ], :void
  attach_function :BN_BLINDING_get_flags, [ :pointer ], :ulong
  attach_function :BN_BLINDING_set_flags, [ :pointer, :ulong ], :void
  attach_function :BN_BLINDING_create_param, [ :pointer, :pointer, :pointer, :pointer, callback([ :pointer, :pointer, :pointer, :pointer, :pointer, :pointer ], :int), :pointer ], :pointer
  attach_function :BN_set_params, [ :int, :int, :int, :int ], :void
  attach_function :BN_get_params, [ :int ], :int
  attach_function :BN_RECP_CTX_init, [ :pointer ], :void
  attach_function :BN_RECP_CTX_new, [  ], :pointer
  attach_function :BN_RECP_CTX_free, [ :pointer ], :void
  attach_function :BN_RECP_CTX_set, [ :pointer, :pointer, :pointer ], :int
  attach_function :BN_mod_mul_reciprocal, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_mod_exp_recp, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_div_recp, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_GF2m_add, [ :pointer, :pointer, :pointer ], :int
  attach_function :BN_GF2m_mod, [ :pointer, :pointer, :pointer ], :int
  attach_function :BN_GF2m_mod_mul, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_GF2m_mod_sqr, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_GF2m_mod_inv, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_GF2m_mod_div, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_GF2m_mod_exp, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_GF2m_mod_sqrt, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_GF2m_mod_solve_quad, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_GF2m_mod_arr, [ :pointer, :pointer, a().q(const).unsigned int ], :int
  attach_function :BN_GF2m_mod_mul_arr, [ :pointer, :pointer, :pointer, a().q(const).unsigned int, :pointer ], :int
  attach_function :BN_GF2m_mod_sqr_arr, [ :pointer, :pointer, a().q(const).unsigned int, :pointer ], :int
  attach_function :BN_GF2m_mod_inv_arr, [ :pointer, :pointer, a().q(const).unsigned int, :pointer ], :int
  attach_function :BN_GF2m_mod_div_arr, [ :pointer, :pointer, :pointer, a().q(const).unsigned int, :pointer ], :int
  attach_function :BN_GF2m_mod_exp_arr, [ :pointer, :pointer, :pointer, a().q(const).unsigned int, :pointer ], :int
  attach_function :BN_GF2m_mod_sqrt_arr, [ :pointer, :pointer, a().q(const).unsigned int, :pointer ], :int
  attach_function :BN_GF2m_mod_solve_quad_arr, [ :pointer, :pointer, a().q(const).unsigned int, :pointer ], :int
  attach_function :BN_GF2m_poly2arr, [ :pointer, a().unsigned int, :int ], :int
  attach_function :BN_GF2m_arr2poly, [ a().q(const).unsigned int, :pointer ], :int
  attach_function :BN_nist_mod_192, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_nist_mod_224, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_nist_mod_256, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_nist_mod_384, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_nist_mod_521, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :BN_get0_nist_prime_192, [  ], :pointer
  attach_function :BN_get0_nist_prime_224, [  ], :pointer
  attach_function :BN_get0_nist_prime_256, [  ], :pointer
  attach_function :BN_get0_nist_prime_384, [  ], :pointer
  attach_function :BN_get0_nist_prime_521, [  ], :pointer
  attach_function :bn_expand2, [ :pointer, :int ], :pointer
  attach_function :bn_dup_expand, [ :pointer, :int ], :pointer
  attach_function :bn_mul_add_words, [ :pointer, :pointer, :int, BN_ULONG ], BN_ULONG
  attach_function :bn_mul_words, [ :pointer, :pointer, :int, BN_ULONG ], BN_ULONG
  attach_function :bn_sqr_words, [ :pointer, :pointer, :int ], :void
  attach_function :bn_div_words, [ BN_ULONG, BN_ULONG, BN_ULONG ], BN_ULONG
  attach_function :bn_add_words, [ :pointer, :pointer, :pointer, :int ], BN_ULONG
  attach_function :bn_sub_words, [ :pointer, :pointer, :pointer, :int ], BN_ULONG
  attach_function :get_rfc2409_prime_768, [ :pointer ], :pointer
  attach_function :get_rfc2409_prime_1024, [ :pointer ], :pointer
  attach_function :get_rfc3526_prime_1536, [ :pointer ], :pointer
  attach_function :get_rfc3526_prime_2048, [ :pointer ], :pointer
  attach_function :get_rfc3526_prime_3072, [ :pointer ], :pointer
  attach_function :get_rfc3526_prime_4096, [ :pointer ], :pointer
  attach_function :get_rfc3526_prime_6144, [ :pointer ], :pointer
  attach_function :get_rfc3526_prime_8192, [ :pointer ], :pointer
  attach_function :BN_bntest_rand, [ :pointer, :int, :int, :int ], :int
  attach_function :ERR_load_BN_strings, [  ], :void
  BN_F_BNRAND = 127
  BN_F_BN_BLINDING_CONVERT_EX = 100
  BN_F_BN_BLINDING_CREATE_PARAM = 128
  BN_F_BN_BLINDING_INVERT_EX = 101
  BN_F_BN_BLINDING_NEW = 102
  BN_F_BN_BLINDING_UPDATE = 103
  BN_F_BN_BN2DEC = 104
  BN_F_BN_BN2HEX = 105
  BN_F_BN_CTX_GET = 116
  BN_F_BN_CTX_NEW = 106
  BN_F_BN_CTX_START = 129
  BN_F_BN_DIV = 107
  BN_F_BN_DIV_NO_BRANCH = 138
  BN_F_BN_DIV_RECP = 130
  BN_F_BN_EXP = 123
  BN_F_BN_EXPAND2 = 108
  BN_F_BN_EXPAND_INTERNAL = 120
  BN_F_BN_GF2M_MOD = 131
  BN_F_BN_GF2M_MOD_EXP = 132
  BN_F_BN_GF2M_MOD_MUL = 133
  BN_F_BN_GF2M_MOD_SOLVE_QUAD = 134
  BN_F_BN_GF2M_MOD_SOLVE_QUAD_ARR = 135
  BN_F_BN_GF2M_MOD_SQR = 136
  BN_F_BN_GF2M_MOD_SQRT = 137
  BN_F_BN_MOD_EXP2_MONT = 118
  BN_F_BN_MOD_EXP_MONT = 109
  BN_F_BN_MOD_EXP_MONT_CONSTTIME = 124
  BN_F_BN_MOD_EXP_MONT_WORD = 117
  BN_F_BN_MOD_EXP_RECP = 125
  BN_F_BN_MOD_EXP_SIMPLE = 126
  BN_F_BN_MOD_INVERSE = 110
  BN_F_BN_MOD_INVERSE_NO_BRANCH = 139
  BN_F_BN_MOD_LSHIFT_QUICK = 119
  BN_F_BN_MOD_MUL_RECIPROCAL = 111
  BN_F_BN_MOD_SQRT = 121
  BN_F_BN_MPI2BN = 112
  BN_F_BN_NEW = 113
  BN_F_BN_RAND = 114
  BN_F_BN_RAND_RANGE = 122
  BN_F_BN_USUB = 115
  BN_R_ARG2_LT_ARG3 = 100
  BN_R_BAD_RECIPROCAL = 101
  BN_R_BIGNUM_TOO_LONG = 114
  BN_R_CALLED_WITH_EVEN_MODULUS = 102
  BN_R_DIV_BY_ZERO = 103
  BN_R_ENCODING_ERROR = 104
  BN_R_EXPAND_ON_STATIC_BIGNUM_DATA = 105
  BN_R_INPUT_NOT_REDUCED = 110
  BN_R_INVALID_LENGTH = 106
  BN_R_INVALID_RANGE = 115
  BN_R_NOT_A_SQUARE = 111
  BN_R_NOT_INITIALIZED = 107
  BN_R_NO_INVERSE = 108
  BN_R_NO_SOLUTION = 116
  BN_R_P_IS_NOT_PRIME = 112
  BN_R_TOO_MANY_ITERATIONS = 113
  BN_R_TOO_MANY_TEMPORARY_VARIABLES = 109
  V_ASN1_UNIVERSAL = 0x00
  V_ASN1_APPLICATION = 0x40
  V_ASN1_CONTEXT_SPECIFIC = 0x80
  V_ASN1_PRIVATE = 0xc0
  V_ASN1_CONSTRUCTED = 0x20
  V_ASN1_PRIMITIVE_TAG = 0x1f
  V_ASN1_PRIMATIVE_TAG = 0x1f
  V_ASN1_APP_CHOOSE = -2
  V_ASN1_OTHER = -3
  V_ASN1_ANY = -4
  V_ASN1_NEG = 0x100
  V_ASN1_UNDEF = -1
  V_ASN1_EOC = 0
  V_ASN1_BOOLEAN = 1
  V_ASN1_INTEGER = 2
  V_ASN1_NEG_INTEGER = (2|0x100)
  V_ASN1_BIT_STRING = 3
  V_ASN1_OCTET_STRING = 4
  V_ASN1_NULL = 5
  V_ASN1_OBJECT = 6
  V_ASN1_OBJECT_DESCRIPTOR = 7
  V_ASN1_EXTERNAL = 8
  V_ASN1_REAL = 9
  V_ASN1_ENUMERATED = 10
  V_ASN1_NEG_ENUMERATED = (10|0x100)
  V_ASN1_UTF8STRING = 12
  V_ASN1_SEQUENCE = 16
  V_ASN1_SET = 17
  V_ASN1_NUMERICSTRING = 18
  V_ASN1_PRINTABLESTRING = 19
  V_ASN1_T61STRING = 20
  V_ASN1_TELETEXSTRING = 20
  V_ASN1_VIDEOTEXSTRING = 21
  V_ASN1_IA5STRING = 22
  V_ASN1_UTCTIME = 23
  V_ASN1_GENERALIZEDTIME = 24
  V_ASN1_GRAPHICSTRING = 25
  V_ASN1_ISO64STRING = 26
  V_ASN1_VISIBLESTRING = 26
  V_ASN1_GENERALSTRING = 27
  V_ASN1_UNIVERSALSTRING = 28
  V_ASN1_BMPSTRING = 30
  B_ASN1_NUMERICSTRING = 0x0001
  B_ASN1_PRINTABLESTRING = 0x0002
  B_ASN1_T61STRING = 0x0004
  B_ASN1_TELETEXSTRING = 0x0004
  B_ASN1_VIDEOTEXSTRING = 0x0008
  B_ASN1_IA5STRING = 0x0010
  B_ASN1_GRAPHICSTRING = 0x0020
  B_ASN1_ISO64STRING = 0x0040
  B_ASN1_VISIBLESTRING = 0x0040
  B_ASN1_GENERALSTRING = 0x0080
  B_ASN1_UNIVERSALSTRING = 0x0100
  B_ASN1_OCTET_STRING = 0x0200
  B_ASN1_BIT_STRING = 0x0400
  B_ASN1_BMPSTRING = 0x0800
  B_ASN1_UNKNOWN = 0x1000
  B_ASN1_UTF8STRING = 0x2000
  B_ASN1_UTCTIME = 0x4000
  B_ASN1_GENERALIZEDTIME = 0x8000
  B_ASN1_SEQUENCE = 0x10000
  MBSTRING_FLAG = 0x1000
  MBSTRING_UTF8 = (0x1000)
  MBSTRING_ASC = (0x1000|1)
  MBSTRING_BMP = (0x1000|2)
  MBSTRING_UNIV = (0x1000|4)
  SMIME_OLDMIME = 0x400
  SMIME_CRLFEOL = 0x800
  SMIME_STREAM = 0x1000
  class Asn1CtxSt < FFI::Struct
    layout(
           :p, :pointer,
           :eos, :int,
           :error, :int,
           :inf, :int,
           :tag, :int,
           :xclass, :int,
           :slen, :long,
           :max, :pointer,
           :q, :pointer,
           :pp, :pointer,
           :line, :int
    )
  end
  class Asn1ConstCtxSt < FFI::Struct
    layout(
           :p, :pointer,
           :eos, :int,
           :error, :int,
           :inf, :int,
           :tag, :int,
           :xclass, :int,
           :slen, :long,
           :max, :pointer,
           :q, :pointer,
           :pp, :pointer,
           :line, :int
    )
  end
  ASN1_OBJECT_FLAG_DYNAMIC = 0x01
  ASN1_OBJECT_FLAG_CRITICAL = 0x02
  ASN1_OBJECT_FLAG_DYNAMIC_STRINGS = 0x04
  ASN1_OBJECT_FLAG_DYNAMIC_DATA = 0x08
  class Asn1ObjectSt < FFI::Struct
    layout(
           :sn, :pointer,
           :ln, :pointer,
           :nid, :int,
           :length, :int,
           :data, :pointer,
           :flags, :int
    )
    def sn=(str)
      @sn = FFI::MemoryPointer.from_string(str)
      self[:sn] = @sn
    end
    def sn
      @sn.get_string(0)
    end
    def ln=(str)
      @ln = FFI::MemoryPointer.from_string(str)
      self[:ln] = @ln
    end
    def ln
      @ln.get_string(0)
    end

  end
  ASN1_STRING_FLAG_BITS_LEFT = 0x08
  ASN1_STRING_FLAG_NDEF = 0x010
  ASN1_STRING_FLAG_CONT = 0x020
  class Asn1StringSt < FFI::Struct
    layout(
           :length, :int,
           :type, :int,
           :data, :pointer,
           :flags, :long
    )
  end
  class ASN1ENCODINGSt < FFI::Struct
    layout(
           :enc, :pointer,
           :len, :long,
           :modified, :int
    )
  end
  ASN1_LONG_UNDEF = 0x7fffffffL
  STABLE_FLAGS_MALLOC = 0x01
  STABLE_NO_MASK = 0x02
  DIRSTRING_TYPE = (0x0002|0x0004|0x0800|0x2000)
  PKCS9STRING_TYPE = ((0x0002|0x0004|0x0800|0x2000)|0x0010)
  class Asn1StringTableSt < FFI::Struct
    layout(
           :nid, :int,
           :minsize, :long,
           :maxsize, :long,
           :mask, :ulong,
           :flags, :ulong
    )
  end
  ub_name = 32768
  ub_common_name = 64
  ub_locality_name = 128
  ub_state_name = 128
  ub_organization_name = 64
  ub_organization_unit_name = 64
  ub_title = 64
  ub_email_address = 128
  attach_function :d2i_of_void, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_of_void, [ :pointer, :pointer ], :int
  ASN1_STRFLGS_ESC_2253 = 1
  ASN1_STRFLGS_ESC_CTRL = 2
  ASN1_STRFLGS_ESC_MSB = 4
  ASN1_STRFLGS_ESC_QUOTE = 8
  CHARTYPE_PRINTABLESTRING = 0x10
  CHARTYPE_FIRST_ESC_2253 = 0x20
  CHARTYPE_LAST_ESC_2253 = 0x40
  ASN1_STRFLGS_UTF8_CONVERT = 0x10
  ASN1_STRFLGS_IGNORE_TYPE = 0x20
  ASN1_STRFLGS_SHOW_TYPE = 0x40
  ASN1_STRFLGS_DUMP_ALL = 0x80
  ASN1_STRFLGS_DUMP_UNKNOWN = 0x100
  ASN1_STRFLGS_DUMP_DER = 0x200
  ASN1_STRFLGS_RFC2253 = (1|2|4|0x10|0x100|0x200)
  class Asn1TypeSt < FFI::Struct
    layout(
           :type, :int,
           :value, ASN1TYPEValue
    )
  end
  class Asn1MethodSt < FFI::Struct
    layout(
           :i2d, :pointer,
           :d2i, :pointer,
           :create, callback([  ], :pointer),
           :destroy, callback([ :pointer ], :void)
    )
    def create=(cb)
      @create = cb
      self[:create] = @create
    end
    def create
      @create
    end
    def destroy=(cb)
      @destroy = cb
      self[:destroy] = @destroy
    end
    def destroy
      @destroy
    end

  end
  class Asn1HeaderSt < FFI::Struct
    layout(
           :header, :pointer,
           :data, :pointer,
           :meth, :pointer
    )
  end
  class BITSTRINGBITNAMESt < FFI::Struct
    layout(
           :bitnum, :int,
           :lname, :pointer,
           :sname, :pointer
    )
    def lname=(str)
      @lname = FFI::MemoryPointer.from_string(str)
      self[:lname] = @lname
    end
    def lname
      @lname.get_string(0)
    end
    def sname=(str)
      @sname = FFI::MemoryPointer.from_string(str)
      self[:sname] = @sname
    end
    def sname
      @sname.get_string(0)
    end

  end
  B_ASN1_TIME = 0x4000|0x8000
  B_ASN1_PRINTABLE = 0x0001|0x0002|0x0004|0x0010|0x0400|0x0100|0x0800|0x2000|0x10000|0x1000
  B_ASN1_DIRECTORYSTRING = 0x0002|0x0004|0x0800|0x0100|0x2000
  B_ASN1_DISPLAYTEXT = 0x0010|0x0040|0x0800|0x2000
  IS_SEQUENCE = 0
  IS_SET = 1
  attach_function :ASN1_TYPE_new, [  ], :pointer
  attach_function :ASN1_TYPE_free, [ :pointer ], :void
  attach_function :d2i_ASN1_TYPE, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_ASN1_TYPE, [ :pointer, :pointer ], :int
  attach_function :ASN1_TYPE_get, [ :pointer ], :int
  attach_function :ASN1_TYPE_set, [ :pointer, :int, :pointer ], :void
  attach_function :ASN1_TYPE_set1, [ :pointer, :int, :pointer ], :int
  attach_function :ASN1_OBJECT_new, [  ], :pointer
  attach_function :ASN1_OBJECT_free, [ :pointer ], :void
  attach_function :i2d_ASN1_OBJECT, [ :pointer, :pointer ], :int
  attach_function :c2i_ASN1_OBJECT, [ :pointer, :pointer, :long ], :pointer
  attach_function :d2i_ASN1_OBJECT, [ :pointer, :pointer, :long ], :pointer
  attach_function :ASN1_STRING_new, [  ], :pointer
  attach_function :ASN1_STRING_free, [ :pointer ], :void
  attach_function :ASN1_STRING_dup, [ :pointer ], :pointer
  attach_function :ASN1_STRING_type_new, [ :int ], :pointer
  attach_function :ASN1_STRING_cmp, [ :pointer, :pointer ], :int
  attach_function :ASN1_STRING_set, [ :pointer, :pointer, :int ], :int
  attach_function :ASN1_STRING_set0, [ :pointer, :pointer, :int ], :void
  attach_function :ASN1_STRING_length, [ :pointer ], :int
  attach_function :ASN1_STRING_length_set, [ :pointer, :int ], :void
  attach_function :ASN1_STRING_type, [ :pointer ], :int
  attach_function :ASN1_STRING_data, [ :pointer ], :pointer
  attach_function :ASN1_BIT_STRING_new, [  ], :pointer
  attach_function :ASN1_BIT_STRING_free, [ :pointer ], :void
  attach_function :d2i_ASN1_BIT_STRING, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_ASN1_BIT_STRING, [ :pointer, :pointer ], :int
  attach_function :i2c_ASN1_BIT_STRING, [ :pointer, :pointer ], :int
  attach_function :c2i_ASN1_BIT_STRING, [ :pointer, :pointer, :long ], :pointer
  attach_function :ASN1_BIT_STRING_set, [ :pointer, :pointer, :int ], :int
  attach_function :ASN1_BIT_STRING_set_bit, [ :pointer, :int, :int ], :int
  attach_function :ASN1_BIT_STRING_get_bit, [ :pointer, :int ], :int
  attach_function :ASN1_BIT_STRING_name_print, [ :pointer, :pointer, :pointer, :int ], :int
  attach_function :ASN1_BIT_STRING_num_asc, [ :string, :pointer ], :int
  attach_function :ASN1_BIT_STRING_set_asc, [ :pointer, :string, :int, :pointer ], :int
  attach_function :i2d_ASN1_BOOLEAN, [ :int, :pointer ], :int
  attach_function :d2i_ASN1_BOOLEAN, [ :pointer, :pointer, :long ], :int
  attach_function :ASN1_INTEGER_new, [  ], :pointer
  attach_function :ASN1_INTEGER_free, [ :pointer ], :void
  attach_function :d2i_ASN1_INTEGER, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_ASN1_INTEGER, [ :pointer, :pointer ], :int
  attach_function :i2c_ASN1_INTEGER, [ :pointer, :pointer ], :int
  attach_function :c2i_ASN1_INTEGER, [ :pointer, :pointer, :long ], :pointer
  attach_function :d2i_ASN1_UINTEGER, [ :pointer, :pointer, :long ], :pointer
  attach_function :ASN1_INTEGER_dup, [ :pointer ], :pointer
  attach_function :ASN1_INTEGER_cmp, [ :pointer, :pointer ], :int
  attach_function :ASN1_ENUMERATED_new, [  ], :pointer
  attach_function :ASN1_ENUMERATED_free, [ :pointer ], :void
  attach_function :d2i_ASN1_ENUMERATED, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_ASN1_ENUMERATED, [ :pointer, :pointer ], :int
  attach_function :ASN1_UTCTIME_check, [ :pointer ], :int
  attach_function :ASN1_UTCTIME_set, [ :pointer, :long ], :pointer
  attach_function :ASN1_UTCTIME_set_string, [ :pointer, :string ], :int
  attach_function :ASN1_UTCTIME_cmp_time_t, [ :pointer, :long ], :int
  attach_function :ASN1_GENERALIZEDTIME_check, [ :pointer ], :int
  attach_function :ASN1_GENERALIZEDTIME_set, [ :pointer, :long ], :pointer
  attach_function :ASN1_GENERALIZEDTIME_set_string, [ :pointer, :string ], :int
  attach_function :ASN1_OCTET_STRING_new, [  ], :pointer
  attach_function :ASN1_OCTET_STRING_free, [ :pointer ], :void
  attach_function :d2i_ASN1_OCTET_STRING, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_ASN1_OCTET_STRING, [ :pointer, :pointer ], :int
  attach_function :ASN1_OCTET_STRING_dup, [ :pointer ], :pointer
  attach_function :ASN1_OCTET_STRING_cmp, [ :pointer, :pointer ], :int
  attach_function :ASN1_OCTET_STRING_set, [ :pointer, :pointer, :int ], :int
  attach_function :ASN1_VISIBLESTRING_new, [  ], :pointer
  attach_function :ASN1_VISIBLESTRING_free, [ :pointer ], :void
  attach_function :d2i_ASN1_VISIBLESTRING, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_ASN1_VISIBLESTRING, [ :pointer, :pointer ], :int
  attach_function :ASN1_UNIVERSALSTRING_new, [  ], :pointer
  attach_function :ASN1_UNIVERSALSTRING_free, [ :pointer ], :void
  attach_function :d2i_ASN1_UNIVERSALSTRING, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_ASN1_UNIVERSALSTRING, [ :pointer, :pointer ], :int
  attach_function :ASN1_UTF8STRING_new, [  ], :pointer
  attach_function :ASN1_UTF8STRING_free, [ :pointer ], :void
  attach_function :d2i_ASN1_UTF8STRING, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_ASN1_UTF8STRING, [ :pointer, :pointer ], :int
  attach_function :ASN1_NULL_new, [  ], :pointer
  attach_function :ASN1_NULL_free, [ :pointer ], :void
  attach_function :d2i_ASN1_NULL, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_ASN1_NULL, [ :pointer, :pointer ], :int
  attach_function :ASN1_BMPSTRING_new, [  ], :pointer
  attach_function :ASN1_BMPSTRING_free, [ :pointer ], :void
  attach_function :d2i_ASN1_BMPSTRING, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_ASN1_BMPSTRING, [ :pointer, :pointer ], :int
  attach_function :UTF8_getc, [ :pointer, :int, :pointer ], :int
  attach_function :UTF8_putc, [ :pointer, :int, :ulong ], :int
  attach_function :ASN1_PRINTABLE_new, [  ], :pointer
  attach_function :ASN1_PRINTABLE_free, [ :pointer ], :void
  attach_function :d2i_ASN1_PRINTABLE, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_ASN1_PRINTABLE, [ :pointer, :pointer ], :int
  attach_function :DIRECTORYSTRING_new, [  ], :pointer
  attach_function :DIRECTORYSTRING_free, [ :pointer ], :void
  attach_function :d2i_DIRECTORYSTRING, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_DIRECTORYSTRING, [ :pointer, :pointer ], :int
  attach_function :DISPLAYTEXT_new, [  ], :pointer
  attach_function :DISPLAYTEXT_free, [ :pointer ], :void
  attach_function :d2i_DISPLAYTEXT, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_DISPLAYTEXT, [ :pointer, :pointer ], :int
  attach_function :ASN1_PRINTABLESTRING_new, [  ], :pointer
  attach_function :ASN1_PRINTABLESTRING_free, [ :pointer ], :void
  attach_function :d2i_ASN1_PRINTABLESTRING, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_ASN1_PRINTABLESTRING, [ :pointer, :pointer ], :int
  attach_function :ASN1_T61STRING_new, [  ], :pointer
  attach_function :ASN1_T61STRING_free, [ :pointer ], :void
  attach_function :d2i_ASN1_T61STRING, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_ASN1_T61STRING, [ :pointer, :pointer ], :int
  attach_function :ASN1_IA5STRING_new, [  ], :pointer
  attach_function :ASN1_IA5STRING_free, [ :pointer ], :void
  attach_function :d2i_ASN1_IA5STRING, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_ASN1_IA5STRING, [ :pointer, :pointer ], :int
  attach_function :ASN1_GENERALSTRING_new, [  ], :pointer
  attach_function :ASN1_GENERALSTRING_free, [ :pointer ], :void
  attach_function :d2i_ASN1_GENERALSTRING, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_ASN1_GENERALSTRING, [ :pointer, :pointer ], :int
  attach_function :ASN1_UTCTIME_new, [  ], :pointer
  attach_function :ASN1_UTCTIME_free, [ :pointer ], :void
  attach_function :d2i_ASN1_UTCTIME, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_ASN1_UTCTIME, [ :pointer, :pointer ], :int
  attach_function :ASN1_GENERALIZEDTIME_new, [  ], :pointer
  attach_function :ASN1_GENERALIZEDTIME_free, [ :pointer ], :void
  attach_function :d2i_ASN1_GENERALIZEDTIME, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_ASN1_GENERALIZEDTIME, [ :pointer, :pointer ], :int
  attach_function :ASN1_TIME_new, [  ], :pointer
  attach_function :ASN1_TIME_free, [ :pointer ], :void
  attach_function :d2i_ASN1_TIME, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_ASN1_TIME, [ :pointer, :pointer ], :int
  attach_function :ASN1_TIME_set, [ :pointer, :long ], :pointer
  attach_function :ASN1_TIME_check, [ :pointer ], :int
  attach_function :ASN1_TIME_to_generalizedtime, [ :pointer, :pointer ], :pointer
  attach_function :i2d_ASN1_SET, [ :pointer, :pointer, :pointer, :int, :int, :int ], :int
  attach_function :d2i_ASN1_SET, [ :pointer, :pointer, :long, :pointer, callback([ :pointer ], :void), :int, :int ], :pointer
  attach_function :i2a_ASN1_INTEGER, [ :pointer, :pointer ], :int
  attach_function :a2i_ASN1_INTEGER, [ :pointer, :pointer, :string, :int ], :int
  attach_function :i2a_ASN1_ENUMERATED, [ :pointer, :pointer ], :int
  attach_function :a2i_ASN1_ENUMERATED, [ :pointer, :pointer, :string, :int ], :int
  attach_function :i2a_ASN1_OBJECT, [ :pointer, :pointer ], :int
  attach_function :a2i_ASN1_STRING, [ :pointer, :pointer, :string, :int ], :int
  attach_function :i2a_ASN1_STRING, [ :pointer, :pointer, :int ], :int
  attach_function :i2t_ASN1_OBJECT, [ :string, :int, :pointer ], :int
  attach_function :a2d_ASN1_OBJECT, [ :pointer, :int, :string, :int ], :int
  attach_function :ASN1_OBJECT_create, [ :int, :pointer, :int, :string, :string ], :pointer
  attach_function :ASN1_INTEGER_set, [ :pointer, :long ], :int
  attach_function :ASN1_INTEGER_get, [ :pointer ], :long
  attach_function :BN_to_ASN1_INTEGER, [ :pointer, :pointer ], :pointer
  attach_function :ASN1_INTEGER_to_BN, [ :pointer, :pointer ], :pointer
  attach_function :ASN1_ENUMERATED_set, [ :pointer, :long ], :int
  attach_function :ASN1_ENUMERATED_get, [ :pointer ], :long
  attach_function :BN_to_ASN1_ENUMERATED, [ :pointer, :pointer ], :pointer
  attach_function :ASN1_ENUMERATED_to_BN, [ :pointer, :pointer ], :pointer
  attach_function :ASN1_PRINTABLE_type, [ :pointer, :int ], :int
  attach_function :i2d_ASN1_bytes, [ :pointer, :pointer, :int, :int ], :int
  attach_function :d2i_ASN1_bytes, [ :pointer, :pointer, :long, :int, :int ], :pointer
  attach_function :ASN1_tag2bit, [ :int ], :ulong
  attach_function :d2i_ASN1_type_bytes, [ :pointer, :pointer, :long, :int ], :pointer
  attach_function :asn1_Finish, [ :pointer ], :int
  attach_function :asn1_const_Finish, [ :pointer ], :int
  attach_function :ASN1_get_object, [ :pointer, :pointer, :pointer, :pointer, :long ], :int
  attach_function :ASN1_check_infinite_end, [ :pointer, :long ], :int
  attach_function :ASN1_const_check_infinite_end, [ :pointer, :long ], :int
  attach_function :ASN1_put_object, [ :pointer, :int, :int, :int, :int ], :void
  attach_function :ASN1_put_eoc, [ :pointer ], :int
  attach_function :ASN1_object_size, [ :int, :int, :int ], :int
  attach_function :ASN1_dup, [ :pointer, :pointer, :string ], :pointer
  attach_function :ASN1_item_dup, [ :pointer, :pointer ], :pointer
  attach_function :ASN1_d2i_fp, [ callback([  ], :pointer), :pointer, :pointer, :pointer ], :pointer
  attach_function :ASN1_item_d2i_fp, [ :pointer, :pointer, :pointer ], :pointer
  attach_function :ASN1_i2d_fp, [ :pointer, :pointer, :pointer ], :int
  attach_function :ASN1_item_i2d_fp, [ :pointer, :pointer, :pointer ], :int
  attach_function :ASN1_STRING_print_ex_fp, [ :pointer, :pointer, :ulong ], :int
  attach_function :ASN1_STRING_to_UTF8, [ :pointer, :pointer ], :int
  attach_function :ASN1_d2i_bio, [ callback([  ], :pointer), :pointer, :pointer, :pointer ], :pointer
  attach_function :ASN1_item_d2i_bio, [ :pointer, :pointer, :pointer ], :pointer
  attach_function :ASN1_i2d_bio, [ :pointer, :pointer, :pointer ], :int
  attach_function :ASN1_item_i2d_bio, [ :pointer, :pointer, :pointer ], :int
  attach_function :ASN1_UTCTIME_print, [ :pointer, :pointer ], :int
  attach_function :ASN1_GENERALIZEDTIME_print, [ :pointer, :pointer ], :int
  attach_function :ASN1_TIME_print, [ :pointer, :pointer ], :int
  attach_function :ASN1_STRING_print, [ :pointer, :pointer ], :int
  attach_function :ASN1_STRING_print_ex, [ :pointer, :pointer, :ulong ], :int
  attach_function :ASN1_parse, [ :pointer, :pointer, :long, :int ], :int
  attach_function :ASN1_parse_dump, [ :pointer, :pointer, :long, :int, :int ], :int
  attach_function :ASN1_tag2str, [ :int ], :string
  attach_function :i2d_ASN1_HEADER, [ :pointer, :pointer ], :int
  attach_function :d2i_ASN1_HEADER, [ :pointer, :pointer, :long ], :pointer
  attach_function :ASN1_HEADER_new, [  ], :pointer
  attach_function :ASN1_HEADER_free, [ :pointer ], :void
  attach_function :ASN1_UNIVERSALSTRING_to_string, [ :pointer ], :int
  attach_function :X509_asn1_meth, [  ], :pointer
  attach_function :RSAPrivateKey_asn1_meth, [  ], :pointer
  attach_function :ASN1_IA5STRING_asn1_meth, [  ], :pointer
  attach_function :ASN1_BIT_STRING_asn1_meth, [  ], :pointer
  attach_function :ASN1_TYPE_set_octetstring, [ :pointer, :pointer, :int ], :int
  attach_function :ASN1_TYPE_get_octetstring, [ :pointer, :pointer, :int ], :int
  attach_function :ASN1_TYPE_set_int_octetstring, [ :pointer, :long, :pointer, :int ], :int
  attach_function :ASN1_TYPE_get_int_octetstring, [ :pointer, :pointer, :pointer, :int ], :int
  attach_function :ASN1_seq_unpack, [ :pointer, :int, :pointer, callback([ :pointer ], :void) ], :pointer
  attach_function :ASN1_seq_pack, [ :pointer, :pointer, :pointer, :pointer ], :pointer
  attach_function :ASN1_unpack_string, [ :pointer, :pointer ], :pointer
  attach_function :ASN1_item_unpack, [ :pointer, :pointer ], :pointer
  attach_function :ASN1_pack_string, [ :pointer, :pointer, :pointer ], :pointer
  attach_function :ASN1_item_pack, [ :pointer, :pointer, :pointer ], :pointer
  attach_function :ASN1_STRING_set_default_mask, [ :ulong ], :void
  attach_function :ASN1_STRING_set_default_mask_asc, [ :string ], :int
  attach_function :ASN1_STRING_get_default_mask, [  ], :ulong
  attach_function :ASN1_mbstring_copy, [ :pointer, :pointer, :int, :int, :ulong ], :int
  attach_function :ASN1_mbstring_ncopy, [ :pointer, :pointer, :int, :int, :ulong, :long, :long ], :int
  attach_function :ASN1_STRING_set_by_NID, [ :pointer, :pointer, :int, :int, :int ], :pointer
  attach_function :ASN1_STRING_TABLE_get, [ :int ], :pointer
  attach_function :ASN1_STRING_TABLE_add, [ :int, :long, :long, :ulong, :ulong ], :int
  attach_function :ASN1_STRING_TABLE_cleanup, [  ], :void
  attach_function :ASN1_item_new, [ :pointer ], :pointer
  attach_function :ASN1_item_free, [ :pointer, :pointer ], :void
  attach_function :ASN1_item_d2i, [ :pointer, :pointer, :long, :pointer ], :pointer
  attach_function :ASN1_item_i2d, [ :pointer, :pointer, :pointer ], :int
  attach_function :ASN1_item_ndef_i2d, [ :pointer, :pointer, :pointer ], :int
  attach_function :ASN1_add_oid_module, [  ], :void
  attach_function :ASN1_generate_nconf, [ :string, :pointer ], :pointer
  attach_function :ASN1_generate_v3, [ :string, :pointer ], :pointer
  attach_function :asn1_output_data_fn, [ :pointer, :pointer, :pointer, :int, :pointer ], :int
  attach_function :int_smime_write_ASN1, [ :pointer, :pointer, :pointer, :int, :int, :int, :pointer, :pointer, :pointer ], :int
  attach_function :SMIME_read_ASN1, [ :pointer, :pointer, :pointer ], :pointer
  attach_function :ERR_load_ASN1_strings, [  ], :void
  ASN1_F_A2D_ASN1_OBJECT = 100
  ASN1_F_A2I_ASN1_ENUMERATED = 101
  ASN1_F_A2I_ASN1_INTEGER = 102
  ASN1_F_A2I_ASN1_STRING = 103
  ASN1_F_APPEND_EXP = 176
  ASN1_F_ASN1_BIT_STRING_SET_BIT = 183
  ASN1_F_ASN1_CB = 177
  ASN1_F_ASN1_CHECK_TLEN = 104
  ASN1_F_ASN1_COLLATE_PRIMITIVE = 105
  ASN1_F_ASN1_COLLECT = 106
  ASN1_F_ASN1_D2I_EX_PRIMITIVE = 108
  ASN1_F_ASN1_D2I_FP = 109
  ASN1_F_ASN1_D2I_READ_BIO = 107
  ASN1_F_ASN1_DIGEST = 184
  ASN1_F_ASN1_DO_ADB = 110
  ASN1_F_ASN1_DUP = 111
  ASN1_F_ASN1_ENUMERATED_SET = 112
  ASN1_F_ASN1_ENUMERATED_TO_BN = 113
  ASN1_F_ASN1_EX_C2I = 204
  ASN1_F_ASN1_FIND_END = 190
  ASN1_F_ASN1_GENERALIZEDTIME_SET = 185
  ASN1_F_ASN1_GENERATE_V3 = 178
  ASN1_F_ASN1_GET_OBJECT = 114
  ASN1_F_ASN1_HEADER_NEW = 115
  ASN1_F_ASN1_I2D_BIO = 116
  ASN1_F_ASN1_I2D_FP = 117
  ASN1_F_ASN1_INTEGER_SET = 118
  ASN1_F_ASN1_INTEGER_TO_BN = 119
  ASN1_F_ASN1_ITEM_D2I_FP = 206
  ASN1_F_ASN1_ITEM_DUP = 191
  ASN1_F_ASN1_ITEM_EX_COMBINE_NEW = 121
  ASN1_F_ASN1_ITEM_EX_D2I = 120
  ASN1_F_ASN1_ITEM_I2D_BIO = 192
  ASN1_F_ASN1_ITEM_I2D_FP = 193
  ASN1_F_ASN1_ITEM_PACK = 198
  ASN1_F_ASN1_ITEM_SIGN = 195
  ASN1_F_ASN1_ITEM_UNPACK = 199
  ASN1_F_ASN1_ITEM_VERIFY = 197
  ASN1_F_ASN1_MBSTRING_NCOPY = 122
  ASN1_F_ASN1_OBJECT_NEW = 123
  ASN1_F_ASN1_OUTPUT_DATA = 207
  ASN1_F_ASN1_PACK_STRING = 124
  ASN1_F_ASN1_PCTX_NEW = 205
  ASN1_F_ASN1_PKCS5_PBE_SET = 125
  ASN1_F_ASN1_SEQ_PACK = 126
  ASN1_F_ASN1_SEQ_UNPACK = 127
  ASN1_F_ASN1_SIGN = 128
  ASN1_F_ASN1_STR2TYPE = 179
  ASN1_F_ASN1_STRING_SET = 186
  ASN1_F_ASN1_STRING_TABLE_ADD = 129
  ASN1_F_ASN1_STRING_TYPE_NEW = 130
  ASN1_F_ASN1_TEMPLATE_EX_D2I = 132
  ASN1_F_ASN1_TEMPLATE_NEW = 133
  ASN1_F_ASN1_TEMPLATE_NOEXP_D2I = 131
  ASN1_F_ASN1_TIME_SET = 175
  ASN1_F_ASN1_TYPE_GET_INT_OCTETSTRING = 134
  ASN1_F_ASN1_TYPE_GET_OCTETSTRING = 135
  ASN1_F_ASN1_UNPACK_STRING = 136
  ASN1_F_ASN1_UTCTIME_SET = 187
  ASN1_F_ASN1_VERIFY = 137
  ASN1_F_B64_READ_ASN1 = 208
  ASN1_F_B64_WRITE_ASN1 = 209
  ASN1_F_BITSTR_CB = 180
  ASN1_F_BN_TO_ASN1_ENUMERATED = 138
  ASN1_F_BN_TO_ASN1_INTEGER = 139
  ASN1_F_C2I_ASN1_BIT_STRING = 189
  ASN1_F_C2I_ASN1_INTEGER = 194
  ASN1_F_C2I_ASN1_OBJECT = 196
  ASN1_F_COLLECT_DATA = 140
  ASN1_F_D2I_ASN1_BIT_STRING = 141
  ASN1_F_D2I_ASN1_BOOLEAN = 142
  ASN1_F_D2I_ASN1_BYTES = 143
  ASN1_F_D2I_ASN1_GENERALIZEDTIME = 144
  ASN1_F_D2I_ASN1_HEADER = 145
  ASN1_F_D2I_ASN1_INTEGER = 146
  ASN1_F_D2I_ASN1_OBJECT = 147
  ASN1_F_D2I_ASN1_SET = 148
  ASN1_F_D2I_ASN1_TYPE_BYTES = 149
  ASN1_F_D2I_ASN1_UINTEGER = 150
  ASN1_F_D2I_ASN1_UTCTIME = 151
  ASN1_F_D2I_NETSCAPE_RSA = 152
  ASN1_F_D2I_NETSCAPE_RSA_2 = 153
  ASN1_F_D2I_PRIVATEKEY = 154
  ASN1_F_D2I_PUBLICKEY = 155
  ASN1_F_D2I_RSA_NET = 200
  ASN1_F_D2I_RSA_NET_2 = 201
  ASN1_F_D2I_X509 = 156
  ASN1_F_D2I_X509_CINF = 157
  ASN1_F_D2I_X509_PKEY = 159
  ASN1_F_I2D_ASN1_SET = 188
  ASN1_F_I2D_ASN1_TIME = 160
  ASN1_F_I2D_DSA_PUBKEY = 161
  ASN1_F_I2D_EC_PUBKEY = 181
  ASN1_F_I2D_PRIVATEKEY = 163
  ASN1_F_I2D_PUBLICKEY = 164
  ASN1_F_I2D_RSA_NET = 162
  ASN1_F_I2D_RSA_PUBKEY = 165
  ASN1_F_LONG_C2I = 166
  ASN1_F_OID_MODULE_INIT = 174
  ASN1_F_PARSE_TAGGING = 182
  ASN1_F_PKCS5_PBE2_SET = 167
  ASN1_F_PKCS5_PBE_SET = 202
  ASN1_F_SMIME_READ_ASN1 = 210
  ASN1_F_SMIME_TEXT = 211
  ASN1_F_X509_CINF_NEW = 168
  ASN1_F_X509_CRL_ADD0_REVOKED = 169
  ASN1_F_X509_INFO_NEW = 170
  ASN1_F_X509_NAME_ENCODE = 203
  ASN1_F_X509_NAME_EX_D2I = 158
  ASN1_F_X509_NAME_EX_NEW = 171
  ASN1_F_X509_NEW = 172
  ASN1_F_X509_PKEY_NEW = 173
  ASN1_R_ADDING_OBJECT = 171
  ASN1_R_ASN1_PARSE_ERROR = 198
  ASN1_R_ASN1_SIG_PARSE_ERROR = 199
  ASN1_R_AUX_ERROR = 100
  ASN1_R_BAD_CLASS = 101
  ASN1_R_BAD_OBJECT_HEADER = 102
  ASN1_R_BAD_PASSWORD_READ = 103
  ASN1_R_BAD_TAG = 104
  ASN1_R_BMPSTRING_IS_WRONG_LENGTH = 210
  ASN1_R_BN_LIB = 105
  ASN1_R_BOOLEAN_IS_WRONG_LENGTH = 106
  ASN1_R_BUFFER_TOO_SMALL = 107
  ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER = 108
  ASN1_R_DATA_IS_WRONG = 109
  ASN1_R_DECODE_ERROR = 110
  ASN1_R_DECODING_ERROR = 111
  ASN1_R_DEPTH_EXCEEDED = 174
  ASN1_R_ENCODE_ERROR = 112
  ASN1_R_ERROR_GETTING_TIME = 173
  ASN1_R_ERROR_LOADING_SECTION = 172
  ASN1_R_ERROR_PARSING_SET_ELEMENT = 113
  ASN1_R_ERROR_SETTING_CIPHER_PARAMS = 114
  ASN1_R_EXPECTING_AN_INTEGER = 115
  ASN1_R_EXPECTING_AN_OBJECT = 116
  ASN1_R_EXPECTING_A_BOOLEAN = 117
  ASN1_R_EXPECTING_A_TIME = 118
  ASN1_R_EXPLICIT_LENGTH_MISMATCH = 119
  ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED = 120
  ASN1_R_FIELD_MISSING = 121
  ASN1_R_FIRST_NUM_TOO_LARGE = 122
  ASN1_R_HEADER_TOO_LONG = 123
  ASN1_R_ILLEGAL_BITSTRING_FORMAT = 175
  ASN1_R_ILLEGAL_BOOLEAN = 176
  ASN1_R_ILLEGAL_CHARACTERS = 124
  ASN1_R_ILLEGAL_FORMAT = 177
  ASN1_R_ILLEGAL_HEX = 178
  ASN1_R_ILLEGAL_IMPLICIT_TAG = 179
  ASN1_R_ILLEGAL_INTEGER = 180
  ASN1_R_ILLEGAL_NESTED_TAGGING = 181
  ASN1_R_ILLEGAL_NULL = 125
  ASN1_R_ILLEGAL_NULL_VALUE = 182
  ASN1_R_ILLEGAL_OBJECT = 183
  ASN1_R_ILLEGAL_OPTIONAL_ANY = 126
  ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE = 170
  ASN1_R_ILLEGAL_TAGGED_ANY = 127
  ASN1_R_ILLEGAL_TIME_VALUE = 184
  ASN1_R_INTEGER_NOT_ASCII_FORMAT = 185
  ASN1_R_INTEGER_TOO_LARGE_FOR_LONG = 128
  ASN1_R_INVALID_BMPSTRING_LENGTH = 129
  ASN1_R_INVALID_DIGIT = 130
  ASN1_R_INVALID_MIME_TYPE = 200
  ASN1_R_INVALID_MODIFIER = 186
  ASN1_R_INVALID_NUMBER = 187
  ASN1_R_INVALID_OBJECT_ENCODING = 212
  ASN1_R_INVALID_SEPARATOR = 131
  ASN1_R_INVALID_TIME_FORMAT = 132
  ASN1_R_INVALID_UNIVERSALSTRING_LENGTH = 133
  ASN1_R_INVALID_UTF8STRING = 134
  ASN1_R_IV_TOO_LARGE = 135
  ASN1_R_LENGTH_ERROR = 136
  ASN1_R_LIST_ERROR = 188
  ASN1_R_MIME_NO_CONTENT_TYPE = 201
  ASN1_R_MIME_PARSE_ERROR = 202
  ASN1_R_MIME_SIG_PARSE_ERROR = 203
  ASN1_R_MISSING_EOC = 137
  ASN1_R_MISSING_SECOND_NUMBER = 138
  ASN1_R_MISSING_VALUE = 189
  ASN1_R_MSTRING_NOT_UNIVERSAL = 139
  ASN1_R_MSTRING_WRONG_TAG = 140
  ASN1_R_NESTED_ASN1_STRING = 197
  ASN1_R_NON_HEX_CHARACTERS = 141
  ASN1_R_NOT_ASCII_FORMAT = 190
  ASN1_R_NOT_ENOUGH_DATA = 142
  ASN1_R_NO_CONTENT_TYPE = 204
  ASN1_R_NO_MATCHING_CHOICE_TYPE = 143
  ASN1_R_NO_MULTIPART_BODY_FAILURE = 205
  ASN1_R_NO_MULTIPART_BOUNDARY = 206
  ASN1_R_NO_SIG_CONTENT_TYPE = 207
  ASN1_R_NULL_IS_WRONG_LENGTH = 144
  ASN1_R_OBJECT_NOT_ASCII_FORMAT = 191
  ASN1_R_ODD_NUMBER_OF_CHARS = 145
  ASN1_R_PRIVATE_KEY_HEADER_MISSING = 146
  ASN1_R_SECOND_NUMBER_TOO_LARGE = 147
  ASN1_R_SEQUENCE_LENGTH_MISMATCH = 148
  ASN1_R_SEQUENCE_NOT_CONSTRUCTED = 149
  ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG = 192
  ASN1_R_SHORT_LINE = 150
  ASN1_R_SIG_INVALID_MIME_TYPE = 208
  ASN1_R_STREAMING_NOT_SUPPORTED = 209
  ASN1_R_STRING_TOO_LONG = 151
  ASN1_R_STRING_TOO_SHORT = 152
  ASN1_R_TAG_VALUE_TOO_HIGH = 153
  ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD = 154
  ASN1_R_TIME_NOT_ASCII_FORMAT = 193
  ASN1_R_TOO_LONG = 155
  ASN1_R_TYPE_NOT_CONSTRUCTED = 156
  ASN1_R_UNABLE_TO_DECODE_RSA_KEY = 157
  ASN1_R_UNABLE_TO_DECODE_RSA_PRIVATE_KEY = 158
  ASN1_R_UNEXPECTED_EOC = 159
  ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH = 211
  ASN1_R_UNKNOWN_FORMAT = 160
  ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM = 161
  ASN1_R_UNKNOWN_OBJECT_TYPE = 162
  ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE = 163
  ASN1_R_UNKNOWN_TAG = 194
  ASN1_R_UNKOWN_FORMAT = 195
  ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE = 164
  ASN1_R_UNSUPPORTED_CIPHER = 165
  ASN1_R_UNSUPPORTED_ENCRYPTION_ALGORITHM = 166
  ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE = 167
  ASN1_R_UNSUPPORTED_TYPE = 196
  ASN1_R_WRONG_TAG = 168
  ASN1_R_WRONG_TYPE = 169
  class ASN1TEMPLATESt < FFI::Struct
    layout(
           :flags, :ulong,
           :tag, :long,
           :offset, :ulong,
           :field_name, :pointer,
           :item, :pointer
    )
    def field_name=(str)
      @field_name = FFI::MemoryPointer.from_string(str)
      self[:field_name] = @field_name
    end
    def field_name
      @field_name.get_string(0)
    end

  end
  class ASN1ADBSt < FFI::Struct
    layout(
           :flags, :ulong,
           :offset, :ulong,
           :app_items, :pointer,
           :tbl, :pointer,
           :tblcount, :long,
           :default_tt, :pointer,
           :null_tt, :pointer
    )
  end
  class ASN1ADBTABLESt < FFI::Struct
    layout(
           :value, :long,
           :tt, ASN1TEMPLATESt
    )
  end
  ASN1_TFLG_OPTIONAL = (0x1)
  ASN1_TFLG_SET_OF = (0x1 << 1)
  ASN1_TFLG_SEQUENCE_OF = (0x2 << 1)
  ASN1_TFLG_SET_ORDER = (0x3 << 1)
  ASN1_TFLG_SK_MASK = (0x3 << 1)
  ASN1_TFLG_IMPTAG = (0x1 << 3)
  ASN1_TFLG_EXPTAG = (0x2 << 3)
  ASN1_TFLG_TAG_MASK = (0x3 << 3)
  ASN1_TFLG_UNIVERSAL = (0x0 << 6)
  ASN1_TFLG_APPLICATION = (0x1 << 6)
  ASN1_TFLG_CONTEXT = (0x2 << 6)
  ASN1_TFLG_PRIVATE = (0x3 << 6)
  ASN1_TFLG_TAG_CLASS = (0x3 << 6)
  ASN1_TFLG_ADB_MASK = (0x3 << 8)
  ASN1_TFLG_ADB_OID = (0x1 << 8)
  ASN1_TFLG_ADB_INT = (0x1 << 9)
  ASN1_TFLG_COMBINE = (0x1 << 10)
  ASN1_TFLG_NDEF = (0x1 << 11)
  class ASN1ITEMSt < FFI::Struct
    layout(
           :itype, :char,
           :utype, :long,
           :templates, :pointer,
           :tcount, :long,
           :funcs, :pointer,
           :size, :long,
           :sname, :pointer
    )
    def sname=(str)
      @sname = FFI::MemoryPointer.from_string(str)
      self[:sname] = @sname
    end
    def sname
      @sname.get_string(0)
    end

  end
  ASN1_ITYPE_PRIMITIVE = 0x0
  ASN1_ITYPE_SEQUENCE = 0x1
  ASN1_ITYPE_CHOICE = 0x2
  ASN1_ITYPE_COMPAT = 0x3
  ASN1_ITYPE_EXTERN = 0x4
  ASN1_ITYPE_MSTRING = 0x5
  ASN1_ITYPE_NDEF_SEQUENCE = 0x6
  class ASN1TLCSt < FFI::Struct
    layout(
           :valid, :char,
           :ret, :int,
           :plen, :long,
           :ptag, :int,
           :pclass, :int,
           :hdrlen, :int
    )
  end
  attach_function :ASN1_new_func, [  ], :pointer
  attach_function :ASN1_free_func, [ :pointer ], :void
  attach_function :ASN1_d2i_func, [ :pointer, :pointer, :long ], :pointer
  attach_function :ASN1_i2d_func, [ :pointer, :pointer ], :int
  attach_function :ASN1_ex_d2i, [ :pointer, :pointer, :long, :pointer, :int, :int, :char, :pointer ], :int
  attach_function :ASN1_ex_i2d, [ :pointer, :pointer, :pointer, :int, :int ], :int
  attach_function :ASN1_ex_new_func, [ :pointer, :pointer ], :int
  attach_function :ASN1_ex_free_func, [ :pointer, :pointer ], :void
  attach_function :ASN1_primitive_i2c, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :ASN1_primitive_c2i, [ :pointer, :pointer, :int, :int, :string, :pointer ], :int
  class ASN1COMPATFUNCSSt < FFI::Struct
    layout(
           :asn1_new, :pointer,
           :asn1_free, :pointer,
           :asn1_d2i, :pointer,
           :asn1_i2d, :pointer
    )
  end
  class ASN1EXTERNFUNCSSt < FFI::Struct
    layout(
           :app_data, :pointer,
           :asn1_ex_new, :pointer,
           :asn1_ex_free, :pointer,
           :asn1_ex_clear, :pointer,
           :asn1_ex_d2i, :pointer,
           :asn1_ex_i2d, :pointer
    )
  end
  class ASN1PRIMITIVEFUNCSSt < FFI::Struct
    layout(
           :app_data, :pointer,
           :flags, :ulong,
           :prim_new, :pointer,
           :prim_free, :pointer,
           :prim_clear, :pointer,
           :prim_c2i, :pointer,
           :prim_i2c, :pointer
    )
  end
  attach_function :ASN1_aux_cb, [ :int, :pointer, :pointer ], :int
  class ASN1AUXSt < FFI::Struct
    layout(
           :app_data, :pointer,
           :flags, :int,
           :ref_offset, :int,
           :ref_lock, :int,
           :asn1_cb, :pointer,
           :enc_offset, :int
    )
  end
  ASN1_AFLG_REFCOUNT = 1
  ASN1_AFLG_ENCODING = 2
  ASN1_AFLG_BROKEN = 4
  ASN1_OP_NEW_PRE = 0
  ASN1_OP_NEW_POST = 1
  ASN1_OP_FREE_PRE = 2
  ASN1_OP_FREE_POST = 3
  ASN1_OP_D2I_PRE = 4
  ASN1_OP_D2I_POST = 5
  ASN1_OP_I2D_PRE = 6
  ASN1_OP_I2D_POST = 7
  attach_function :ASN1_item_ex_new, [ :pointer, :pointer ], :int
  attach_function :ASN1_item_ex_free, [ :pointer, :pointer ], :void
  attach_function :ASN1_template_new, [ :pointer, :pointer ], :int
  attach_function :ASN1_primitive_new, [ :pointer, :pointer ], :int
  attach_function :ASN1_template_free, [ :pointer, :pointer ], :void
  attach_function :ASN1_template_d2i, [ :pointer, :pointer, :long, :pointer ], :int
  attach_function :ASN1_item_ex_d2i, [ :pointer, :pointer, :long, :pointer, :int, :int, :char, :pointer ], :int
  attach_function :ASN1_item_ex_i2d, [ :pointer, :pointer, :pointer, :int, :int ], :int
  attach_function :ASN1_template_i2d, [ :pointer, :pointer, :pointer ], :int
  attach_function :ASN1_primitive_free, [ :pointer, :pointer ], :void
  attach_function :asn1_ex_i2c, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :asn1_ex_c2i, [ :pointer, :pointer, :int, :int, :string, :pointer ], :int
  attach_function :asn1_get_choice_selector, [ :pointer, :pointer ], :int
  attach_function :asn1_set_choice_selector, [ :pointer, :int, :pointer ], :int
  attach_function :asn1_get_field_ptr, [ :pointer, :pointer ], :pointer
  attach_function :asn1_do_adb, [ :pointer, :pointer, :int ], :pointer
  attach_function :asn1_do_lock, [ :pointer, :int, :pointer ], :int
  attach_function :asn1_enc_init, [ :pointer, :pointer ], :void
  attach_function :asn1_enc_free, [ :pointer, :pointer ], :void
  attach_function :asn1_enc_restore, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :asn1_enc_save, [ :pointer, :pointer, :int, :pointer ], :int
  EVP_MAX_MD_SIZE = 64
  EVP_MAX_KEY_LENGTH = 32
  EVP_MAX_IV_LENGTH = 16
  EVP_MAX_BLOCK_LENGTH = 32
  PKCS5_SALT_LEN = 8
  PKCS5_DEFAULT_ITER = 2048
  SN_undef = UNDEF
  LN_undef = undefined
  NID_undef = 0
  OBJ_undef = 0
  SN_itu_t = ITU-T
  LN_itu_t = itu-t
  NID_itu_t = 645
  OBJ_itu_t = 0
  NID_ccitt = 404
  OBJ_ccitt = 0
  SN_iso = ISO
  LN_iso = iso
  NID_iso = 181
  OBJ_iso = 1
  SN_joint_iso_itu_t = JOINT-ISO-ITU-T
  LN_joint_iso_itu_t = joint-iso-itu-t
  NID_joint_iso_itu_t = 646
  OBJ_joint_iso_itu_t = 2
  NID_joint_iso_ccitt = 393
  OBJ_joint_iso_ccitt = 2
  SN_member_body = member-body
  LN_member_body = ISO Member Body
  NID_member_body = 182
  SN_identified_organization = identified-organization
  NID_identified_organization = 676
  SN_hmac_md5 = HMAC-MD5
  LN_hmac_md5 = hmac-md5
  NID_hmac_md5 = 780
  SN_hmac_sha1 = HMAC-SHA1
  LN_hmac_sha1 = hmac-sha1
  NID_hmac_sha1 = 781
  SN_certicom_arc = certicom-arc
  NID_certicom_arc = 677
  SN_international_organizations = international-organizations
  LN_international_organizations = International Organizations
  NID_international_organizations = 647
  SN_wap = wap
  NID_wap = 678
  SN_wap_wsg = wap-wsg
  NID_wap_wsg = 679
  SN_selected_attribute_types = selected-attribute-types
  LN_selected_attribute_types = Selected Attribute Types
  NID_selected_attribute_types = 394
  SN_clearance = clearance
  NID_clearance = 395
  SN_ISO_US = ISO-US
  LN_ISO_US = ISO US Member Body
  NID_ISO_US = 183
  SN_X9_57 = X9-57
  LN_X9_57 = X9.57
  NID_X9_57 = 184
  SN_X9cm = X9cm
  LN_X9cm = X9.57 CM ?
  NID_X9cm = 185
  SN_dsa = DSA
  LN_dsa = dsaEncryption
  NID_dsa = 116
  SN_dsaWithSHA1 = DSA-SHA1
  LN_dsaWithSHA1 = dsaWithSHA1
  NID_dsaWithSHA1 = 113
  SN_ansi_X9_62 = ansi-X9-62
  LN_ansi_X9_62 = ANSI X9.62
  NID_ansi_X9_62 = 405
  SN_X9_62_prime_field = prime-field
  NID_X9_62_prime_field = 406
  SN_X9_62_characteristic_two_field = characteristic-two-field
  NID_X9_62_characteristic_two_field = 407
  SN_X9_62_id_characteristic_two_basis = id-characteristic-two-basis
  NID_X9_62_id_characteristic_two_basis = 680
  SN_X9_62_onBasis = onBasis
  NID_X9_62_onBasis = 681
  SN_X9_62_tpBasis = tpBasis
  NID_X9_62_tpBasis = 682
  SN_X9_62_ppBasis = ppBasis
  NID_X9_62_ppBasis = 683
  SN_X9_62_id_ecPublicKey = id-ecPublicKey
  NID_X9_62_id_ecPublicKey = 408
  SN_X9_62_c2pnb163v1 = c2pnb163v1
  NID_X9_62_c2pnb163v1 = 684
  SN_X9_62_c2pnb163v2 = c2pnb163v2
  NID_X9_62_c2pnb163v2 = 685
  SN_X9_62_c2pnb163v3 = c2pnb163v3
  NID_X9_62_c2pnb163v3 = 686
  SN_X9_62_c2pnb176v1 = c2pnb176v1
  NID_X9_62_c2pnb176v1 = 687
  SN_X9_62_c2tnb191v1 = c2tnb191v1
  NID_X9_62_c2tnb191v1 = 688
  SN_X9_62_c2tnb191v2 = c2tnb191v2
  NID_X9_62_c2tnb191v2 = 689
  SN_X9_62_c2tnb191v3 = c2tnb191v3
  NID_X9_62_c2tnb191v3 = 690
  SN_X9_62_c2onb191v4 = c2onb191v4
  NID_X9_62_c2onb191v4 = 691
  SN_X9_62_c2onb191v5 = c2onb191v5
  NID_X9_62_c2onb191v5 = 692
  SN_X9_62_c2pnb208w1 = c2pnb208w1
  NID_X9_62_c2pnb208w1 = 693
  SN_X9_62_c2tnb239v1 = c2tnb239v1
  NID_X9_62_c2tnb239v1 = 694
  SN_X9_62_c2tnb239v2 = c2tnb239v2
  NID_X9_62_c2tnb239v2 = 695
  SN_X9_62_c2tnb239v3 = c2tnb239v3
  NID_X9_62_c2tnb239v3 = 696
  SN_X9_62_c2onb239v4 = c2onb239v4
  NID_X9_62_c2onb239v4 = 697
  SN_X9_62_c2onb239v5 = c2onb239v5
  NID_X9_62_c2onb239v5 = 698
  SN_X9_62_c2pnb272w1 = c2pnb272w1
  NID_X9_62_c2pnb272w1 = 699
  SN_X9_62_c2pnb304w1 = c2pnb304w1
  NID_X9_62_c2pnb304w1 = 700
  SN_X9_62_c2tnb359v1 = c2tnb359v1
  NID_X9_62_c2tnb359v1 = 701
  SN_X9_62_c2pnb368w1 = c2pnb368w1
  NID_X9_62_c2pnb368w1 = 702
  SN_X9_62_c2tnb431r1 = c2tnb431r1
  NID_X9_62_c2tnb431r1 = 703
  SN_X9_62_prime192v1 = prime192v1
  NID_X9_62_prime192v1 = 409
  SN_X9_62_prime192v2 = prime192v2
  NID_X9_62_prime192v2 = 410
  SN_X9_62_prime192v3 = prime192v3
  NID_X9_62_prime192v3 = 411
  SN_X9_62_prime239v1 = prime239v1
  NID_X9_62_prime239v1 = 412
  SN_X9_62_prime239v2 = prime239v2
  NID_X9_62_prime239v2 = 413
  SN_X9_62_prime239v3 = prime239v3
  NID_X9_62_prime239v3 = 414
  SN_X9_62_prime256v1 = prime256v1
  NID_X9_62_prime256v1 = 415
  SN_ecdsa_with_SHA1 = ecdsa-with-SHA1
  NID_ecdsa_with_SHA1 = 416
  SN_ecdsa_with_Recommended = ecdsa-with-Recommended
  NID_ecdsa_with_Recommended = 791
  SN_ecdsa_with_Specified = ecdsa-with-Specified
  NID_ecdsa_with_Specified = 792
  SN_ecdsa_with_SHA224 = ecdsa-with-SHA224
  NID_ecdsa_with_SHA224 = 793
  SN_ecdsa_with_SHA256 = ecdsa-with-SHA256
  NID_ecdsa_with_SHA256 = 794
  SN_ecdsa_with_SHA384 = ecdsa-with-SHA384
  NID_ecdsa_with_SHA384 = 795
  SN_ecdsa_with_SHA512 = ecdsa-with-SHA512
  NID_ecdsa_with_SHA512 = 796
  SN_secp112r1 = secp112r1
  NID_secp112r1 = 704
  SN_secp112r2 = secp112r2
  NID_secp112r2 = 705
  SN_secp128r1 = secp128r1
  NID_secp128r1 = 706
  SN_secp128r2 = secp128r2
  NID_secp128r2 = 707
  SN_secp160k1 = secp160k1
  NID_secp160k1 = 708
  SN_secp160r1 = secp160r1
  NID_secp160r1 = 709
  SN_secp160r2 = secp160r2
  NID_secp160r2 = 710
  SN_secp192k1 = secp192k1
  NID_secp192k1 = 711
  SN_secp224k1 = secp224k1
  NID_secp224k1 = 712
  SN_secp224r1 = secp224r1
  NID_secp224r1 = 713
  SN_secp256k1 = secp256k1
  NID_secp256k1 = 714
  SN_secp384r1 = secp384r1
  NID_secp384r1 = 715
  SN_secp521r1 = secp521r1
  NID_secp521r1 = 716
  SN_sect113r1 = sect113r1
  NID_sect113r1 = 717
  SN_sect113r2 = sect113r2
  NID_sect113r2 = 718
  SN_sect131r1 = sect131r1
  NID_sect131r1 = 719
  SN_sect131r2 = sect131r2
  NID_sect131r2 = 720
  SN_sect163k1 = sect163k1
  NID_sect163k1 = 721
  SN_sect163r1 = sect163r1
  NID_sect163r1 = 722
  SN_sect163r2 = sect163r2
  NID_sect163r2 = 723
  SN_sect193r1 = sect193r1
  NID_sect193r1 = 724
  SN_sect193r2 = sect193r2
  NID_sect193r2 = 725
  SN_sect233k1 = sect233k1
  NID_sect233k1 = 726
  SN_sect233r1 = sect233r1
  NID_sect233r1 = 727
  SN_sect239k1 = sect239k1
  NID_sect239k1 = 728
  SN_sect283k1 = sect283k1
  NID_sect283k1 = 729
  SN_sect283r1 = sect283r1
  NID_sect283r1 = 730
  SN_sect409k1 = sect409k1
  NID_sect409k1 = 731
  SN_sect409r1 = sect409r1
  NID_sect409r1 = 732
  SN_sect571k1 = sect571k1
  NID_sect571k1 = 733
  SN_sect571r1 = sect571r1
  NID_sect571r1 = 734
  SN_wap_wsg_idm_ecid_wtls1 = wap-wsg-idm-ecid-wtls1
  NID_wap_wsg_idm_ecid_wtls1 = 735
  SN_wap_wsg_idm_ecid_wtls3 = wap-wsg-idm-ecid-wtls3
  NID_wap_wsg_idm_ecid_wtls3 = 736
  SN_wap_wsg_idm_ecid_wtls4 = wap-wsg-idm-ecid-wtls4
  NID_wap_wsg_idm_ecid_wtls4 = 737
  SN_wap_wsg_idm_ecid_wtls5 = wap-wsg-idm-ecid-wtls5
  NID_wap_wsg_idm_ecid_wtls5 = 738
  SN_wap_wsg_idm_ecid_wtls6 = wap-wsg-idm-ecid-wtls6
  NID_wap_wsg_idm_ecid_wtls6 = 739
  SN_wap_wsg_idm_ecid_wtls7 = wap-wsg-idm-ecid-wtls7
  NID_wap_wsg_idm_ecid_wtls7 = 740
  SN_wap_wsg_idm_ecid_wtls8 = wap-wsg-idm-ecid-wtls8
  NID_wap_wsg_idm_ecid_wtls8 = 741
  SN_wap_wsg_idm_ecid_wtls9 = wap-wsg-idm-ecid-wtls9
  NID_wap_wsg_idm_ecid_wtls9 = 742
  SN_wap_wsg_idm_ecid_wtls10 = wap-wsg-idm-ecid-wtls10
  NID_wap_wsg_idm_ecid_wtls10 = 743
  SN_wap_wsg_idm_ecid_wtls11 = wap-wsg-idm-ecid-wtls11
  NID_wap_wsg_idm_ecid_wtls11 = 744
  SN_wap_wsg_idm_ecid_wtls12 = wap-wsg-idm-ecid-wtls12
  NID_wap_wsg_idm_ecid_wtls12 = 745
  SN_cast5_cbc = CAST5-CBC
  LN_cast5_cbc = cast5-cbc
  NID_cast5_cbc = 108
  SN_cast5_ecb = CAST5-ECB
  LN_cast5_ecb = cast5-ecb
  NID_cast5_ecb = 109
  SN_cast5_cfb64 = CAST5-CFB
  LN_cast5_cfb64 = cast5-cfb
  NID_cast5_cfb64 = 110
  SN_cast5_ofb64 = CAST5-OFB
  LN_cast5_ofb64 = cast5-ofb
  NID_cast5_ofb64 = 111
  LN_pbeWithMD5AndCast5_CBC = pbeWithMD5AndCast5CBC
  NID_pbeWithMD5AndCast5_CBC = 112
  SN_id_PasswordBasedMAC = id-PasswordBasedMAC
  LN_id_PasswordBasedMAC = password based MAC
  NID_id_PasswordBasedMAC = 782
  SN_id_DHBasedMac = id-DHBasedMac
  LN_id_DHBasedMac = Diffie-Hellman based MAC
  NID_id_DHBasedMac = 783
  SN_rsadsi = rsadsi
  LN_rsadsi = RSA Data Security, Inc.
  NID_rsadsi = 1
  SN_pkcs = pkcs
  LN_pkcs = RSA Data Security, Inc. PKCS
  NID_pkcs = 2
  SN_pkcs1 = pkcs1
  NID_pkcs1 = 186
  LN_rsaEncryption = rsaEncryption
  NID_rsaEncryption = 6
  SN_md2WithRSAEncryption = RSA-MD2
  LN_md2WithRSAEncryption = md2WithRSAEncryption
  NID_md2WithRSAEncryption = 7
  SN_md4WithRSAEncryption = RSA-MD4
  LN_md4WithRSAEncryption = md4WithRSAEncryption
  NID_md4WithRSAEncryption = 396
  SN_md5WithRSAEncryption = RSA-MD5
  LN_md5WithRSAEncryption = md5WithRSAEncryption
  NID_md5WithRSAEncryption = 8
  SN_sha1WithRSAEncryption = RSA-SHA1
  LN_sha1WithRSAEncryption = sha1WithRSAEncryption
  NID_sha1WithRSAEncryption = 65
  SN_sha256WithRSAEncryption = RSA-SHA256
  LN_sha256WithRSAEncryption = sha256WithRSAEncryption
  NID_sha256WithRSAEncryption = 668
  SN_sha384WithRSAEncryption = RSA-SHA384
  LN_sha384WithRSAEncryption = sha384WithRSAEncryption
  NID_sha384WithRSAEncryption = 669
  SN_sha512WithRSAEncryption = RSA-SHA512
  LN_sha512WithRSAEncryption = sha512WithRSAEncryption
  NID_sha512WithRSAEncryption = 670
  SN_sha224WithRSAEncryption = RSA-SHA224
  LN_sha224WithRSAEncryption = sha224WithRSAEncryption
  NID_sha224WithRSAEncryption = 671
  SN_pkcs3 = pkcs3
  NID_pkcs3 = 27
  LN_dhKeyAgreement = dhKeyAgreement
  NID_dhKeyAgreement = 28
  SN_pkcs5 = pkcs5
  NID_pkcs5 = 187
  SN_pbeWithMD2AndDES_CBC = PBE-MD2-DES
  LN_pbeWithMD2AndDES_CBC = pbeWithMD2AndDES-CBC
  NID_pbeWithMD2AndDES_CBC = 9
  SN_pbeWithMD5AndDES_CBC = PBE-MD5-DES
  LN_pbeWithMD5AndDES_CBC = pbeWithMD5AndDES-CBC
  NID_pbeWithMD5AndDES_CBC = 10
  SN_pbeWithMD2AndRC2_CBC = PBE-MD2-RC2-64
  LN_pbeWithMD2AndRC2_CBC = pbeWithMD2AndRC2-CBC
  NID_pbeWithMD2AndRC2_CBC = 168
  SN_pbeWithMD5AndRC2_CBC = PBE-MD5-RC2-64
  LN_pbeWithMD5AndRC2_CBC = pbeWithMD5AndRC2-CBC
  NID_pbeWithMD5AndRC2_CBC = 169
  SN_pbeWithSHA1AndDES_CBC = PBE-SHA1-DES
  LN_pbeWithSHA1AndDES_CBC = pbeWithSHA1AndDES-CBC
  NID_pbeWithSHA1AndDES_CBC = 170
  SN_pbeWithSHA1AndRC2_CBC = PBE-SHA1-RC2-64
  LN_pbeWithSHA1AndRC2_CBC = pbeWithSHA1AndRC2-CBC
  NID_pbeWithSHA1AndRC2_CBC = 68
  LN_id_pbkdf2 = PBKDF2
  NID_id_pbkdf2 = 69
  LN_pbes2 = PBES2
  NID_pbes2 = 161
  LN_pbmac1 = PBMAC1
  NID_pbmac1 = 162
  SN_pkcs7 = pkcs7
  NID_pkcs7 = 20
  LN_pkcs7_data = pkcs7-data
  NID_pkcs7_data = 21
  LN_pkcs7_signed = pkcs7-signedData
  NID_pkcs7_signed = 22
  LN_pkcs7_enveloped = pkcs7-envelopedData
  NID_pkcs7_enveloped = 23
  LN_pkcs7_signedAndEnveloped = pkcs7-signedAndEnvelopedData
  NID_pkcs7_signedAndEnveloped = 24
  LN_pkcs7_digest = pkcs7-digestData
  NID_pkcs7_digest = 25
  LN_pkcs7_encrypted = pkcs7-encryptedData
  NID_pkcs7_encrypted = 26
  SN_pkcs9 = pkcs9
  NID_pkcs9 = 47
  LN_pkcs9_emailAddress = emailAddress
  NID_pkcs9_emailAddress = 48
  LN_pkcs9_unstructuredName = unstructuredName
  NID_pkcs9_unstructuredName = 49
  LN_pkcs9_contentType = contentType
  NID_pkcs9_contentType = 50
  LN_pkcs9_messageDigest = messageDigest
  NID_pkcs9_messageDigest = 51
  LN_pkcs9_signingTime = signingTime
  NID_pkcs9_signingTime = 52
  LN_pkcs9_countersignature = countersignature
  NID_pkcs9_countersignature = 53
  LN_pkcs9_challengePassword = challengePassword
  NID_pkcs9_challengePassword = 54
  LN_pkcs9_unstructuredAddress = unstructuredAddress
  NID_pkcs9_unstructuredAddress = 55
  LN_pkcs9_extCertAttributes = extendedCertificateAttributes
  NID_pkcs9_extCertAttributes = 56
  SN_ext_req = extReq
  LN_ext_req = Extension Request
  NID_ext_req = 172
  SN_SMIMECapabilities = SMIME-CAPS
  LN_SMIMECapabilities = S/MIME Capabilities
  NID_SMIMECapabilities = 167
  SN_SMIME = SMIME
  LN_SMIME = S/MIME
  NID_SMIME = 188
  SN_id_smime_mod = id-smime-mod
  NID_id_smime_mod = 189
  SN_id_smime_ct = id-smime-ct
  NID_id_smime_ct = 190
  SN_id_smime_aa = id-smime-aa
  NID_id_smime_aa = 191
  SN_id_smime_alg = id-smime-alg
  NID_id_smime_alg = 192
  SN_id_smime_cd = id-smime-cd
  NID_id_smime_cd = 193
  SN_id_smime_spq = id-smime-spq
  NID_id_smime_spq = 194
  SN_id_smime_cti = id-smime-cti
  NID_id_smime_cti = 195
  SN_id_smime_mod_cms = id-smime-mod-cms
  NID_id_smime_mod_cms = 196
  SN_id_smime_mod_ess = id-smime-mod-ess
  NID_id_smime_mod_ess = 197
  SN_id_smime_mod_oid = id-smime-mod-oid
  NID_id_smime_mod_oid = 198
  SN_id_smime_mod_msg_v3 = id-smime-mod-msg-v3
  NID_id_smime_mod_msg_v3 = 199
  SN_id_smime_mod_ets_eSignature_88 = id-smime-mod-ets-eSignature-88
  NID_id_smime_mod_ets_eSignature_88 = 200
  SN_id_smime_mod_ets_eSignature_97 = id-smime-mod-ets-eSignature-97
  NID_id_smime_mod_ets_eSignature_97 = 201
  SN_id_smime_mod_ets_eSigPolicy_88 = id-smime-mod-ets-eSigPolicy-88
  NID_id_smime_mod_ets_eSigPolicy_88 = 202
  SN_id_smime_mod_ets_eSigPolicy_97 = id-smime-mod-ets-eSigPolicy-97
  NID_id_smime_mod_ets_eSigPolicy_97 = 203
  SN_id_smime_ct_receipt = id-smime-ct-receipt
  NID_id_smime_ct_receipt = 204
  SN_id_smime_ct_authData = id-smime-ct-authData
  NID_id_smime_ct_authData = 205
  SN_id_smime_ct_publishCert = id-smime-ct-publishCert
  NID_id_smime_ct_publishCert = 206
  SN_id_smime_ct_TSTInfo = id-smime-ct-TSTInfo
  NID_id_smime_ct_TSTInfo = 207
  SN_id_smime_ct_TDTInfo = id-smime-ct-TDTInfo
  NID_id_smime_ct_TDTInfo = 208
  SN_id_smime_ct_contentInfo = id-smime-ct-contentInfo
  NID_id_smime_ct_contentInfo = 209
  SN_id_smime_ct_DVCSRequestData = id-smime-ct-DVCSRequestData
  NID_id_smime_ct_DVCSRequestData = 210
  SN_id_smime_ct_DVCSResponseData = id-smime-ct-DVCSResponseData
  NID_id_smime_ct_DVCSResponseData = 211
  SN_id_smime_ct_compressedData = id-smime-ct-compressedData
  NID_id_smime_ct_compressedData = 786
  SN_id_ct_asciiTextWithCRLF = id-ct-asciiTextWithCRLF
  NID_id_ct_asciiTextWithCRLF = 787
  SN_id_smime_aa_receiptRequest = id-smime-aa-receiptRequest
  NID_id_smime_aa_receiptRequest = 212
  SN_id_smime_aa_securityLabel = id-smime-aa-securityLabel
  NID_id_smime_aa_securityLabel = 213
  SN_id_smime_aa_mlExpandHistory = id-smime-aa-mlExpandHistory
  NID_id_smime_aa_mlExpandHistory = 214
  SN_id_smime_aa_contentHint = id-smime-aa-contentHint
  NID_id_smime_aa_contentHint = 215
  SN_id_smime_aa_msgSigDigest = id-smime-aa-msgSigDigest
  NID_id_smime_aa_msgSigDigest = 216
  SN_id_smime_aa_encapContentType = id-smime-aa-encapContentType
  NID_id_smime_aa_encapContentType = 217
  SN_id_smime_aa_contentIdentifier = id-smime-aa-contentIdentifier
  NID_id_smime_aa_contentIdentifier = 218
  SN_id_smime_aa_macValue = id-smime-aa-macValue
  NID_id_smime_aa_macValue = 219
  SN_id_smime_aa_equivalentLabels = id-smime-aa-equivalentLabels
  NID_id_smime_aa_equivalentLabels = 220
  SN_id_smime_aa_contentReference = id-smime-aa-contentReference
  NID_id_smime_aa_contentReference = 221
  SN_id_smime_aa_encrypKeyPref = id-smime-aa-encrypKeyPref
  NID_id_smime_aa_encrypKeyPref = 222
  SN_id_smime_aa_signingCertificate = id-smime-aa-signingCertificate
  NID_id_smime_aa_signingCertificate = 223
  SN_id_smime_aa_smimeEncryptCerts = id-smime-aa-smimeEncryptCerts
  NID_id_smime_aa_smimeEncryptCerts = 224
  SN_id_smime_aa_timeStampToken = id-smime-aa-timeStampToken
  NID_id_smime_aa_timeStampToken = 225
  SN_id_smime_aa_ets_sigPolicyId = id-smime-aa-ets-sigPolicyId
  NID_id_smime_aa_ets_sigPolicyId = 226
  SN_id_smime_aa_ets_commitmentType = id-smime-aa-ets-commitmentType
  NID_id_smime_aa_ets_commitmentType = 227
  SN_id_smime_aa_ets_signerLocation = id-smime-aa-ets-signerLocation
  NID_id_smime_aa_ets_signerLocation = 228
  SN_id_smime_aa_ets_signerAttr = id-smime-aa-ets-signerAttr
  NID_id_smime_aa_ets_signerAttr = 229
  SN_id_smime_aa_ets_otherSigCert = id-smime-aa-ets-otherSigCert
  NID_id_smime_aa_ets_otherSigCert = 230
  SN_id_smime_aa_ets_contentTimestamp = id-smime-aa-ets-contentTimestamp
  NID_id_smime_aa_ets_contentTimestamp = 231
  SN_id_smime_aa_ets_CertificateRefs = id-smime-aa-ets-CertificateRefs
  NID_id_smime_aa_ets_CertificateRefs = 232
  SN_id_smime_aa_ets_RevocationRefs = id-smime-aa-ets-RevocationRefs
  NID_id_smime_aa_ets_RevocationRefs = 233
  SN_id_smime_aa_ets_certValues = id-smime-aa-ets-certValues
  NID_id_smime_aa_ets_certValues = 234
  SN_id_smime_aa_ets_revocationValues = id-smime-aa-ets-revocationValues
  NID_id_smime_aa_ets_revocationValues = 235
  SN_id_smime_aa_ets_escTimeStamp = id-smime-aa-ets-escTimeStamp
  NID_id_smime_aa_ets_escTimeStamp = 236
  SN_id_smime_aa_ets_certCRLTimestamp = id-smime-aa-ets-certCRLTimestamp
  NID_id_smime_aa_ets_certCRLTimestamp = 237
  SN_id_smime_aa_ets_archiveTimeStamp = id-smime-aa-ets-archiveTimeStamp
  NID_id_smime_aa_ets_archiveTimeStamp = 238
  SN_id_smime_aa_signatureType = id-smime-aa-signatureType
  NID_id_smime_aa_signatureType = 239
  SN_id_smime_aa_dvcs_dvc = id-smime-aa-dvcs-dvc
  NID_id_smime_aa_dvcs_dvc = 240
  SN_id_smime_alg_ESDHwith3DES = id-smime-alg-ESDHwith3DES
  NID_id_smime_alg_ESDHwith3DES = 241
  SN_id_smime_alg_ESDHwithRC2 = id-smime-alg-ESDHwithRC2
  NID_id_smime_alg_ESDHwithRC2 = 242
  SN_id_smime_alg_3DESwrap = id-smime-alg-3DESwrap
  NID_id_smime_alg_3DESwrap = 243
  SN_id_smime_alg_RC2wrap = id-smime-alg-RC2wrap
  NID_id_smime_alg_RC2wrap = 244
  SN_id_smime_alg_ESDH = id-smime-alg-ESDH
  NID_id_smime_alg_ESDH = 245
  SN_id_smime_alg_CMS3DESwrap = id-smime-alg-CMS3DESwrap
  NID_id_smime_alg_CMS3DESwrap = 246
  SN_id_smime_alg_CMSRC2wrap = id-smime-alg-CMSRC2wrap
  NID_id_smime_alg_CMSRC2wrap = 247
  SN_id_smime_cd_ldap = id-smime-cd-ldap
  NID_id_smime_cd_ldap = 248
  SN_id_smime_spq_ets_sqt_uri = id-smime-spq-ets-sqt-uri
  NID_id_smime_spq_ets_sqt_uri = 249
  SN_id_smime_spq_ets_sqt_unotice = id-smime-spq-ets-sqt-unotice
  NID_id_smime_spq_ets_sqt_unotice = 250
  SN_id_smime_cti_ets_proofOfOrigin = id-smime-cti-ets-proofOfOrigin
  NID_id_smime_cti_ets_proofOfOrigin = 251
  SN_id_smime_cti_ets_proofOfReceipt = id-smime-cti-ets-proofOfReceipt
  NID_id_smime_cti_ets_proofOfReceipt = 252
  SN_id_smime_cti_ets_proofOfDelivery = id-smime-cti-ets-proofOfDelivery
  NID_id_smime_cti_ets_proofOfDelivery = 253
  SN_id_smime_cti_ets_proofOfSender = id-smime-cti-ets-proofOfSender
  NID_id_smime_cti_ets_proofOfSender = 254
  SN_id_smime_cti_ets_proofOfApproval = id-smime-cti-ets-proofOfApproval
  NID_id_smime_cti_ets_proofOfApproval = 255
  SN_id_smime_cti_ets_proofOfCreation = id-smime-cti-ets-proofOfCreation
  NID_id_smime_cti_ets_proofOfCreation = 256
  LN_friendlyName = friendlyName
  NID_friendlyName = 156
  LN_localKeyID = localKeyID
  NID_localKeyID = 157
  SN_ms_csp_name = CSPName
  LN_ms_csp_name = Microsoft CSP Name
  NID_ms_csp_name = 417
  SN_LocalKeySet = LocalKeySet
  LN_LocalKeySet = Microsoft Local Key set
  NID_LocalKeySet = 856
  LN_x509Certificate = x509Certificate
  NID_x509Certificate = 158
  LN_sdsiCertificate = sdsiCertificate
  NID_sdsiCertificate = 159
  LN_x509Crl = x509Crl
  NID_x509Crl = 160
  SN_pbe_WithSHA1And128BitRC4 = PBE-SHA1-RC4-128
  LN_pbe_WithSHA1And128BitRC4 = pbeWithSHA1And128BitRC4
  NID_pbe_WithSHA1And128BitRC4 = 144
  SN_pbe_WithSHA1And40BitRC4 = PBE-SHA1-RC4-40
  LN_pbe_WithSHA1And40BitRC4 = pbeWithSHA1And40BitRC4
  NID_pbe_WithSHA1And40BitRC4 = 145
  SN_pbe_WithSHA1And3_Key_TripleDES_CBC = PBE-SHA1-3DES
  LN_pbe_WithSHA1And3_Key_TripleDES_CBC = pbeWithSHA1And3-KeyTripleDES-CBC
  NID_pbe_WithSHA1And3_Key_TripleDES_CBC = 146
  SN_pbe_WithSHA1And2_Key_TripleDES_CBC = PBE-SHA1-2DES
  LN_pbe_WithSHA1And2_Key_TripleDES_CBC = pbeWithSHA1And2-KeyTripleDES-CBC
  NID_pbe_WithSHA1And2_Key_TripleDES_CBC = 147
  SN_pbe_WithSHA1And128BitRC2_CBC = PBE-SHA1-RC2-128
  LN_pbe_WithSHA1And128BitRC2_CBC = pbeWithSHA1And128BitRC2-CBC
  NID_pbe_WithSHA1And128BitRC2_CBC = 148
  SN_pbe_WithSHA1And40BitRC2_CBC = PBE-SHA1-RC2-40
  LN_pbe_WithSHA1And40BitRC2_CBC = pbeWithSHA1And40BitRC2-CBC
  NID_pbe_WithSHA1And40BitRC2_CBC = 149
  LN_keyBag = keyBag
  NID_keyBag = 150
  LN_pkcs8ShroudedKeyBag = pkcs8ShroudedKeyBag
  NID_pkcs8ShroudedKeyBag = 151
  LN_certBag = certBag
  NID_certBag = 152
  LN_crlBag = crlBag
  NID_crlBag = 153
  LN_secretBag = secretBag
  NID_secretBag = 154
  LN_safeContentsBag = safeContentsBag
  NID_safeContentsBag = 155
  SN_md2 = MD2
  LN_md2 = md2
  NID_md2 = 3
  SN_md4 = MD4
  LN_md4 = md4
  NID_md4 = 257
  SN_md5 = MD5
  LN_md5 = md5
  NID_md5 = 4
  SN_md5_sha1 = MD5-SHA1
  LN_md5_sha1 = md5-sha1
  NID_md5_sha1 = 114
  LN_hmacWithMD5 = hmacWithMD5
  NID_hmacWithMD5 = 797
  LN_hmacWithSHA1 = hmacWithSHA1
  NID_hmacWithSHA1 = 163
  LN_hmacWithSHA224 = hmacWithSHA224
  NID_hmacWithSHA224 = 798
  LN_hmacWithSHA256 = hmacWithSHA256
  NID_hmacWithSHA256 = 799
  LN_hmacWithSHA384 = hmacWithSHA384
  NID_hmacWithSHA384 = 800
  LN_hmacWithSHA512 = hmacWithSHA512
  NID_hmacWithSHA512 = 801
  SN_rc2_cbc = RC2-CBC
  LN_rc2_cbc = rc2-cbc
  NID_rc2_cbc = 37
  SN_rc2_ecb = RC2-ECB
  LN_rc2_ecb = rc2-ecb
  NID_rc2_ecb = 38
  SN_rc2_cfb64 = RC2-CFB
  LN_rc2_cfb64 = rc2-cfb
  NID_rc2_cfb64 = 39
  SN_rc2_ofb64 = RC2-OFB
  LN_rc2_ofb64 = rc2-ofb
  NID_rc2_ofb64 = 40
  SN_rc2_40_cbc = RC2-40-CBC
  LN_rc2_40_cbc = rc2-40-cbc
  NID_rc2_40_cbc = 98
  SN_rc2_64_cbc = RC2-64-CBC
  LN_rc2_64_cbc = rc2-64-cbc
  NID_rc2_64_cbc = 166
  SN_rc4 = RC4
  LN_rc4 = rc4
  NID_rc4 = 5
  SN_rc4_40 = RC4-40
  LN_rc4_40 = rc4-40
  NID_rc4_40 = 97
  SN_des_ede3_cbc = DES-EDE3-CBC
  LN_des_ede3_cbc = des-ede3-cbc
  NID_des_ede3_cbc = 44
  SN_rc5_cbc = RC5-CBC
  LN_rc5_cbc = rc5-cbc
  NID_rc5_cbc = 120
  SN_rc5_ecb = RC5-ECB
  LN_rc5_ecb = rc5-ecb
  NID_rc5_ecb = 121
  SN_rc5_cfb64 = RC5-CFB
  LN_rc5_cfb64 = rc5-cfb
  NID_rc5_cfb64 = 122
  SN_rc5_ofb64 = RC5-OFB
  LN_rc5_ofb64 = rc5-ofb
  NID_rc5_ofb64 = 123
  SN_ms_ext_req = msExtReq
  LN_ms_ext_req = Microsoft Extension Request
  NID_ms_ext_req = 171
  SN_ms_code_ind = msCodeInd
  LN_ms_code_ind = Microsoft Individual Code Signing
  NID_ms_code_ind = 134
  SN_ms_code_com = msCodeCom
  LN_ms_code_com = Microsoft Commercial Code Signing
  NID_ms_code_com = 135
  SN_ms_ctl_sign = msCTLSign
  LN_ms_ctl_sign = Microsoft Trust List Signing
  NID_ms_ctl_sign = 136
  SN_ms_sgc = msSGC
  LN_ms_sgc = Microsoft Server Gated Crypto
  NID_ms_sgc = 137
  SN_ms_efs = msEFS
  LN_ms_efs = Microsoft Encrypted File System
  NID_ms_efs = 138
  SN_ms_smartcard_login = msSmartcardLogin
  LN_ms_smartcard_login = Microsoft Smartcardlogin
  NID_ms_smartcard_login = 648
  SN_ms_upn = msUPN
  LN_ms_upn = Microsoft Universal Principal Name
  NID_ms_upn = 649
  SN_idea_cbc = IDEA-CBC
  LN_idea_cbc = idea-cbc
  NID_idea_cbc = 34
  SN_idea_ecb = IDEA-ECB
  LN_idea_ecb = idea-ecb
  NID_idea_ecb = 36
  SN_idea_cfb64 = IDEA-CFB
  LN_idea_cfb64 = idea-cfb
  NID_idea_cfb64 = 35
  SN_idea_ofb64 = IDEA-OFB
  LN_idea_ofb64 = idea-ofb
  NID_idea_ofb64 = 46
  SN_bf_cbc = BF-CBC
  LN_bf_cbc = bf-cbc
  NID_bf_cbc = 91
  SN_bf_ecb = BF-ECB
  LN_bf_ecb = bf-ecb
  NID_bf_ecb = 92
  SN_bf_cfb64 = BF-CFB
  LN_bf_cfb64 = bf-cfb
  NID_bf_cfb64 = 93
  SN_bf_ofb64 = BF-OFB
  LN_bf_ofb64 = bf-ofb
  NID_bf_ofb64 = 94
  SN_id_pkix = PKIX
  NID_id_pkix = 127
  SN_id_pkix_mod = id-pkix-mod
  NID_id_pkix_mod = 258
  SN_id_pe = id-pe
  NID_id_pe = 175
  SN_id_qt = id-qt
  NID_id_qt = 259
  SN_id_kp = id-kp
  NID_id_kp = 128
  SN_id_it = id-it
  NID_id_it = 260
  SN_id_pkip = id-pkip
  NID_id_pkip = 261
  SN_id_alg = id-alg
  NID_id_alg = 262
  SN_id_cmc = id-cmc
  NID_id_cmc = 263
  SN_id_on = id-on
  NID_id_on = 264
  SN_id_pda = id-pda
  NID_id_pda = 265
  SN_id_aca = id-aca
  NID_id_aca = 266
  SN_id_qcs = id-qcs
  NID_id_qcs = 267
  SN_id_cct = id-cct
  NID_id_cct = 268
  SN_id_ppl = id-ppl
  NID_id_ppl = 662
  SN_id_ad = id-ad
  NID_id_ad = 176
  SN_id_pkix1_explicit_88 = id-pkix1-explicit-88
  NID_id_pkix1_explicit_88 = 269
  SN_id_pkix1_implicit_88 = id-pkix1-implicit-88
  NID_id_pkix1_implicit_88 = 270
  SN_id_pkix1_explicit_93 = id-pkix1-explicit-93
  NID_id_pkix1_explicit_93 = 271
  SN_id_pkix1_implicit_93 = id-pkix1-implicit-93
  NID_id_pkix1_implicit_93 = 272
  SN_id_mod_crmf = id-mod-crmf
  NID_id_mod_crmf = 273
  SN_id_mod_cmc = id-mod-cmc
  NID_id_mod_cmc = 274
  SN_id_mod_kea_profile_88 = id-mod-kea-profile-88
  NID_id_mod_kea_profile_88 = 275
  SN_id_mod_kea_profile_93 = id-mod-kea-profile-93
  NID_id_mod_kea_profile_93 = 276
  SN_id_mod_cmp = id-mod-cmp
  NID_id_mod_cmp = 277
  SN_id_mod_qualified_cert_88 = id-mod-qualified-cert-88
  NID_id_mod_qualified_cert_88 = 278
  SN_id_mod_qualified_cert_93 = id-mod-qualified-cert-93
  NID_id_mod_qualified_cert_93 = 279
  SN_id_mod_attribute_cert = id-mod-attribute-cert
  NID_id_mod_attribute_cert = 280
  SN_id_mod_timestamp_protocol = id-mod-timestamp-protocol
  NID_id_mod_timestamp_protocol = 281
  SN_id_mod_ocsp = id-mod-ocsp
  NID_id_mod_ocsp = 282
  SN_id_mod_dvcs = id-mod-dvcs
  NID_id_mod_dvcs = 283
  SN_id_mod_cmp2000 = id-mod-cmp2000
  NID_id_mod_cmp2000 = 284
  SN_info_access = authorityInfoAccess
  LN_info_access = Authority Information Access
  NID_info_access = 177
  SN_biometricInfo = biometricInfo
  LN_biometricInfo = Biometric Info
  NID_biometricInfo = 285
  SN_qcStatements = qcStatements
  NID_qcStatements = 286
  SN_ac_auditEntity = ac-auditEntity
  NID_ac_auditEntity = 287
  SN_ac_targeting = ac-targeting
  NID_ac_targeting = 288
  SN_aaControls = aaControls
  NID_aaControls = 289
  SN_sbgp_ipAddrBlock = sbgp-ipAddrBlock
  NID_sbgp_ipAddrBlock = 290
  SN_sbgp_autonomousSysNum = sbgp-autonomousSysNum
  NID_sbgp_autonomousSysNum = 291
  SN_sbgp_routerIdentifier = sbgp-routerIdentifier
  NID_sbgp_routerIdentifier = 292
  SN_ac_proxying = ac-proxying
  NID_ac_proxying = 397
  SN_sinfo_access = subjectInfoAccess
  LN_sinfo_access = Subject Information Access
  NID_sinfo_access = 398
  SN_proxyCertInfo = proxyCertInfo
  LN_proxyCertInfo = Proxy Certificate Information
  NID_proxyCertInfo = 663
  SN_id_qt_cps = id-qt-cps
  LN_id_qt_cps = Policy Qualifier CPS
  NID_id_qt_cps = 164
  SN_id_qt_unotice = id-qt-unotice
  LN_id_qt_unotice = Policy Qualifier User Notice
  NID_id_qt_unotice = 165
  SN_textNotice = textNotice
  NID_textNotice = 293
  SN_server_auth = serverAuth
  LN_server_auth = TLS Web Server Authentication
  NID_server_auth = 129
  SN_client_auth = clientAuth
  LN_client_auth = TLS Web Client Authentication
  NID_client_auth = 130
  SN_code_sign = codeSigning
  LN_code_sign = Code Signing
  NID_code_sign = 131
  SN_email_protect = emailProtection
  LN_email_protect = E-mail Protection
  NID_email_protect = 132
  SN_ipsecEndSystem = ipsecEndSystem
  LN_ipsecEndSystem = IPSec End System
  NID_ipsecEndSystem = 294
  SN_ipsecTunnel = ipsecTunnel
  LN_ipsecTunnel = IPSec Tunnel
  NID_ipsecTunnel = 295
  SN_ipsecUser = ipsecUser
  LN_ipsecUser = IPSec User
  NID_ipsecUser = 296
  SN_time_stamp = timeStamping
  LN_time_stamp = Time Stamping
  NID_time_stamp = 133
  SN_OCSP_sign = OCSPSigning
  LN_OCSP_sign = OCSP Signing
  NID_OCSP_sign = 180
  SN_dvcs = DVCS
  LN_dvcs = dvcs
  NID_dvcs = 297
  SN_id_it_caProtEncCert = id-it-caProtEncCert
  NID_id_it_caProtEncCert = 298
  SN_id_it_signKeyPairTypes = id-it-signKeyPairTypes
  NID_id_it_signKeyPairTypes = 299
  SN_id_it_encKeyPairTypes = id-it-encKeyPairTypes
  NID_id_it_encKeyPairTypes = 300
  SN_id_it_preferredSymmAlg = id-it-preferredSymmAlg
  NID_id_it_preferredSymmAlg = 301
  SN_id_it_caKeyUpdateInfo = id-it-caKeyUpdateInfo
  NID_id_it_caKeyUpdateInfo = 302
  SN_id_it_currentCRL = id-it-currentCRL
  NID_id_it_currentCRL = 303
  SN_id_it_unsupportedOIDs = id-it-unsupportedOIDs
  NID_id_it_unsupportedOIDs = 304
  SN_id_it_subscriptionRequest = id-it-subscriptionRequest
  NID_id_it_subscriptionRequest = 305
  SN_id_it_subscriptionResponse = id-it-subscriptionResponse
  NID_id_it_subscriptionResponse = 306
  SN_id_it_keyPairParamReq = id-it-keyPairParamReq
  NID_id_it_keyPairParamReq = 307
  SN_id_it_keyPairParamRep = id-it-keyPairParamRep
  NID_id_it_keyPairParamRep = 308
  SN_id_it_revPassphrase = id-it-revPassphrase
  NID_id_it_revPassphrase = 309
  SN_id_it_implicitConfirm = id-it-implicitConfirm
  NID_id_it_implicitConfirm = 310
  SN_id_it_confirmWaitTime = id-it-confirmWaitTime
  NID_id_it_confirmWaitTime = 311
  SN_id_it_origPKIMessage = id-it-origPKIMessage
  NID_id_it_origPKIMessage = 312
  SN_id_it_suppLangTags = id-it-suppLangTags
  NID_id_it_suppLangTags = 784
  SN_id_regCtrl = id-regCtrl
  NID_id_regCtrl = 313
  SN_id_regInfo = id-regInfo
  NID_id_regInfo = 314
  SN_id_regCtrl_regToken = id-regCtrl-regToken
  NID_id_regCtrl_regToken = 315
  SN_id_regCtrl_authenticator = id-regCtrl-authenticator
  NID_id_regCtrl_authenticator = 316
  SN_id_regCtrl_pkiPublicationInfo = id-regCtrl-pkiPublicationInfo
  NID_id_regCtrl_pkiPublicationInfo = 317
  SN_id_regCtrl_pkiArchiveOptions = id-regCtrl-pkiArchiveOptions
  NID_id_regCtrl_pkiArchiveOptions = 318
  SN_id_regCtrl_oldCertID = id-regCtrl-oldCertID
  NID_id_regCtrl_oldCertID = 319
  SN_id_regCtrl_protocolEncrKey = id-regCtrl-protocolEncrKey
  NID_id_regCtrl_protocolEncrKey = 320
  SN_id_regInfo_utf8Pairs = id-regInfo-utf8Pairs
  NID_id_regInfo_utf8Pairs = 321
  SN_id_regInfo_certReq = id-regInfo-certReq
  NID_id_regInfo_certReq = 322
  SN_id_alg_des40 = id-alg-des40
  NID_id_alg_des40 = 323
  SN_id_alg_noSignature = id-alg-noSignature
  NID_id_alg_noSignature = 324
  SN_id_alg_dh_sig_hmac_sha1 = id-alg-dh-sig-hmac-sha1
  NID_id_alg_dh_sig_hmac_sha1 = 325
  SN_id_alg_dh_pop = id-alg-dh-pop
  NID_id_alg_dh_pop = 326
  SN_id_cmc_statusInfo = id-cmc-statusInfo
  NID_id_cmc_statusInfo = 327
  SN_id_cmc_identification = id-cmc-identification
  NID_id_cmc_identification = 328
  SN_id_cmc_identityProof = id-cmc-identityProof
  NID_id_cmc_identityProof = 329
  SN_id_cmc_dataReturn = id-cmc-dataReturn
  NID_id_cmc_dataReturn = 330
  SN_id_cmc_transactionId = id-cmc-transactionId
  NID_id_cmc_transactionId = 331
  SN_id_cmc_senderNonce = id-cmc-senderNonce
  NID_id_cmc_senderNonce = 332
  SN_id_cmc_recipientNonce = id-cmc-recipientNonce
  NID_id_cmc_recipientNonce = 333
  SN_id_cmc_addExtensions = id-cmc-addExtensions
  NID_id_cmc_addExtensions = 334
  SN_id_cmc_encryptedPOP = id-cmc-encryptedPOP
  NID_id_cmc_encryptedPOP = 335
  SN_id_cmc_decryptedPOP = id-cmc-decryptedPOP
  NID_id_cmc_decryptedPOP = 336
  SN_id_cmc_lraPOPWitness = id-cmc-lraPOPWitness
  NID_id_cmc_lraPOPWitness = 337
  SN_id_cmc_getCert = id-cmc-getCert
  NID_id_cmc_getCert = 338
  SN_id_cmc_getCRL = id-cmc-getCRL
  NID_id_cmc_getCRL = 339
  SN_id_cmc_revokeRequest = id-cmc-revokeRequest
  NID_id_cmc_revokeRequest = 340
  SN_id_cmc_regInfo = id-cmc-regInfo
  NID_id_cmc_regInfo = 341
  SN_id_cmc_responseInfo = id-cmc-responseInfo
  NID_id_cmc_responseInfo = 342
  SN_id_cmc_queryPending = id-cmc-queryPending
  NID_id_cmc_queryPending = 343
  SN_id_cmc_popLinkRandom = id-cmc-popLinkRandom
  NID_id_cmc_popLinkRandom = 344
  SN_id_cmc_popLinkWitness = id-cmc-popLinkWitness
  NID_id_cmc_popLinkWitness = 345
  SN_id_cmc_confirmCertAcceptance = id-cmc-confirmCertAcceptance
  NID_id_cmc_confirmCertAcceptance = 346
  SN_id_on_personalData = id-on-personalData
  NID_id_on_personalData = 347
  SN_id_on_permanentIdentifier = id-on-permanentIdentifier
  LN_id_on_permanentIdentifier = Permanent Identifier
  NID_id_on_permanentIdentifier = 858
  SN_id_pda_dateOfBirth = id-pda-dateOfBirth
  NID_id_pda_dateOfBirth = 348
  SN_id_pda_placeOfBirth = id-pda-placeOfBirth
  NID_id_pda_placeOfBirth = 349
  SN_id_pda_gender = id-pda-gender
  NID_id_pda_gender = 351
  SN_id_pda_countryOfCitizenship = id-pda-countryOfCitizenship
  NID_id_pda_countryOfCitizenship = 352
  SN_id_pda_countryOfResidence = id-pda-countryOfResidence
  NID_id_pda_countryOfResidence = 353
  SN_id_aca_authenticationInfo = id-aca-authenticationInfo
  NID_id_aca_authenticationInfo = 354
  SN_id_aca_accessIdentity = id-aca-accessIdentity
  NID_id_aca_accessIdentity = 355
  SN_id_aca_chargingIdentity = id-aca-chargingIdentity
  NID_id_aca_chargingIdentity = 356
  SN_id_aca_group = id-aca-group
  NID_id_aca_group = 357
  SN_id_aca_role = id-aca-role
  NID_id_aca_role = 358
  SN_id_aca_encAttrs = id-aca-encAttrs
  NID_id_aca_encAttrs = 399
  SN_id_qcs_pkixQCSyntax_v1 = id-qcs-pkixQCSyntax-v1
  NID_id_qcs_pkixQCSyntax_v1 = 359
  SN_id_cct_crs = id-cct-crs
  NID_id_cct_crs = 360
  SN_id_cct_PKIData = id-cct-PKIData
  NID_id_cct_PKIData = 361
  SN_id_cct_PKIResponse = id-cct-PKIResponse
  NID_id_cct_PKIResponse = 362
  SN_id_ppl_anyLanguage = id-ppl-anyLanguage
  LN_id_ppl_anyLanguage = Any language
  NID_id_ppl_anyLanguage = 664
  SN_id_ppl_inheritAll = id-ppl-inheritAll
  LN_id_ppl_inheritAll = Inherit all
  NID_id_ppl_inheritAll = 665
  SN_Independent = id-ppl-independent
  LN_Independent = Independent
  NID_Independent = 667
  SN_ad_OCSP = OCSP
  LN_ad_OCSP = OCSP
  NID_ad_OCSP = 178
  SN_ad_ca_issuers = caIssuers
  LN_ad_ca_issuers = CA Issuers
  NID_ad_ca_issuers = 179
  SN_ad_timeStamping = ad_timestamping
  LN_ad_timeStamping = AD Time Stamping
  NID_ad_timeStamping = 363
  SN_ad_dvcs = AD_DVCS
  LN_ad_dvcs = ad dvcs
  NID_ad_dvcs = 364
  SN_caRepository = caRepository
  LN_caRepository = CA Repository
  NID_caRepository = 785
  SN_id_pkix_OCSP_basic = basicOCSPResponse
  LN_id_pkix_OCSP_basic = Basic OCSP Response
  NID_id_pkix_OCSP_basic = 365
  SN_id_pkix_OCSP_Nonce = Nonce
  LN_id_pkix_OCSP_Nonce = OCSP Nonce
  NID_id_pkix_OCSP_Nonce = 366
  SN_id_pkix_OCSP_CrlID = CrlID
  LN_id_pkix_OCSP_CrlID = OCSP CRL ID
  NID_id_pkix_OCSP_CrlID = 367
  SN_id_pkix_OCSP_acceptableResponses = acceptableResponses
  LN_id_pkix_OCSP_acceptableResponses = Acceptable OCSP Responses
  NID_id_pkix_OCSP_acceptableResponses = 368
  SN_id_pkix_OCSP_noCheck = noCheck
  LN_id_pkix_OCSP_noCheck = OCSP No Check
  NID_id_pkix_OCSP_noCheck = 369
  SN_id_pkix_OCSP_archiveCutoff = archiveCutoff
  LN_id_pkix_OCSP_archiveCutoff = OCSP Archive Cutoff
  NID_id_pkix_OCSP_archiveCutoff = 370
  SN_id_pkix_OCSP_serviceLocator = serviceLocator
  LN_id_pkix_OCSP_serviceLocator = OCSP Service Locator
  NID_id_pkix_OCSP_serviceLocator = 371
  SN_id_pkix_OCSP_extendedStatus = extendedStatus
  LN_id_pkix_OCSP_extendedStatus = Extended OCSP Status
  NID_id_pkix_OCSP_extendedStatus = 372
  SN_id_pkix_OCSP_valid = valid
  NID_id_pkix_OCSP_valid = 373
  SN_id_pkix_OCSP_path = path
  NID_id_pkix_OCSP_path = 374
  SN_id_pkix_OCSP_trustRoot = trustRoot
  LN_id_pkix_OCSP_trustRoot = Trust Root
  NID_id_pkix_OCSP_trustRoot = 375
  SN_algorithm = algorithm
  LN_algorithm = algorithm
  NID_algorithm = 376
  SN_md5WithRSA = RSA-NP-MD5
  LN_md5WithRSA = md5WithRSA
  NID_md5WithRSA = 104
  SN_des_ecb = DES-ECB
  LN_des_ecb = des-ecb
  NID_des_ecb = 29
  SN_des_cbc = DES-CBC
  LN_des_cbc = des-cbc
  NID_des_cbc = 31
  SN_des_ofb64 = DES-OFB
  LN_des_ofb64 = des-ofb
  NID_des_ofb64 = 45
  SN_des_cfb64 = DES-CFB
  LN_des_cfb64 = des-cfb
  NID_des_cfb64 = 30
  SN_rsaSignature = rsaSignature
  NID_rsaSignature = 377
  SN_dsa_2 = DSA-old
  LN_dsa_2 = dsaEncryption-old
  NID_dsa_2 = 67
  SN_dsaWithSHA = DSA-SHA
  LN_dsaWithSHA = dsaWithSHA
  NID_dsaWithSHA = 66
  SN_shaWithRSAEncryption = RSA-SHA
  LN_shaWithRSAEncryption = shaWithRSAEncryption
  NID_shaWithRSAEncryption = 42
  SN_des_ede_ecb = DES-EDE
  LN_des_ede_ecb = des-ede
  NID_des_ede_ecb = 32
  SN_des_ede3_ecb = DES-EDE3
  LN_des_ede3_ecb = des-ede3
  NID_des_ede3_ecb = 33
  SN_des_ede_cbc = DES-EDE-CBC
  LN_des_ede_cbc = des-ede-cbc
  NID_des_ede_cbc = 43
  SN_des_ede_cfb64 = DES-EDE-CFB
  LN_des_ede_cfb64 = des-ede-cfb
  NID_des_ede_cfb64 = 60
  SN_des_ede3_cfb64 = DES-EDE3-CFB
  LN_des_ede3_cfb64 = des-ede3-cfb
  NID_des_ede3_cfb64 = 61
  SN_des_ede_ofb64 = DES-EDE-OFB
  LN_des_ede_ofb64 = des-ede-ofb
  NID_des_ede_ofb64 = 62
  SN_des_ede3_ofb64 = DES-EDE3-OFB
  LN_des_ede3_ofb64 = des-ede3-ofb
  NID_des_ede3_ofb64 = 63
  SN_desx_cbc = DESX-CBC
  LN_desx_cbc = desx-cbc
  NID_desx_cbc = 80
  SN_sha = SHA
  LN_sha = sha
  NID_sha = 41
  SN_sha1 = SHA1
  LN_sha1 = sha1
  NID_sha1 = 64
  SN_dsaWithSHA1_2 = DSA-SHA1-old
  LN_dsaWithSHA1_2 = dsaWithSHA1-old
  NID_dsaWithSHA1_2 = 70
  SN_sha1WithRSA = RSA-SHA1-2
  LN_sha1WithRSA = sha1WithRSA
  NID_sha1WithRSA = 115
  SN_ripemd160 = RIPEMD160
  LN_ripemd160 = ripemd160
  NID_ripemd160 = 117
  SN_ripemd160WithRSA = RSA-RIPEMD160
  LN_ripemd160WithRSA = ripemd160WithRSA
  NID_ripemd160WithRSA = 119
  SN_sxnet = SXNetID
  LN_sxnet = Strong Extranet ID
  NID_sxnet = 143
  SN_X500 = X500
  LN_X500 = directory services (X.500)
  NID_X500 = 11
  SN_X509 = X509
  NID_X509 = 12
  SN_commonName = CN
  LN_commonName = commonName
  NID_commonName = 13
  SN_surname = SN
  LN_surname = surname
  NID_surname = 100
  LN_serialNumber = serialNumber
  NID_serialNumber = 105
  SN_countryName = C
  LN_countryName = countryName
  NID_countryName = 14
  SN_localityName = L
  LN_localityName = localityName
  NID_localityName = 15
  SN_stateOrProvinceName = ST
  LN_stateOrProvinceName = stateOrProvinceName
  NID_stateOrProvinceName = 16
  SN_streetAddress = street
  LN_streetAddress = streetAddress
  NID_streetAddress = 660
  SN_organizationName = O
  LN_organizationName = organizationName
  NID_organizationName = 17
  SN_organizationalUnitName = OU
  LN_organizationalUnitName = organizationalUnitName
  NID_organizationalUnitName = 18
  SN_title = title
  LN_title = title
  NID_title = 106
  LN_description = description
  NID_description = 107
  LN_searchGuide = searchGuide
  NID_searchGuide = 859
  LN_businessCategory = businessCategory
  NID_businessCategory = 860
  LN_postalAddress = postalAddress
  NID_postalAddress = 861
  LN_postalCode = postalCode
  NID_postalCode = 661
  LN_postOfficeBox = postOfficeBox
  NID_postOfficeBox = 862
  LN_physicalDeliveryOfficeName = physicalDeliveryOfficeName
  NID_physicalDeliveryOfficeName = 863
  LN_telephoneNumber = telephoneNumber
  NID_telephoneNumber = 864
  LN_telexNumber = telexNumber
  NID_telexNumber = 865
  LN_teletexTerminalIdentifier = teletexTerminalIdentifier
  NID_teletexTerminalIdentifier = 866
  LN_facsimileTelephoneNumber = facsimileTelephoneNumber
  NID_facsimileTelephoneNumber = 867
  LN_x121Address = x121Address
  NID_x121Address = 868
  LN_internationaliSDNNumber = internationaliSDNNumber
  NID_internationaliSDNNumber = 869
  LN_registeredAddress = registeredAddress
  NID_registeredAddress = 870
  LN_destinationIndicator = destinationIndicator
  NID_destinationIndicator = 871
  LN_preferredDeliveryMethod = preferredDeliveryMethod
  NID_preferredDeliveryMethod = 872
  LN_presentationAddress = presentationAddress
  NID_presentationAddress = 873
  LN_supportedApplicationContext = supportedApplicationContext
  NID_supportedApplicationContext = 874
  SN_member = member
  NID_member = 875
  SN_owner = owner
  NID_owner = 876
  LN_roleOccupant = roleOccupant
  NID_roleOccupant = 877
  SN_seeAlso = seeAlso
  NID_seeAlso = 878
  LN_userPassword = userPassword
  NID_userPassword = 879
  LN_userCertificate = userCertificate
  NID_userCertificate = 880
  LN_cACertificate = cACertificate
  NID_cACertificate = 881
  LN_authorityRevocationList = authorityRevocationList
  NID_authorityRevocationList = 882
  LN_certificateRevocationList = certificateRevocationList
  NID_certificateRevocationList = 883
  LN_crossCertificatePair = crossCertificatePair
  NID_crossCertificatePair = 884
  SN_name = name
  LN_name = name
  NID_name = 173
  SN_givenName = GN
  LN_givenName = givenName
  NID_givenName = 99
  SN_initials = initials
  LN_initials = initials
  NID_initials = 101
  LN_generationQualifier = generationQualifier
  NID_generationQualifier = 509
  LN_x500UniqueIdentifier = x500UniqueIdentifier
  NID_x500UniqueIdentifier = 503
  SN_dnQualifier = dnQualifier
  LN_dnQualifier = dnQualifier
  NID_dnQualifier = 174
  LN_enhancedSearchGuide = enhancedSearchGuide
  NID_enhancedSearchGuide = 885
  LN_protocolInformation = protocolInformation
  NID_protocolInformation = 886
  LN_distinguishedName = distinguishedName
  NID_distinguishedName = 887
  LN_uniqueMember = uniqueMember
  NID_uniqueMember = 888
  LN_houseIdentifier = houseIdentifier
  NID_houseIdentifier = 889
  LN_supportedAlgorithms = supportedAlgorithms
  NID_supportedAlgorithms = 890
  LN_deltaRevocationList = deltaRevocationList
  NID_deltaRevocationList = 891
  SN_dmdName = dmdName
  NID_dmdName = 892
  LN_pseudonym = pseudonym
  NID_pseudonym = 510
  SN_role = role
  LN_role = role
  NID_role = 400
  SN_X500algorithms = X500algorithms
  LN_X500algorithms = directory services - algorithms
  NID_X500algorithms = 378
  SN_rsa = RSA
  LN_rsa = rsa
  NID_rsa = 19
  SN_mdc2WithRSA = RSA-MDC2
  LN_mdc2WithRSA = mdc2WithRSA
  NID_mdc2WithRSA = 96
  SN_mdc2 = MDC2
  LN_mdc2 = mdc2
  NID_mdc2 = 95
  SN_id_ce = id-ce
  NID_id_ce = 81
  SN_subject_directory_attributes = subjectDirectoryAttributes
  LN_subject_directory_attributes = X509v3 Subject Directory Attributes
  NID_subject_directory_attributes = 769
  SN_subject_key_identifier = subjectKeyIdentifier
  LN_subject_key_identifier = X509v3 Subject Key Identifier
  NID_subject_key_identifier = 82
  SN_key_usage = keyUsage
  LN_key_usage = X509v3 Key Usage
  NID_key_usage = 83
  SN_private_key_usage_period = privateKeyUsagePeriod
  LN_private_key_usage_period = X509v3 Private Key Usage Period
  NID_private_key_usage_period = 84
  SN_subject_alt_name = subjectAltName
  LN_subject_alt_name = X509v3 Subject Alternative Name
  NID_subject_alt_name = 85
  SN_issuer_alt_name = issuerAltName
  LN_issuer_alt_name = X509v3 Issuer Alternative Name
  NID_issuer_alt_name = 86
  SN_basic_constraints = basicConstraints
  LN_basic_constraints = X509v3 Basic Constraints
  NID_basic_constraints = 87
  SN_crl_number = crlNumber
  LN_crl_number = X509v3 CRL Number
  NID_crl_number = 88
  SN_crl_reason = CRLReason
  LN_crl_reason = X509v3 CRL Reason Code
  NID_crl_reason = 141
  SN_invalidity_date = invalidityDate
  LN_invalidity_date = Invalidity Date
  NID_invalidity_date = 142
  SN_delta_crl = deltaCRL
  LN_delta_crl = X509v3 Delta CRL Indicator
  NID_delta_crl = 140
  SN_issuing_distribution_point = issuingDistributionPoint
  LN_issuing_distribution_point = X509v3 Issuing Distrubution Point
  NID_issuing_distribution_point = 770
  SN_certificate_issuer = certificateIssuer
  LN_certificate_issuer = X509v3 Certificate Issuer
  NID_certificate_issuer = 771
  SN_name_constraints = nameConstraints
  LN_name_constraints = X509v3 Name Constraints
  NID_name_constraints = 666
  SN_crl_distribution_points = crlDistributionPoints
  LN_crl_distribution_points = X509v3 CRL Distribution Points
  NID_crl_distribution_points = 103
  SN_certificate_policies = certificatePolicies
  LN_certificate_policies = X509v3 Certificate Policies
  NID_certificate_policies = 89
  SN_any_policy = anyPolicy
  LN_any_policy = X509v3 Any Policy
  NID_any_policy = 746
  SN_policy_mappings = policyMappings
  LN_policy_mappings = X509v3 Policy Mappings
  NID_policy_mappings = 747
  SN_authority_key_identifier = authorityKeyIdentifier
  LN_authority_key_identifier = X509v3 Authority Key Identifier
  NID_authority_key_identifier = 90
  SN_policy_constraints = policyConstraints
  LN_policy_constraints = X509v3 Policy Constraints
  NID_policy_constraints = 401
  SN_ext_key_usage = extendedKeyUsage
  LN_ext_key_usage = X509v3 Extended Key Usage
  NID_ext_key_usage = 126
  SN_freshest_crl = freshestCRL
  LN_freshest_crl = X509v3 Freshest CRL
  NID_freshest_crl = 857
  SN_inhibit_any_policy = inhibitAnyPolicy
  LN_inhibit_any_policy = X509v3 Inhibit Any Policy
  NID_inhibit_any_policy = 748
  SN_target_information = targetInformation
  LN_target_information = X509v3 AC Targeting
  NID_target_information = 402
  SN_no_rev_avail = noRevAvail
  LN_no_rev_avail = X509v3 No Revocation Available
  NID_no_rev_avail = 403
  SN_netscape = Netscape
  LN_netscape = Netscape Communications Corp.
  NID_netscape = 57
  SN_netscape_cert_extension = nsCertExt
  LN_netscape_cert_extension = Netscape Certificate Extension
  NID_netscape_cert_extension = 58
  SN_netscape_data_type = nsDataType
  LN_netscape_data_type = Netscape Data Type
  NID_netscape_data_type = 59
  SN_netscape_cert_type = nsCertType
  LN_netscape_cert_type = Netscape Cert Type
  NID_netscape_cert_type = 71
  SN_netscape_base_url = nsBaseUrl
  LN_netscape_base_url = Netscape Base Url
  NID_netscape_base_url = 72
  SN_netscape_revocation_url = nsRevocationUrl
  LN_netscape_revocation_url = Netscape Revocation Url
  NID_netscape_revocation_url = 73
  SN_netscape_ca_revocation_url = nsCaRevocationUrl
  LN_netscape_ca_revocation_url = Netscape CA Revocation Url
  NID_netscape_ca_revocation_url = 74
  SN_netscape_renewal_url = nsRenewalUrl
  LN_netscape_renewal_url = Netscape Renewal Url
  NID_netscape_renewal_url = 75
  SN_netscape_ca_policy_url = nsCaPolicyUrl
  LN_netscape_ca_policy_url = Netscape CA Policy Url
  NID_netscape_ca_policy_url = 76
  SN_netscape_ssl_server_name = nsSslServerName
  LN_netscape_ssl_server_name = Netscape SSL Server Name
  NID_netscape_ssl_server_name = 77
  SN_netscape_comment = nsComment
  LN_netscape_comment = Netscape Comment
  NID_netscape_comment = 78
  SN_netscape_cert_sequence = nsCertSequence
  LN_netscape_cert_sequence = Netscape Certificate Sequence
  NID_netscape_cert_sequence = 79
  SN_ns_sgc = nsSGC
  LN_ns_sgc = Netscape Server Gated Crypto
  NID_ns_sgc = 139
  SN_org = ORG
  LN_org = org
  NID_org = 379
  SN_dod = DOD
  LN_dod = dod
  NID_dod = 380
  SN_iana = IANA
  LN_iana = iana
  NID_iana = 381
  SN_Directory = directory
  LN_Directory = Directory
  NID_Directory = 382
  SN_Management = mgmt
  LN_Management = Management
  NID_Management = 383
  SN_Experimental = experimental
  LN_Experimental = Experimental
  NID_Experimental = 384
  SN_Private = private
  LN_Private = Private
  NID_Private = 385
  SN_Security = security
  LN_Security = Security
  NID_Security = 386
  SN_SNMPv2 = snmpv2
  LN_SNMPv2 = SNMPv2
  NID_SNMPv2 = 387
  LN_Mail = Mail
  NID_Mail = 388
  SN_Enterprises = enterprises
  LN_Enterprises = Enterprises
  NID_Enterprises = 389
  SN_dcObject = dcobject
  LN_dcObject = dcObject
  NID_dcObject = 390
  SN_mime_mhs = mime-mhs
  LN_mime_mhs = MIME MHS
  NID_mime_mhs = 504
  SN_mime_mhs_headings = mime-mhs-headings
  LN_mime_mhs_headings = mime-mhs-headings
  NID_mime_mhs_headings = 505
  SN_mime_mhs_bodies = mime-mhs-bodies
  LN_mime_mhs_bodies = mime-mhs-bodies
  NID_mime_mhs_bodies = 506
  SN_id_hex_partial_message = id-hex-partial-message
  LN_id_hex_partial_message = id-hex-partial-message
  NID_id_hex_partial_message = 507
  SN_id_hex_multipart_message = id-hex-multipart-message
  LN_id_hex_multipart_message = id-hex-multipart-message
  NID_id_hex_multipart_message = 508
  SN_rle_compression = RLE
  LN_rle_compression = run length compression
  NID_rle_compression = 124
  SN_zlib_compression = ZLIB
  LN_zlib_compression = zlib compression
  NID_zlib_compression = 125
  SN_aes_128_ecb = AES-128-ECB
  LN_aes_128_ecb = aes-128-ecb
  NID_aes_128_ecb = 418
  SN_aes_128_cbc = AES-128-CBC
  LN_aes_128_cbc = aes-128-cbc
  NID_aes_128_cbc = 419
  SN_aes_128_ofb128 = AES-128-OFB
  LN_aes_128_ofb128 = aes-128-ofb
  NID_aes_128_ofb128 = 420
  SN_aes_128_cfb128 = AES-128-CFB
  LN_aes_128_cfb128 = aes-128-cfb
  NID_aes_128_cfb128 = 421
  SN_aes_192_ecb = AES-192-ECB
  LN_aes_192_ecb = aes-192-ecb
  NID_aes_192_ecb = 422
  SN_aes_192_cbc = AES-192-CBC
  LN_aes_192_cbc = aes-192-cbc
  NID_aes_192_cbc = 423
  SN_aes_192_ofb128 = AES-192-OFB
  LN_aes_192_ofb128 = aes-192-ofb
  NID_aes_192_ofb128 = 424
  SN_aes_192_cfb128 = AES-192-CFB
  LN_aes_192_cfb128 = aes-192-cfb
  NID_aes_192_cfb128 = 425
  SN_aes_256_ecb = AES-256-ECB
  LN_aes_256_ecb = aes-256-ecb
  NID_aes_256_ecb = 426
  SN_aes_256_cbc = AES-256-CBC
  LN_aes_256_cbc = aes-256-cbc
  NID_aes_256_cbc = 427
  SN_aes_256_ofb128 = AES-256-OFB
  LN_aes_256_ofb128 = aes-256-ofb
  NID_aes_256_ofb128 = 428
  SN_aes_256_cfb128 = AES-256-CFB
  LN_aes_256_cfb128 = aes-256-cfb
  NID_aes_256_cfb128 = 429
  SN_aes_128_cfb1 = AES-128-CFB1
  LN_aes_128_cfb1 = aes-128-cfb1
  NID_aes_128_cfb1 = 650
  SN_aes_192_cfb1 = AES-192-CFB1
  LN_aes_192_cfb1 = aes-192-cfb1
  NID_aes_192_cfb1 = 651
  SN_aes_256_cfb1 = AES-256-CFB1
  LN_aes_256_cfb1 = aes-256-cfb1
  NID_aes_256_cfb1 = 652
  SN_aes_128_cfb8 = AES-128-CFB8
  LN_aes_128_cfb8 = aes-128-cfb8
  NID_aes_128_cfb8 = 653
  SN_aes_192_cfb8 = AES-192-CFB8
  LN_aes_192_cfb8 = aes-192-cfb8
  NID_aes_192_cfb8 = 654
  SN_aes_256_cfb8 = AES-256-CFB8
  LN_aes_256_cfb8 = aes-256-cfb8
  NID_aes_256_cfb8 = 655
  SN_des_cfb1 = DES-CFB1
  LN_des_cfb1 = des-cfb1
  NID_des_cfb1 = 656
  SN_des_cfb8 = DES-CFB8
  LN_des_cfb8 = des-cfb8
  NID_des_cfb8 = 657
  SN_des_ede3_cfb1 = DES-EDE3-CFB1
  LN_des_ede3_cfb1 = des-ede3-cfb1
  NID_des_ede3_cfb1 = 658
  SN_des_ede3_cfb8 = DES-EDE3-CFB8
  LN_des_ede3_cfb8 = des-ede3-cfb8
  NID_des_ede3_cfb8 = 659
  SN_id_aes128_wrap = id-aes128-wrap
  NID_id_aes128_wrap = 788
  SN_id_aes192_wrap = id-aes192-wrap
  NID_id_aes192_wrap = 789
  SN_id_aes256_wrap = id-aes256-wrap
  NID_id_aes256_wrap = 790
  SN_sha256 = SHA256
  LN_sha256 = sha256
  NID_sha256 = 672
  SN_sha384 = SHA384
  LN_sha384 = sha384
  NID_sha384 = 673
  SN_sha512 = SHA512
  LN_sha512 = sha512
  NID_sha512 = 674
  SN_sha224 = SHA224
  LN_sha224 = sha224
  NID_sha224 = 675
  SN_dsa_with_SHA224 = dsa_with_SHA224
  NID_dsa_with_SHA224 = 802
  SN_dsa_with_SHA256 = dsa_with_SHA256
  NID_dsa_with_SHA256 = 803
  SN_hold_instruction_code = holdInstructionCode
  LN_hold_instruction_code = Hold Instruction Code
  NID_hold_instruction_code = 430
  SN_hold_instruction_none = holdInstructionNone
  LN_hold_instruction_none = Hold Instruction None
  NID_hold_instruction_none = 431
  SN_hold_instruction_call_issuer = holdInstructionCallIssuer
  LN_hold_instruction_call_issuer = Hold Instruction Call Issuer
  NID_hold_instruction_call_issuer = 432
  SN_hold_instruction_reject = holdInstructionReject
  LN_hold_instruction_reject = Hold Instruction Reject
  NID_hold_instruction_reject = 433
  SN_data = data
  NID_data = 434
  SN_pss = pss
  NID_pss = 435
  SN_ucl = ucl
  NID_ucl = 436
  SN_pilot = pilot
  NID_pilot = 437
  LN_pilotAttributeType = pilotAttributeType
  NID_pilotAttributeType = 438
  LN_pilotAttributeSyntax = pilotAttributeSyntax
  NID_pilotAttributeSyntax = 439
  LN_pilotObjectClass = pilotObjectClass
  NID_pilotObjectClass = 440
  LN_pilotGroups = pilotGroups
  NID_pilotGroups = 441
  LN_iA5StringSyntax = iA5StringSyntax
  NID_iA5StringSyntax = 442
  LN_caseIgnoreIA5StringSyntax = caseIgnoreIA5StringSyntax
  NID_caseIgnoreIA5StringSyntax = 443
  LN_pilotObject = pilotObject
  NID_pilotObject = 444
  LN_pilotPerson = pilotPerson
  NID_pilotPerson = 445
  SN_account = account
  NID_account = 446
  SN_document = document
  NID_document = 447
  SN_room = room
  NID_room = 448
  LN_documentSeries = documentSeries
  NID_documentSeries = 449
  SN_Domain = domain
  LN_Domain = Domain
  NID_Domain = 392
  LN_rFC822localPart = rFC822localPart
  NID_rFC822localPart = 450
  LN_dNSDomain = dNSDomain
  NID_dNSDomain = 451
  LN_domainRelatedObject = domainRelatedObject
  NID_domainRelatedObject = 452
  LN_friendlyCountry = friendlyCountry
  NID_friendlyCountry = 453
  LN_simpleSecurityObject = simpleSecurityObject
  NID_simpleSecurityObject = 454
  LN_pilotOrganization = pilotOrganization
  NID_pilotOrganization = 455
  LN_pilotDSA = pilotDSA
  NID_pilotDSA = 456
  LN_qualityLabelledData = qualityLabelledData
  NID_qualityLabelledData = 457
  SN_userId = UID
  LN_userId = userId
  NID_userId = 458
  LN_textEncodedORAddress = textEncodedORAddress
  NID_textEncodedORAddress = 459
  SN_rfc822Mailbox = mail
  LN_rfc822Mailbox = rfc822Mailbox
  NID_rfc822Mailbox = 460
  SN_info = info
  NID_info = 461
  LN_favouriteDrink = favouriteDrink
  NID_favouriteDrink = 462
  LN_roomNumber = roomNumber
  NID_roomNumber = 463
  SN_photo = photo
  NID_photo = 464
  LN_userClass = userClass
  NID_userClass = 465
  SN_host = host
  NID_host = 466
  SN_manager = manager
  NID_manager = 467
  LN_documentIdentifier = documentIdentifier
  NID_documentIdentifier = 468
  LN_documentTitle = documentTitle
  NID_documentTitle = 469
  LN_documentVersion = documentVersion
  NID_documentVersion = 470
  LN_documentAuthor = documentAuthor
  NID_documentAuthor = 471
  LN_documentLocation = documentLocation
  NID_documentLocation = 472
  LN_homeTelephoneNumber = homeTelephoneNumber
  NID_homeTelephoneNumber = 473
  SN_secretary = secretary
  NID_secretary = 474
  LN_otherMailbox = otherMailbox
  NID_otherMailbox = 475
  LN_lastModifiedTime = lastModifiedTime
  NID_lastModifiedTime = 476
  LN_lastModifiedBy = lastModifiedBy
  NID_lastModifiedBy = 477
  SN_domainComponent = DC
  LN_domainComponent = domainComponent
  NID_domainComponent = 391
  LN_aRecord = aRecord
  NID_aRecord = 478
  LN_pilotAttributeType27 = pilotAttributeType27
  NID_pilotAttributeType27 = 479
  LN_mXRecord = mXRecord
  NID_mXRecord = 480
  LN_nSRecord = nSRecord
  NID_nSRecord = 481
  LN_sOARecord = sOARecord
  NID_sOARecord = 482
  LN_cNAMERecord = cNAMERecord
  NID_cNAMERecord = 483
  LN_associatedDomain = associatedDomain
  NID_associatedDomain = 484
  LN_associatedName = associatedName
  NID_associatedName = 485
  LN_homePostalAddress = homePostalAddress
  NID_homePostalAddress = 486
  LN_personalTitle = personalTitle
  NID_personalTitle = 487
  LN_mobileTelephoneNumber = mobileTelephoneNumber
  NID_mobileTelephoneNumber = 488
  LN_pagerTelephoneNumber = pagerTelephoneNumber
  NID_pagerTelephoneNumber = 489
  LN_friendlyCountryName = friendlyCountryName
  NID_friendlyCountryName = 490
  LN_organizationalStatus = organizationalStatus
  NID_organizationalStatus = 491
  LN_janetMailbox = janetMailbox
  NID_janetMailbox = 492
  LN_mailPreferenceOption = mailPreferenceOption
  NID_mailPreferenceOption = 493
  LN_buildingName = buildingName
  NID_buildingName = 494
  LN_dSAQuality = dSAQuality
  NID_dSAQuality = 495
  LN_singleLevelQuality = singleLevelQuality
  NID_singleLevelQuality = 496
  LN_subtreeMinimumQuality = subtreeMinimumQuality
  NID_subtreeMinimumQuality = 497
  LN_subtreeMaximumQuality = subtreeMaximumQuality
  NID_subtreeMaximumQuality = 498
  LN_personalSignature = personalSignature
  NID_personalSignature = 499
  LN_dITRedirect = dITRedirect
  NID_dITRedirect = 500
  SN_audio = audio
  NID_audio = 501
  LN_documentPublisher = documentPublisher
  NID_documentPublisher = 502
  SN_id_set = id-set
  LN_id_set = Secure Electronic Transactions
  NID_id_set = 512
  SN_set_ctype = set-ctype
  LN_set_ctype = content types
  NID_set_ctype = 513
  SN_set_msgExt = set-msgExt
  LN_set_msgExt = message extensions
  NID_set_msgExt = 514
  SN_set_attr = set-attr
  NID_set_attr = 515
  SN_set_policy = set-policy
  NID_set_policy = 516
  SN_set_certExt = set-certExt
  LN_set_certExt = certificate extensions
  NID_set_certExt = 517
  SN_set_brand = set-brand
  NID_set_brand = 518
  SN_setct_PANData = setct-PANData
  NID_setct_PANData = 519
  SN_setct_PANToken = setct-PANToken
  NID_setct_PANToken = 520
  SN_setct_PANOnly = setct-PANOnly
  NID_setct_PANOnly = 521
  SN_setct_OIData = setct-OIData
  NID_setct_OIData = 522
  SN_setct_PI = setct-PI
  NID_setct_PI = 523
  SN_setct_PIData = setct-PIData
  NID_setct_PIData = 524
  SN_setct_PIDataUnsigned = setct-PIDataUnsigned
  NID_setct_PIDataUnsigned = 525
  SN_setct_HODInput = setct-HODInput
  NID_setct_HODInput = 526
  SN_setct_AuthResBaggage = setct-AuthResBaggage
  NID_setct_AuthResBaggage = 527
  SN_setct_AuthRevReqBaggage = setct-AuthRevReqBaggage
  NID_setct_AuthRevReqBaggage = 528
  SN_setct_AuthRevResBaggage = setct-AuthRevResBaggage
  NID_setct_AuthRevResBaggage = 529
  SN_setct_CapTokenSeq = setct-CapTokenSeq
  NID_setct_CapTokenSeq = 530
  SN_setct_PInitResData = setct-PInitResData
  NID_setct_PInitResData = 531
  SN_setct_PI_TBS = setct-PI-TBS
  NID_setct_PI_TBS = 532
  SN_setct_PResData = setct-PResData
  NID_setct_PResData = 533
  SN_setct_AuthReqTBS = setct-AuthReqTBS
  NID_setct_AuthReqTBS = 534
  SN_setct_AuthResTBS = setct-AuthResTBS
  NID_setct_AuthResTBS = 535
  SN_setct_AuthResTBSX = setct-AuthResTBSX
  NID_setct_AuthResTBSX = 536
  SN_setct_AuthTokenTBS = setct-AuthTokenTBS
  NID_setct_AuthTokenTBS = 537
  SN_setct_CapTokenData = setct-CapTokenData
  NID_setct_CapTokenData = 538
  SN_setct_CapTokenTBS = setct-CapTokenTBS
  NID_setct_CapTokenTBS = 539
  SN_setct_AcqCardCodeMsg = setct-AcqCardCodeMsg
  NID_setct_AcqCardCodeMsg = 540
  SN_setct_AuthRevReqTBS = setct-AuthRevReqTBS
  NID_setct_AuthRevReqTBS = 541
  SN_setct_AuthRevResData = setct-AuthRevResData
  NID_setct_AuthRevResData = 542
  SN_setct_AuthRevResTBS = setct-AuthRevResTBS
  NID_setct_AuthRevResTBS = 543
  SN_setct_CapReqTBS = setct-CapReqTBS
  NID_setct_CapReqTBS = 544
  SN_setct_CapReqTBSX = setct-CapReqTBSX
  NID_setct_CapReqTBSX = 545
  SN_setct_CapResData = setct-CapResData
  NID_setct_CapResData = 546
  SN_setct_CapRevReqTBS = setct-CapRevReqTBS
  NID_setct_CapRevReqTBS = 547
  SN_setct_CapRevReqTBSX = setct-CapRevReqTBSX
  NID_setct_CapRevReqTBSX = 548
  SN_setct_CapRevResData = setct-CapRevResData
  NID_setct_CapRevResData = 549
  SN_setct_CredReqTBS = setct-CredReqTBS
  NID_setct_CredReqTBS = 550
  SN_setct_CredReqTBSX = setct-CredReqTBSX
  NID_setct_CredReqTBSX = 551
  SN_setct_CredResData = setct-CredResData
  NID_setct_CredResData = 552
  SN_setct_CredRevReqTBS = setct-CredRevReqTBS
  NID_setct_CredRevReqTBS = 553
  SN_setct_CredRevReqTBSX = setct-CredRevReqTBSX
  NID_setct_CredRevReqTBSX = 554
  SN_setct_CredRevResData = setct-CredRevResData
  NID_setct_CredRevResData = 555
  SN_setct_PCertReqData = setct-PCertReqData
  NID_setct_PCertReqData = 556
  SN_setct_PCertResTBS = setct-PCertResTBS
  NID_setct_PCertResTBS = 557
  SN_setct_BatchAdminReqData = setct-BatchAdminReqData
  NID_setct_BatchAdminReqData = 558
  SN_setct_BatchAdminResData = setct-BatchAdminResData
  NID_setct_BatchAdminResData = 559
  SN_setct_CardCInitResTBS = setct-CardCInitResTBS
  NID_setct_CardCInitResTBS = 560
  SN_setct_MeAqCInitResTBS = setct-MeAqCInitResTBS
  NID_setct_MeAqCInitResTBS = 561
  SN_setct_RegFormResTBS = setct-RegFormResTBS
  NID_setct_RegFormResTBS = 562
  SN_setct_CertReqData = setct-CertReqData
  NID_setct_CertReqData = 563
  SN_setct_CertReqTBS = setct-CertReqTBS
  NID_setct_CertReqTBS = 564
  SN_setct_CertResData = setct-CertResData
  NID_setct_CertResData = 565
  SN_setct_CertInqReqTBS = setct-CertInqReqTBS
  NID_setct_CertInqReqTBS = 566
  SN_setct_ErrorTBS = setct-ErrorTBS
  NID_setct_ErrorTBS = 567
  SN_setct_PIDualSignedTBE = setct-PIDualSignedTBE
  NID_setct_PIDualSignedTBE = 568
  SN_setct_PIUnsignedTBE = setct-PIUnsignedTBE
  NID_setct_PIUnsignedTBE = 569
  SN_setct_AuthReqTBE = setct-AuthReqTBE
  NID_setct_AuthReqTBE = 570
  SN_setct_AuthResTBE = setct-AuthResTBE
  NID_setct_AuthResTBE = 571
  SN_setct_AuthResTBEX = setct-AuthResTBEX
  NID_setct_AuthResTBEX = 572
  SN_setct_AuthTokenTBE = setct-AuthTokenTBE
  NID_setct_AuthTokenTBE = 573
  SN_setct_CapTokenTBE = setct-CapTokenTBE
  NID_setct_CapTokenTBE = 574
  SN_setct_CapTokenTBEX = setct-CapTokenTBEX
  NID_setct_CapTokenTBEX = 575
  SN_setct_AcqCardCodeMsgTBE = setct-AcqCardCodeMsgTBE
  NID_setct_AcqCardCodeMsgTBE = 576
  SN_setct_AuthRevReqTBE = setct-AuthRevReqTBE
  NID_setct_AuthRevReqTBE = 577
  SN_setct_AuthRevResTBE = setct-AuthRevResTBE
  NID_setct_AuthRevResTBE = 578
  SN_setct_AuthRevResTBEB = setct-AuthRevResTBEB
  NID_setct_AuthRevResTBEB = 579
  SN_setct_CapReqTBE = setct-CapReqTBE
  NID_setct_CapReqTBE = 580
  SN_setct_CapReqTBEX = setct-CapReqTBEX
  NID_setct_CapReqTBEX = 581
  SN_setct_CapResTBE = setct-CapResTBE
  NID_setct_CapResTBE = 582
  SN_setct_CapRevReqTBE = setct-CapRevReqTBE
  NID_setct_CapRevReqTBE = 583
  SN_setct_CapRevReqTBEX = setct-CapRevReqTBEX
  NID_setct_CapRevReqTBEX = 584
  SN_setct_CapRevResTBE = setct-CapRevResTBE
  NID_setct_CapRevResTBE = 585
  SN_setct_CredReqTBE = setct-CredReqTBE
  NID_setct_CredReqTBE = 586
  SN_setct_CredReqTBEX = setct-CredReqTBEX
  NID_setct_CredReqTBEX = 587
  SN_setct_CredResTBE = setct-CredResTBE
  NID_setct_CredResTBE = 588
  SN_setct_CredRevReqTBE = setct-CredRevReqTBE
  NID_setct_CredRevReqTBE = 589
  SN_setct_CredRevReqTBEX = setct-CredRevReqTBEX
  NID_setct_CredRevReqTBEX = 590
  SN_setct_CredRevResTBE = setct-CredRevResTBE
  NID_setct_CredRevResTBE = 591
  SN_setct_BatchAdminReqTBE = setct-BatchAdminReqTBE
  NID_setct_BatchAdminReqTBE = 592
  SN_setct_BatchAdminResTBE = setct-BatchAdminResTBE
  NID_setct_BatchAdminResTBE = 593
  SN_setct_RegFormReqTBE = setct-RegFormReqTBE
  NID_setct_RegFormReqTBE = 594
  SN_setct_CertReqTBE = setct-CertReqTBE
  NID_setct_CertReqTBE = 595
  SN_setct_CertReqTBEX = setct-CertReqTBEX
  NID_setct_CertReqTBEX = 596
  SN_setct_CertResTBE = setct-CertResTBE
  NID_setct_CertResTBE = 597
  SN_setct_CRLNotificationTBS = setct-CRLNotificationTBS
  NID_setct_CRLNotificationTBS = 598
  SN_setct_CRLNotificationResTBS = setct-CRLNotificationResTBS
  NID_setct_CRLNotificationResTBS = 599
  SN_setct_BCIDistributionTBS = setct-BCIDistributionTBS
  NID_setct_BCIDistributionTBS = 600
  SN_setext_genCrypt = setext-genCrypt
  LN_setext_genCrypt = generic cryptogram
  NID_setext_genCrypt = 601
  SN_setext_miAuth = setext-miAuth
  LN_setext_miAuth = merchant initiated auth
  NID_setext_miAuth = 602
  SN_setext_pinSecure = setext-pinSecure
  NID_setext_pinSecure = 603
  SN_setext_pinAny = setext-pinAny
  NID_setext_pinAny = 604
  SN_setext_track2 = setext-track2
  NID_setext_track2 = 605
  SN_setext_cv = setext-cv
  LN_setext_cv = additional verification
  NID_setext_cv = 606
  SN_set_policy_root = set-policy-root
  NID_set_policy_root = 607
  SN_setCext_hashedRoot = setCext-hashedRoot
  NID_setCext_hashedRoot = 608
  SN_setCext_certType = setCext-certType
  NID_setCext_certType = 609
  SN_setCext_merchData = setCext-merchData
  NID_setCext_merchData = 610
  SN_setCext_cCertRequired = setCext-cCertRequired
  NID_setCext_cCertRequired = 611
  SN_setCext_tunneling = setCext-tunneling
  NID_setCext_tunneling = 612
  SN_setCext_setExt = setCext-setExt
  NID_setCext_setExt = 613
  SN_setCext_setQualf = setCext-setQualf
  NID_setCext_setQualf = 614
  SN_setCext_PGWYcapabilities = setCext-PGWYcapabilities
  NID_setCext_PGWYcapabilities = 615
  SN_setCext_TokenIdentifier = setCext-TokenIdentifier
  NID_setCext_TokenIdentifier = 616
  SN_setCext_Track2Data = setCext-Track2Data
  NID_setCext_Track2Data = 617
  SN_setCext_TokenType = setCext-TokenType
  NID_setCext_TokenType = 618
  SN_setCext_IssuerCapabilities = setCext-IssuerCapabilities
  NID_setCext_IssuerCapabilities = 619
  SN_setAttr_Cert = setAttr-Cert
  NID_setAttr_Cert = 620
  SN_setAttr_PGWYcap = setAttr-PGWYcap
  LN_setAttr_PGWYcap = payment gateway capabilities
  NID_setAttr_PGWYcap = 621
  SN_setAttr_TokenType = setAttr-TokenType
  NID_setAttr_TokenType = 622
  SN_setAttr_IssCap = setAttr-IssCap
  LN_setAttr_IssCap = issuer capabilities
  NID_setAttr_IssCap = 623
  SN_set_rootKeyThumb = set-rootKeyThumb
  NID_set_rootKeyThumb = 624
  SN_set_addPolicy = set-addPolicy
  NID_set_addPolicy = 625
  SN_setAttr_Token_EMV = setAttr-Token-EMV
  NID_setAttr_Token_EMV = 626
  SN_setAttr_Token_B0Prime = setAttr-Token-B0Prime
  NID_setAttr_Token_B0Prime = 627
  SN_setAttr_IssCap_CVM = setAttr-IssCap-CVM
  NID_setAttr_IssCap_CVM = 628
  SN_setAttr_IssCap_T2 = setAttr-IssCap-T2
  NID_setAttr_IssCap_T2 = 629
  SN_setAttr_IssCap_Sig = setAttr-IssCap-Sig
  NID_setAttr_IssCap_Sig = 630
  SN_setAttr_GenCryptgrm = setAttr-GenCryptgrm
  LN_setAttr_GenCryptgrm = generate cryptogram
  NID_setAttr_GenCryptgrm = 631
  SN_setAttr_T2Enc = setAttr-T2Enc
  LN_setAttr_T2Enc = encrypted track 2
  NID_setAttr_T2Enc = 632
  SN_setAttr_T2cleartxt = setAttr-T2cleartxt
  LN_setAttr_T2cleartxt = cleartext track 2
  NID_setAttr_T2cleartxt = 633
  SN_setAttr_TokICCsig = setAttr-TokICCsig
  LN_setAttr_TokICCsig = ICC or token signature
  NID_setAttr_TokICCsig = 634
  SN_setAttr_SecDevSig = setAttr-SecDevSig
  LN_setAttr_SecDevSig = secure device signature
  NID_setAttr_SecDevSig = 635
  SN_set_brand_IATA_ATA = set-brand-IATA-ATA
  NID_set_brand_IATA_ATA = 636
  SN_set_brand_Diners = set-brand-Diners
  NID_set_brand_Diners = 637
  SN_set_brand_AmericanExpress = set-brand-AmericanExpress
  NID_set_brand_AmericanExpress = 638
  SN_set_brand_JCB = set-brand-JCB
  NID_set_brand_JCB = 639
  SN_set_brand_Visa = set-brand-Visa
  NID_set_brand_Visa = 640
  SN_set_brand_MasterCard = set-brand-MasterCard
  NID_set_brand_MasterCard = 641
  SN_set_brand_Novus = set-brand-Novus
  NID_set_brand_Novus = 642
  SN_des_cdmf = DES-CDMF
  LN_des_cdmf = des-cdmf
  NID_des_cdmf = 643
  SN_rsaOAEPEncryptionSET = rsaOAEPEncryptionSET
  NID_rsaOAEPEncryptionSET = 644
  SN_ipsec3 = Oakley-EC2N-3
  LN_ipsec3 = ipsec3
  NID_ipsec3 = 749
  SN_ipsec4 = Oakley-EC2N-4
  LN_ipsec4 = ipsec4
  NID_ipsec4 = 750
  SN_whirlpool = whirlpool
  NID_whirlpool = 804
  SN_cryptopro = cryptopro
  NID_cryptopro = 805
  SN_cryptocom = cryptocom
  NID_cryptocom = 806
  SN_id_GostR3411_94_with_GostR3410_2001 = id-GostR3411-94-with-GostR3410-2001
  LN_id_GostR3411_94_with_GostR3410_2001 = GOST R 34.11-94 with GOST R 34.10-2001
  NID_id_GostR3411_94_with_GostR3410_2001 = 807
  SN_id_GostR3411_94_with_GostR3410_94 = id-GostR3411-94-with-GostR3410-94
  LN_id_GostR3411_94_with_GostR3410_94 = GOST R 34.11-94 with GOST R 34.10-94
  NID_id_GostR3411_94_with_GostR3410_94 = 808
  SN_id_GostR3411_94 = md_gost94
  LN_id_GostR3411_94 = GOST R 34.11-94
  NID_id_GostR3411_94 = 809
  SN_id_HMACGostR3411_94 = id-HMACGostR3411-94
  LN_id_HMACGostR3411_94 = HMAC GOST 34.11-94
  NID_id_HMACGostR3411_94 = 810
  SN_id_GostR3410_2001 = gost2001
  LN_id_GostR3410_2001 = GOST R 34.10-2001
  NID_id_GostR3410_2001 = 811
  SN_id_GostR3410_94 = gost94
  LN_id_GostR3410_94 = GOST R 34.10-94
  NID_id_GostR3410_94 = 812
  SN_id_Gost28147_89 = gost89
  LN_id_Gost28147_89 = GOST 28147-89
  NID_id_Gost28147_89 = 813
  SN_gost89_cnt = gost89-cnt
  NID_gost89_cnt = 814
  SN_id_Gost28147_89_MAC = gost-mac
  LN_id_Gost28147_89_MAC = GOST 28147-89 MAC
  NID_id_Gost28147_89_MAC = 815
  SN_id_GostR3411_94_prf = prf-gostr3411-94
  LN_id_GostR3411_94_prf = GOST R 34.11-94 PRF
  NID_id_GostR3411_94_prf = 816
  SN_id_GostR3410_2001DH = id-GostR3410-2001DH
  LN_id_GostR3410_2001DH = GOST R 34.10-2001 DH
  NID_id_GostR3410_2001DH = 817
  SN_id_GostR3410_94DH = id-GostR3410-94DH
  LN_id_GostR3410_94DH = GOST R 34.10-94 DH
  NID_id_GostR3410_94DH = 818
  SN_id_Gost28147_89_CryptoPro_KeyMeshing = id-Gost28147-89-CryptoPro-KeyMeshing
  NID_id_Gost28147_89_CryptoPro_KeyMeshing = 819
  SN_id_Gost28147_89_None_KeyMeshing = id-Gost28147-89-None-KeyMeshing
  NID_id_Gost28147_89_None_KeyMeshing = 820
  SN_id_GostR3411_94_TestParamSet = id-GostR3411-94-TestParamSet
  NID_id_GostR3411_94_TestParamSet = 821
  SN_id_GostR3411_94_CryptoProParamSet = id-GostR3411-94-CryptoProParamSet
  NID_id_GostR3411_94_CryptoProParamSet = 822
  SN_id_Gost28147_89_TestParamSet = id-Gost28147-89-TestParamSet
  NID_id_Gost28147_89_TestParamSet = 823
  SN_id_Gost28147_89_CryptoPro_A_ParamSet = id-Gost28147-89-CryptoPro-A-ParamSet
  NID_id_Gost28147_89_CryptoPro_A_ParamSet = 824
  SN_id_Gost28147_89_CryptoPro_B_ParamSet = id-Gost28147-89-CryptoPro-B-ParamSet
  NID_id_Gost28147_89_CryptoPro_B_ParamSet = 825
  SN_id_Gost28147_89_CryptoPro_C_ParamSet = id-Gost28147-89-CryptoPro-C-ParamSet
  NID_id_Gost28147_89_CryptoPro_C_ParamSet = 826
  SN_id_Gost28147_89_CryptoPro_D_ParamSet = id-Gost28147-89-CryptoPro-D-ParamSet
  NID_id_Gost28147_89_CryptoPro_D_ParamSet = 827
  SN_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet = id-Gost28147-89-CryptoPro-Oscar-1-1-ParamSet
  NID_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet = 828
  SN_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet = id-Gost28147-89-CryptoPro-Oscar-1-0-ParamSet
  NID_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet = 829
  SN_id_Gost28147_89_CryptoPro_RIC_1_ParamSet = id-Gost28147-89-CryptoPro-RIC-1-ParamSet
  NID_id_Gost28147_89_CryptoPro_RIC_1_ParamSet = 830
  SN_id_GostR3410_94_TestParamSet = id-GostR3410-94-TestParamSet
  NID_id_GostR3410_94_TestParamSet = 831
  SN_id_GostR3410_94_CryptoPro_A_ParamSet = id-GostR3410-94-CryptoPro-A-ParamSet
  NID_id_GostR3410_94_CryptoPro_A_ParamSet = 832
  SN_id_GostR3410_94_CryptoPro_B_ParamSet = id-GostR3410-94-CryptoPro-B-ParamSet
  NID_id_GostR3410_94_CryptoPro_B_ParamSet = 833
  SN_id_GostR3410_94_CryptoPro_C_ParamSet = id-GostR3410-94-CryptoPro-C-ParamSet
  NID_id_GostR3410_94_CryptoPro_C_ParamSet = 834
  SN_id_GostR3410_94_CryptoPro_D_ParamSet = id-GostR3410-94-CryptoPro-D-ParamSet
  NID_id_GostR3410_94_CryptoPro_D_ParamSet = 835
  SN_id_GostR3410_94_CryptoPro_XchA_ParamSet = id-GostR3410-94-CryptoPro-XchA-ParamSet
  NID_id_GostR3410_94_CryptoPro_XchA_ParamSet = 836
  SN_id_GostR3410_94_CryptoPro_XchB_ParamSet = id-GostR3410-94-CryptoPro-XchB-ParamSet
  NID_id_GostR3410_94_CryptoPro_XchB_ParamSet = 837
  SN_id_GostR3410_94_CryptoPro_XchC_ParamSet = id-GostR3410-94-CryptoPro-XchC-ParamSet
  NID_id_GostR3410_94_CryptoPro_XchC_ParamSet = 838
  SN_id_GostR3410_2001_TestParamSet = id-GostR3410-2001-TestParamSet
  NID_id_GostR3410_2001_TestParamSet = 839
  SN_id_GostR3410_2001_CryptoPro_A_ParamSet = id-GostR3410-2001-CryptoPro-A-ParamSet
  NID_id_GostR3410_2001_CryptoPro_A_ParamSet = 840
  SN_id_GostR3410_2001_CryptoPro_B_ParamSet = id-GostR3410-2001-CryptoPro-B-ParamSet
  NID_id_GostR3410_2001_CryptoPro_B_ParamSet = 841
  SN_id_GostR3410_2001_CryptoPro_C_ParamSet = id-GostR3410-2001-CryptoPro-C-ParamSet
  NID_id_GostR3410_2001_CryptoPro_C_ParamSet = 842
  SN_id_GostR3410_2001_CryptoPro_XchA_ParamSet = id-GostR3410-2001-CryptoPro-XchA-ParamSet
  NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet = 843
  SN_id_GostR3410_2001_CryptoPro_XchB_ParamSet = id-GostR3410-2001-CryptoPro-XchB-ParamSet
  NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet = 844
  SN_id_GostR3410_94_a = id-GostR3410-94-a
  NID_id_GostR3410_94_a = 845
  SN_id_GostR3410_94_aBis = id-GostR3410-94-aBis
  NID_id_GostR3410_94_aBis = 846
  SN_id_GostR3410_94_b = id-GostR3410-94-b
  NID_id_GostR3410_94_b = 847
  SN_id_GostR3410_94_bBis = id-GostR3410-94-bBis
  NID_id_GostR3410_94_bBis = 848
  SN_id_Gost28147_89_cc = id-Gost28147-89-cc
  LN_id_Gost28147_89_cc = GOST 28147-89 Cryptocom ParamSet
  NID_id_Gost28147_89_cc = 849
  SN_id_GostR3410_94_cc = gost94cc
  LN_id_GostR3410_94_cc = GOST 34.10-94 Cryptocom
  NID_id_GostR3410_94_cc = 850
  SN_id_GostR3410_2001_cc = gost2001cc
  LN_id_GostR3410_2001_cc = GOST 34.10-2001 Cryptocom
  NID_id_GostR3410_2001_cc = 851
  SN_id_GostR3411_94_with_GostR3410_94_cc = id-GostR3411-94-with-GostR3410-94-cc
  LN_id_GostR3411_94_with_GostR3410_94_cc = GOST R 34.11-94 with GOST R 34.10-94 Cryptocom
  NID_id_GostR3411_94_with_GostR3410_94_cc = 852
  SN_id_GostR3411_94_with_GostR3410_2001_cc = id-GostR3411-94-with-GostR3410-2001-cc
  LN_id_GostR3411_94_with_GostR3410_2001_cc = GOST R 34.11-94 with GOST R 34.10-2001 Cryptocom
  NID_id_GostR3411_94_with_GostR3410_2001_cc = 853
  SN_id_GostR3410_2001_ParamSet_cc = id-GostR3410-2001-ParamSet-cc
  LN_id_GostR3410_2001_ParamSet_cc = GOST R 3410-2001 Parameter Set Cryptocom
  NID_id_GostR3410_2001_ParamSet_cc = 854
  SN_camellia_128_cbc = CAMELLIA-128-CBC
  LN_camellia_128_cbc = camellia-128-cbc
  NID_camellia_128_cbc = 751
  SN_camellia_192_cbc = CAMELLIA-192-CBC
  LN_camellia_192_cbc = camellia-192-cbc
  NID_camellia_192_cbc = 752
  SN_camellia_256_cbc = CAMELLIA-256-CBC
  LN_camellia_256_cbc = camellia-256-cbc
  NID_camellia_256_cbc = 753
  SN_camellia_128_ecb = CAMELLIA-128-ECB
  LN_camellia_128_ecb = camellia-128-ecb
  NID_camellia_128_ecb = 754
  SN_camellia_128_ofb128 = CAMELLIA-128-OFB
  LN_camellia_128_ofb128 = camellia-128-ofb
  NID_camellia_128_ofb128 = 766
  SN_camellia_128_cfb128 = CAMELLIA-128-CFB
  LN_camellia_128_cfb128 = camellia-128-cfb
  NID_camellia_128_cfb128 = 757
  SN_camellia_192_ecb = CAMELLIA-192-ECB
  LN_camellia_192_ecb = camellia-192-ecb
  NID_camellia_192_ecb = 755
  SN_camellia_192_ofb128 = CAMELLIA-192-OFB
  LN_camellia_192_ofb128 = camellia-192-ofb
  NID_camellia_192_ofb128 = 767
  SN_camellia_192_cfb128 = CAMELLIA-192-CFB
  LN_camellia_192_cfb128 = camellia-192-cfb
  NID_camellia_192_cfb128 = 758
  SN_camellia_256_ecb = CAMELLIA-256-ECB
  LN_camellia_256_ecb = camellia-256-ecb
  NID_camellia_256_ecb = 756
  SN_camellia_256_ofb128 = CAMELLIA-256-OFB
  LN_camellia_256_ofb128 = camellia-256-ofb
  NID_camellia_256_ofb128 = 768
  SN_camellia_256_cfb128 = CAMELLIA-256-CFB
  LN_camellia_256_cfb128 = camellia-256-cfb
  NID_camellia_256_cfb128 = 759
  SN_camellia_128_cfb1 = CAMELLIA-128-CFB1
  LN_camellia_128_cfb1 = camellia-128-cfb1
  NID_camellia_128_cfb1 = 760
  SN_camellia_192_cfb1 = CAMELLIA-192-CFB1
  LN_camellia_192_cfb1 = camellia-192-cfb1
  NID_camellia_192_cfb1 = 761
  SN_camellia_256_cfb1 = CAMELLIA-256-CFB1
  LN_camellia_256_cfb1 = camellia-256-cfb1
  NID_camellia_256_cfb1 = 762
  SN_camellia_128_cfb8 = CAMELLIA-128-CFB8
  LN_camellia_128_cfb8 = camellia-128-cfb8
  NID_camellia_128_cfb8 = 763
  SN_camellia_192_cfb8 = CAMELLIA-192-CFB8
  LN_camellia_192_cfb8 = camellia-192-cfb8
  NID_camellia_192_cfb8 = 764
  SN_camellia_256_cfb8 = CAMELLIA-256-CFB8
  LN_camellia_256_cfb8 = camellia-256-cfb8
  NID_camellia_256_cfb8 = 765
  SN_kisa = KISA
  LN_kisa = kisa
  NID_kisa = 773
  SN_seed_ecb = SEED-ECB
  LN_seed_ecb = seed-ecb
  NID_seed_ecb = 776
  SN_seed_cbc = SEED-CBC
  LN_seed_cbc = seed-cbc
  NID_seed_cbc = 777
  SN_seed_cfb128 = SEED-CFB
  LN_seed_cfb128 = seed-cfb
  NID_seed_cfb128 = 779
  SN_seed_ofb128 = SEED-OFB
  LN_seed_ofb128 = seed-ofb
  NID_seed_ofb128 = 778
  SN_hmac = HMAC
  LN_hmac = hmac
  NID_hmac = 855
  OBJ_NAME_TYPE_UNDEF = 0x00
  OBJ_NAME_TYPE_MD_METH = 0x01
  OBJ_NAME_TYPE_CIPHER_METH = 0x02
  OBJ_NAME_TYPE_PKEY_METH = 0x03
  OBJ_NAME_TYPE_COMP_METH = 0x04
  OBJ_NAME_TYPE_NUM = 0x05
  OBJ_NAME_ALIAS = 0x8000
  OBJ_BSEARCH_VALUE_ON_NOMATCH = 0x01
  OBJ_BSEARCH_FIRST_VALUE_ON_MATCH = 0x02
  class ObjNameSt < FFI::Struct
    layout(
           :type, :int,
           :alias, :int,
           :name, :pointer,
           :data, :pointer
    )
    def name=(str)
      @name = FFI::MemoryPointer.from_string(str)
      self[:name] = @name
    end
    def name
      @name.get_string(0)
    end
    def data=(str)
      @data = FFI::MemoryPointer.from_string(str)
      self[:data] = @data
    end
    def data
      @data.get_string(0)
    end

  end
  attach_function :OBJ_NAME_init, [  ], :int
  attach_function :OBJ_NAME_new_index, [ callback([ :string ], :ulong), callback([ :string, :string ], :int), callback([ :string, :int, :string ], :void) ], :int
  attach_function :OBJ_NAME_get, [ :string, :int ], :string
  attach_function :OBJ_NAME_add, [ :string, :int, :string ], :int
  attach_function :OBJ_NAME_remove, [ :string, :int ], :int
  attach_function :OBJ_NAME_cleanup, [ :int ], :void
  attach_function :OBJ_NAME_do_all, [ :int, callback([ :pointer, :pointer ], :void), :pointer ], :void
  attach_function :OBJ_NAME_do_all_sorted, [ :int, callback([ :pointer, :pointer ], :void), :pointer ], :void
  attach_function :OBJ_dup, [ :pointer ], :pointer
  attach_function :OBJ_nid2obj, [ :int ], :pointer
  attach_function :OBJ_nid2ln, [ :int ], :string
  attach_function :OBJ_nid2sn, [ :int ], :string
  attach_function :OBJ_obj2nid, [ :pointer ], :int
  attach_function :OBJ_txt2obj, [ :string, :int ], :pointer
  attach_function :OBJ_obj2txt, [ :string, :int, :pointer, :int ], :int
  attach_function :OBJ_txt2nid, [ :string ], :int
  attach_function :OBJ_ln2nid, [ :string ], :int
  attach_function :OBJ_sn2nid, [ :string ], :int
  attach_function :OBJ_cmp, [ :pointer, :pointer ], :int
  attach_function :OBJ_bsearch, [ :string, :string, :int, :int, callback([ :pointer, :pointer ], :int) ], :string
  attach_function :OBJ_bsearch_ex, [ :string, :string, :int, :int, callback([ :pointer, :pointer ], :int), :int ], :string
  attach_function :OBJ_new_nid, [ :int ], :int
  attach_function :OBJ_add_object, [ :pointer ], :int
  attach_function :OBJ_create, [ :string, :string, :string ], :int
  attach_function :OBJ_cleanup, [  ], :void
  attach_function :OBJ_create_objects, [ :pointer ], :int
  attach_function :ERR_load_OBJ_strings, [  ], :void
  OBJ_F_OBJ_ADD_OBJECT = 105
  OBJ_F_OBJ_CREATE = 100
  OBJ_F_OBJ_DUP = 101
  OBJ_F_OBJ_NAME_NEW_INDEX = 106
  OBJ_F_OBJ_NID2LN = 102
  OBJ_F_OBJ_NID2OBJ = 103
  OBJ_F_OBJ_NID2SN = 104
  OBJ_R_MALLOC_FAILURE = 100
  OBJ_R_UNKNOWN_NID = 101
  EVP_PK_RSA = 0x0001
  EVP_PK_DSA = 0x0002
  EVP_PK_DH = 0x0004
  EVP_PK_EC = 0x0008
  EVP_PKT_SIGN = 0x0010
  EVP_PKT_ENC = 0x0020
  EVP_PKT_EXCH = 0x0040
  EVP_PKS_RSA = 0x0100
  EVP_PKS_DSA = 0x0200
  EVP_PKS_EC = 0x0400
  EVP_PKT_EXP = 0x1000
  EVP_PKEY_NONE = 0
  EVP_PKEY_RSA = 6
  EVP_PKEY_RSA2 = 19
  EVP_PKEY_DSA = 116
  EVP_PKEY_DSA1 = 67
  EVP_PKEY_DSA2 = 66
  EVP_PKEY_DSA3 = 113
  EVP_PKEY_DSA4 = 70
  EVP_PKEY_DH = 28
  EVP_PKEY_EC = 408
  class EvpPkeyStPkey < FFI::Union
    layout(
           :ptr, :pointer,
           :rsa, :pointer,
           :dsa, :pointer,
           :dh, :pointer,
           :ec, :pointer
    )
    def ptr=(str)
      @ptr = FFI::MemoryPointer.from_string(str)
      self[:ptr] = @ptr
    end
    def ptr
      @ptr.get_string(0)
    end

  end
# FIXME: Nested structures are not correctly supported at the moment.
# Please check the order of the declarations in the structure below.
#   class EvpPkeySt < FFI::Struct
#     layout(
#            :type, :int,
#            :save_type, :int,
#            :references, :int,
#            :save_parameters, :int,
#            :attributes, :pointer,
#            :pkey, EvpPkeyStPkey
#     )
#   end
  EVP_PKEY_MO_SIGN = 0x0001
  EVP_PKEY_MO_VERIFY = 0x0002
  EVP_PKEY_MO_ENCRYPT = 0x0004
  EVP_PKEY_MO_DECRYPT = 0x0008
  class EnvMdSt < FFI::Struct
    layout(
           :type, :int,
           :pkey_type, :int,
           :md_size, :int,
           :flags, :ulong,
           :init, callback([ :pointer ], :int),
           :update, callback([ :pointer, :pointer, :uint ], :int),
           :final, callback([ :pointer, :pointer ], :int),
           :copy, callback([ :pointer, :pointer ], :int),
           :cleanup, callback([ :pointer ], :int),
           :sign, callback([ :int, :pointer, :uint, :pointer, :pointer, :pointer ], :int),
           :verify, callback([ :int, :pointer, :uint, :pointer, :uint, :pointer ], :int),
           :required_pkey_type, [:int, 5],
           :block_size, :int,
           :ctx_size, :int
    )
    def init=(cb)
      @init = cb
      self[:init] = @init
    end
    def init
      @init
    end
    def update=(cb)
      @update = cb
      self[:update] = @update
    end
    def update
      @update
    end
    def final=(cb)
      @final = cb
      self[:final] = @final
    end
    def final
      @final
    end
    def copy=(cb)
      @copy = cb
      self[:copy] = @copy
    end
    def copy
      @copy
    end
    def cleanup=(cb)
      @cleanup = cb
      self[:cleanup] = @cleanup
    end
    def cleanup
      @cleanup
    end
    def sign=(cb)
      @sign = cb
      self[:sign] = @sign
    end
    def sign
      @sign
    end
    def verify=(cb)
      @verify = cb
      self[:verify] = @verify
    end
    def verify
      @verify
    end

  end
  attach_function :evp_sign_method, [ :int, :pointer, :uint, :pointer, :pointer, :pointer ], :int
  attach_function :evp_verify_method, [ :int, :pointer, :uint, :pointer, :uint, :pointer ], :int
  class EVPMDSVCTX < FFI::Struct
    layout(
           :mctx, :pointer,
           :key, :pointer
    )
  end
  EVP_MD_FLAG_ONESHOT = 0x0001
  EVP_MD_FLAG_FIPS = 0x0400
  EVP_MD_FLAG_SVCTX = 0x0800
  class EnvMdCtxSt < FFI::Struct
    layout(
           :digest, :pointer,
           :engine, :pointer,
           :flags, :ulong,
           :md_data, :pointer
    )
  end
  EVP_MD_CTX_FLAG_ONESHOT = 0x0001
  EVP_MD_CTX_FLAG_CLEANED = 0x0002
  EVP_MD_CTX_FLAG_REUSE = 0x0004
  EVP_MD_CTX_FLAG_NON_FIPS_ALLOW = 0x0008
  EVP_MD_CTX_FLAG_PAD_MASK = 0xF0
  EVP_MD_CTX_FLAG_PAD_PKCS1 = 0x00
  EVP_MD_CTX_FLAG_PAD_X931 = 0x10
  EVP_MD_CTX_FLAG_PAD_PSS = 0x20
  EVP_MD_CTX_FLAG_PSS_MDLEN = 0xFFFF
  EVP_MD_CTX_FLAG_PSS_MREC = 0xFFFE
  class EvpCipherSt < FFI::Struct
    layout(
           :nid, :int,
           :block_size, :int,
           :key_len, :int,
           :iv_len, :int,
           :flags, :ulong,
           :init, callback([ :pointer, :pointer, :pointer, :int ], :int),
           :do_cipher, callback([ :pointer, :pointer, :pointer, :uint ], :int),
           :cleanup, callback([ :pointer ], :int),
           :ctx_size, :int,
           :set_asn1_parameters, callback([ :pointer, :pointer ], :int),
           :get_asn1_parameters, callback([ :pointer, :pointer ], :int),
           :ctrl, callback([ :pointer, :int, :int, :pointer ], :int),
           :app_data, :pointer
    )
    def init=(cb)
      @init = cb
      self[:init] = @init
    end
    def init
      @init
    end
    def do_cipher=(cb)
      @do_cipher = cb
      self[:do_cipher] = @do_cipher
    end
    def do_cipher
      @do_cipher
    end
    def cleanup=(cb)
      @cleanup = cb
      self[:cleanup] = @cleanup
    end
    def cleanup
      @cleanup
    end
    def set_asn1_parameters=(cb)
      @set_asn1_parameters = cb
      self[:set_asn1_parameters] = @set_asn1_parameters
    end
    def set_asn1_parameters
      @set_asn1_parameters
    end
    def get_asn1_parameters=(cb)
      @get_asn1_parameters = cb
      self[:get_asn1_parameters] = @get_asn1_parameters
    end
    def get_asn1_parameters
      @get_asn1_parameters
    end
    def ctrl=(cb)
      @ctrl = cb
      self[:ctrl] = @ctrl
    end
    def ctrl
      @ctrl
    end

  end
  EVP_CIPH_STREAM_CIPHER = 0x0
  EVP_CIPH_ECB_MODE = 0x1
  EVP_CIPH_CBC_MODE = 0x2
  EVP_CIPH_CFB_MODE = 0x3
  EVP_CIPH_OFB_MODE = 0x4
  EVP_CIPH_MODE = 0x7
  EVP_CIPH_VARIABLE_LENGTH = 0x8
  EVP_CIPH_CUSTOM_IV = 0x10
  EVP_CIPH_ALWAYS_CALL_INIT = 0x20
  EVP_CIPH_CTRL_INIT = 0x40
  EVP_CIPH_CUSTOM_KEY_LENGTH = 0x80
  EVP_CIPH_NO_PADDING = 0x100
  EVP_CIPH_RAND_KEY = 0x200
  EVP_CIPH_FLAG_FIPS = 0x400
  EVP_CIPH_FLAG_NON_FIPS_ALLOW = 0x800
  EVP_CIPH_FLAG_DEFAULT_ASN1 = 0x1000
  EVP_CIPH_FLAG_LENGTH_BITS = 0x2000
  EVP_CTRL_INIT = 0x0
  EVP_CTRL_SET_KEY_LENGTH = 0x1
  EVP_CTRL_GET_RC2_KEY_BITS = 0x2
  EVP_CTRL_SET_RC2_KEY_BITS = 0x3
  EVP_CTRL_GET_RC5_ROUNDS = 0x4
  EVP_CTRL_SET_RC5_ROUNDS = 0x5
  EVP_CTRL_RAND_KEY = 0x6
  class EvpCipherInfoSt < FFI::Struct
    layout(
           :cipher, :pointer,
           :iv, [:uchar, 16]
    )
  end
  class EvpCipherCtxSt < FFI::Struct
    layout(
           :cipher, :pointer,
           :engine, :pointer,
           :encrypt, :int,
           :buf_len, :int,
           :oiv, [:uchar, 16],
           :iv, [:uchar, 16],
           :buf, [:uchar, 32],
           :num, :int,
           :app_data, :pointer,
           :key_len, :int,
           :flags, :ulong,
           :cipher_data, :pointer,
           :final_used, :int,
           :block_mask, :int,
           :final, [:uchar, 32]
    )
  end
  class EvpEncodeCtxSt < FFI::Struct
    layout(
           :num, :int,
           :length, :int,
           :enc_data, [:uchar, 80],
           :line_num, :int,
           :expect_nl, :int
    )
  end
  attach_function :EVP_PBE_KEYGEN, [ :pointer, :string, :int, :pointer, :pointer, :pointer, :int ], :int
  attach_function :EVP_MD_type, [ :pointer ], :int
  attach_function :EVP_MD_pkey_type, [ :pointer ], :int
  attach_function :EVP_MD_size, [ :pointer ], :int
  attach_function :EVP_MD_block_size, [ :pointer ], :int
  attach_function :EVP_MD_CTX_md, [ :pointer ], :pointer
  attach_function :EVP_CIPHER_nid, [ :pointer ], :int
  attach_function :EVP_CIPHER_block_size, [ :pointer ], :int
  attach_function :EVP_CIPHER_key_length, [ :pointer ], :int
  attach_function :EVP_CIPHER_iv_length, [ :pointer ], :int
  attach_function :EVP_CIPHER_flags, [ :pointer ], :ulong
  attach_function :EVP_CIPHER_CTX_cipher, [ :pointer ], :pointer
  attach_function :EVP_CIPHER_CTX_nid, [ :pointer ], :int
  attach_function :EVP_CIPHER_CTX_block_size, [ :pointer ], :int
  attach_function :EVP_CIPHER_CTX_key_length, [ :pointer ], :int
  attach_function :EVP_CIPHER_CTX_iv_length, [ :pointer ], :int
  attach_function :EVP_CIPHER_CTX_get_app_data, [ :pointer ], :pointer
  attach_function :EVP_CIPHER_CTX_set_app_data, [ :pointer, :pointer ], :void
  attach_function :EVP_CIPHER_CTX_flags, [ :pointer ], :ulong
  attach_function :EVP_Cipher, [ :pointer, :pointer, :pointer, :uint ], :int
  attach_function :EVP_MD_CTX_init, [ :pointer ], :void
  attach_function :EVP_MD_CTX_cleanup, [ :pointer ], :int
  attach_function :EVP_MD_CTX_create, [  ], :pointer
  attach_function :EVP_MD_CTX_destroy, [ :pointer ], :void
  attach_function :EVP_MD_CTX_copy_ex, [ :pointer, :pointer ], :int
  attach_function :EVP_MD_CTX_set_flags, [ :pointer, :int ], :void
  attach_function :EVP_MD_CTX_clear_flags, [ :pointer, :int ], :void
  attach_function :EVP_MD_CTX_test_flags, [ :pointer, :int ], :int
  attach_function :EVP_DigestInit_ex, [ :pointer, :pointer, :pointer ], :int
  attach_function :EVP_DigestUpdate, [ :pointer, :pointer, :uint ], :int
  attach_function :EVP_DigestFinal_ex, [ :pointer, :pointer, :pointer ], :int
  attach_function :EVP_Digest, [ :pointer, :uint, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :EVP_MD_CTX_copy, [ :pointer, :pointer ], :int
  attach_function :EVP_DigestInit, [ :pointer, :pointer ], :int
  attach_function :EVP_DigestFinal, [ :pointer, :pointer, :pointer ], :int
  attach_function :EVP_read_pw_string, [ :string, :int, :string, :int ], :int
  attach_function :EVP_set_pw_prompt, [ :string ], :void
  attach_function :EVP_get_pw_prompt, [  ], :string
  attach_function :EVP_BytesToKey, [ :pointer, :pointer, :pointer, :pointer, :int, :int, :pointer, :pointer ], :int
  attach_function :EVP_CIPHER_CTX_set_flags, [ :pointer, :int ], :void
  attach_function :EVP_CIPHER_CTX_clear_flags, [ :pointer, :int ], :void
  attach_function :EVP_CIPHER_CTX_test_flags, [ :pointer, :int ], :int
  attach_function :EVP_EncryptInit, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :EVP_EncryptInit_ex, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :EVP_EncryptUpdate, [ :pointer, :pointer, :pointer, :pointer, :int ], :int
  attach_function :EVP_EncryptFinal_ex, [ :pointer, :pointer, :pointer ], :int
  attach_function :EVP_EncryptFinal, [ :pointer, :pointer, :pointer ], :int
  attach_function :EVP_DecryptInit, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :EVP_DecryptInit_ex, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :EVP_DecryptUpdate, [ :pointer, :pointer, :pointer, :pointer, :int ], :int
  attach_function :EVP_DecryptFinal, [ :pointer, :pointer, :pointer ], :int
  attach_function :EVP_DecryptFinal_ex, [ :pointer, :pointer, :pointer ], :int
  attach_function :EVP_CipherInit, [ :pointer, :pointer, :pointer, :pointer, :int ], :int
  attach_function :EVP_CipherInit_ex, [ :pointer, :pointer, :pointer, :pointer, :pointer, :int ], :int
  attach_function :EVP_CipherUpdate, [ :pointer, :pointer, :pointer, :pointer, :int ], :int
  attach_function :EVP_CipherFinal, [ :pointer, :pointer, :pointer ], :int
  attach_function :EVP_CipherFinal_ex, [ :pointer, :pointer, :pointer ], :int
  attach_function :EVP_SignFinal, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :EVP_VerifyFinal, [ :pointer, :pointer, :uint, :pointer ], :int
  attach_function :EVP_OpenInit, [ :pointer, :pointer, :pointer, :int, :pointer, :pointer ], :int
  attach_function :EVP_OpenFinal, [ :pointer, :pointer, :pointer ], :int
  attach_function :EVP_SealInit, [ :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :int ], :int
  attach_function :EVP_SealFinal, [ :pointer, :pointer, :pointer ], :int
  attach_function :EVP_EncodeInit, [ :pointer ], :void
  attach_function :EVP_EncodeUpdate, [ :pointer, :pointer, :pointer, :pointer, :int ], :void
  attach_function :EVP_EncodeFinal, [ :pointer, :pointer, :pointer ], :void
  attach_function :EVP_EncodeBlock, [ :pointer, :pointer, :int ], :int
  attach_function :EVP_DecodeInit, [ :pointer ], :void
  attach_function :EVP_DecodeUpdate, [ :pointer, :pointer, :pointer, :pointer, :int ], :int
  attach_function :EVP_DecodeFinal, [ :pointer, :pointer, :pointer ], :int
  attach_function :EVP_DecodeBlock, [ :pointer, :pointer, :int ], :int
  attach_function :EVP_CIPHER_CTX_init, [ :pointer ], :void
  attach_function :EVP_CIPHER_CTX_cleanup, [ :pointer ], :int
  attach_function :EVP_CIPHER_CTX_new, [  ], :pointer
  attach_function :EVP_CIPHER_CTX_free, [ :pointer ], :void
  attach_function :EVP_CIPHER_CTX_set_key_length, [ :pointer, :int ], :int
  attach_function :EVP_CIPHER_CTX_set_padding, [ :pointer, :int ], :int
  attach_function :EVP_CIPHER_CTX_ctrl, [ :pointer, :int, :int, :pointer ], :int
  attach_function :EVP_CIPHER_CTX_rand_key, [ :pointer, :pointer ], :int
  attach_function :BIO_f_md, [  ], :pointer
  attach_function :BIO_f_base64, [  ], :pointer
  attach_function :BIO_f_cipher, [  ], :pointer
  attach_function :BIO_f_reliable, [  ], :pointer
  attach_function :BIO_set_cipher, [ :pointer, :pointer, :pointer, :pointer, :int ], :void
  attach_function :EVP_md_null, [  ], :pointer
  attach_function :EVP_md2, [  ], :pointer
  attach_function :EVP_md4, [  ], :pointer
  attach_function :EVP_md5, [  ], :pointer
  attach_function :EVP_sha, [  ], :pointer
  attach_function :EVP_sha1, [  ], :pointer
  attach_function :EVP_dss, [  ], :pointer
  attach_function :EVP_dss1, [  ], :pointer
  attach_function :EVP_ecdsa, [  ], :pointer
  attach_function :EVP_sha224, [  ], :pointer
  attach_function :EVP_sha256, [  ], :pointer
  attach_function :EVP_sha384, [  ], :pointer
  attach_function :EVP_sha512, [  ], :pointer
  attach_function :EVP_ripemd160, [  ], :pointer
  attach_function :EVP_enc_null, [  ], :pointer
  attach_function :EVP_des_ecb, [  ], :pointer
  attach_function :EVP_des_ede, [  ], :pointer
  attach_function :EVP_des_ede3, [  ], :pointer
  attach_function :EVP_des_ede_ecb, [  ], :pointer
  attach_function :EVP_des_ede3_ecb, [  ], :pointer
  attach_function :EVP_des_cfb64, [  ], :pointer
  attach_function :EVP_des_cfb1, [  ], :pointer
  attach_function :EVP_des_cfb8, [  ], :pointer
  attach_function :EVP_des_ede_cfb64, [  ], :pointer
  attach_function :EVP_des_ede3_cfb64, [  ], :pointer
  attach_function :EVP_des_ede3_cfb1, [  ], :pointer
  attach_function :EVP_des_ede3_cfb8, [  ], :pointer
  attach_function :EVP_des_ofb, [  ], :pointer
  attach_function :EVP_des_ede_ofb, [  ], :pointer
  attach_function :EVP_des_ede3_ofb, [  ], :pointer
  attach_function :EVP_des_cbc, [  ], :pointer
  attach_function :EVP_des_ede_cbc, [  ], :pointer
  attach_function :EVP_des_ede3_cbc, [  ], :pointer
  attach_function :EVP_desx_cbc, [  ], :pointer
  attach_function :EVP_rc4, [  ], :pointer
  attach_function :EVP_rc4_40, [  ], :pointer
  attach_function :EVP_rc2_ecb, [  ], :pointer
  attach_function :EVP_rc2_cbc, [  ], :pointer
  attach_function :EVP_rc2_40_cbc, [  ], :pointer
  attach_function :EVP_rc2_64_cbc, [  ], :pointer
  attach_function :EVP_rc2_cfb64, [  ], :pointer
  attach_function :EVP_rc2_ofb, [  ], :pointer
  attach_function :EVP_bf_ecb, [  ], :pointer
  attach_function :EVP_bf_cbc, [  ], :pointer
  attach_function :EVP_bf_cfb64, [  ], :pointer
  attach_function :EVP_bf_ofb, [  ], :pointer
  attach_function :EVP_cast5_ecb, [  ], :pointer
  attach_function :EVP_cast5_cbc, [  ], :pointer
  attach_function :EVP_cast5_cfb64, [  ], :pointer
  attach_function :EVP_cast5_ofb, [  ], :pointer
  attach_function :EVP_aes_128_ecb, [  ], :pointer
  attach_function :EVP_aes_128_cbc, [  ], :pointer
  attach_function :EVP_aes_128_cfb1, [  ], :pointer
  attach_function :EVP_aes_128_cfb8, [  ], :pointer
  attach_function :EVP_aes_128_cfb128, [  ], :pointer
  attach_function :EVP_aes_128_ofb, [  ], :pointer
  attach_function :EVP_aes_192_ecb, [  ], :pointer
  attach_function :EVP_aes_192_cbc, [  ], :pointer
  attach_function :EVP_aes_192_cfb1, [  ], :pointer
  attach_function :EVP_aes_192_cfb8, [  ], :pointer
  attach_function :EVP_aes_192_cfb128, [  ], :pointer
  attach_function :EVP_aes_192_ofb, [  ], :pointer
  attach_function :EVP_aes_256_ecb, [  ], :pointer
  attach_function :EVP_aes_256_cbc, [  ], :pointer
  attach_function :EVP_aes_256_cfb1, [  ], :pointer
  attach_function :EVP_aes_256_cfb8, [  ], :pointer
  attach_function :EVP_aes_256_cfb128, [  ], :pointer
  attach_function :EVP_aes_256_ofb, [  ], :pointer
  attach_function :OPENSSL_add_all_algorithms_noconf, [  ], :void
  attach_function :OPENSSL_add_all_algorithms_conf, [  ], :void
  attach_function :OpenSSL_add_all_ciphers, [  ], :void
  attach_function :OpenSSL_add_all_digests, [  ], :void
  attach_function :EVP_add_cipher, [ :pointer ], :int
  attach_function :EVP_add_digest, [ :pointer ], :int
  attach_function :EVP_get_cipherbyname, [ :string ], :pointer
  attach_function :EVP_get_digestbyname, [ :string ], :pointer
  attach_function :EVP_cleanup, [  ], :void
  attach_function :EVP_PKEY_decrypt, [ :pointer, :pointer, :int, :pointer ], :int
  attach_function :EVP_PKEY_encrypt, [ :pointer, :pointer, :int, :pointer ], :int
  attach_function :EVP_PKEY_type, [ :int ], :int
  attach_function :EVP_PKEY_bits, [ :pointer ], :int
  attach_function :EVP_PKEY_size, [ :pointer ], :int
  attach_function :EVP_PKEY_assign, [ :pointer, :int, :string ], :int
  attach_function :EVP_PKEY_set1_RSA, [ :pointer, :pointer ], :int
  attach_function :EVP_PKEY_get1_RSA, [ :pointer ], :pointer
  attach_function :EVP_PKEY_set1_DSA, [ :pointer, :pointer ], :int
  attach_function :EVP_PKEY_get1_DSA, [ :pointer ], :pointer
  attach_function :EVP_PKEY_set1_DH, [ :pointer, :pointer ], :int
  attach_function :EVP_PKEY_get1_DH, [ :pointer ], :pointer
  attach_function :EVP_PKEY_set1_EC_KEY, [ :pointer, :pointer ], :int
  attach_function :EVP_PKEY_get1_EC_KEY, [ :pointer ], :pointer
  attach_function :EVP_PKEY_new, [  ], :pointer
  attach_function :EVP_PKEY_free, [ :pointer ], :void
  attach_function :d2i_PublicKey, [ :int, :pointer, :pointer, :long ], :pointer
  attach_function :i2d_PublicKey, [ :pointer, :pointer ], :int
  attach_function :d2i_PrivateKey, [ :int, :pointer, :pointer, :long ], :pointer
  attach_function :d2i_AutoPrivateKey, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_PrivateKey, [ :pointer, :pointer ], :int
  attach_function :EVP_PKEY_copy_parameters, [ :pointer, :pointer ], :int
  attach_function :EVP_PKEY_missing_parameters, [ :pointer ], :int
  attach_function :EVP_PKEY_save_parameters, [ :pointer, :int ], :int
  attach_function :EVP_PKEY_cmp_parameters, [ :pointer, :pointer ], :int
  attach_function :EVP_PKEY_cmp, [ :pointer, :pointer ], :int
  attach_function :EVP_CIPHER_type, [ :pointer ], :int
  attach_function :EVP_CIPHER_param_to_asn1, [ :pointer, :pointer ], :int
  attach_function :EVP_CIPHER_asn1_to_param, [ :pointer, :pointer ], :int
  attach_function :EVP_CIPHER_set_asn1_iv, [ :pointer, :pointer ], :int
  attach_function :EVP_CIPHER_get_asn1_iv, [ :pointer, :pointer ], :int
  attach_function :PKCS5_PBE_keyivgen, [ :pointer, :string, :int, :pointer, :pointer, :pointer, :int ], :int
  attach_function :PKCS5_PBKDF2_HMAC_SHA1, [ :string, :int, :pointer, :int, :int, :int, :pointer ], :int
  attach_function :PKCS5_v2_PBE_keyivgen, [ :pointer, :string, :int, :pointer, :pointer, :pointer, :int ], :int
  attach_function :PKCS5_PBE_add, [  ], :void
  attach_function :EVP_PBE_CipherInit, [ :pointer, :string, :int, :pointer, :pointer, :int ], :int
  attach_function :EVP_PBE_alg_add, [ :int, :pointer, :pointer, :pointer ], :int
  attach_function :EVP_PBE_cleanup, [  ], :void
  attach_function :EVP_add_alg_module, [  ], :void
  attach_function :ERR_load_EVP_strings, [  ], :void
  EVP_F_AESNI_INIT_KEY = 163
  EVP_F_AES_INIT_KEY = 133
  EVP_F_ALG_MODULE_INIT = 138
  EVP_F_CAMELLIA_INIT_KEY = 159
  EVP_F_D2I_PKEY = 100
  EVP_F_DO_EVP_ENC_ENGINE = 140
  EVP_F_DO_EVP_ENC_ENGINE_FULL = 141
  EVP_F_DO_EVP_MD_ENGINE = 139
  EVP_F_DO_EVP_MD_ENGINE_FULL = 142
  EVP_F_DSAPKEY2PKCS8 = 134
  EVP_F_DSA_PKEY2PKCS8 = 135
  EVP_F_ECDSA_PKEY2PKCS8 = 129
  EVP_F_ECKEY_PKEY2PKCS8 = 132
  EVP_F_EVP_CIPHERINIT = 137
  EVP_F_EVP_CIPHERINIT_EX = 123
  EVP_F_EVP_CIPHER_CTX_CTRL = 124
  EVP_F_EVP_CIPHER_CTX_SET_KEY_LENGTH = 122
  EVP_F_EVP_DECRYPTFINAL_EX = 101
  EVP_F_EVP_DIGESTINIT = 136
  EVP_F_EVP_DIGESTINIT_EX = 128
  EVP_F_EVP_ENCRYPTFINAL_EX = 127
  EVP_F_EVP_MD_CTX_COPY_EX = 110
  EVP_F_EVP_OPENINIT = 102
  EVP_F_EVP_PBE_ALG_ADD = 115
  EVP_F_EVP_PBE_CIPHERINIT = 116
  EVP_F_EVP_PKCS82PKEY = 111
  EVP_F_EVP_PKEY2PKCS8_BROKEN = 113
  EVP_F_EVP_PKEY_COPY_PARAMETERS = 103
  EVP_F_EVP_PKEY_DECRYPT = 104
  EVP_F_EVP_PKEY_ENCRYPT = 105
  EVP_F_EVP_PKEY_GET1_DH = 119
  EVP_F_EVP_PKEY_GET1_DSA = 120
  EVP_F_EVP_PKEY_GET1_ECDSA = 130
  EVP_F_EVP_PKEY_GET1_EC_KEY = 131
  EVP_F_EVP_PKEY_GET1_RSA = 121
  EVP_F_EVP_PKEY_NEW = 106
  EVP_F_EVP_RIJNDAEL = 126
  EVP_F_EVP_SIGNFINAL = 107
  EVP_F_EVP_VERIFYFINAL = 108
  EVP_F_PKCS5_PBE_KEYIVGEN = 117
  EVP_F_PKCS5_V2_PBE_KEYIVGEN = 118
  EVP_F_PKCS8_SET_BROKEN = 112
  EVP_F_RC2_MAGIC_TO_METH = 109
  EVP_F_RC5_CTRL = 125
  EVP_R_AES_KEY_SETUP_FAILED = 143
  EVP_R_ASN1_LIB = 140
  EVP_R_BAD_BLOCK_LENGTH = 136
  EVP_R_BAD_DECRYPT = 100
  EVP_R_BAD_KEY_LENGTH = 137
  EVP_R_BN_DECODE_ERROR = 112
  EVP_R_BN_PUBKEY_ERROR = 113
  EVP_R_CAMELLIA_KEY_SETUP_FAILED = 157
  EVP_R_CIPHER_PARAMETER_ERROR = 122
  EVP_R_CTRL_NOT_IMPLEMENTED = 132
  EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED = 133
  EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH = 138
  EVP_R_DECODE_ERROR = 114
  EVP_R_DIFFERENT_KEY_TYPES = 101
  EVP_R_DISABLED_FOR_FIPS = 144
  EVP_R_ENCODE_ERROR = 115
  EVP_R_ERROR_LOADING_SECTION = 145
  EVP_R_ERROR_SETTING_FIPS_MODE = 146
  EVP_R_EVP_PBE_CIPHERINIT_ERROR = 119
  EVP_R_EXPECTING_AN_RSA_KEY = 127
  EVP_R_EXPECTING_A_DH_KEY = 128
  EVP_R_EXPECTING_A_DSA_KEY = 129
  EVP_R_EXPECTING_A_ECDSA_KEY = 141
  EVP_R_EXPECTING_A_EC_KEY = 142
  EVP_R_FIPS_MODE_NOT_SUPPORTED = 147
  EVP_R_INITIALIZATION_ERROR = 134
  EVP_R_INPUT_NOT_INITIALIZED = 111
  EVP_R_INVALID_FIPS_MODE = 148
  EVP_R_INVALID_KEY_LENGTH = 130
  EVP_R_IV_TOO_LARGE = 102
  EVP_R_KEYGEN_FAILURE = 120
  EVP_R_MISSING_PARAMETERS = 103
  EVP_R_NO_CIPHER_SET = 131
  EVP_R_NO_DIGEST_SET = 139
  EVP_R_NO_DSA_PARAMETERS = 116
  EVP_R_NO_SIGN_FUNCTION_CONFIGURED = 104
  EVP_R_NO_VERIFY_FUNCTION_CONFIGURED = 105
  EVP_R_PKCS8_UNKNOWN_BROKEN_TYPE = 117
  EVP_R_PUBLIC_KEY_NOT_RSA = 106
  EVP_R_UNKNOWN_OPTION = 149
  EVP_R_UNKNOWN_PBE_ALGORITHM = 121
  EVP_R_UNSUPORTED_NUMBER_OF_ROUNDS = 135
  EVP_R_UNSUPPORTED_CIPHER = 107
  EVP_R_UNSUPPORTED_KEYLENGTH = 123
  EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION = 124
  EVP_R_UNSUPPORTED_KEY_SIZE = 108
  EVP_R_UNSUPPORTED_PRF = 125
  EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM = 118
  EVP_R_UNSUPPORTED_SALT_TYPE = 126
  EVP_R_WRONG_FINAL_BLOCK_LENGTH = 109
  EVP_R_WRONG_PUBLIC_KEY_TYPE = 110
  EVP_R_SEED_KEY_SETUP_FAILED = 162
  AES_ENCRYPT = 1
  AES_DECRYPT = 0
  AES_MAXNR = 14
  AES_BLOCK_SIZE = 16
  class AesKeySt < FFI::Struct
    layout(
           :rd_key, [:uint, 4*(14+1)],
           :rounds, :int
    )
  end
  attach_function :AES_options, [  ], :string
  attach_function :AES_set_encrypt_key, [ :pointer, :int, :pointer ], :int
  attach_function :AES_set_decrypt_key, [ :pointer, :int, :pointer ], :int
  attach_function :AES_encrypt, [ :pointer, :pointer, :pointer ], :void
  attach_function :AES_decrypt, [ :pointer, :pointer, :pointer ], :void
  attach_function :AES_ecb_encrypt, [ :pointer, :pointer, :pointer, :int ], :void
  attach_function :AES_cbc_encrypt, [ :pointer, :pointer, :ulong, :pointer, :pointer, :int ], :void
  attach_function :AES_cfb128_encrypt, [ :pointer, :pointer, :ulong, :pointer, :pointer, :pointer, :int ], :void
  attach_function :AES_cfb1_encrypt, [ :pointer, :pointer, :ulong, :pointer, :pointer, :pointer, :int ], :void
  attach_function :AES_cfb8_encrypt, [ :pointer, :pointer, :ulong, :pointer, :pointer, :pointer, :int ], :void
  attach_function :AES_cfbr_encrypt_block, [ :pointer, :pointer, :int, :pointer, :pointer, :int ], :void
  attach_function :AES_ofb128_encrypt, [ :pointer, :pointer, :ulong, :pointer, :pointer, :pointer ], :void
  attach_function :AES_ctr128_encrypt, [ :pointer, :pointer, :ulong, :pointer, [:uchar, 16], [:uchar, 16], :pointer ], :void
  attach_function :AES_ige_encrypt, [ :pointer, :pointer, :ulong, :pointer, :pointer, :int ], :void
  attach_function :AES_bi_ige_encrypt, [ :pointer, :pointer, :ulong, :pointer, :pointer, :pointer, :int ], :void
  attach_function :AES_wrap_key, [ :pointer, :pointer, :pointer, :pointer, :uint ], :int
  attach_function :AES_unwrap_key, [ :pointer, :pointer, :pointer, :pointer, :uint ], :int
  class Rc4KeySt < FFI::Struct
    layout(
           :x, RC4_INT,
           :y, RC4_INT,
           :data, [RC4_INT, 256]
    )
  end
  attach_function :RC4_options, [  ], :string
  attach_function :RC4_set_key, [ :pointer, :int, :pointer ], :void
  attach_function :RC4, [ :pointer, :ulong, :pointer, :pointer ], :void
  BF_ENCRYPT = 1
  BF_DECRYPT = 0
  BF_ROUNDS = 16
  BF_BLOCK = 8
  class BfKeySt < FFI::Struct
    layout(
           :P, [:uint, 16+2],
           :S, [:uint, 4*256]
    )
  end
  attach_function :BF_set_key, [ :pointer, :int, :pointer ], :void
  attach_function :BF_encrypt, [ :pointer, :pointer ], :void
  attach_function :BF_decrypt, [ :pointer, :pointer ], :void
  attach_function :BF_ecb_encrypt, [ :pointer, :pointer, :pointer, :int ], :void
  attach_function :BF_cbc_encrypt, [ :pointer, :pointer, :long, :pointer, :pointer, :int ], :void
  attach_function :BF_cfb64_encrypt, [ :pointer, :pointer, :long, :pointer, :pointer, :pointer, :int ], :void
  attach_function :BF_ofb64_encrypt, [ :pointer, :pointer, :long, :pointer, :pointer, :pointer ], :void
  attach_function :BF_options, [  ], :string
  class DESKs < FFI::Struct
    layout(
           :ks, [DESKeyScheduleKs, 16]
    )
  end
  class DESKeyScheduleKs < FFI::Union
    layout(
           :cblock, [:uchar, 8],
           :deslong, [DES_LONG, 2]
    )
  end
  class OsslOldDesKsStructKs < FFI::Union
    layout(
           :_, [:uchar, 8],
           :pad, [DES_LONG, 2]
    )
  end
# FIXME: Nested structures are not correctly supported at the moment.
# Please check the order of the declarations in the structure below.
#   class OsslOldDesKsStruct < FFI::Struct
#     layout(
#            :ks, OsslOldDesKsStructKs
#     )
#   end
  attach_function :_ossl_old_des_options, [  ], :string
  attach_function :_ossl_old_des_ecb3_encrypt, [ :pointer, :pointer, [OsslOldDesKsStruct, 16], OsslOldDesKsStruct, OsslOldDesKsStruct, :int ], :void
  attach_function :_ossl_old_des_cbc_cksum, [ :pointer, :pointer, :long, OsslOldDesKsStruct, :pointer ], DES_LONG
  attach_function :_ossl_old_des_cbc_encrypt, [ :pointer, :pointer, :long, OsslOldDesKsStruct, :pointer, :int ], :void
  attach_function :_ossl_old_des_ncbc_encrypt, [ :pointer, :pointer, :long, OsslOldDesKsStruct, :pointer, :int ], :void
  attach_function :_ossl_old_des_xcbc_encrypt, [ :pointer, :pointer, :long, OsslOldDesKsStruct, :pointer, :pointer, :pointer, :int ], :void
  attach_function :_ossl_old_des_cfb_encrypt, [ :pointer, :pointer, :int, :long, OsslOldDesKsStruct, :pointer, :int ], :void
  attach_function :_ossl_old_des_ecb_encrypt, [ :pointer, :pointer, OsslOldDesKsStruct, :int ], :void
  attach_function :_ossl_old_des_encrypt, [ :pointer, OsslOldDesKsStruct, :int ], :void
  attach_function :_ossl_old_des_encrypt2, [ :pointer, OsslOldDesKsStruct, :int ], :void
  attach_function :_ossl_old_des_encrypt3, [ :pointer, OsslOldDesKsStruct, OsslOldDesKsStruct, OsslOldDesKsStruct ], :void
  attach_function :_ossl_old_des_decrypt3, [ :pointer, OsslOldDesKsStruct, OsslOldDesKsStruct, OsslOldDesKsStruct ], :void
  attach_function :_ossl_old_des_ede3_cbc_encrypt, [ :pointer, :pointer, :long, OsslOldDesKsStruct, OsslOldDesKsStruct, OsslOldDesKsStruct, :pointer, :int ], :void
  attach_function :_ossl_old_des_ede3_cfb64_encrypt, [ :pointer, :pointer, :long, OsslOldDesKsStruct, OsslOldDesKsStruct, OsslOldDesKsStruct, :pointer, :pointer, :int ], :void
  attach_function :_ossl_old_des_ede3_ofb64_encrypt, [ :pointer, :pointer, :long, OsslOldDesKsStruct, OsslOldDesKsStruct, OsslOldDesKsStruct, :pointer, :pointer ], :void
  attach_function :_ossl_old_des_enc_read, [ :int, :string, :int, OsslOldDesKsStruct, :pointer ], :int
  attach_function :_ossl_old_des_enc_write, [ :int, :string, :int, OsslOldDesKsStruct, :pointer ], :int
  attach_function :_ossl_old_des_fcrypt, [ :string, :string, :string ], :string
  attach_function :_ossl_old_des_crypt, [ :string, :string ], :string
  attach_function :_ossl_old_crypt, [ :string, :string ], :string
  attach_function :_ossl_old_des_ofb_encrypt, [ :pointer, :pointer, :int, :long, OsslOldDesKsStruct, :pointer ], :void
  attach_function :_ossl_old_des_pcbc_encrypt, [ :pointer, :pointer, :long, OsslOldDesKsStruct, :pointer, :int ], :void
  attach_function :_ossl_old_des_quad_cksum, [ :pointer, :pointer, :long, :int, :pointer ], DES_LONG
  attach_function :_ossl_old_des_random_seed, [ :uchar ], :void
  attach_function :_ossl_old_des_random_key, [ :uchar ], :void
  attach_function :_ossl_old_des_read_password, [ :pointer, :string, :int ], :int
  attach_function :_ossl_old_des_read_2passwords, [ :pointer, :pointer, :string, :int ], :int
  attach_function :_ossl_old_des_set_odd_parity, [ :pointer ], :void
  attach_function :_ossl_old_des_is_weak_key, [ :pointer ], :int
  attach_function :_ossl_old_des_set_key, [ :pointer, OsslOldDesKsStruct ], :int
  attach_function :_ossl_old_des_key_sched, [ :pointer, OsslOldDesKsStruct ], :int
  attach_function :_ossl_old_des_string_to_key, [ :string, :pointer ], :void
  attach_function :_ossl_old_des_string_to_2keys, [ :string, :pointer, :pointer ], :void
  attach_function :_ossl_old_des_cfb64_encrypt, [ :pointer, :pointer, :long, OsslOldDesKsStruct, :pointer, :pointer, :int ], :void
  attach_function :_ossl_old_des_ofb64_encrypt, [ :pointer, :pointer, :long, OsslOldDesKsStruct, :pointer, :pointer ], :void
  attach_function :_ossl_096_des_random_seed, [ :pointer ], :void
  attach_function :UI_new, [  ], :pointer
  attach_function :UI_new_method, [ :pointer ], :pointer
  attach_function :UI_free, [ :pointer ], :void
  attach_function :UI_add_input_string, [ :pointer, :string, :int, :string, :int, :int ], :int
  attach_function :UI_dup_input_string, [ :pointer, :string, :int, :string, :int, :int ], :int
  attach_function :UI_add_verify_string, [ :pointer, :string, :int, :string, :int, :int, :string ], :int
  attach_function :UI_dup_verify_string, [ :pointer, :string, :int, :string, :int, :int, :string ], :int
  attach_function :UI_add_input_boolean, [ :pointer, :string, :string, :string, :string, :int, :string ], :int
  attach_function :UI_dup_input_boolean, [ :pointer, :string, :string, :string, :string, :int, :string ], :int
  attach_function :UI_add_info_string, [ :pointer, :string ], :int
  attach_function :UI_dup_info_string, [ :pointer, :string ], :int
  attach_function :UI_add_error_string, [ :pointer, :string ], :int
  attach_function :UI_dup_error_string, [ :pointer, :string ], :int
  UI_INPUT_FLAG_ECHO = 0x01
  UI_INPUT_FLAG_DEFAULT_PWD = 0x02
  UI_INPUT_FLAG_USER_BASE = 16
  attach_function :UI_construct_prompt, [ :pointer, :string, :string ], :string
  attach_function :UI_add_user_data, [ :pointer, :pointer ], :pointer
  attach_function :UI_get0_user_data, [ :pointer ], :pointer
  attach_function :UI_get0_result, [ :pointer, :int ], :string
  attach_function :UI_process, [ :pointer ], :int
  attach_function :UI_ctrl, [ :pointer, :int, :long, :pointer, callback([  ], :void) ], :int
  UI_CTRL_PRINT_ERRORS = 1
  UI_CTRL_IS_REDOABLE = 2
  attach_function :UI_get_ex_new_index, [ :long, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :UI_set_ex_data, [ :pointer, :int, :pointer ], :int
  attach_function :UI_get_ex_data, [ :pointer, :int ], :pointer
  attach_function :UI_set_default_method, [ :pointer ], :void
  attach_function :UI_get_default_method, [  ], :pointer
  attach_function :UI_get_method, [ :pointer ], :pointer
  attach_function :UI_set_method, [ :pointer, :pointer ], :pointer
  attach_function :UI_OpenSSL, [  ], :pointer
  UIT_NONE = 0
  UIT_PROMPT = 1
  UIT_VERIFY = 2
  UIT_BOOLEAN = 3
  UIT_INFO = 4
  UIT_ERROR = 5

  attach_function :UI_create_method, [ :string ], :pointer
  attach_function :UI_destroy_method, [ :pointer ], :void
  attach_function :UI_method_set_opener, [ :pointer, callback([ :pointer ], :int) ], :int
  attach_function :UI_method_set_writer, [ :pointer, callback([ :pointer, :pointer ], :int) ], :int
  attach_function :UI_method_set_flusher, [ :pointer, callback([ :pointer ], :int) ], :int
  attach_function :UI_method_set_reader, [ :pointer, callback([ :pointer, :pointer ], :int) ], :int
  attach_function :UI_method_set_closer, [ :pointer, callback([ :pointer ], :int) ], :int
  attach_function :UI_method_get_opener, [ :pointer ], :pointer
  attach_function :UI_method_get_writer, [ :pointer ], :pointer
  attach_function :UI_method_get_flusher, [ :pointer ], :pointer
  attach_function :UI_method_get_reader, [ :pointer ], :pointer
  attach_function :UI_method_get_closer, [ :pointer ], :pointer
  attach_function :UI_get_string_type, [ :pointer ], :int
  attach_function :UI_get_input_flags, [ :pointer ], :int
  attach_function :UI_get0_output_string, [ :pointer ], :string
  attach_function :UI_get0_action_string, [ :pointer ], :string
  attach_function :UI_get0_result_string, [ :pointer ], :string
  attach_function :UI_get0_test_string, [ :pointer ], :string
  attach_function :UI_get_result_minsize, [ :pointer ], :int
  attach_function :UI_get_result_maxsize, [ :pointer ], :int
  attach_function :UI_set_result, [ :pointer, :pointer, :string ], :int
  attach_function :UI_UTIL_read_pw_string, [ :string, :int, :string, :int ], :int
  attach_function :UI_UTIL_read_pw, [ :string, :string, :int, :string, :int ], :int
  attach_function :ERR_load_UI_strings, [  ], :void
  UI_F_GENERAL_ALLOCATE_BOOLEAN = 108
  UI_F_GENERAL_ALLOCATE_PROMPT = 109
  UI_F_GENERAL_ALLOCATE_STRING = 100
  UI_F_UI_CTRL = 111
  UI_F_UI_DUP_ERROR_STRING = 101
  UI_F_UI_DUP_INFO_STRING = 102
  UI_F_UI_DUP_INPUT_BOOLEAN = 110
  UI_F_UI_DUP_INPUT_STRING = 103
  UI_F_UI_DUP_VERIFY_STRING = 106
  UI_F_UI_GET0_RESULT = 107
  UI_F_UI_NEW_METHOD = 104
  UI_F_UI_SET_RESULT = 105
  UI_R_COMMON_OK_AND_CANCEL_CHARACTERS = 104
  UI_R_INDEX_TOO_LARGE = 102
  UI_R_INDEX_TOO_SMALL = 103
  UI_R_NO_RESULT_BUFFER = 105
  UI_R_RESULT_TOO_LARGE = 100
  UI_R_RESULT_TOO_SMALL = 101
  UI_R_UNKNOWN_CONTROL_COMMAND = 106
  attach_function :_ossl_old_des_read_pw_string, [ :string, :int, :string, :int ], :int
  attach_function :_ossl_old_des_read_pw, [ :string, :string, :int, :string, :int ], :int
  DES_ENCRYPT = 1
  DES_DECRYPT = 0
  DES_CBC_MODE = 0
  DES_PCBC_MODE = 1
  attach_function :DES_options, [  ], :string
  attach_function :DES_ecb3_encrypt, [ :pointer, :pointer, :pointer, :pointer, :pointer, :int ], :void
  attach_function :DES_cbc_cksum, [ :pointer, :pointer, :long, :pointer, :pointer ], DES_LONG
  attach_function :DES_cbc_encrypt, [ :pointer, :pointer, :long, :pointer, :pointer, :int ], :void
  attach_function :DES_ncbc_encrypt, [ :pointer, :pointer, :long, :pointer, :pointer, :int ], :void
  attach_function :DES_xcbc_encrypt, [ :pointer, :pointer, :long, :pointer, :pointer, :pointer, :pointer, :int ], :void
  attach_function :DES_cfb_encrypt, [ :pointer, :pointer, :int, :long, :pointer, :pointer, :int ], :void
  attach_function :DES_ecb_encrypt, [ :pointer, :pointer, :pointer, :int ], :void
  attach_function :DES_encrypt1, [ :pointer, :pointer, :int ], :void
  attach_function :DES_encrypt2, [ :pointer, :pointer, :int ], :void
  attach_function :DES_encrypt3, [ :pointer, :pointer, :pointer, :pointer ], :void
  attach_function :DES_decrypt3, [ :pointer, :pointer, :pointer, :pointer ], :void
  attach_function :DES_ede3_cbc_encrypt, [ :pointer, :pointer, :long, :pointer, :pointer, :pointer, :pointer, :int ], :void
  attach_function :DES_ede3_cbcm_encrypt, [ :pointer, :pointer, :long, :pointer, :pointer, :pointer, :pointer, :pointer, :int ], :void
  attach_function :DES_ede3_cfb64_encrypt, [ :pointer, :pointer, :long, :pointer, :pointer, :pointer, :pointer, :pointer, :int ], :void
  attach_function :DES_ede3_cfb_encrypt, [ :pointer, :pointer, :int, :long, :pointer, :pointer, :pointer, :pointer, :int ], :void
  attach_function :DES_ede3_ofb64_encrypt, [ :pointer, :pointer, :long, :pointer, :pointer, :pointer, :pointer, :pointer ], :void
  attach_function :DES_enc_read, [ :int, :pointer, :int, :pointer, :pointer ], :int
  attach_function :DES_enc_write, [ :int, :pointer, :int, :pointer, :pointer ], :int
  attach_function :DES_fcrypt, [ :string, :string, :string ], :string
  attach_function :DES_crypt, [ :string, :string ], :string
  attach_function :DES_ofb_encrypt, [ :pointer, :pointer, :int, :long, :pointer, :pointer ], :void
  attach_function :DES_pcbc_encrypt, [ :pointer, :pointer, :long, :pointer, :pointer, :int ], :void
  attach_function :DES_quad_cksum, [ :pointer, a().DES_cblock, :long, :int, :pointer ], DES_LONG
  attach_function :DES_random_key, [ :pointer ], :int
  attach_function :DES_set_odd_parity, [ :pointer ], :void
  attach_function :DES_check_key_parity, [ :pointer ], :int
  attach_function :DES_is_weak_key, [ :pointer ], :int
  attach_function :DES_set_key, [ :pointer, :pointer ], :int
  attach_function :DES_key_sched, [ :pointer, :pointer ], :int
  attach_function :DES_set_key_checked, [ :pointer, :pointer ], :int
  attach_function :DES_set_key_unchecked, [ :pointer, :pointer ], :void
  attach_function :DES_string_to_key, [ :string, :pointer ], :void
  attach_function :DES_string_to_2keys, [ :string, :pointer, :pointer ], :void
  attach_function :DES_cfb64_encrypt, [ :pointer, :pointer, :long, :pointer, :pointer, :pointer, :int ], :void
  attach_function :DES_ofb64_encrypt, [ :pointer, :pointer, :long, :pointer, :pointer, :pointer ], :void
  attach_function :DES_read_password, [ :pointer, :string, :int ], :int
  attach_function :DES_read_2passwords, [ :pointer, :pointer, :string, :int ], :int
  CAST_ENCRYPT = 1
  CAST_DECRYPT = 0
  CAST_BLOCK = 8
  CAST_KEY_LENGTH = 16
  class CastKeySt < FFI::Struct
    layout(
           :data, [:ulong, 32],
           :short_key, :int
    )
  end
  attach_function :CAST_set_key, [ :pointer, :int, :pointer ], :void
  attach_function :CAST_ecb_encrypt, [ :pointer, :pointer, :pointer, :int ], :void
  attach_function :CAST_encrypt, [ :pointer, :pointer ], :void
  attach_function :CAST_decrypt, [ :pointer, :pointer ], :void
  attach_function :CAST_cbc_encrypt, [ :pointer, :pointer, :long, :pointer, :pointer, :int ], :void
  attach_function :CAST_cfb64_encrypt, [ :pointer, :pointer, :long, :pointer, :pointer, :pointer, :int ], :void
  attach_function :CAST_ofb64_encrypt, [ :pointer, :pointer, :long, :pointer, :pointer, :pointer ], :void
  HMAC_MAX_MD_CBLOCK = 128
  class HmacCtxSt < FFI::Struct
    layout(
           :md, :pointer,
           :md_ctx, EnvMdCtxSt,
           :i_ctx, EnvMdCtxSt,
           :o_ctx, EnvMdCtxSt,
           :key_length, :uint,
           :key, [:uchar, 128]
    )
  end
  attach_function :HMAC_CTX_init, [ :pointer ], :void
  attach_function :HMAC_CTX_cleanup, [ :pointer ], :void
  attach_function :HMAC_Init, [ :pointer, :pointer, :int, :pointer ], :void
  attach_function :HMAC_Init_ex, [ :pointer, :pointer, :int, :pointer, :pointer ], :void
  attach_function :HMAC_Update, [ :pointer, :pointer, :uint ], :void
  attach_function :HMAC_Final, [ :pointer, :pointer, :pointer ], :void
  attach_function :HMAC, [ :pointer, :pointer, :int, :pointer, :uint, :pointer, :pointer ], :pointer
  attach_function :HMAC_CTX_set_flags, [ :pointer, :ulong ], :void
  OPENSSL_DH_MAX_MODULUS_BITS = 10000
  OPENSSL_DH_FIPS_MIN_MODULUS_BITS = 1024
  DH_FLAG_CACHE_MONT_P = 0x01
  DH_FLAG_NO_EXP_CONSTTIME = 0x02
  class DhMethod < FFI::Struct
    layout(
           :name, :pointer,
           :generate_key, callback([ :pointer ], :int),
           :compute_key, callback([ :pointer, :pointer, :pointer ], :int),
           :bn_mod_exp, callback([ :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer ], :int),
           :init, callback([ :pointer ], :int),
           :finish, callback([ :pointer ], :int),
           :flags, :int,
           :app_data, :pointer,
           :generate_params, callback([ :pointer, :int, :int, :pointer ], :int)
    )
    def name=(str)
      @name = FFI::MemoryPointer.from_string(str)
      self[:name] = @name
    end
    def name
      @name.get_string(0)
    end
    def generate_key=(cb)
      @generate_key = cb
      self[:generate_key] = @generate_key
    end
    def generate_key
      @generate_key
    end
    def compute_key=(cb)
      @compute_key = cb
      self[:compute_key] = @compute_key
    end
    def compute_key
      @compute_key
    end
    def bn_mod_exp=(cb)
      @bn_mod_exp = cb
      self[:bn_mod_exp] = @bn_mod_exp
    end
    def bn_mod_exp
      @bn_mod_exp
    end
    def init=(cb)
      @init = cb
      self[:init] = @init
    end
    def init
      @init
    end
    def finish=(cb)
      @finish = cb
      self[:finish] = @finish
    end
    def finish
      @finish
    end
    def app_data=(str)
      @app_data = FFI::MemoryPointer.from_string(str)
      self[:app_data] = @app_data
    end
    def app_data
      @app_data.get_string(0)
    end
    def generate_params=(cb)
      @generate_params = cb
      self[:generate_params] = @generate_params
    end
    def generate_params
      @generate_params
    end

  end
  class DhSt < FFI::Struct
    layout(
           :pad, :int,
           :version, :int,
           :p, :pointer,
           :g, :pointer,
           :length, :long,
           :pub_key, :pointer,
           :priv_key, :pointer,
           :flags, :int,
           :method_mont_p, :pointer,
           :q, :pointer,
           :j, :pointer,
           :seed, :pointer,
           :seedlen, :int,
           :counter, :pointer,
           :references, :int,
           :ex_data, CryptoExDataSt,
           :meth, :pointer,
           :engine, :pointer
    )
  end
  DH_GENERATOR_2 = 2
  DH_GENERATOR_5 = 5
  DH_CHECK_P_NOT_PRIME = 0x01
  DH_CHECK_P_NOT_SAFE_PRIME = 0x02
  DH_UNABLE_TO_CHECK_GENERATOR = 0x04
  DH_NOT_SUITABLE_GENERATOR = 0x08
  DH_CHECK_PUBKEY_TOO_SMALL = 0x01
  DH_CHECK_PUBKEY_TOO_LARGE = 0x02
  DH_CHECK_P_NOT_STRONG_PRIME = 0x02
  attach_function :DH_OpenSSL, [  ], :pointer
  attach_function :DH_set_default_method, [ :pointer ], :void
  attach_function :DH_get_default_method, [  ], :pointer
  attach_function :DH_set_method, [ :pointer, :pointer ], :int
  attach_function :DH_new_method, [ :pointer ], :pointer
  attach_function :DH_new, [  ], :pointer
  attach_function :DH_free, [ :pointer ], :void
  attach_function :DH_up_ref, [ :pointer ], :int
  attach_function :DH_size, [ :pointer ], :int
  attach_function :DH_get_ex_new_index, [ :long, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :DH_set_ex_data, [ :pointer, :int, :pointer ], :int
  attach_function :DH_get_ex_data, [ :pointer, :int ], :pointer
  attach_function :DH_generate_parameters, [ :int, :int, callback([ :int, :int, :pointer ], :void), :pointer ], :pointer
  attach_function :DH_generate_parameters_ex, [ :pointer, :int, :int, :pointer ], :int
  attach_function :DH_check, [ :pointer, :pointer ], :int
  attach_function :DH_check_pub_key, [ :pointer, :pointer, :pointer ], :int
  attach_function :DH_generate_key, [ :pointer ], :int
  attach_function :DH_compute_key, [ :pointer, :pointer, :pointer ], :int
  attach_function :d2i_DHparams, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_DHparams, [ :pointer, :pointer ], :int
  attach_function :DHparams_print_fp, [ :pointer, :pointer ], :int
  attach_function :DHparams_print, [ :pointer, :pointer ], :int
  attach_function :ERR_load_DH_strings, [  ], :void
  DH_F_COMPUTE_KEY = 102
  DH_F_DHPARAMS_PRINT = 100
  DH_F_DHPARAMS_PRINT_FP = 101
  DH_F_DH_BUILTIN_GENPARAMS = 106
  DH_F_DH_COMPUTE_KEY = 107
  DH_F_DH_GENERATE_KEY = 108
  DH_F_DH_GENERATE_PARAMETERS = 109
  DH_F_DH_NEW_METHOD = 105
  DH_F_GENERATE_KEY = 103
  DH_F_GENERATE_PARAMETERS = 104
  DH_R_BAD_GENERATOR = 101
  DH_R_INVALID_PUBKEY = 102
  DH_R_KEY_SIZE_TOO_SMALL = 104
  DH_R_MODULUS_TOO_LARGE = 103
  DH_R_NO_PRIVATE_VALUE = 100
  OPENSSL_DSA_MAX_MODULUS_BITS = 10000
  OPENSSL_DSA_FIPS_MIN_MODULUS_BITS = 1024
  DSA_FLAG_CACHE_MONT_P = 0x01
  DSA_FLAG_NO_EXP_CONSTTIME = 0x02
  DSA_FLAG_FIPS_METHOD = 0x0400
  DSA_FLAG_NON_FIPS_ALLOW = 0x0400
  class DSASIGSt < FFI::Struct
    layout(
           :r, :pointer,
           :s, :pointer
    )
  end
  class DsaMethod < FFI::Struct
    layout(
           :name, :pointer,
           :dsa_do_sign, callback([ :pointer, :int, :pointer ], :pointer),
           :dsa_sign_setup, callback([ :pointer, :pointer, :pointer, :pointer ], :int),
           :dsa_do_verify, callback([ :pointer, :int, :pointer, :pointer ], :int),
           :dsa_mod_exp, callback([ :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer ], :int),
           :bn_mod_exp, callback([ :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer ], :int),
           :init, callback([ :pointer ], :int),
           :finish, callback([ :pointer ], :int),
           :flags, :int,
           :app_data, :pointer,
           :dsa_paramgen, callback([ :pointer, :int, :pointer, :int, :pointer, :pointer, :pointer ], :int),
           :dsa_keygen, callback([ :pointer ], :int)
    )
    def name=(str)
      @name = FFI::MemoryPointer.from_string(str)
      self[:name] = @name
    end
    def name
      @name.get_string(0)
    end
    def dsa_do_sign=(cb)
      @dsa_do_sign = cb
      self[:dsa_do_sign] = @dsa_do_sign
    end
    def dsa_do_sign
      @dsa_do_sign
    end
    def dsa_sign_setup=(cb)
      @dsa_sign_setup = cb
      self[:dsa_sign_setup] = @dsa_sign_setup
    end
    def dsa_sign_setup
      @dsa_sign_setup
    end
    def dsa_do_verify=(cb)
      @dsa_do_verify = cb
      self[:dsa_do_verify] = @dsa_do_verify
    end
    def dsa_do_verify
      @dsa_do_verify
    end
    def dsa_mod_exp=(cb)
      @dsa_mod_exp = cb
      self[:dsa_mod_exp] = @dsa_mod_exp
    end
    def dsa_mod_exp
      @dsa_mod_exp
    end
    def bn_mod_exp=(cb)
      @bn_mod_exp = cb
      self[:bn_mod_exp] = @bn_mod_exp
    end
    def bn_mod_exp
      @bn_mod_exp
    end
    def init=(cb)
      @init = cb
      self[:init] = @init
    end
    def init
      @init
    end
    def finish=(cb)
      @finish = cb
      self[:finish] = @finish
    end
    def finish
      @finish
    end
    def app_data=(str)
      @app_data = FFI::MemoryPointer.from_string(str)
      self[:app_data] = @app_data
    end
    def app_data
      @app_data.get_string(0)
    end
    def dsa_paramgen=(cb)
      @dsa_paramgen = cb
      self[:dsa_paramgen] = @dsa_paramgen
    end
    def dsa_paramgen
      @dsa_paramgen
    end
    def dsa_keygen=(cb)
      @dsa_keygen = cb
      self[:dsa_keygen] = @dsa_keygen
    end
    def dsa_keygen
      @dsa_keygen
    end

  end
  class DsaSt < FFI::Struct
    layout(
           :pad, :int,
           :version, :long,
           :write_params, :int,
           :p, :pointer,
           :q, :pointer,
           :g, :pointer,
           :pub_key, :pointer,
           :priv_key, :pointer,
           :kinv, :pointer,
           :r, :pointer,
           :flags, :int,
           :method_mont_p, :pointer,
           :references, :int,
           :ex_data, CryptoExDataSt,
           :meth, :pointer,
           :engine, :pointer
    )
  end
  attach_function :DSA_SIG_new, [  ], :pointer
  attach_function :DSA_SIG_free, [ :pointer ], :void
  attach_function :i2d_DSA_SIG, [ :pointer, :pointer ], :int
  attach_function :d2i_DSA_SIG, [ :pointer, :pointer, :long ], :pointer
  attach_function :DSA_do_sign, [ :pointer, :int, :pointer ], :pointer
  attach_function :DSA_do_verify, [ :pointer, :int, :pointer, :pointer ], :int
  attach_function :DSA_OpenSSL, [  ], :pointer
  attach_function :DSA_set_default_method, [ :pointer ], :void
  attach_function :DSA_get_default_method, [  ], :pointer
  attach_function :DSA_set_method, [ :pointer, :pointer ], :int
  attach_function :DSA_new, [  ], :pointer
  attach_function :DSA_new_method, [ :pointer ], :pointer
  attach_function :DSA_free, [ :pointer ], :void
  attach_function :DSA_up_ref, [ :pointer ], :int
  attach_function :DSA_size, [ :pointer ], :int
  attach_function :DSA_sign_setup, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :DSA_sign, [ :int, :pointer, :int, :pointer, :pointer, :pointer ], :int
  attach_function :DSA_verify, [ :int, :pointer, :int, :pointer, :int, :pointer ], :int
  attach_function :DSA_get_ex_new_index, [ :long, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :DSA_set_ex_data, [ :pointer, :int, :pointer ], :int
  attach_function :DSA_get_ex_data, [ :pointer, :int ], :pointer
  attach_function :d2i_DSAPublicKey, [ :pointer, :pointer, :long ], :pointer
  attach_function :d2i_DSAPrivateKey, [ :pointer, :pointer, :long ], :pointer
  attach_function :d2i_DSAparams, [ :pointer, :pointer, :long ], :pointer
  attach_function :DSA_generate_parameters, [ :int, :pointer, :int, :pointer, :pointer, callback([ :int, :int, :pointer ], :void), :pointer ], :pointer
  attach_function :DSA_generate_parameters_ex, [ :pointer, :int, :pointer, :int, :pointer, :pointer, :pointer ], :int
  attach_function :DSA_generate_key, [ :pointer ], :int
  attach_function :i2d_DSAPublicKey, [ :pointer, :pointer ], :int
  attach_function :i2d_DSAPrivateKey, [ :pointer, :pointer ], :int
  attach_function :i2d_DSAparams, [ :pointer, :pointer ], :int
  attach_function :DSAparams_print, [ :pointer, :pointer ], :int
  attach_function :DSA_print, [ :pointer, :pointer, :int ], :int
  attach_function :DSAparams_print_fp, [ :pointer, :pointer ], :int
  attach_function :DSA_print_fp, [ :pointer, :pointer, :int ], :int
  DSS_prime_checks = 50
  attach_function :DSA_dup_DH, [ :pointer ], :pointer
  attach_function :ERR_load_DSA_strings, [  ], :void
  DSA_F_D2I_DSA_SIG = 110
  DSA_F_DSAPARAMS_PRINT = 100
  DSA_F_DSAPARAMS_PRINT_FP = 101
  DSA_F_DSA_BUILTIN_KEYGEN = 119
  DSA_F_DSA_BUILTIN_PARAMGEN = 118
  DSA_F_DSA_DO_SIGN = 112
  DSA_F_DSA_DO_VERIFY = 113
  DSA_F_DSA_GENERATE_PARAMETERS = 117
  DSA_F_DSA_NEW_METHOD = 103
  DSA_F_DSA_PRINT = 104
  DSA_F_DSA_PRINT_FP = 105
  DSA_F_DSA_SET_DEFAULT_METHOD = 115
  DSA_F_DSA_SET_METHOD = 116
  DSA_F_DSA_SIGN = 106
  DSA_F_DSA_SIGN_SETUP = 107
  DSA_F_DSA_SIG_NEW = 109
  DSA_F_DSA_VERIFY = 108
  DSA_F_I2D_DSA_SIG = 111
  DSA_F_SIG_CB = 114
  DSA_R_BAD_Q_VALUE = 102
  DSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE = 100
  DSA_R_KEY_SIZE_TOO_SMALL = 106
  DSA_R_MISSING_PARAMETERS = 101
  DSA_R_MODULUS_TOO_LARGE = 103
  DSA_R_NON_FIPS_METHOD = 104
  DSA_R_OPERATION_NOT_ALLOWED_IN_FIPS_MODE = 105
  RSA_FLAG_FIPS_METHOD = 0x0400
  RSA_FLAG_NON_FIPS_ALLOW = 0x0400
  class RsaMethSt < FFI::Struct
    layout(
           :name, :pointer,
           :rsa_pub_enc, callback([ :int, :pointer, :pointer, :pointer, :int ], :int),
           :rsa_pub_dec, callback([ :int, :pointer, :pointer, :pointer, :int ], :int),
           :rsa_priv_enc, callback([ :int, :pointer, :pointer, :pointer, :int ], :int),
           :rsa_priv_dec, callback([ :int, :pointer, :pointer, :pointer, :int ], :int),
           :rsa_mod_exp, callback([ :pointer, :pointer, :pointer, :pointer ], :int),
           :bn_mod_exp, callback([ :pointer, :pointer, :pointer, :pointer, :pointer, :pointer ], :int),
           :init, callback([ :pointer ], :int),
           :finish, callback([ :pointer ], :int),
           :flags, :int,
           :app_data, :pointer,
           :rsa_sign, callback([ :int, :pointer, :uint, :pointer, :pointer, :pointer ], :int),
           :rsa_verify, callback([ :int, :pointer, :uint, :pointer, :uint, :pointer ], :int),
           :rsa_keygen, callback([ :pointer, :int, :pointer, :pointer ], :int)
    )
    def name=(str)
      @name = FFI::MemoryPointer.from_string(str)
      self[:name] = @name
    end
    def name
      @name.get_string(0)
    end
    def rsa_pub_enc=(cb)
      @rsa_pub_enc = cb
      self[:rsa_pub_enc] = @rsa_pub_enc
    end
    def rsa_pub_enc
      @rsa_pub_enc
    end
    def rsa_pub_dec=(cb)
      @rsa_pub_dec = cb
      self[:rsa_pub_dec] = @rsa_pub_dec
    end
    def rsa_pub_dec
      @rsa_pub_dec
    end
    def rsa_priv_enc=(cb)
      @rsa_priv_enc = cb
      self[:rsa_priv_enc] = @rsa_priv_enc
    end
    def rsa_priv_enc
      @rsa_priv_enc
    end
    def rsa_priv_dec=(cb)
      @rsa_priv_dec = cb
      self[:rsa_priv_dec] = @rsa_priv_dec
    end
    def rsa_priv_dec
      @rsa_priv_dec
    end
    def rsa_mod_exp=(cb)
      @rsa_mod_exp = cb
      self[:rsa_mod_exp] = @rsa_mod_exp
    end
    def rsa_mod_exp
      @rsa_mod_exp
    end
    def bn_mod_exp=(cb)
      @bn_mod_exp = cb
      self[:bn_mod_exp] = @bn_mod_exp
    end
    def bn_mod_exp
      @bn_mod_exp
    end
    def init=(cb)
      @init = cb
      self[:init] = @init
    end
    def init
      @init
    end
    def finish=(cb)
      @finish = cb
      self[:finish] = @finish
    end
    def finish
      @finish
    end
    def app_data=(str)
      @app_data = FFI::MemoryPointer.from_string(str)
      self[:app_data] = @app_data
    end
    def app_data
      @app_data.get_string(0)
    end
    def rsa_sign=(cb)
      @rsa_sign = cb
      self[:rsa_sign] = @rsa_sign
    end
    def rsa_sign
      @rsa_sign
    end
    def rsa_verify=(cb)
      @rsa_verify = cb
      self[:rsa_verify] = @rsa_verify
    end
    def rsa_verify
      @rsa_verify
    end
    def rsa_keygen=(cb)
      @rsa_keygen = cb
      self[:rsa_keygen] = @rsa_keygen
    end
    def rsa_keygen
      @rsa_keygen
    end

  end
  class RsaSt < FFI::Struct
    layout(
           :pad, :int,
           :version, :long,
           :meth, :pointer,
           :engine, :pointer,
           :n, :pointer,
           :e, :pointer,
           :d, :pointer,
           :p, :pointer,
           :q, :pointer,
           :dmp1, :pointer,
           :dmq1, :pointer,
           :iqmp, :pointer,
           :ex_data, CryptoExDataSt,
           :references, :int,
           :flags, :int,
           :_method_mod_n, :pointer,
           :_method_mod_p, :pointer,
           :_method_mod_q, :pointer,
           :bignum_data, :pointer,
           :blinding, :pointer,
           :mt_blinding, :pointer
    )
    def bignum_data=(str)
      @bignum_data = FFI::MemoryPointer.from_string(str)
      self[:bignum_data] = @bignum_data
    end
    def bignum_data
      @bignum_data.get_string(0)
    end

  end
  OPENSSL_RSA_MAX_MODULUS_BITS = 16384
  OPENSSL_RSA_FIPS_MIN_MODULUS_BITS = 1024
  OPENSSL_RSA_SMALL_MODULUS_BITS = 3072
  OPENSSL_RSA_MAX_PUBEXP_BITS = 64
  RSA_3 = 0x3
  RSA_F4 = 0x10001
  RSA_METHOD_FLAG_NO_CHECK = 0x0001
  RSA_FLAG_CACHE_PUBLIC = 0x0002
  RSA_FLAG_CACHE_PRIVATE = 0x0004
  RSA_FLAG_BLINDING = 0x0008
  RSA_FLAG_THREAD_SAFE = 0x0010
  RSA_FLAG_EXT_PKEY = 0x0020
  RSA_FLAG_SIGN_VER = 0x0040
  RSA_FLAG_NO_BLINDING = 0x0080
  RSA_FLAG_NO_CONSTTIME = 0x0100
  RSA_FLAG_NO_EXP_CONSTTIME = 0x0100
  RSA_PKCS1_PADDING = 1
  RSA_SSLV23_PADDING = 2
  RSA_NO_PADDING = 3
  RSA_PKCS1_OAEP_PADDING = 4
  RSA_X931_PADDING = 5
  RSA_PKCS1_PADDING_SIZE = 11
  attach_function :RSA_new, [  ], :pointer
  attach_function :RSA_new_method, [ :pointer ], :pointer
  attach_function :RSA_size, [ :pointer ], :int
  attach_function :RSA_generate_key, [ :int, :ulong, callback([ :int, :int, :pointer ], :void), :pointer ], :pointer
  attach_function :RSA_generate_key_ex, [ :pointer, :int, :pointer, :pointer ], :int
  attach_function :RSA_X931_derive_ex, [ :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :RSA_X931_generate_key_ex, [ :pointer, :int, :pointer, :pointer ], :int
  attach_function :RSA_check_key, [ :pointer ], :int
  attach_function :RSA_public_encrypt, [ :int, :pointer, :pointer, :pointer, :int ], :int
  attach_function :RSA_private_encrypt, [ :int, :pointer, :pointer, :pointer, :int ], :int
  attach_function :RSA_public_decrypt, [ :int, :pointer, :pointer, :pointer, :int ], :int
  attach_function :RSA_private_decrypt, [ :int, :pointer, :pointer, :pointer, :int ], :int
  attach_function :RSA_free, [ :pointer ], :void
  attach_function :RSA_up_ref, [ :pointer ], :int
  attach_function :RSA_flags, [ :pointer ], :int
  attach_function :RSA_set_default_method, [ :pointer ], :void
  attach_function :RSA_get_default_method, [  ], :pointer
  attach_function :RSA_get_method, [ :pointer ], :pointer
  attach_function :RSA_set_method, [ :pointer, :pointer ], :int
  attach_function :RSA_memory_lock, [ :pointer ], :int
  attach_function :RSA_PKCS1_SSLeay, [  ], :pointer
  attach_function :RSA_null_method, [  ], :pointer
  attach_function :d2i_RSAPublicKey, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_RSAPublicKey, [ :pointer, :pointer ], :int
  attach_function :d2i_RSAPrivateKey, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_RSAPrivateKey, [ :pointer, :pointer ], :int
  attach_function :RSA_print_fp, [ :pointer, :pointer, :int ], :int
  attach_function :RSA_print, [ :pointer, :pointer, :int ], :int
  attach_function :i2d_RSA_NET, [ :pointer, :pointer, callback([ :string, :int, :string, :int ], :int), :int ], :int
  attach_function :d2i_RSA_NET, [ :pointer, :pointer, :long, callback([ :string, :int, :string, :int ], :int), :int ], :pointer
  attach_function :i2d_Netscape_RSA, [ :pointer, :pointer, callback([ :string, :int, :string, :int ], :int) ], :int
  attach_function :d2i_Netscape_RSA, [ :pointer, :pointer, :long, callback([ :string, :int, :string, :int ], :int) ], :pointer
  attach_function :RSA_sign, [ :int, :pointer, :uint, :pointer, :pointer, :pointer ], :int
  attach_function :RSA_verify, [ :int, :pointer, :uint, :pointer, :uint, :pointer ], :int
  attach_function :RSA_sign_ASN1_OCTET_STRING, [ :int, :pointer, :uint, :pointer, :pointer, :pointer ], :int
  attach_function :RSA_verify_ASN1_OCTET_STRING, [ :int, :pointer, :uint, :pointer, :uint, :pointer ], :int
  attach_function :RSA_blinding_on, [ :pointer, :pointer ], :int
  attach_function :RSA_blinding_off, [ :pointer ], :void
  attach_function :RSA_setup_blinding, [ :pointer, :pointer ], :pointer
  attach_function :RSA_padding_add_PKCS1_type_1, [ :pointer, :int, :pointer, :int ], :int
  attach_function :RSA_padding_check_PKCS1_type_1, [ :pointer, :int, :pointer, :int, :int ], :int
  attach_function :RSA_padding_add_PKCS1_type_2, [ :pointer, :int, :pointer, :int ], :int
  attach_function :RSA_padding_check_PKCS1_type_2, [ :pointer, :int, :pointer, :int, :int ], :int
  attach_function :PKCS1_MGF1, [ :pointer, :long, :pointer, :long, :pointer ], :int
  attach_function :RSA_padding_add_PKCS1_OAEP, [ :pointer, :int, :pointer, :int, :pointer, :int ], :int
  attach_function :RSA_padding_check_PKCS1_OAEP, [ :pointer, :int, :pointer, :int, :int, :pointer, :int ], :int
  attach_function :RSA_padding_add_SSLv23, [ :pointer, :int, :pointer, :int ], :int
  attach_function :RSA_padding_check_SSLv23, [ :pointer, :int, :pointer, :int, :int ], :int
  attach_function :RSA_padding_add_none, [ :pointer, :int, :pointer, :int ], :int
  attach_function :RSA_padding_check_none, [ :pointer, :int, :pointer, :int, :int ], :int
  attach_function :RSA_padding_add_X931, [ :pointer, :int, :pointer, :int ], :int
  attach_function :RSA_padding_check_X931, [ :pointer, :int, :pointer, :int, :int ], :int
  attach_function :RSA_X931_hash_id, [ :int ], :int
  attach_function :RSA_verify_PKCS1_PSS, [ :pointer, :pointer, :pointer, :pointer, :int ], :int
  attach_function :RSA_padding_add_PKCS1_PSS, [ :pointer, :pointer, :pointer, :pointer, :int ], :int
  attach_function :RSA_get_ex_new_index, [ :long, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :RSA_set_ex_data, [ :pointer, :int, :pointer ], :int
  attach_function :RSA_get_ex_data, [ :pointer, :int ], :pointer
  attach_function :RSAPublicKey_dup, [ :pointer ], :pointer
  attach_function :RSAPrivateKey_dup, [ :pointer ], :pointer
  attach_function :ERR_load_RSA_strings, [  ], :void
  RSA_F_FIPS_RSA_SIGN = 140
  RSA_F_FIPS_RSA_VERIFY = 141
  RSA_F_MEMORY_LOCK = 100
  RSA_F_RSA_BUILTIN_KEYGEN = 129
  RSA_F_RSA_CHECK_KEY = 123
  RSA_F_RSA_EAY_PRIVATE_DECRYPT = 101
  RSA_F_RSA_EAY_PRIVATE_ENCRYPT = 102
  RSA_F_RSA_EAY_PUBLIC_DECRYPT = 103
  RSA_F_RSA_EAY_PUBLIC_ENCRYPT = 104
  RSA_F_RSA_GENERATE_KEY = 105
  RSA_F_RSA_MEMORY_LOCK = 130
  RSA_F_RSA_NEW_METHOD = 106
  RSA_F_RSA_NULL = 124
  RSA_F_RSA_NULL_MOD_EXP = 131
  RSA_F_RSA_NULL_PRIVATE_DECRYPT = 132
  RSA_F_RSA_NULL_PRIVATE_ENCRYPT = 133
  RSA_F_RSA_NULL_PUBLIC_DECRYPT = 134
  RSA_F_RSA_NULL_PUBLIC_ENCRYPT = 135
  RSA_F_RSA_PADDING_ADD_NONE = 107
  RSA_F_RSA_PADDING_ADD_PKCS1_OAEP = 121
  RSA_F_RSA_PADDING_ADD_PKCS1_PSS = 125
  RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_1 = 108
  RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_2 = 109
  RSA_F_RSA_PADDING_ADD_SSLV23 = 110
  RSA_F_RSA_PADDING_ADD_X931 = 127
  RSA_F_RSA_PADDING_CHECK_NONE = 111
  RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP = 122
  RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1 = 112
  RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2 = 113
  RSA_F_RSA_PADDING_CHECK_SSLV23 = 114
  RSA_F_RSA_PADDING_CHECK_X931 = 128
  RSA_F_RSA_PRINT = 115
  RSA_F_RSA_PRINT_FP = 116
  RSA_F_RSA_PRIVATE_ENCRYPT = 137
  RSA_F_RSA_PUBLIC_DECRYPT = 138
  RSA_F_RSA_SETUP_BLINDING = 136
  RSA_F_RSA_SET_DEFAULT_METHOD = 139
  RSA_F_RSA_SET_METHOD = 142
  RSA_F_RSA_SIGN = 117
  RSA_F_RSA_SIGN_ASN1_OCTET_STRING = 118
  RSA_F_RSA_VERIFY = 119
  RSA_F_RSA_VERIFY_ASN1_OCTET_STRING = 120
  RSA_F_RSA_VERIFY_PKCS1_PSS = 126
  RSA_R_ALGORITHM_MISMATCH = 100
  RSA_R_BAD_E_VALUE = 101
  RSA_R_BAD_FIXED_HEADER_DECRYPT = 102
  RSA_R_BAD_PAD_BYTE_COUNT = 103
  RSA_R_BAD_SIGNATURE = 104
  RSA_R_BLOCK_TYPE_IS_NOT_01 = 106
  RSA_R_BLOCK_TYPE_IS_NOT_02 = 107
  RSA_R_DATA_GREATER_THAN_MOD_LEN = 108
  RSA_R_DATA_TOO_LARGE = 109
  RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE = 110
  RSA_R_DATA_TOO_LARGE_FOR_MODULUS = 132
  RSA_R_DATA_TOO_SMALL = 111
  RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE = 122
  RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY = 112
  RSA_R_DMP1_NOT_CONGRUENT_TO_D = 124
  RSA_R_DMQ1_NOT_CONGRUENT_TO_D = 125
  RSA_R_D_E_NOT_CONGRUENT_TO_1 = 123
  RSA_R_FIRST_OCTET_INVALID = 133
  RSA_R_INVALID_HEADER = 137
  RSA_R_INVALID_MESSAGE_LENGTH = 131
  RSA_R_INVALID_PADDING = 138
  RSA_R_INVALID_TRAILER = 139
  RSA_R_IQMP_NOT_INVERSE_OF_Q = 126
  RSA_R_KEY_SIZE_TOO_SMALL = 120
  RSA_R_LAST_OCTET_INVALID = 134
  RSA_R_MODULUS_TOO_LARGE = 105
  RSA_R_NON_FIPS_METHOD = 141
  RSA_R_NO_PUBLIC_EXPONENT = 140
  RSA_R_NULL_BEFORE_BLOCK_MISSING = 113
  RSA_R_N_DOES_NOT_EQUAL_P_Q = 127
  RSA_R_OAEP_DECODING_ERROR = 121
  RSA_R_OPERATION_NOT_ALLOWED_IN_FIPS_MODE = 142
  RSA_R_PADDING_CHECK_FAILED = 114
  RSA_R_P_NOT_PRIME = 128
  RSA_R_Q_NOT_PRIME = 129
  RSA_R_RSA_OPERATIONS_NOT_SUPPORTED = 130
  RSA_R_SLEN_CHECK_FAILED = 136
  RSA_R_SLEN_RECOVERY_FAILED = 135
  RSA_R_SSLV3_ROLLBACK_ATTACK = 115
  RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD = 116
  RSA_R_UNKNOWN_ALGORITHM_TYPE = 117
  RSA_R_UNKNOWN_PADDING_TYPE = 118
  RSA_R_WRONG_SIGNATURE_LENGTH = 119
  OPENSSL_ECC_MAX_FIELD_BITS = 661
  POINT_CONVERSION_COMPRESSED = 2
  POINT_CONVERSION_UNCOMPRESSED = 4
  POINT_CONVERSION_HYBRID = 6

  attach_function :EC_GFp_simple_method, [  ], :pointer
  attach_function :EC_GFp_mont_method, [  ], :pointer
  attach_function :EC_GFp_nist_method, [  ], :pointer
  attach_function :EC_GF2m_simple_method, [  ], :pointer
  attach_function :EC_GROUP_new, [ :pointer ], :pointer
  attach_function :EC_GROUP_free, [ :pointer ], :void
  attach_function :EC_GROUP_clear_free, [ :pointer ], :void
  attach_function :EC_GROUP_copy, [ :pointer, :pointer ], :int
  attach_function :EC_GROUP_dup, [ :pointer ], :pointer
  attach_function :EC_GROUP_method_of, [ :pointer ], :pointer
  attach_function :EC_METHOD_get_field_type, [ :pointer ], :int
  attach_function :EC_GROUP_set_generator, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :EC_GROUP_get0_generator, [ :pointer ], :pointer
  attach_function :EC_GROUP_get_order, [ :pointer, :pointer, :pointer ], :int
  attach_function :EC_GROUP_get_cofactor, [ :pointer, :pointer, :pointer ], :int
  attach_function :EC_GROUP_set_curve_name, [ :pointer, :int ], :void
  attach_function :EC_GROUP_get_curve_name, [ :pointer ], :int
  attach_function :EC_GROUP_set_asn1_flag, [ :pointer, :int ], :void
  attach_function :EC_GROUP_get_asn1_flag, [ :pointer ], :int
  attach_function :EC_GROUP_set_point_conversion_form, [ :pointer, :int ], :void
  attach_function :EC_GROUP_get_point_conversion_form, [ :pointer ], :int
  attach_function :EC_GROUP_get0_seed, [ :pointer ], :pointer
  attach_function :EC_GROUP_get_seed_len, [ :pointer ], :uint
  attach_function :EC_GROUP_set_seed, [ :pointer, :pointer, :uint ], :uint
  attach_function :EC_GROUP_set_curve_GFp, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :EC_GROUP_get_curve_GFp, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :EC_GROUP_set_curve_GF2m, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :EC_GROUP_get_curve_GF2m, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :EC_GROUP_get_degree, [ :pointer ], :int
  attach_function :EC_GROUP_check, [ :pointer, :pointer ], :int
  attach_function :EC_GROUP_check_discriminant, [ :pointer, :pointer ], :int
  attach_function :EC_GROUP_cmp, [ :pointer, :pointer, :pointer ], :int
  attach_function :EC_GROUP_new_curve_GFp, [ :pointer, :pointer, :pointer, :pointer ], :pointer
  attach_function :EC_GROUP_new_curve_GF2m, [ :pointer, :pointer, :pointer, :pointer ], :pointer
  attach_function :EC_GROUP_new_by_curve_name, [ :int ], :pointer
  class ECBuiltinCurve < FFI::Struct
    layout(
           :nid, :int,
           :comment, :pointer
    )
    def comment=(str)
      @comment = FFI::MemoryPointer.from_string(str)
      self[:comment] = @comment
    end
    def comment
      @comment.get_string(0)
    end

  end
  attach_function :EC_get_builtin_curves, [ :pointer, :uint ], :uint
  attach_function :EC_POINT_new, [ :pointer ], :pointer
  attach_function :EC_POINT_free, [ :pointer ], :void
  attach_function :EC_POINT_clear_free, [ :pointer ], :void
  attach_function :EC_POINT_copy, [ :pointer, :pointer ], :int
  attach_function :EC_POINT_dup, [ :pointer, :pointer ], :pointer
  attach_function :EC_POINT_method_of, [ :pointer ], :pointer
  attach_function :EC_POINT_set_to_infinity, [ :pointer, :pointer ], :int
  attach_function :EC_POINT_set_Jprojective_coordinates_GFp, [ :pointer, :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :EC_POINT_get_Jprojective_coordinates_GFp, [ :pointer, :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :EC_POINT_set_affine_coordinates_GFp, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :EC_POINT_get_affine_coordinates_GFp, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :EC_POINT_set_compressed_coordinates_GFp, [ :pointer, :pointer, :pointer, :int, :pointer ], :int
  attach_function :EC_POINT_set_affine_coordinates_GF2m, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :EC_POINT_get_affine_coordinates_GF2m, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :EC_POINT_set_compressed_coordinates_GF2m, [ :pointer, :pointer, :pointer, :int, :pointer ], :int
  attach_function :EC_POINT_point2oct, [ :pointer, :pointer, :int, :pointer, :uint, :pointer ], :uint
  attach_function :EC_POINT_oct2point, [ :pointer, :pointer, :pointer, :uint, :pointer ], :int
  attach_function :EC_POINT_point2bn, [ :pointer, :pointer, :int, :pointer, :pointer ], :pointer
  attach_function :EC_POINT_bn2point, [ :pointer, :pointer, :pointer, :pointer ], :pointer
  attach_function :EC_POINT_point2hex, [ :pointer, :pointer, :int, :pointer ], :string
  attach_function :EC_POINT_hex2point, [ :pointer, :string, :pointer, :pointer ], :pointer
  attach_function :EC_POINT_add, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :EC_POINT_dbl, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :EC_POINT_invert, [ :pointer, :pointer, :pointer ], :int
  attach_function :EC_POINT_is_at_infinity, [ :pointer, :pointer ], :int
  attach_function :EC_POINT_is_on_curve, [ :pointer, :pointer, :pointer ], :int
  attach_function :EC_POINT_cmp, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :EC_POINT_make_affine, [ :pointer, :pointer, :pointer ], :int
  attach_function :EC_POINTs_make_affine, [ :pointer, :uint, a().p.EC_POINT, :pointer ], :pointer
  attach_function :EC_POINTs_mul, [ :pointer, :pointer, :pointer, :uint, a().p.q(const).EC_POINT, a().p.q(const).BIGNUM, :pointer ], :pointer
  attach_function :EC_POINT_mul, [ :pointer, :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :EC_GROUP_precompute_mult, [ :pointer, :pointer ], :int
  attach_function :EC_GROUP_have_precompute_mult, [ :pointer ], :int
  attach_function :EC_GROUP_get_basis_type, [ :pointer ], :int
  attach_function :EC_GROUP_get_trinomial_basis, [ :pointer, :pointer ], :int
  attach_function :EC_GROUP_get_pentanomial_basis, [ :pointer, :pointer, :pointer, :pointer ], :int
  OPENSSL_EC_NAMED_CURVE = 0x001
  attach_function :d2i_ECPKParameters, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_ECPKParameters, [ :pointer, :pointer ], :int
  attach_function :ECPKParameters_print, [ :pointer, :pointer, :int ], :int
  attach_function :ECPKParameters_print_fp, [ :pointer, :pointer, :int ], :int
  EC_PKEY_NO_PARAMETERS = 0x001
  EC_PKEY_NO_PUBKEY = 0x002
  attach_function :EC_KEY_new, [  ], :pointer
  attach_function :EC_KEY_new_by_curve_name, [ :int ], :pointer
  attach_function :EC_KEY_free, [ :pointer ], :void
  attach_function :EC_KEY_copy, [ :pointer, :pointer ], :pointer
  attach_function :EC_KEY_dup, [ :pointer ], :pointer
  attach_function :EC_KEY_up_ref, [ :pointer ], :int
  attach_function :EC_KEY_get0_group, [ :pointer ], :pointer
  attach_function :EC_KEY_set_group, [ :pointer, :pointer ], :int
  attach_function :EC_KEY_get0_private_key, [ :pointer ], :pointer
  attach_function :EC_KEY_set_private_key, [ :pointer, :pointer ], :int
  attach_function :EC_KEY_get0_public_key, [ :pointer ], :pointer
  attach_function :EC_KEY_set_public_key, [ :pointer, :pointer ], :int
  attach_function :EC_KEY_get_enc_flags, [ :pointer ], :uint
  attach_function :EC_KEY_set_enc_flags, [ :pointer, :uint ], :void
  attach_function :EC_KEY_get_conv_form, [ :pointer ], :int
  attach_function :EC_KEY_set_conv_form, [ :pointer, :int ], :void
  attach_function :EC_KEY_get_key_method_data, [ :pointer, callback([ :pointer ], :pointer), callback([ :pointer ], :void), callback([ :pointer ], :void) ], :pointer
  attach_function :EC_KEY_insert_key_method_data, [ :pointer, :pointer, callback([ :pointer ], :pointer), callback([ :pointer ], :void), callback([ :pointer ], :void) ], :pointer
  attach_function :EC_KEY_set_asn1_flag, [ :pointer, :int ], :void
  attach_function :EC_KEY_precompute_mult, [ :pointer, :pointer ], :int
  attach_function :EC_KEY_generate_key, [ :pointer ], :int
  attach_function :EC_KEY_check_key, [ :pointer ], :int
  attach_function :d2i_ECPrivateKey, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_ECPrivateKey, [ :pointer, :pointer ], :int
  attach_function :d2i_ECParameters, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_ECParameters, [ :pointer, :pointer ], :int
  attach_function :o2i_ECPublicKey, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2o_ECPublicKey, [ :pointer, :pointer ], :int
  attach_function :ECParameters_print, [ :pointer, :pointer ], :int
  attach_function :EC_KEY_print, [ :pointer, :pointer, :int ], :int
  attach_function :ECParameters_print_fp, [ :pointer, :pointer ], :int
  attach_function :EC_KEY_print_fp, [ :pointer, :pointer, :int ], :int
  attach_function :ERR_load_EC_strings, [  ], :void
  EC_F_COMPUTE_WNAF = 143
  EC_F_D2I_ECPARAMETERS = 144
  EC_F_D2I_ECPKPARAMETERS = 145
  EC_F_D2I_ECPRIVATEKEY = 146
  EC_F_ECPARAMETERS_PRINT = 147
  EC_F_ECPARAMETERS_PRINT_FP = 148
  EC_F_ECPKPARAMETERS_PRINT = 149
  EC_F_ECPKPARAMETERS_PRINT_FP = 150
  EC_F_ECP_NIST_MOD_192 = 203
  EC_F_ECP_NIST_MOD_224 = 204
  EC_F_ECP_NIST_MOD_256 = 205
  EC_F_ECP_NIST_MOD_521 = 206
  EC_F_EC_ASN1_GROUP2CURVE = 153
  EC_F_EC_ASN1_GROUP2FIELDID = 154
  EC_F_EC_ASN1_GROUP2PARAMETERS = 155
  EC_F_EC_ASN1_GROUP2PKPARAMETERS = 156
  EC_F_EC_ASN1_PARAMETERS2GROUP = 157
  EC_F_EC_ASN1_PKPARAMETERS2GROUP = 158
  EC_F_EC_EX_DATA_SET_DATA = 211
  EC_F_EC_GF2M_MONTGOMERY_POINT_MULTIPLY = 208
  EC_F_EC_GF2M_SIMPLE_GROUP_CHECK_DISCRIMINANT = 159
  EC_F_EC_GF2M_SIMPLE_GROUP_SET_CURVE = 195
  EC_F_EC_GF2M_SIMPLE_OCT2POINT = 160
  EC_F_EC_GF2M_SIMPLE_POINT2OCT = 161
  EC_F_EC_GF2M_SIMPLE_POINT_GET_AFFINE_COORDINATES = 162
  EC_F_EC_GF2M_SIMPLE_POINT_SET_AFFINE_COORDINATES = 163
  EC_F_EC_GF2M_SIMPLE_SET_COMPRESSED_COORDINATES = 164
  EC_F_EC_GFP_MONT_FIELD_DECODE = 133
  EC_F_EC_GFP_MONT_FIELD_ENCODE = 134
  EC_F_EC_GFP_MONT_FIELD_MUL = 131
  EC_F_EC_GFP_MONT_FIELD_SET_TO_ONE = 209
  EC_F_EC_GFP_MONT_FIELD_SQR = 132
  EC_F_EC_GFP_MONT_GROUP_SET_CURVE = 189
  EC_F_EC_GFP_MONT_GROUP_SET_CURVE_GFP = 135
  EC_F_EC_GFP_NIST_FIELD_MUL = 200
  EC_F_EC_GFP_NIST_FIELD_SQR = 201
  EC_F_EC_GFP_NIST_GROUP_SET_CURVE = 202
  EC_F_EC_GFP_SIMPLE_GROUP_CHECK_DISCRIMINANT = 165
  EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE = 166
  EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE_GFP = 100
  EC_F_EC_GFP_SIMPLE_GROUP_SET_GENERATOR = 101
  EC_F_EC_GFP_SIMPLE_MAKE_AFFINE = 102
  EC_F_EC_GFP_SIMPLE_OCT2POINT = 103
  EC_F_EC_GFP_SIMPLE_POINT2OCT = 104
  EC_F_EC_GFP_SIMPLE_POINTS_MAKE_AFFINE = 137
  EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES = 167
  EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES_GFP = 105
  EC_F_EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES = 168
  EC_F_EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES_GFP = 128
  EC_F_EC_GFP_SIMPLE_SET_COMPRESSED_COORDINATES = 169
  EC_F_EC_GFP_SIMPLE_SET_COMPRESSED_COORDINATES_GFP = 129
  EC_F_EC_GROUP_CHECK = 170
  EC_F_EC_GROUP_CHECK_DISCRIMINANT = 171
  EC_F_EC_GROUP_COPY = 106
  EC_F_EC_GROUP_GET0_GENERATOR = 139
  EC_F_EC_GROUP_GET_COFACTOR = 140
  EC_F_EC_GROUP_GET_CURVE_GF2M = 172
  EC_F_EC_GROUP_GET_CURVE_GFP = 130
  EC_F_EC_GROUP_GET_DEGREE = 173
  EC_F_EC_GROUP_GET_ORDER = 141
  EC_F_EC_GROUP_GET_PENTANOMIAL_BASIS = 193
  EC_F_EC_GROUP_GET_TRINOMIAL_BASIS = 194
  EC_F_EC_GROUP_NEW = 108
  EC_F_EC_GROUP_NEW_BY_CURVE_NAME = 174
  EC_F_EC_GROUP_NEW_FROM_DATA = 175
  EC_F_EC_GROUP_PRECOMPUTE_MULT = 142
  EC_F_EC_GROUP_SET_CURVE_GF2M = 176
  EC_F_EC_GROUP_SET_CURVE_GFP = 109
  EC_F_EC_GROUP_SET_EXTRA_DATA = 110
  EC_F_EC_GROUP_SET_GENERATOR = 111
  EC_F_EC_KEY_CHECK_KEY = 177
  EC_F_EC_KEY_COPY = 178
  EC_F_EC_KEY_GENERATE_KEY = 179
  EC_F_EC_KEY_NEW = 182
  EC_F_EC_KEY_PRINT = 180
  EC_F_EC_KEY_PRINT_FP = 181
  EC_F_EC_POINTS_MAKE_AFFINE = 136
  EC_F_EC_POINTS_MUL = 138
  EC_F_EC_POINT_ADD = 112
  EC_F_EC_POINT_CMP = 113
  EC_F_EC_POINT_COPY = 114
  EC_F_EC_POINT_DBL = 115
  EC_F_EC_POINT_GET_AFFINE_COORDINATES_GF2M = 183
  EC_F_EC_POINT_GET_AFFINE_COORDINATES_GFP = 116
  EC_F_EC_POINT_GET_JPROJECTIVE_COORDINATES_GFP = 117
  EC_F_EC_POINT_INVERT = 210
  EC_F_EC_POINT_IS_AT_INFINITY = 118
  EC_F_EC_POINT_IS_ON_CURVE = 119
  EC_F_EC_POINT_MAKE_AFFINE = 120
  EC_F_EC_POINT_MUL = 184
  EC_F_EC_POINT_NEW = 121
  EC_F_EC_POINT_OCT2POINT = 122
  EC_F_EC_POINT_POINT2OCT = 123
  EC_F_EC_POINT_SET_AFFINE_COORDINATES_GF2M = 185
  EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP = 124
  EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GF2M = 186
  EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GFP = 125
  EC_F_EC_POINT_SET_JPROJECTIVE_COORDINATES_GFP = 126
  EC_F_EC_POINT_SET_TO_INFINITY = 127
  EC_F_EC_PRE_COMP_DUP = 207
  EC_F_EC_PRE_COMP_NEW = 196
  EC_F_EC_WNAF_MUL = 187
  EC_F_EC_WNAF_PRECOMPUTE_MULT = 188
  EC_F_I2D_ECPARAMETERS = 190
  EC_F_I2D_ECPKPARAMETERS = 191
  EC_F_I2D_ECPRIVATEKEY = 192
  EC_F_I2O_ECPUBLICKEY = 151
  EC_F_O2I_ECPUBLICKEY = 152
  EC_R_ASN1_ERROR = 115
  EC_R_ASN1_UNKNOWN_FIELD = 116
  EC_R_BUFFER_TOO_SMALL = 100
  EC_R_D2I_ECPKPARAMETERS_FAILURE = 117
  EC_R_DISCRIMINANT_IS_ZERO = 118
  EC_R_EC_GROUP_NEW_BY_NAME_FAILURE = 119
  EC_R_FIELD_TOO_LARGE = 138
  EC_R_GROUP2PKPARAMETERS_FAILURE = 120
  EC_R_I2D_ECPKPARAMETERS_FAILURE = 121
  EC_R_INCOMPATIBLE_OBJECTS = 101
  EC_R_INVALID_ARGUMENT = 112
  EC_R_INVALID_COMPRESSED_POINT = 110
  EC_R_INVALID_COMPRESSION_BIT = 109
  EC_R_INVALID_ENCODING = 102
  EC_R_INVALID_FIELD = 103
  EC_R_INVALID_FORM = 104
  EC_R_INVALID_GROUP_ORDER = 122
  EC_R_INVALID_PENTANOMIAL_BASIS = 132
  EC_R_INVALID_PRIVATE_KEY = 123
  EC_R_INVALID_TRINOMIAL_BASIS = 137
  EC_R_MISSING_PARAMETERS = 124
  EC_R_MISSING_PRIVATE_KEY = 125
  EC_R_NOT_A_NIST_PRIME = 135
  EC_R_NOT_A_SUPPORTED_NIST_PRIME = 136
  EC_R_NOT_IMPLEMENTED = 126
  EC_R_NOT_INITIALIZED = 111
  EC_R_NO_FIELD_MOD = 133
  EC_R_PASSED_NULL_PARAMETER = 134
  EC_R_PKPARAMETERS2GROUP_FAILURE = 127
  EC_R_POINT_AT_INFINITY = 106
  EC_R_POINT_IS_NOT_ON_CURVE = 107
  EC_R_SLOT_FULL = 108
  EC_R_UNDEFINED_GENERATOR = 113
  EC_R_UNDEFINED_ORDER = 128
  EC_R_UNKNOWN_GROUP = 129
  EC_R_UNKNOWN_ORDER = 114
  EC_R_UNSUPPORTED_FIELD = 131
  EC_R_WRONG_ORDER = 130
  attach_function :ECDH_OpenSSL, [  ], :pointer
  attach_function :ECDH_set_default_method, [ :pointer ], :void
  attach_function :ECDH_get_default_method, [  ], :pointer
  attach_function :ECDH_set_method, [ :pointer, :pointer ], :int
  attach_function :ECDH_compute_key, [ :pointer, :uint, :pointer, :pointer, callback([ :pointer, :uint, :pointer, :pointer ], :pointer) ], :pointer
  attach_function :ECDH_get_ex_new_index, [ :long, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :ECDH_set_ex_data, [ :pointer, :int, :pointer ], :int
  attach_function :ECDH_get_ex_data, [ :pointer, :int ], :pointer
  attach_function :ERR_load_ECDH_strings, [  ], :void
  ECDH_F_ECDH_COMPUTE_KEY = 100
  ECDH_F_ECDH_DATA_NEW_METHOD = 101
  ECDH_R_KDF_FAILED = 102
  ECDH_R_NO_PRIVATE_VALUE = 100
  ECDH_R_POINT_ARITHMETIC_FAILURE = 101
  class ECDSASIGSt < FFI::Struct
    layout(
           :r, :pointer,
           :s, :pointer
    )
  end
  attach_function :ECDSA_SIG_new, [  ], :pointer
  attach_function :ECDSA_SIG_free, [ :pointer ], :void
  attach_function :i2d_ECDSA_SIG, [ :pointer, :pointer ], :int
  attach_function :d2i_ECDSA_SIG, [ :pointer, :pointer, :long ], :pointer
  attach_function :ECDSA_do_sign, [ :pointer, :int, :pointer ], :pointer
  attach_function :ECDSA_do_sign_ex, [ :pointer, :int, :pointer, :pointer, :pointer ], :pointer
  attach_function :ECDSA_do_verify, [ :pointer, :int, :pointer, :pointer ], :int
  attach_function :ECDSA_OpenSSL, [  ], :pointer
  attach_function :ECDSA_set_default_method, [ :pointer ], :void
  attach_function :ECDSA_get_default_method, [  ], :pointer
  attach_function :ECDSA_set_method, [ :pointer, :pointer ], :int
  attach_function :ECDSA_size, [ :pointer ], :int
  attach_function :ECDSA_sign_setup, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :ECDSA_sign, [ :int, :pointer, :int, :pointer, :pointer, :pointer ], :int
  attach_function :ECDSA_sign_ex, [ :int, :pointer, :int, :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :ECDSA_verify, [ :int, :pointer, :int, :pointer, :int, :pointer ], :int
  attach_function :ECDSA_get_ex_new_index, [ :long, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :ECDSA_set_ex_data, [ :pointer, :int, :pointer ], :int
  attach_function :ECDSA_get_ex_data, [ :pointer, :int ], :pointer
  attach_function :ERR_load_ECDSA_strings, [  ], :void
  ECDSA_F_ECDSA_DATA_NEW_METHOD = 100
  ECDSA_F_ECDSA_DO_SIGN = 101
  ECDSA_F_ECDSA_DO_VERIFY = 102
  ECDSA_F_ECDSA_SIGN_SETUP = 103
  ECDSA_R_BAD_SIGNATURE = 100
  ECDSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE = 101
  ECDSA_R_ERR_EC_LIB = 102
  ECDSA_R_MISSING_PARAMETERS = 103
  ECDSA_R_NEED_NEW_SETUP_VALUES = 106
  ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED = 104
  ECDSA_R_SIGNATURE_MALLOC_FAILED = 105
  class RandMethSt < FFI::Struct
    layout(
           :seed, callback([ :pointer, :int ], :void),
           :bytes, callback([ :pointer, :int ], :int),
           :cleanup, callback([  ], :void),
           :add, callback([ :pointer, :int, :double ], :void),
           :pseudorand, callback([ :pointer, :int ], :int),
           :status, callback([  ], :int)
    )
    def seed=(cb)
      @seed = cb
      self[:seed] = @seed
    end
    def seed
      @seed
    end
    def bytes=(cb)
      @bytes = cb
      self[:bytes] = @bytes
    end
    def bytes
      @bytes
    end
    def cleanup=(cb)
      @cleanup = cb
      self[:cleanup] = @cleanup
    end
    def cleanup
      @cleanup
    end
    def add=(cb)
      @add = cb
      self[:add] = @add
    end
    def add
      @add
    end
    def pseudorand=(cb)
      @pseudorand = cb
      self[:pseudorand] = @pseudorand
    end
    def pseudorand
      @pseudorand
    end
    def status=(cb)
      @status = cb
      self[:status] = @status
    end
    def status
      @status
    end

  end
  attach_function :RAND_set_rand_method, [ :pointer ], :int
  attach_function :RAND_get_rand_method, [  ], :pointer
  attach_function :RAND_set_rand_engine, [ :pointer ], :int
  attach_function :RAND_SSLeay, [  ], :pointer
  attach_function :RAND_cleanup, [  ], :void
  attach_function :RAND_bytes, [ :pointer, :int ], :int
  attach_function :RAND_pseudo_bytes, [ :pointer, :int ], :int
  attach_function :RAND_seed, [ :pointer, :int ], :void
  attach_function :RAND_add, [ :pointer, :int, :double ], :void
  attach_function :RAND_load_file, [ :string, :long ], :int
  attach_function :RAND_write_file, [ :string ], :int
  attach_function :RAND_file_name, [ :string, :uint ], :string
  attach_function :RAND_status, [  ], :int
  attach_function :RAND_query_egd_bytes, [ :string, :pointer, :int ], :int
  attach_function :RAND_egd, [ :string ], :int
  attach_function :RAND_egd_bytes, [ :string, :int ], :int
  attach_function :RAND_poll, [  ], :int
  attach_function :ERR_load_RAND_strings, [  ], :void
  RAND_F_ENG_RAND_GET_RAND_METHOD = 108
  RAND_F_FIPS_RAND = 103
  RAND_F_FIPS_RAND_BYTES = 102
  RAND_F_FIPS_RAND_GET_RAND_METHOD = 109
  RAND_F_FIPS_RAND_SET_DT = 106
  RAND_F_FIPS_SET_DT = 104
  RAND_F_FIPS_SET_PRNG_SEED = 107
  RAND_F_FIPS_SET_TEST_MODE = 105
  RAND_F_RAND_GET_RAND_METHOD = 101
  RAND_F_SSLEAY_RAND_BYTES = 100
  RAND_R_NON_FIPS_METHOD = 105
  RAND_R_NOT_IN_TEST_MODE = 106
  RAND_R_NO_KEY_SET = 107
  RAND_R_PRNG_ASKING_FOR_TOO_MUCH = 101
  RAND_R_PRNG_ERROR = 108
  RAND_R_PRNG_KEYED = 109
  RAND_R_PRNG_NOT_REKEYED = 102
  RAND_R_PRNG_NOT_RESEEDED = 103
  RAND_R_PRNG_NOT_SEEDED = 100
  RAND_R_PRNG_SEED_MUST_NOT_MATCH_KEY = 110
  RAND_R_PRNG_STUCK = 104
  class BufMemSt < FFI::Struct
    layout(
           :length, :int,
           :data, :pointer,
           :max, :int
    )
    def data=(str)
      @data = FFI::MemoryPointer.from_string(str)
      self[:data] = @data
    end
    def data
      @data.get_string(0)
    end

  end
  attach_function :BUF_MEM_new, [  ], :pointer
  attach_function :BUF_MEM_free, [ :pointer ], :void
  attach_function :BUF_MEM_grow, [ :pointer, :int ], :int
  attach_function :BUF_MEM_grow_clean, [ :pointer, :int ], :int
  attach_function :BUF_strdup, [ :string ], :string
  attach_function :BUF_strndup, [ :string, :uint ], :string
  attach_function :BUF_memdup, [ :pointer, :uint ], :pointer
  attach_function :BUF_strlcpy, [ :string, :string, :uint ], :uint
  attach_function :BUF_strlcat, [ :string, :string, :uint ], :uint
  attach_function :ERR_load_BUF_strings, [  ], :void
  BUF_F_BUF_MEMDUP = 103
  BUF_F_BUF_MEM_GROW = 100
  BUF_F_BUF_MEM_GROW_CLEAN = 105
  BUF_F_BUF_MEM_NEW = 101
  BUF_F_BUF_STRDUP = 102
  BUF_F_BUF_STRNDUP = 104
  SHA_LBLOCK = 16
  SHA_CBLOCK = (16*4)
  SHA_LAST_BLOCK = ((16*4) -8)
  SHA_DIGEST_LENGTH = 20
  class SHAstateSt < FFI::Struct
    layout(
           :h0, :uint,
           :h1, :uint,
           :h2, :uint,
           :h3, :uint,
           :h4, :uint,
           :Nl, :uint,
           :Nh, :uint,
           :data, [:uint, 16],
           :num, :uint
    )
  end
  attach_function :SHA_Init, [ :pointer ], :int
  attach_function :SHA_Update, [ :pointer, :pointer, :uint ], :int
  attach_function :SHA_Final, [ :pointer, :pointer ], :int
  attach_function :SHA, [ :pointer, :uint, :pointer ], :pointer
  attach_function :SHA_Transform, [ :pointer, :pointer ], :void
  attach_function :SHA1_Init, [ :pointer ], :int
  attach_function :SHA1_Update, [ :pointer, :pointer, :uint ], :int
  attach_function :SHA1_Final, [ :pointer, :pointer ], :int
  attach_function :SHA1, [ :pointer, :uint, :pointer ], :pointer
  attach_function :SHA1_Transform, [ :pointer, :pointer ], :void
  SHA256_CBLOCK = (16*4)
  SHA224_DIGEST_LENGTH = 28
  SHA256_DIGEST_LENGTH = 32
  class SHA256stateSt < FFI::Struct
    layout(
           :h, [:uint, 8],
           :Nl, :uint,
           :Nh, :uint,
           :data, [:uint, 16],
           :num, :uint,
           :md_len, :uint
    )
  end
  attach_function :SHA224_Init, [ :pointer ], :int
  attach_function :SHA224_Update, [ :pointer, :pointer, :uint ], :int
  attach_function :SHA224_Final, [ :pointer, :pointer ], :int
  attach_function :SHA224, [ :pointer, :uint, :pointer ], :pointer
  attach_function :SHA256_Init, [ :pointer ], :int
  attach_function :SHA256_Update, [ :pointer, :pointer, :uint ], :int
  attach_function :SHA256_Final, [ :pointer, :pointer ], :int
  attach_function :SHA256, [ :pointer, :uint, :pointer ], :pointer
  attach_function :SHA256_Transform, [ :pointer, :pointer ], :void
  SHA384_DIGEST_LENGTH = 48
  SHA512_DIGEST_LENGTH = 64
  SHA512_CBLOCK = (16*8)
  class SHA512stateSt < FFI::Struct
    layout(
           :h, [:ulong_long, 8],
           :Nl, :ulong_long,
           :Nh, :ulong_long,
           :num, :uint,
           :md_len, :uint,
           :u, SHA512CTXU
    )
  end
  attach_function :SHA384_Init, [ :pointer ], :int
  attach_function :SHA384_Update, [ :pointer, :pointer, :uint ], :int
  attach_function :SHA384_Final, [ :pointer, :pointer ], :int
  attach_function :SHA384, [ :pointer, :uint, :pointer ], :pointer
  attach_function :SHA512_Init, [ :pointer ], :int
  attach_function :SHA512_Update, [ :pointer, :pointer, :uint ], :int
  attach_function :SHA512_Final, [ :pointer, :pointer ], :int
  attach_function :SHA512, [ :pointer, :uint, :pointer ], :pointer
  attach_function :SHA512_Transform, [ :pointer, :pointer ], :void
  X509_FILETYPE_PEM = 1
  X509_FILETYPE_ASN1 = 2
  X509_FILETYPE_DEFAULT = 3
  X509v3_KU_DIGITAL_SIGNATURE = 0x0080
  X509v3_KU_NON_REPUDIATION = 0x0040
  X509v3_KU_KEY_ENCIPHERMENT = 0x0020
  X509v3_KU_DATA_ENCIPHERMENT = 0x0010
  X509v3_KU_KEY_AGREEMENT = 0x0008
  X509v3_KU_KEY_CERT_SIGN = 0x0004
  X509v3_KU_CRL_SIGN = 0x0002
  X509v3_KU_ENCIPHER_ONLY = 0x0001
  X509v3_KU_DECIPHER_ONLY = 0x8000
  X509v3_KU_UNDEF = 0xffff
  class X509ObjectsSt < FFI::Struct
    layout(
           :nid, :int,
           :a2i, callback([  ], :int),
           :i2a, callback([  ], :int)
    )
    def a2i=(cb)
      @a2i = cb
      self[:a2i] = @a2i
    end
    def a2i
      @a2i
    end
    def i2a=(cb)
      @i2a = cb
      self[:i2a] = @i2a
    end
    def i2a
      @i2a
    end

  end
  class X509AlgorSt < FFI::Struct
    layout(
           :algorithm, :pointer,
           :parameter, :pointer
    )
  end
  class X509ValSt < FFI::Struct
    layout(
           :notBefore, :pointer,
           :notAfter, :pointer
    )
  end
  class X509PubkeySt < FFI::Struct
    layout(
           :algor, :pointer,
           :public_key, :pointer,
           :pkey, :pointer
    )
  end
  class X509SigSt < FFI::Struct
    layout(
           :algor, :pointer,
           :digest, :pointer
    )
  end
  class X509NameEntrySt < FFI::Struct
    layout(
           :object, :pointer,
           :value, :pointer,
           :set, :int,
           :size, :int
    )
  end
  class X509NameSt < FFI::Struct
    layout(
           :entries, :pointer,
           :modified, :int,
           :bytes, :pointer,
           :hash, :ulong
    )
  end
  X509_EX_V_NETSCAPE_HACK = 0x8000
  X509_EX_V_INIT = 0x0001
  class X509ExtensionSt < FFI::Struct
    layout(
           :object, :pointer,
           :critical, :int,
           :value, :pointer
    )
  end
  class X509AttributesSt < FFI::Struct
    layout(
           :object, :pointer,
           :single, :int,
           :value, X509ATTRIBUTEValue
    )
  end
  class X509ReqInfoSt < FFI::Struct
    layout(
           :enc, ASN1ENCODINGSt,
           :version, :pointer,
           :subject, :pointer,
           :pubkey, :pointer,
           :attributes, :pointer
    )
  end
  class X509ReqSt < FFI::Struct
    layout(
           :req_info, :pointer,
           :sig_alg, :pointer,
           :signature, :pointer,
           :references, :int
    )
  end
  class X509CinfSt < FFI::Struct
    layout(
           :version, :pointer,
           :serialNumber, :pointer,
           :signature, :pointer,
           :issuer, :pointer,
           :validity, :pointer,
           :subject, :pointer,
           :key, :pointer,
           :issuerUID, :pointer,
           :subjectUID, :pointer,
           :extensions, :pointer
    )
  end
  class X509CertAuxSt < FFI::Struct
    layout(
           :trust, :pointer,
           :reject, :pointer,
           :alias, :pointer,
           :keyid, :pointer,
           :other, :pointer
    )
  end
  class X509St < FFI::Struct
    layout(
           :cert_info, :pointer,
           :sig_alg, :pointer,
           :signature, :pointer,
           :valid, :int,
           :references, :int,
           :name, :pointer,
           :ex_data, CryptoExDataSt,
           :ex_pathlen, :long,
           :ex_pcpathlen, :long,
           :ex_flags, :ulong,
           :ex_kusage, :ulong,
           :ex_xkusage, :ulong,
           :ex_nscert, :ulong,
           :skid, :pointer,
           :akid, :pointer,
           :policy_cache, :pointer,
           :sha1_hash, [:uchar, 20],
           :aux, :pointer
    )
    def name=(str)
      @name = FFI::MemoryPointer.from_string(str)
      self[:name] = @name
    end
    def name
      @name.get_string(0)
    end

  end
  class X509TrustSt < FFI::Struct
    layout(
           :trust, :int,
           :flags, :int,
           :check_trust, callback([ :pointer, :pointer, :int ], :int),
           :name, :pointer,
           :arg1, :int,
           :arg2, :pointer
    )
    def check_trust=(cb)
      @check_trust = cb
      self[:check_trust] = @check_trust
    end
    def check_trust
      @check_trust
    end
    def name=(str)
      @name = FFI::MemoryPointer.from_string(str)
      self[:name] = @name
    end
    def name
      @name.get_string(0)
    end

  end
  class X509CertPairSt < FFI::Struct
    layout(
           :forward, :pointer,
           :reverse, :pointer
    )
  end
  X509_TRUST_DEFAULT = -1
  X509_TRUST_COMPAT = 1
  X509_TRUST_SSL_CLIENT = 2
  X509_TRUST_SSL_SERVER = 3
  X509_TRUST_EMAIL = 4
  X509_TRUST_OBJECT_SIGN = 5
  X509_TRUST_OCSP_SIGN = 6
  X509_TRUST_OCSP_REQUEST = 7
  X509_TRUST_MIN = 1
  X509_TRUST_MAX = 7
  X509_TRUST_DYNAMIC = 1
  X509_TRUST_DYNAMIC_NAME = 2
  X509_TRUST_TRUSTED = 1
  X509_TRUST_REJECTED = 2
  X509_TRUST_UNTRUSTED = 3
  X509_FLAG_COMPAT = 0
  X509_FLAG_NO_HEADER = 1
  X509_FLAG_NO_VERSION = (1L << 1)
  X509_FLAG_NO_SERIAL = (1L << 2)
  X509_FLAG_NO_SIGNAME = (1L << 3)
  X509_FLAG_NO_ISSUER = (1L << 4)
  X509_FLAG_NO_VALIDITY = (1L << 5)
  X509_FLAG_NO_SUBJECT = (1L << 6)
  X509_FLAG_NO_PUBKEY = (1L << 7)
  X509_FLAG_NO_EXTENSIONS = (1L << 8)
  X509_FLAG_NO_SIGDUMP = (1L << 9)
  X509_FLAG_NO_AUX = (1L << 10)
  X509_FLAG_NO_ATTRIBUTES = (1L << 11)
  XN_FLAG_SEP_MASK = (0xf << 16)
  XN_FLAG_COMPAT = 0
  XN_FLAG_SEP_COMMA_PLUS = (1 << 16)
  XN_FLAG_SEP_CPLUS_SPC = (2 << 16)
  XN_FLAG_SEP_SPLUS_SPC = (3 << 16)
  XN_FLAG_SEP_MULTILINE = (4 << 16)
  XN_FLAG_DN_REV = (1 << 20)
  XN_FLAG_FN_MASK = (0x3 << 21)
  XN_FLAG_FN_SN = 0
  XN_FLAG_FN_LN = (1 << 21)
  XN_FLAG_FN_OID = (2 << 21)
  XN_FLAG_FN_NONE = (3 << 21)
  XN_FLAG_SPC_EQ = (1 << 23)
  XN_FLAG_DUMP_UNKNOWN_FIELDS = (1 << 24)
  XN_FLAG_FN_ALIGN = (1 << 25)
  XN_FLAG_RFC2253 = ((1|2|4|0x10|0x100|0x200)|(1 << 16)|(1 << 20)|0|(1 << 24))
  XN_FLAG_ONELINE = ((1|2|4|0x10|0x100|0x200)|8|(2 << 16)|(1 << 23)|0)
  XN_FLAG_MULTILINE = (2|4|(4 << 16)|(1 << 23)|(1 << 21)|(1 << 25))
  class X509RevokedSt < FFI::Struct
    layout(
           :serialNumber, :pointer,
           :revocationDate, :pointer,
           :extensions, :pointer,
           :sequence, :int
    )
  end
  class X509CrlInfoSt < FFI::Struct
    layout(
           :version, :pointer,
           :sig_alg, :pointer,
           :issuer, :pointer,
           :lastUpdate, :pointer,
           :nextUpdate, :pointer,
           :revoked, :pointer,
           :extensions, :pointer,
           :enc, ASN1ENCODINGSt
    )
  end
  class X509CrlSt < FFI::Struct
    layout(
           :crl, :pointer,
           :sig_alg, :pointer,
           :signature, :pointer,
           :references, :int
    )
  end
  class PrivateKeySt < FFI::Struct
    layout(
           :version, :int,
           :enc_algor, :pointer,
           :enc_pkey, :pointer,
           :dec_pkey, :pointer,
           :key_length, :int,
           :key_data, :pointer,
           :key_free, :int,
           :cipher, EvpCipherInfoSt,
           :references, :int
    )
    def key_data=(str)
      @key_data = FFI::MemoryPointer.from_string(str)
      self[:key_data] = @key_data
    end
    def key_data
      @key_data.get_string(0)
    end

  end
  class X509InfoSt < FFI::Struct
    layout(
           :x509, :pointer,
           :crl, :pointer,
           :x_pkey, :pointer,
           :enc_cipher, EvpCipherInfoSt,
           :enc_len, :int,
           :enc_data, :pointer,
           :references, :int
    )
    def enc_data=(str)
      @enc_data = FFI::MemoryPointer.from_string(str)
      self[:enc_data] = @enc_data
    end
    def enc_data
      @enc_data.get_string(0)
    end

  end
  class NetscapeSpkacSt < FFI::Struct
    layout(
           :pubkey, :pointer,
           :challenge, :pointer
    )
  end
  class NetscapeSpkiSt < FFI::Struct
    layout(
           :spkac, :pointer,
           :sig_algor, :pointer,
           :signature, :pointer
    )
  end
  class NetscapeCertificateSequence < FFI::Struct
    layout(
           :type, :pointer,
           :certs, :pointer
    )
  end
  class PBEPARAMSt < FFI::Struct
    layout(
           :salt, :pointer,
           :iter, :pointer
    )
  end
  class PBE2PARAMSt < FFI::Struct
    layout(
           :keyfunc, :pointer,
           :encryption, :pointer
    )
  end
  class PBKDF2PARAMSt < FFI::Struct
    layout(
           :salt, :pointer,
           :iter, :pointer,
           :keylength, :pointer,
           :prf, :pointer
    )
  end
  PKCS8_OK = 0
  PKCS8_NO_OCTET = 1
  PKCS8_EMBEDDED_PARAM = 2
  PKCS8_NS_DB = 3
  class Pkcs8PrivKeyInfoSt < FFI::Struct
    layout(
           :broken, :int,
           :version, :pointer,
           :pkeyalg, :pointer,
           :pkey, :pointer,
           :attributes, :pointer
    )
  end
  class LhashNodeSt < FFI::Struct
    layout(
           :data, :pointer,
           :next, :pointer,
           :hash, :ulong
    )
  end
  callback(:LHASH_COMP_FN_TYPE, [ :pointer, :pointer ], :int)
  callback(:LHASH_HASH_FN_TYPE, [ :pointer ], :ulong)
  callback(:LHASH_DOALL_FN_TYPE, [ :pointer ], :void)
  callback(:LHASH_DOALL_ARG_FN_TYPE, [ :pointer, :pointer ], :void)
  class LhashSt < FFI::Struct
    layout(
           :b, :pointer,
           :comp, :LHASH_COMP_FN_TYPE,
           :hash, :LHASH_HASH_FN_TYPE,
           :num_nodes, :uint,
           :num_alloc_nodes, :uint,
           :p, :uint,
           :pmax, :uint,
           :up_load, :ulong,
           :down_load, :ulong,
           :num_items, :ulong,
           :num_expands, :ulong,
           :num_expand_reallocs, :ulong,
           :num_contracts, :ulong,
           :num_contract_reallocs, :ulong,
           :num_hash_calls, :ulong,
           :num_comp_calls, :ulong,
           :num_insert, :ulong,
           :num_replace, :ulong,
           :num_delete, :ulong,
           :num_no_delete, :ulong,
           :num_retrieve, :ulong,
           :num_retrieve_miss, :ulong,
           :num_hash_comps, :ulong,
           :error, :int
    )
    def comp=(cb)
      @comp = cb
      self[:comp] = @comp
    end
    def comp
      @comp
    end
    def hash=(cb)
      @hash = cb
      self[:hash] = @hash
    end
    def hash
      @hash
    end

  end
  LH_LOAD_MULT = 256
  attach_function :lh_new, [ :LHASH_HASH_FN_TYPE, :LHASH_COMP_FN_TYPE ], :pointer
  attach_function :lh_free, [ :pointer ], :void
  attach_function :lh_insert, [ :pointer, :pointer ], :pointer
  attach_function :lh_delete, [ :pointer, :pointer ], :pointer
  attach_function :lh_retrieve, [ :pointer, :pointer ], :pointer
  attach_function :lh_doall, [ :pointer, :LHASH_DOALL_FN_TYPE ], :void
  attach_function :lh_doall_arg, [ :pointer, :LHASH_DOALL_ARG_FN_TYPE, :pointer ], :void
  attach_function :lh_strhash, [ :string ], :ulong
  attach_function :lh_num_items, [ :pointer ], :ulong
  attach_function :lh_stats, [ :pointer, :pointer ], :void
  attach_function :lh_node_stats, [ :pointer, :pointer ], :void
  attach_function :lh_node_usage_stats, [ :pointer, :pointer ], :void
  attach_function :lh_stats_bio, [ :pointer, :pointer ], :void
  attach_function :lh_node_stats_bio, [ :pointer, :pointer ], :void
  attach_function :lh_node_usage_stats_bio, [ :pointer, :pointer ], :void
  class X509HashDirSt < FFI::Struct
    layout(
           :num_dirs, :int,
           :dirs, :pointer,
           :dirs_type, :pointer,
           :num_dirs_alloced, :int
    )
  end
  class X509FileSt < FFI::Struct
    layout(
           :num_paths, :int,
           :num_alloced, :int,
           :paths, :pointer,
           :path_type, :pointer
    )
  end
  X509_LU_RETRY = -1
  X509_LU_FAIL = 0
  X509_LU_X509 = 1
  X509_LU_CRL = 2
  X509_LU_PKEY = 3
  class X509ObjectSt < FFI::Struct
    layout(
           :type, :int,
           :data, X509OBJECTData
    )
  end
  class X509LookupMethodSt < FFI::Struct
    layout(
           :name, :pointer,
           :new_item, callback([ :pointer ], :int),
           :free, callback([ :pointer ], :void),
           :init, callback([ :pointer ], :int),
           :shutdown, callback([ :pointer ], :int),
           :ctrl, callback([ :pointer, :int, :string, :long, :pointer ], :int),
           :get_by_subject, callback([ :pointer, :int, :pointer, :pointer ], :int),
           :get_by_issuer_serial, callback([ :pointer, :int, :pointer, :pointer, :pointer ], :int),
           :get_by_fingerprint, callback([ :pointer, :int, :pointer, :int, :pointer ], :int),
           :get_by_alias, callback([ :pointer, :int, :string, :int, :pointer ], :int)
    )
    def name=(str)
      @name = FFI::MemoryPointer.from_string(str)
      self[:name] = @name
    end
    def name
      @name.get_string(0)
    end
    def new_item=(cb)
      @new_item = cb
      self[:new_item] = @new_item
    end
    def new_item
      @new_item
    end
    def free=(cb)
      @free = cb
      self[:free] = @free
    end
    def free
      @free
    end
    def init=(cb)
      @init = cb
      self[:init] = @init
    end
    def init
      @init
    end
    def shutdown=(cb)
      @shutdown = cb
      self[:shutdown] = @shutdown
    end
    def shutdown
      @shutdown
    end
    def ctrl=(cb)
      @ctrl = cb
      self[:ctrl] = @ctrl
    end
    def ctrl
      @ctrl
    end
    def get_by_subject=(cb)
      @get_by_subject = cb
      self[:get_by_subject] = @get_by_subject
    end
    def get_by_subject
      @get_by_subject
    end
    def get_by_issuer_serial=(cb)
      @get_by_issuer_serial = cb
      self[:get_by_issuer_serial] = @get_by_issuer_serial
    end
    def get_by_issuer_serial
      @get_by_issuer_serial
    end
    def get_by_fingerprint=(cb)
      @get_by_fingerprint = cb
      self[:get_by_fingerprint] = @get_by_fingerprint
    end
    def get_by_fingerprint
      @get_by_fingerprint
    end
    def get_by_alias=(cb)
      @get_by_alias = cb
      self[:get_by_alias] = @get_by_alias
    end
    def get_by_alias
      @get_by_alias
    end

  end
  class X509VERIFYPARAMSt < FFI::Struct
    layout(
           :name, :pointer,
           :check_time, :long,
           :inh_flags, :ulong,
           :flags, :ulong,
           :purpose, :int,
           :trust, :int,
           :depth, :int,
           :policies, :pointer
    )
    def name=(str)
      @name = FFI::MemoryPointer.from_string(str)
      self[:name] = @name
    end
    def name
      @name.get_string(0)
    end

  end
  class X509StoreSt < FFI::Struct
    layout(
           :cache, :int,
           :objs, :pointer,
           :get_cert_methods, :pointer,
           :param, :pointer,
           :verify, callback([ :pointer ], :int),
           :verify_cb, callback([ :int, :pointer ], :int),
           :get_issuer, callback([ :pointer, :pointer, :pointer ], :int),
           :check_issued, callback([ :pointer, :pointer, :pointer ], :int),
           :check_revocation, callback([ :pointer ], :int),
           :get_crl, callback([ :pointer, :pointer, :pointer ], :int),
           :check_crl, callback([ :pointer, :pointer ], :int),
           :cert_crl, callback([ :pointer, :pointer, :pointer ], :int),
           :cleanup, callback([ :pointer ], :int),
           :ex_data, CryptoExDataSt,
           :references, :int
    )
    def verify=(cb)
      @verify = cb
      self[:verify] = @verify
    end
    def verify
      @verify
    end
    def verify_cb=(cb)
      @verify_cb = cb
      self[:verify_cb] = @verify_cb
    end
    def verify_cb
      @verify_cb
    end
    def get_issuer=(cb)
      @get_issuer = cb
      self[:get_issuer] = @get_issuer
    end
    def get_issuer
      @get_issuer
    end
    def check_issued=(cb)
      @check_issued = cb
      self[:check_issued] = @check_issued
    end
    def check_issued
      @check_issued
    end
    def check_revocation=(cb)
      @check_revocation = cb
      self[:check_revocation] = @check_revocation
    end
    def check_revocation
      @check_revocation
    end
    def get_crl=(cb)
      @get_crl = cb
      self[:get_crl] = @get_crl
    end
    def get_crl
      @get_crl
    end
    def check_crl=(cb)
      @check_crl = cb
      self[:check_crl] = @check_crl
    end
    def check_crl
      @check_crl
    end
    def cert_crl=(cb)
      @cert_crl = cb
      self[:cert_crl] = @cert_crl
    end
    def cert_crl
      @cert_crl
    end
    def cleanup=(cb)
      @cleanup = cb
      self[:cleanup] = @cleanup
    end
    def cleanup
      @cleanup
    end

  end
  attach_function :X509_STORE_set_depth, [ :pointer, :int ], :int
  class X509LookupSt < FFI::Struct
    layout(
           :init, :int,
           :skip, :int,
           :method, :pointer,
           :method_data, :pointer,
           :store_ctx, :pointer
    )
    def method_data=(str)
      @method_data = FFI::MemoryPointer.from_string(str)
      self[:method_data] = @method_data
    end
    def method_data
      @method_data.get_string(0)
    end

  end
  class X509StoreCtxSt < FFI::Struct
    layout(
           :ctx, :pointer,
           :current_method, :int,
           :cert, :pointer,
           :untrusted, :pointer,
           :crls, :pointer,
           :param, :pointer,
           :other_ctx, :pointer,
           :verify, callback([ :pointer ], :int),
           :verify_cb, callback([ :int, :pointer ], :int),
           :get_issuer, callback([ :pointer, :pointer, :pointer ], :int),
           :check_issued, callback([ :pointer, :pointer, :pointer ], :int),
           :check_revocation, callback([ :pointer ], :int),
           :get_crl, callback([ :pointer, :pointer, :pointer ], :int),
           :check_crl, callback([ :pointer, :pointer ], :int),
           :cert_crl, callback([ :pointer, :pointer, :pointer ], :int),
           :check_policy, callback([ :pointer ], :int),
           :cleanup, callback([ :pointer ], :int),
           :valid, :int,
           :last_untrusted, :int,
           :chain, :pointer,
           :tree, :pointer,
           :explicit_policy, :int,
           :error_depth, :int,
           :error, :int,
           :current_cert, :pointer,
           :current_issuer, :pointer,
           :current_crl, :pointer,
           :ex_data, CryptoExDataSt
    )
    def verify=(cb)
      @verify = cb
      self[:verify] = @verify
    end
    def verify
      @verify
    end
    def verify_cb=(cb)
      @verify_cb = cb
      self[:verify_cb] = @verify_cb
    end
    def verify_cb
      @verify_cb
    end
    def get_issuer=(cb)
      @get_issuer = cb
      self[:get_issuer] = @get_issuer
    end
    def get_issuer
      @get_issuer
    end
    def check_issued=(cb)
      @check_issued = cb
      self[:check_issued] = @check_issued
    end
    def check_issued
      @check_issued
    end
    def check_revocation=(cb)
      @check_revocation = cb
      self[:check_revocation] = @check_revocation
    end
    def check_revocation
      @check_revocation
    end
    def get_crl=(cb)
      @get_crl = cb
      self[:get_crl] = @get_crl
    end
    def get_crl
      @get_crl
    end
    def check_crl=(cb)
      @check_crl = cb
      self[:check_crl] = @check_crl
    end
    def check_crl
      @check_crl
    end
    def cert_crl=(cb)
      @cert_crl = cb
      self[:cert_crl] = @cert_crl
    end
    def cert_crl
      @cert_crl
    end
    def check_policy=(cb)
      @check_policy = cb
      self[:check_policy] = @check_policy
    end
    def check_policy
      @check_policy
    end
    def cleanup=(cb)
      @cleanup = cb
      self[:cleanup] = @cleanup
    end
    def cleanup
      @cleanup
    end

  end
  attach_function :X509_STORE_CTX_set_depth, [ :pointer, :int ], :void
  X509_L_FILE_LOAD = 1
  X509_L_ADD_DIR = 2
  X509_V_OK = 0
  X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT = 2
  X509_V_ERR_UNABLE_TO_GET_CRL = 3
  X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE = 4
  X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE = 5
  X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY = 6
  X509_V_ERR_CERT_SIGNATURE_FAILURE = 7
  X509_V_ERR_CRL_SIGNATURE_FAILURE = 8
  X509_V_ERR_CERT_NOT_YET_VALID = 9
  X509_V_ERR_CERT_HAS_EXPIRED = 10
  X509_V_ERR_CRL_NOT_YET_VALID = 11
  X509_V_ERR_CRL_HAS_EXPIRED = 12
  X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD = 13
  X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD = 14
  X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD = 15
  X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD = 16
  X509_V_ERR_OUT_OF_MEM = 17
  X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT = 18
  X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN = 19
  X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 20
  X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE = 21
  X509_V_ERR_CERT_CHAIN_TOO_LONG = 22
  X509_V_ERR_CERT_REVOKED = 23
  X509_V_ERR_INVALID_CA = 24
  X509_V_ERR_PATH_LENGTH_EXCEEDED = 25
  X509_V_ERR_INVALID_PURPOSE = 26
  X509_V_ERR_CERT_UNTRUSTED = 27
  X509_V_ERR_CERT_REJECTED = 28
  X509_V_ERR_SUBJECT_ISSUER_MISMATCH = 29
  X509_V_ERR_AKID_SKID_MISMATCH = 30
  X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH = 31
  X509_V_ERR_KEYUSAGE_NO_CERTSIGN = 32
  X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER = 33
  X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION = 34
  X509_V_ERR_KEYUSAGE_NO_CRL_SIGN = 35
  X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION = 36
  X509_V_ERR_INVALID_NON_CA = 37
  X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED = 38
  X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE = 39
  X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED = 40
  X509_V_ERR_INVALID_EXTENSION = 41
  X509_V_ERR_INVALID_POLICY_EXTENSION = 42
  X509_V_ERR_NO_EXPLICIT_POLICY = 43
  X509_V_ERR_UNNESTED_RESOURCE = 44
  X509_V_ERR_APPLICATION_VERIFICATION = 50
  X509_V_FLAG_CB_ISSUER_CHECK = 0x1
  X509_V_FLAG_USE_CHECK_TIME = 0x2
  X509_V_FLAG_CRL_CHECK = 0x4
  X509_V_FLAG_CRL_CHECK_ALL = 0x8
  X509_V_FLAG_IGNORE_CRITICAL = 0x10
  X509_V_FLAG_X509_STRICT = 0x20
  X509_V_FLAG_ALLOW_PROXY_CERTS = 0x40
  X509_V_FLAG_POLICY_CHECK = 0x80
  X509_V_FLAG_EXPLICIT_POLICY = 0x100
  X509_V_FLAG_INHIBIT_ANY = 0x200
  X509_V_FLAG_INHIBIT_MAP = 0x400
  X509_V_FLAG_NOTIFY_POLICY = 0x800
  X509_V_FLAG_CHECK_SS_SIGNATURE = 0x4000
  X509_VP_FLAG_DEFAULT = 0x1
  X509_VP_FLAG_OVERWRITE = 0x2
  X509_VP_FLAG_RESET_FLAGS = 0x4
  X509_VP_FLAG_LOCKED = 0x8
  X509_VP_FLAG_ONCE = 0x10
  X509_V_FLAG_POLICY_MASK = (0x80|0x100|0x200|0x400)
  attach_function :X509_OBJECT_idx_by_subject, [ :pointer, :int, :pointer ], :int
  attach_function :X509_OBJECT_retrieve_by_subject, [ :pointer, :int, :pointer ], :pointer
  attach_function :X509_OBJECT_retrieve_match, [ :pointer, :pointer ], :pointer
  attach_function :X509_OBJECT_up_ref_count, [ :pointer ], :void
  attach_function :X509_OBJECT_free_contents, [ :pointer ], :void
  attach_function :X509_STORE_new, [  ], :pointer
  attach_function :X509_STORE_free, [ :pointer ], :void
  attach_function :X509_STORE_set_flags, [ :pointer, :ulong ], :int
  attach_function :X509_STORE_set_purpose, [ :pointer, :int ], :int
  attach_function :X509_STORE_set_trust, [ :pointer, :int ], :int
  attach_function :X509_STORE_set1_param, [ :pointer, :pointer ], :int
  attach_function :X509_STORE_CTX_new, [  ], :pointer
  attach_function :X509_STORE_CTX_get1_issuer, [ :pointer, :pointer, :pointer ], :int
  attach_function :X509_STORE_CTX_free, [ :pointer ], :void
  attach_function :X509_STORE_CTX_init, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :X509_STORE_CTX_trusted_stack, [ :pointer, :pointer ], :void
  attach_function :X509_STORE_CTX_cleanup, [ :pointer ], :void
  attach_function :X509_STORE_add_lookup, [ :pointer, :pointer ], :pointer
  attach_function :X509_LOOKUP_hash_dir, [  ], :pointer
  attach_function :X509_LOOKUP_file, [  ], :pointer
  attach_function :X509_STORE_add_cert, [ :pointer, :pointer ], :int
  attach_function :X509_STORE_add_crl, [ :pointer, :pointer ], :int
  attach_function :X509_STORE_get_by_subject, [ :pointer, :int, :pointer, :pointer ], :int
  attach_function :X509_LOOKUP_ctrl, [ :pointer, :int, :string, :long, :pointer ], :int
  attach_function :X509_load_cert_file, [ :pointer, :string, :int ], :int
  attach_function :X509_load_crl_file, [ :pointer, :string, :int ], :int
  attach_function :X509_load_cert_crl_file, [ :pointer, :string, :int ], :int
  attach_function :X509_LOOKUP_new, [ :pointer ], :pointer
  attach_function :X509_LOOKUP_free, [ :pointer ], :void
  attach_function :X509_LOOKUP_init, [ :pointer ], :int
  attach_function :X509_LOOKUP_by_subject, [ :pointer, :int, :pointer, :pointer ], :int
  attach_function :X509_LOOKUP_by_issuer_serial, [ :pointer, :int, :pointer, :pointer, :pointer ], :int
  attach_function :X509_LOOKUP_by_fingerprint, [ :pointer, :int, :pointer, :int, :pointer ], :int
  attach_function :X509_LOOKUP_by_alias, [ :pointer, :int, :string, :int, :pointer ], :int
  attach_function :X509_LOOKUP_shutdown, [ :pointer ], :int
  attach_function :X509_STORE_load_locations, [ :pointer, :string, :string ], :int
  attach_function :X509_STORE_set_default_paths, [ :pointer ], :int
  attach_function :X509_STORE_CTX_get_ex_new_index, [ :long, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :X509_STORE_CTX_set_ex_data, [ :pointer, :int, :pointer ], :int
  attach_function :X509_STORE_CTX_get_ex_data, [ :pointer, :int ], :pointer
  attach_function :X509_STORE_CTX_get_error, [ :pointer ], :int
  attach_function :X509_STORE_CTX_set_error, [ :pointer, :int ], :void
  attach_function :X509_STORE_CTX_get_error_depth, [ :pointer ], :int
  attach_function :X509_STORE_CTX_get_current_cert, [ :pointer ], :pointer
  attach_function :X509_STORE_CTX_get_chain, [ :pointer ], :pointer
  attach_function :X509_STORE_CTX_get1_chain, [ :pointer ], :pointer
  attach_function :X509_STORE_CTX_set_cert, [ :pointer, :pointer ], :void
  attach_function :X509_STORE_CTX_set_chain, [ :pointer, :pointer ], :void
  attach_function :X509_STORE_CTX_set0_crls, [ :pointer, :pointer ], :void
  attach_function :X509_STORE_CTX_set_purpose, [ :pointer, :int ], :int
  attach_function :X509_STORE_CTX_set_trust, [ :pointer, :int ], :int
  attach_function :X509_STORE_CTX_purpose_inherit, [ :pointer, :int, :int, :int ], :int
  attach_function :X509_STORE_CTX_set_flags, [ :pointer, :ulong ], :void
  attach_function :X509_STORE_CTX_set_time, [ :pointer, :ulong, :long ], :void
  attach_function :X509_STORE_CTX_set_verify_cb, [ :pointer, callback([ :int, :pointer ], :int) ], :void
  attach_function :X509_STORE_CTX_get0_policy_tree, [ :pointer ], :pointer
  attach_function :X509_STORE_CTX_get_explicit_policy, [ :pointer ], :int
  attach_function :X509_STORE_CTX_get0_param, [ :pointer ], :pointer
  attach_function :X509_STORE_CTX_set0_param, [ :pointer, :pointer ], :void
  attach_function :X509_STORE_CTX_set_default, [ :pointer, :string ], :int
  attach_function :X509_VERIFY_PARAM_new, [  ], :pointer
  attach_function :X509_VERIFY_PARAM_free, [ :pointer ], :void
  attach_function :X509_VERIFY_PARAM_inherit, [ :pointer, :pointer ], :int
  attach_function :X509_VERIFY_PARAM_set1, [ :pointer, :pointer ], :int
  attach_function :X509_VERIFY_PARAM_set1_name, [ :pointer, :string ], :int
  attach_function :X509_VERIFY_PARAM_set_flags, [ :pointer, :ulong ], :int
  attach_function :X509_VERIFY_PARAM_clear_flags, [ :pointer, :ulong ], :int
  attach_function :X509_VERIFY_PARAM_get_flags, [ :pointer ], :ulong
  attach_function :X509_VERIFY_PARAM_set_purpose, [ :pointer, :int ], :int
  attach_function :X509_VERIFY_PARAM_set_trust, [ :pointer, :int ], :int
  attach_function :X509_VERIFY_PARAM_set_depth, [ :pointer, :int ], :void
  attach_function :X509_VERIFY_PARAM_set_time, [ :pointer, :long ], :void
  attach_function :X509_VERIFY_PARAM_add0_policy, [ :pointer, :pointer ], :int
  attach_function :X509_VERIFY_PARAM_set1_policies, [ :pointer, :pointer ], :int
  attach_function :X509_VERIFY_PARAM_get_depth, [ :pointer ], :int
  attach_function :X509_VERIFY_PARAM_add0_table, [ :pointer ], :int
  attach_function :X509_VERIFY_PARAM_lookup, [ :string ], :pointer
  attach_function :X509_VERIFY_PARAM_table_cleanup, [  ], :void
  attach_function :X509_policy_check, [ :pointer, :pointer, :pointer, :pointer, :uint ], :int
  attach_function :X509_policy_tree_free, [ :pointer ], :void
  attach_function :X509_policy_tree_level_count, [ :pointer ], :int
  attach_function :X509_policy_tree_get0_level, [ :pointer, :int ], :pointer
  attach_function :X509_policy_tree_get0_policies, [ :pointer ], :pointer
  attach_function :X509_policy_tree_get0_user_policies, [ :pointer ], :pointer
  attach_function :X509_policy_level_node_count, [ :pointer ], :int
  attach_function :X509_policy_level_get0_node, [ :pointer, :int ], :pointer
  attach_function :X509_policy_node_get0_policy, [ :pointer ], :pointer
  attach_function :X509_policy_node_get0_qualifiers, [ :pointer ], :pointer
  attach_function :X509_policy_node_get0_parent, [ :pointer ], :pointer
  class Pkcs7IssuerAndSerialSt < FFI::Struct
    layout(
           :issuer, :pointer,
           :serial, :pointer
    )
  end
  class Pkcs7SignerInfoSt < FFI::Struct
    layout(
           :version, :pointer,
           :issuer_and_serial, :pointer,
           :digest_alg, :pointer,
           :auth_attr, :pointer,
           :digest_enc_alg, :pointer,
           :enc_digest, :pointer,
           :unauth_attr, :pointer,
           :pkey, :pointer
    )
  end
  class Pkcs7RecipInfoSt < FFI::Struct
    layout(
           :version, :pointer,
           :issuer_and_serial, :pointer,
           :key_enc_algor, :pointer,
           :enc_key, :pointer,
           :cert, :pointer
    )
  end
  class Pkcs7SignedSt < FFI::Struct
    layout(
           :version, :pointer,
           :md_algs, :pointer,
           :cert, :pointer,
           :crl, :pointer,
           :signer_info, :pointer,
           :contents, :pointer
    )
  end
  class Pkcs7EncContentSt < FFI::Struct
    layout(
           :content_type, :pointer,
           :algorithm, :pointer,
           :enc_data, :pointer,
           :cipher, :pointer
    )
  end
  class Pkcs7EnvelopedSt < FFI::Struct
    layout(
           :version, :pointer,
           :recipientinfo, :pointer,
           :enc_data, :pointer
    )
  end
  class Pkcs7SignedandenvelopedSt < FFI::Struct
    layout(
           :version, :pointer,
           :md_algs, :pointer,
           :cert, :pointer,
           :crl, :pointer,
           :signer_info, :pointer,
           :enc_data, :pointer,
           :recipientinfo, :pointer
    )
  end
  class Pkcs7DigestSt < FFI::Struct
    layout(
           :version, :pointer,
           :md, :pointer,
           :contents, :pointer,
           :digest, :pointer
    )
  end
  class Pkcs7EncryptedSt < FFI::Struct
    layout(
           :version, :pointer,
           :enc_data, :pointer
    )
  end
  PKCS7_S_HEADER = 0
  PKCS7_S_BODY = 1
  PKCS7_S_TAIL = 2
  class Pkcs7St < FFI::Struct
    layout(
           :asn1, :pointer,
           :length, :long,
           :state, :int,
           :detached, :int,
           :type, :pointer,
           :d, PKCS7D
    )
  end
  PKCS7_OP_SET_DETACHED_SIGNATURE = 1
  PKCS7_OP_GET_DETACHED_SIGNATURE = 2
  PKCS7_TEXT = 0x1
  PKCS7_NOCERTS = 0x2
  PKCS7_NOSIGS = 0x4
  PKCS7_NOCHAIN = 0x8
  PKCS7_NOINTERN = 0x10
  PKCS7_NOVERIFY = 0x20
  PKCS7_DETACHED = 0x40
  PKCS7_BINARY = 0x80
  PKCS7_NOATTR = 0x100
  PKCS7_NOSMIMECAP = 0x200
  PKCS7_NOOLDMIMETYPE = 0x400
  PKCS7_CRLFEOL = 0x800
  PKCS7_STREAM = 0x1000
  PKCS7_NOCRL = 0x2000
  SMIME_TEXT = 0x1
  SMIME_NOCERTS = 0x2
  SMIME_NOSIGS = 0x4
  SMIME_NOCHAIN = 0x8
  SMIME_NOINTERN = 0x10
  SMIME_NOVERIFY = 0x20
  SMIME_DETACHED = 0x40
  SMIME_BINARY = 0x80
  SMIME_NOATTR = 0x100
  attach_function :PKCS7_ISSUER_AND_SERIAL_new, [  ], :pointer
  attach_function :PKCS7_ISSUER_AND_SERIAL_free, [ :pointer ], :void
  attach_function :d2i_PKCS7_ISSUER_AND_SERIAL, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_PKCS7_ISSUER_AND_SERIAL, [ :pointer, :pointer ], :int
  attach_function :PKCS7_ISSUER_AND_SERIAL_digest, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :d2i_PKCS7_fp, [ :pointer, :pointer ], :pointer
  attach_function :i2d_PKCS7_fp, [ :pointer, :pointer ], :int
  attach_function :PKCS7_dup, [ :pointer ], :pointer
  attach_function :d2i_PKCS7_bio, [ :pointer, :pointer ], :pointer
  attach_function :i2d_PKCS7_bio, [ :pointer, :pointer ], :int
  attach_function :PKCS7_SIGNER_INFO_new, [  ], :pointer
  attach_function :PKCS7_SIGNER_INFO_free, [ :pointer ], :void
  attach_function :d2i_PKCS7_SIGNER_INFO, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_PKCS7_SIGNER_INFO, [ :pointer, :pointer ], :int
  attach_function :PKCS7_RECIP_INFO_new, [  ], :pointer
  attach_function :PKCS7_RECIP_INFO_free, [ :pointer ], :void
  attach_function :d2i_PKCS7_RECIP_INFO, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_PKCS7_RECIP_INFO, [ :pointer, :pointer ], :int
  attach_function :PKCS7_SIGNED_new, [  ], :pointer
  attach_function :PKCS7_SIGNED_free, [ :pointer ], :void
  attach_function :d2i_PKCS7_SIGNED, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_PKCS7_SIGNED, [ :pointer, :pointer ], :int
  attach_function :PKCS7_ENC_CONTENT_new, [  ], :pointer
  attach_function :PKCS7_ENC_CONTENT_free, [ :pointer ], :void
  attach_function :d2i_PKCS7_ENC_CONTENT, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_PKCS7_ENC_CONTENT, [ :pointer, :pointer ], :int
  attach_function :PKCS7_ENVELOPE_new, [  ], :pointer
  attach_function :PKCS7_ENVELOPE_free, [ :pointer ], :void
  attach_function :d2i_PKCS7_ENVELOPE, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_PKCS7_ENVELOPE, [ :pointer, :pointer ], :int
  attach_function :PKCS7_SIGN_ENVELOPE_new, [  ], :pointer
  attach_function :PKCS7_SIGN_ENVELOPE_free, [ :pointer ], :void
  attach_function :d2i_PKCS7_SIGN_ENVELOPE, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_PKCS7_SIGN_ENVELOPE, [ :pointer, :pointer ], :int
  attach_function :PKCS7_DIGEST_new, [  ], :pointer
  attach_function :PKCS7_DIGEST_free, [ :pointer ], :void
  attach_function :d2i_PKCS7_DIGEST, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_PKCS7_DIGEST, [ :pointer, :pointer ], :int
  attach_function :PKCS7_ENCRYPT_new, [  ], :pointer
  attach_function :PKCS7_ENCRYPT_free, [ :pointer ], :void
  attach_function :d2i_PKCS7_ENCRYPT, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_PKCS7_ENCRYPT, [ :pointer, :pointer ], :int
  attach_function :PKCS7_new, [  ], :pointer
  attach_function :PKCS7_free, [ :pointer ], :void
  attach_function :d2i_PKCS7, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_PKCS7, [ :pointer, :pointer ], :int
  attach_function :i2d_PKCS7_NDEF, [ :pointer, :pointer ], :int
  attach_function :PKCS7_ctrl, [ :pointer, :int, :long, :string ], :long
  attach_function :PKCS7_set_type, [ :pointer, :int ], :int
  attach_function :PKCS7_set0_type_other, [ :pointer, :int, :pointer ], :int
  attach_function :PKCS7_set_content, [ :pointer, :pointer ], :int
  attach_function :PKCS7_SIGNER_INFO_set, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :PKCS7_add_signer, [ :pointer, :pointer ], :int
  attach_function :PKCS7_add_certificate, [ :pointer, :pointer ], :int
  attach_function :PKCS7_add_crl, [ :pointer, :pointer ], :int
  attach_function :PKCS7_content_new, [ :pointer, :int ], :int
  attach_function :PKCS7_dataVerify, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :PKCS7_signatureVerify, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :PKCS7_dataInit, [ :pointer, :pointer ], :pointer
  attach_function :PKCS7_dataFinal, [ :pointer, :pointer ], :int
  attach_function :PKCS7_dataDecode, [ :pointer, :pointer, :pointer, :pointer ], :pointer
  attach_function :PKCS7_add_signature, [ :pointer, :pointer, :pointer, :pointer ], :pointer
  attach_function :PKCS7_cert_from_signer_info, [ :pointer, :pointer ], :pointer
  attach_function :PKCS7_set_digest, [ :pointer, :pointer ], :int
  attach_function :PKCS7_get_signer_info, [ :pointer ], :pointer
  attach_function :PKCS7_add_recipient, [ :pointer, :pointer ], :pointer
  attach_function :PKCS7_add_recipient_info, [ :pointer, :pointer ], :int
  attach_function :PKCS7_RECIP_INFO_set, [ :pointer, :pointer ], :int
  attach_function :PKCS7_set_cipher, [ :pointer, :pointer ], :int
  attach_function :PKCS7_get_issuer_and_serial, [ :pointer, :int ], :pointer
  attach_function :PKCS7_digest_from_attributes, [ :pointer ], :pointer
  attach_function :PKCS7_add_signed_attribute, [ :pointer, :int, :int, :pointer ], :int
  attach_function :PKCS7_add_attribute, [ :pointer, :int, :int, :pointer ], :int
  attach_function :PKCS7_get_attribute, [ :pointer, :int ], :pointer
  attach_function :PKCS7_get_signed_attribute, [ :pointer, :int ], :pointer
  attach_function :PKCS7_set_signed_attributes, [ :pointer, :pointer ], :int
  attach_function :PKCS7_set_attributes, [ :pointer, :pointer ], :int
  attach_function :PKCS7_sign, [ :pointer, :pointer, :pointer, :pointer, :int ], :pointer
  attach_function :PKCS7_verify, [ :pointer, :pointer, :pointer, :pointer, :pointer, :int ], :int
  attach_function :PKCS7_get0_signers, [ :pointer, :pointer, :int ], :pointer
  attach_function :PKCS7_encrypt, [ :pointer, :pointer, :pointer, :int ], :pointer
  attach_function :PKCS7_decrypt, [ :pointer, :pointer, :pointer, :pointer, :int ], :int
  attach_function :PKCS7_add_attrib_smimecap, [ :pointer, :pointer ], :int
  attach_function :PKCS7_get_smimecap, [ :pointer ], :pointer
  attach_function :PKCS7_simple_smimecap, [ :pointer, :int, :int ], :int
  attach_function :SMIME_write_PKCS7, [ :pointer, :pointer, :pointer, :int ], :int
  attach_function :SMIME_read_PKCS7, [ :pointer, :pointer ], :pointer
  attach_function :SMIME_crlf_copy, [ :pointer, :pointer, :int ], :int
  attach_function :SMIME_text, [ :pointer, :pointer ], :int
  attach_function :ERR_load_PKCS7_strings, [  ], :void
  PKCS7_F_B64_READ_PKCS7 = 120
  PKCS7_F_B64_WRITE_PKCS7 = 121
  PKCS7_F_PKCS7_ADD_ATTRIB_SMIMECAP = 118
  PKCS7_F_PKCS7_ADD_CERTIFICATE = 100
  PKCS7_F_PKCS7_ADD_CRL = 101
  PKCS7_F_PKCS7_ADD_RECIPIENT_INFO = 102
  PKCS7_F_PKCS7_ADD_SIGNER = 103
  PKCS7_F_PKCS7_BIO_ADD_DIGEST = 125
  PKCS7_F_PKCS7_CTRL = 104
  PKCS7_F_PKCS7_DATADECODE = 112
  PKCS7_F_PKCS7_DATAFINAL = 128
  PKCS7_F_PKCS7_DATAINIT = 105
  PKCS7_F_PKCS7_DATASIGN = 106
  PKCS7_F_PKCS7_DATAVERIFY = 107
  PKCS7_F_PKCS7_DECRYPT = 114
  PKCS7_F_PKCS7_ENCRYPT = 115
  PKCS7_F_PKCS7_FIND_DIGEST = 127
  PKCS7_F_PKCS7_GET0_SIGNERS = 124
  PKCS7_F_PKCS7_SET_CIPHER = 108
  PKCS7_F_PKCS7_SET_CONTENT = 109
  PKCS7_F_PKCS7_SET_DIGEST = 126
  PKCS7_F_PKCS7_SET_TYPE = 110
  PKCS7_F_PKCS7_SIGN = 116
  PKCS7_F_PKCS7_SIGNATUREVERIFY = 113
  PKCS7_F_PKCS7_SIMPLE_SMIMECAP = 119
  PKCS7_F_PKCS7_VERIFY = 117
  PKCS7_F_SMIME_READ_PKCS7 = 122
  PKCS7_F_SMIME_TEXT = 123
  PKCS7_R_CERTIFICATE_VERIFY_ERROR = 117
  PKCS7_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER = 144
  PKCS7_R_CIPHER_NOT_INITIALIZED = 116
  PKCS7_R_CONTENT_AND_DATA_PRESENT = 118
  PKCS7_R_DECODE_ERROR = 130
  PKCS7_R_DECRYPTED_KEY_IS_WRONG_LENGTH = 100
  PKCS7_R_DECRYPT_ERROR = 119
  PKCS7_R_DIGEST_FAILURE = 101
  PKCS7_R_ERROR_ADDING_RECIPIENT = 120
  PKCS7_R_ERROR_SETTING_CIPHER = 121
  PKCS7_R_INVALID_MIME_TYPE = 131
  PKCS7_R_INVALID_NULL_POINTER = 143
  PKCS7_R_MIME_NO_CONTENT_TYPE = 132
  PKCS7_R_MIME_PARSE_ERROR = 133
  PKCS7_R_MIME_SIG_PARSE_ERROR = 134
  PKCS7_R_MISSING_CERIPEND_INFO = 103
  PKCS7_R_NO_CONTENT = 122
  PKCS7_R_NO_CONTENT_TYPE = 135
  PKCS7_R_NO_MULTIPART_BODY_FAILURE = 136
  PKCS7_R_NO_MULTIPART_BOUNDARY = 137
  PKCS7_R_NO_RECIPIENT_MATCHES_CERTIFICATE = 115
  PKCS7_R_NO_RECIPIENT_MATCHES_KEY = 146
  PKCS7_R_NO_SIGNATURES_ON_DATA = 123
  PKCS7_R_NO_SIGNERS = 142
  PKCS7_R_NO_SIG_CONTENT_TYPE = 138
  PKCS7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE = 104
  PKCS7_R_PKCS7_ADD_SIGNATURE_ERROR = 124
  PKCS7_R_PKCS7_DATAFINAL = 126
  PKCS7_R_PKCS7_DATAFINAL_ERROR = 125
  PKCS7_R_PKCS7_DATASIGN = 145
  PKCS7_R_PKCS7_PARSE_ERROR = 139
  PKCS7_R_PKCS7_SIG_PARSE_ERROR = 140
  PKCS7_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE = 127
  PKCS7_R_SIGNATURE_FAILURE = 105
  PKCS7_R_SIGNER_CERTIFICATE_NOT_FOUND = 128
  PKCS7_R_SIG_INVALID_MIME_TYPE = 141
  PKCS7_R_SMIME_TEXT_ERROR = 129
  PKCS7_R_UNABLE_TO_FIND_CERTIFICATE = 106
  PKCS7_R_UNABLE_TO_FIND_MEM_BIO = 107
  PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST = 108
  PKCS7_R_UNKNOWN_DIGEST_TYPE = 109
  PKCS7_R_UNKNOWN_OPERATION = 110
  PKCS7_R_UNSUPPORTED_CIPHER_TYPE = 111
  PKCS7_R_UNSUPPORTED_CONTENT_TYPE = 112
  PKCS7_R_WRONG_CONTENT_TYPE = 113
  PKCS7_R_WRONG_PKCS7_TYPE = 114
  X509_EXT_PACK_UNKNOWN = 1
  X509_EXT_PACK_STRING = 2
  attach_function :X509_verify_cert_error_string, [ :long ], :string
  attach_function :X509_verify, [ :pointer, :pointer ], :int
  attach_function :X509_REQ_verify, [ :pointer, :pointer ], :int
  attach_function :X509_CRL_verify, [ :pointer, :pointer ], :int
  attach_function :NETSCAPE_SPKI_verify, [ :pointer, :pointer ], :int
  attach_function :NETSCAPE_SPKI_b64_decode, [ :string, :int ], :pointer
  attach_function :NETSCAPE_SPKI_b64_encode, [ :pointer ], :string
  attach_function :NETSCAPE_SPKI_get_pubkey, [ :pointer ], :pointer
  attach_function :NETSCAPE_SPKI_set_pubkey, [ :pointer, :pointer ], :int
  attach_function :NETSCAPE_SPKI_print, [ :pointer, :pointer ], :int
  attach_function :X509_signature_print, [ :pointer, :pointer, :pointer ], :int
  attach_function :X509_sign, [ :pointer, :pointer, :pointer ], :int
  attach_function :X509_REQ_sign, [ :pointer, :pointer, :pointer ], :int
  attach_function :X509_CRL_sign, [ :pointer, :pointer, :pointer ], :int
  attach_function :NETSCAPE_SPKI_sign, [ :pointer, :pointer, :pointer ], :int
  attach_function :X509_pubkey_digest, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :X509_digest, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :X509_CRL_digest, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :X509_REQ_digest, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :X509_NAME_digest, [ :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :d2i_X509_fp, [ :pointer, :pointer ], :pointer
  attach_function :i2d_X509_fp, [ :pointer, :pointer ], :int
  attach_function :d2i_X509_CRL_fp, [ :pointer, :pointer ], :pointer
  attach_function :i2d_X509_CRL_fp, [ :pointer, :pointer ], :int
  attach_function :d2i_X509_REQ_fp, [ :pointer, :pointer ], :pointer
  attach_function :i2d_X509_REQ_fp, [ :pointer, :pointer ], :int
  attach_function :d2i_RSAPrivateKey_fp, [ :pointer, :pointer ], :pointer
  attach_function :i2d_RSAPrivateKey_fp, [ :pointer, :pointer ], :int
  attach_function :d2i_RSAPublicKey_fp, [ :pointer, :pointer ], :pointer
  attach_function :i2d_RSAPublicKey_fp, [ :pointer, :pointer ], :int
  attach_function :d2i_RSA_PUBKEY_fp, [ :pointer, :pointer ], :pointer
  attach_function :i2d_RSA_PUBKEY_fp, [ :pointer, :pointer ], :int
  attach_function :d2i_DSA_PUBKEY_fp, [ :pointer, :pointer ], :pointer
  attach_function :i2d_DSA_PUBKEY_fp, [ :pointer, :pointer ], :int
  attach_function :d2i_DSAPrivateKey_fp, [ :pointer, :pointer ], :pointer
  attach_function :i2d_DSAPrivateKey_fp, [ :pointer, :pointer ], :int
  attach_function :d2i_EC_PUBKEY_fp, [ :pointer, :pointer ], :pointer
  attach_function :i2d_EC_PUBKEY_fp, [ :pointer, :pointer ], :int
  attach_function :d2i_ECPrivateKey_fp, [ :pointer, :pointer ], :pointer
  attach_function :i2d_ECPrivateKey_fp, [ :pointer, :pointer ], :int
  attach_function :d2i_PKCS8_fp, [ :pointer, :pointer ], :pointer
  attach_function :i2d_PKCS8_fp, [ :pointer, :pointer ], :int
  attach_function :d2i_PKCS8_PRIV_KEY_INFO_fp, [ :pointer, :pointer ], :pointer
  attach_function :i2d_PKCS8_PRIV_KEY_INFO_fp, [ :pointer, :pointer ], :int
  attach_function :i2d_PKCS8PrivateKeyInfo_fp, [ :pointer, :pointer ], :int
  attach_function :i2d_PrivateKey_fp, [ :pointer, :pointer ], :int
  attach_function :d2i_PrivateKey_fp, [ :pointer, :pointer ], :pointer
  attach_function :i2d_PUBKEY_fp, [ :pointer, :pointer ], :int
  attach_function :d2i_PUBKEY_fp, [ :pointer, :pointer ], :pointer
  attach_function :d2i_X509_bio, [ :pointer, :pointer ], :pointer
  attach_function :i2d_X509_bio, [ :pointer, :pointer ], :int
  attach_function :d2i_X509_CRL_bio, [ :pointer, :pointer ], :pointer
  attach_function :i2d_X509_CRL_bio, [ :pointer, :pointer ], :int
  attach_function :d2i_X509_REQ_bio, [ :pointer, :pointer ], :pointer
  attach_function :i2d_X509_REQ_bio, [ :pointer, :pointer ], :int
  attach_function :d2i_RSAPrivateKey_bio, [ :pointer, :pointer ], :pointer
  attach_function :i2d_RSAPrivateKey_bio, [ :pointer, :pointer ], :int
  attach_function :d2i_RSAPublicKey_bio, [ :pointer, :pointer ], :pointer
  attach_function :i2d_RSAPublicKey_bio, [ :pointer, :pointer ], :int
  attach_function :d2i_RSA_PUBKEY_bio, [ :pointer, :pointer ], :pointer
  attach_function :i2d_RSA_PUBKEY_bio, [ :pointer, :pointer ], :int
  attach_function :d2i_DSA_PUBKEY_bio, [ :pointer, :pointer ], :pointer
  attach_function :i2d_DSA_PUBKEY_bio, [ :pointer, :pointer ], :int
  attach_function :d2i_DSAPrivateKey_bio, [ :pointer, :pointer ], :pointer
  attach_function :i2d_DSAPrivateKey_bio, [ :pointer, :pointer ], :int
  attach_function :d2i_EC_PUBKEY_bio, [ :pointer, :pointer ], :pointer
  attach_function :i2d_EC_PUBKEY_bio, [ :pointer, :pointer ], :int
  attach_function :d2i_ECPrivateKey_bio, [ :pointer, :pointer ], :pointer
  attach_function :i2d_ECPrivateKey_bio, [ :pointer, :pointer ], :int
  attach_function :d2i_PKCS8_bio, [ :pointer, :pointer ], :pointer
  attach_function :i2d_PKCS8_bio, [ :pointer, :pointer ], :int
  attach_function :d2i_PKCS8_PRIV_KEY_INFO_bio, [ :pointer, :pointer ], :pointer
  attach_function :i2d_PKCS8_PRIV_KEY_INFO_bio, [ :pointer, :pointer ], :int
  attach_function :i2d_PKCS8PrivateKeyInfo_bio, [ :pointer, :pointer ], :int
  attach_function :i2d_PrivateKey_bio, [ :pointer, :pointer ], :int
  attach_function :d2i_PrivateKey_bio, [ :pointer, :pointer ], :pointer
  attach_function :i2d_PUBKEY_bio, [ :pointer, :pointer ], :int
  attach_function :d2i_PUBKEY_bio, [ :pointer, :pointer ], :pointer
  attach_function :X509_dup, [ :pointer ], :pointer
  attach_function :X509_ATTRIBUTE_dup, [ :pointer ], :pointer
  attach_function :X509_EXTENSION_dup, [ :pointer ], :pointer
  attach_function :X509_CRL_dup, [ :pointer ], :pointer
  attach_function :X509_REQ_dup, [ :pointer ], :pointer
  attach_function :X509_ALGOR_dup, [ :pointer ], :pointer
  attach_function :X509_ALGOR_set0, [ :pointer, :pointer, :int, :pointer ], :int
  attach_function :X509_ALGOR_get0, [ :pointer, :pointer, :pointer, :pointer ], :void
  attach_function :X509_NAME_dup, [ :pointer ], :pointer
  attach_function :X509_NAME_ENTRY_dup, [ :pointer ], :pointer
  attach_function :X509_cmp_time, [ :pointer, :pointer ], :int
  attach_function :X509_cmp_current_time, [ :pointer ], :int
  attach_function :X509_time_adj, [ :pointer, :long, :pointer ], :pointer
  attach_function :X509_gmtime_adj, [ :pointer, :long ], :pointer
  attach_function :X509_get_default_cert_area, [  ], :string
  attach_function :X509_get_default_cert_dir, [  ], :string
  attach_function :X509_get_default_cert_file, [  ], :string
  attach_function :X509_get_default_cert_dir_env, [  ], :string
  attach_function :X509_get_default_cert_file_env, [  ], :string
  attach_function :X509_get_default_private_dir, [  ], :string
  attach_function :X509_to_X509_REQ, [ :pointer, :pointer, :pointer ], :pointer
  attach_function :X509_REQ_to_X509, [ :pointer, :int, :pointer ], :pointer
  attach_function :X509_ALGOR_new, [  ], :pointer
  attach_function :X509_ALGOR_free, [ :pointer ], :void
  attach_function :d2i_X509_ALGOR, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_X509_ALGOR, [ :pointer, :pointer ], :int
  attach_function :d2i_X509_ALGORS, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_X509_ALGORS, [ :pointer, :pointer ], :int
  attach_function :X509_VAL_new, [  ], :pointer
  attach_function :X509_VAL_free, [ :pointer ], :void
  attach_function :d2i_X509_VAL, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_X509_VAL, [ :pointer, :pointer ], :int
  attach_function :X509_PUBKEY_new, [  ], :pointer
  attach_function :X509_PUBKEY_free, [ :pointer ], :void
  attach_function :d2i_X509_PUBKEY, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_X509_PUBKEY, [ :pointer, :pointer ], :int
  attach_function :X509_PUBKEY_set, [ :pointer, :pointer ], :int
  attach_function :X509_PUBKEY_get, [ :pointer ], :pointer
  attach_function :X509_get_pubkey_parameters, [ :pointer, :pointer ], :int
  attach_function :i2d_PUBKEY, [ :pointer, :pointer ], :int
  attach_function :d2i_PUBKEY, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_RSA_PUBKEY, [ :pointer, :pointer ], :int
  attach_function :d2i_RSA_PUBKEY, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_DSA_PUBKEY, [ :pointer, :pointer ], :int
  attach_function :d2i_DSA_PUBKEY, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_EC_PUBKEY, [ :pointer, :pointer ], :int
  attach_function :d2i_EC_PUBKEY, [ :pointer, :pointer, :long ], :pointer
  attach_function :X509_SIG_new, [  ], :pointer
  attach_function :X509_SIG_free, [ :pointer ], :void
  attach_function :d2i_X509_SIG, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_X509_SIG, [ :pointer, :pointer ], :int
  attach_function :X509_REQ_INFO_new, [  ], :pointer
  attach_function :X509_REQ_INFO_free, [ :pointer ], :void
  attach_function :d2i_X509_REQ_INFO, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_X509_REQ_INFO, [ :pointer, :pointer ], :int
  attach_function :X509_REQ_new, [  ], :pointer
  attach_function :X509_REQ_free, [ :pointer ], :void
  attach_function :d2i_X509_REQ, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_X509_REQ, [ :pointer, :pointer ], :int
  attach_function :X509_ATTRIBUTE_new, [  ], :pointer
  attach_function :X509_ATTRIBUTE_free, [ :pointer ], :void
  attach_function :d2i_X509_ATTRIBUTE, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_X509_ATTRIBUTE, [ :pointer, :pointer ], :int
  attach_function :X509_ATTRIBUTE_create, [ :int, :int, :pointer ], :pointer
  attach_function :X509_EXTENSION_new, [  ], :pointer
  attach_function :X509_EXTENSION_free, [ :pointer ], :void
  attach_function :d2i_X509_EXTENSION, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_X509_EXTENSION, [ :pointer, :pointer ], :int
  attach_function :d2i_X509_EXTENSIONS, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_X509_EXTENSIONS, [ :pointer, :pointer ], :int
  attach_function :X509_NAME_ENTRY_new, [  ], :pointer
  attach_function :X509_NAME_ENTRY_free, [ :pointer ], :void
  attach_function :d2i_X509_NAME_ENTRY, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_X509_NAME_ENTRY, [ :pointer, :pointer ], :int
  attach_function :X509_NAME_new, [  ], :pointer
  attach_function :X509_NAME_free, [ :pointer ], :void
  attach_function :d2i_X509_NAME, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_X509_NAME, [ :pointer, :pointer ], :int
  attach_function :X509_NAME_set, [ :pointer, :pointer ], :int
  attach_function :X509_CINF_new, [  ], :pointer
  attach_function :X509_CINF_free, [ :pointer ], :void
  attach_function :d2i_X509_CINF, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_X509_CINF, [ :pointer, :pointer ], :int
  attach_function :X509_new, [  ], :pointer
  attach_function :X509_free, [ :pointer ], :void
  attach_function :d2i_X509, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_X509, [ :pointer, :pointer ], :int
  attach_function :X509_CERT_AUX_new, [  ], :pointer
  attach_function :X509_CERT_AUX_free, [ :pointer ], :void
  attach_function :d2i_X509_CERT_AUX, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_X509_CERT_AUX, [ :pointer, :pointer ], :int
  attach_function :X509_CERT_PAIR_new, [  ], :pointer
  attach_function :X509_CERT_PAIR_free, [ :pointer ], :void
  attach_function :d2i_X509_CERT_PAIR, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_X509_CERT_PAIR, [ :pointer, :pointer ], :int
  attach_function :X509_get_ex_new_index, [ :long, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :X509_set_ex_data, [ :pointer, :int, :pointer ], :int
  attach_function :X509_get_ex_data, [ :pointer, :int ], :pointer
  attach_function :i2d_X509_AUX, [ :pointer, :pointer ], :int
  attach_function :d2i_X509_AUX, [ :pointer, :pointer, :long ], :pointer
  attach_function :X509_alias_set1, [ :pointer, :pointer, :int ], :int
  attach_function :X509_keyid_set1, [ :pointer, :pointer, :int ], :int
  attach_function :X509_alias_get0, [ :pointer, :pointer ], :pointer
  attach_function :X509_keyid_get0, [ :pointer, :pointer ], :pointer
  attach_function :X509_TRUST_set_default, [ callback([ :int, :pointer, :int ], :int) ], :pointer
  attach_function :X509_TRUST_set, [ :pointer, :int ], :int
  attach_function :X509_add1_trust_object, [ :pointer, :pointer ], :int
  attach_function :X509_add1_reject_object, [ :pointer, :pointer ], :int
  attach_function :X509_trust_clear, [ :pointer ], :void
  attach_function :X509_reject_clear, [ :pointer ], :void
  attach_function :X509_REVOKED_new, [  ], :pointer
  attach_function :X509_REVOKED_free, [ :pointer ], :void
  attach_function :d2i_X509_REVOKED, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_X509_REVOKED, [ :pointer, :pointer ], :int
  attach_function :X509_CRL_INFO_new, [  ], :pointer
  attach_function :X509_CRL_INFO_free, [ :pointer ], :void
  attach_function :d2i_X509_CRL_INFO, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_X509_CRL_INFO, [ :pointer, :pointer ], :int
  attach_function :X509_CRL_new, [  ], :pointer
  attach_function :X509_CRL_free, [ :pointer ], :void
  attach_function :d2i_X509_CRL, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_X509_CRL, [ :pointer, :pointer ], :int
  attach_function :X509_CRL_add0_revoked, [ :pointer, :pointer ], :int
  attach_function :X509_PKEY_new, [  ], :pointer
  attach_function :X509_PKEY_free, [ :pointer ], :void
  attach_function :i2d_X509_PKEY, [ :pointer, :pointer ], :int
  attach_function :d2i_X509_PKEY, [ :pointer, :pointer, :long ], :pointer
  attach_function :NETSCAPE_SPKI_new, [  ], :pointer
  attach_function :NETSCAPE_SPKI_free, [ :pointer ], :void
  attach_function :d2i_NETSCAPE_SPKI, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_NETSCAPE_SPKI, [ :pointer, :pointer ], :int
  attach_function :NETSCAPE_SPKAC_new, [  ], :pointer
  attach_function :NETSCAPE_SPKAC_free, [ :pointer ], :void
  attach_function :d2i_NETSCAPE_SPKAC, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_NETSCAPE_SPKAC, [ :pointer, :pointer ], :int
  attach_function :NETSCAPE_CERT_SEQUENCE_new, [  ], :pointer
  attach_function :NETSCAPE_CERT_SEQUENCE_free, [ :pointer ], :void
  attach_function :d2i_NETSCAPE_CERT_SEQUENCE, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_NETSCAPE_CERT_SEQUENCE, [ :pointer, :pointer ], :int
  attach_function :X509_INFO_new, [  ], :pointer
  attach_function :X509_INFO_free, [ :pointer ], :void
  attach_function :X509_NAME_oneline, [ :pointer, :string, :int ], :string
  attach_function :ASN1_verify, [ :pointer, :pointer, :pointer, :string, :pointer ], :int
  attach_function :ASN1_digest, [ :pointer, :pointer, :string, :pointer, :pointer ], :int
  attach_function :ASN1_sign, [ :pointer, :pointer, :pointer, :pointer, :string, :pointer, :pointer ], :int
  attach_function :ASN1_item_digest, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :ASN1_item_verify, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :ASN1_item_sign, [ :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :X509_set_version, [ :pointer, :long ], :int
  attach_function :X509_set_serialNumber, [ :pointer, :pointer ], :int
  attach_function :X509_get_serialNumber, [ :pointer ], :pointer
  attach_function :X509_set_issuer_name, [ :pointer, :pointer ], :int
  attach_function :X509_get_issuer_name, [ :pointer ], :pointer
  attach_function :X509_set_subject_name, [ :pointer, :pointer ], :int
  attach_function :X509_get_subject_name, [ :pointer ], :pointer
  attach_function :X509_set_notBefore, [ :pointer, :pointer ], :int
  attach_function :X509_set_notAfter, [ :pointer, :pointer ], :int
  attach_function :X509_set_pubkey, [ :pointer, :pointer ], :int
  attach_function :X509_get_pubkey, [ :pointer ], :pointer
  attach_function :X509_get0_pubkey_bitstr, [ :pointer ], :pointer
  attach_function :X509_certificate_type, [ :pointer, :pointer ], :int
  attach_function :X509_REQ_set_version, [ :pointer, :long ], :int
  attach_function :X509_REQ_set_subject_name, [ :pointer, :pointer ], :int
  attach_function :X509_REQ_set_pubkey, [ :pointer, :pointer ], :int
  attach_function :X509_REQ_get_pubkey, [ :pointer ], :pointer
  attach_function :X509_REQ_extension_nid, [ :int ], :int
  attach_function :X509_REQ_get_extension_nids, [  ], :pointer
  attach_function :X509_REQ_set_extension_nids, [ :pointer ], :void
  attach_function :X509_REQ_get_extensions, [ :pointer ], :pointer
  attach_function :X509_REQ_add_extensions_nid, [ :pointer, :pointer, :int ], :int
  attach_function :X509_REQ_add_extensions, [ :pointer, :pointer ], :int
  attach_function :X509_REQ_get_attr_count, [ :pointer ], :int
  attach_function :X509_REQ_get_attr_by_NID, [ :pointer, :int, :int ], :int
  attach_function :X509_REQ_get_attr_by_OBJ, [ :pointer, :pointer, :int ], :int
  attach_function :X509_REQ_get_attr, [ :pointer, :int ], :pointer
  attach_function :X509_REQ_delete_attr, [ :pointer, :int ], :pointer
  attach_function :X509_REQ_add1_attr, [ :pointer, :pointer ], :int
  attach_function :X509_REQ_add1_attr_by_OBJ, [ :pointer, :pointer, :int, :pointer, :int ], :int
  attach_function :X509_REQ_add1_attr_by_NID, [ :pointer, :int, :int, :pointer, :int ], :int
  attach_function :X509_REQ_add1_attr_by_txt, [ :pointer, :string, :int, :pointer, :int ], :int
  attach_function :X509_CRL_set_version, [ :pointer, :long ], :int
  attach_function :X509_CRL_set_issuer_name, [ :pointer, :pointer ], :int
  attach_function :X509_CRL_set_lastUpdate, [ :pointer, :pointer ], :int
  attach_function :X509_CRL_set_nextUpdate, [ :pointer, :pointer ], :int
  attach_function :X509_CRL_sort, [ :pointer ], :int
  attach_function :X509_REVOKED_set_serialNumber, [ :pointer, :pointer ], :int
  attach_function :X509_REVOKED_set_revocationDate, [ :pointer, :pointer ], :int
  attach_function :X509_REQ_check_private_key, [ :pointer, :pointer ], :int
  attach_function :X509_check_private_key, [ :pointer, :pointer ], :int
  attach_function :X509_issuer_and_serial_cmp, [ :pointer, :pointer ], :int
  attach_function :X509_issuer_and_serial_hash, [ :pointer ], :ulong
  attach_function :X509_issuer_name_cmp, [ :pointer, :pointer ], :int
  attach_function :X509_issuer_name_hash, [ :pointer ], :ulong
  attach_function :X509_subject_name_cmp, [ :pointer, :pointer ], :int
  attach_function :X509_subject_name_hash, [ :pointer ], :ulong
  attach_function :X509_cmp, [ :pointer, :pointer ], :int
  attach_function :X509_NAME_cmp, [ :pointer, :pointer ], :int
  attach_function :X509_NAME_hash, [ :pointer ], :ulong
  attach_function :X509_CRL_cmp, [ :pointer, :pointer ], :int
  attach_function :X509_print_ex_fp, [ :pointer, :pointer, :ulong, :ulong ], :int
  attach_function :X509_print_fp, [ :pointer, :pointer ], :int
  attach_function :X509_CRL_print_fp, [ :pointer, :pointer ], :int
  attach_function :X509_REQ_print_fp, [ :pointer, :pointer ], :int
  attach_function :X509_NAME_print_ex_fp, [ :pointer, :pointer, :int, :ulong ], :int
  attach_function :X509_NAME_print, [ :pointer, :pointer, :int ], :int
  attach_function :X509_NAME_print_ex, [ :pointer, :pointer, :int, :ulong ], :int
  attach_function :X509_print_ex, [ :pointer, :pointer, :ulong, :ulong ], :int
  attach_function :X509_print, [ :pointer, :pointer ], :int
  attach_function :X509_ocspid_print, [ :pointer, :pointer ], :int
  attach_function :X509_CERT_AUX_print, [ :pointer, :pointer, :int ], :int
  attach_function :X509_CRL_print, [ :pointer, :pointer ], :int
  attach_function :X509_REQ_print_ex, [ :pointer, :pointer, :ulong, :ulong ], :int
  attach_function :X509_REQ_print, [ :pointer, :pointer ], :int
  attach_function :X509_NAME_entry_count, [ :pointer ], :int
  attach_function :X509_NAME_get_text_by_NID, [ :pointer, :int, :string, :int ], :int
  attach_function :X509_NAME_get_text_by_OBJ, [ :pointer, :pointer, :string, :int ], :int
  attach_function :X509_NAME_get_index_by_NID, [ :pointer, :int, :int ], :int
  attach_function :X509_NAME_get_index_by_OBJ, [ :pointer, :pointer, :int ], :int
  attach_function :X509_NAME_get_entry, [ :pointer, :int ], :pointer
  attach_function :X509_NAME_delete_entry, [ :pointer, :int ], :pointer
  attach_function :X509_NAME_add_entry, [ :pointer, :pointer, :int, :int ], :int
  attach_function :X509_NAME_add_entry_by_OBJ, [ :pointer, :pointer, :int, :pointer, :int, :int, :int ], :int
  attach_function :X509_NAME_add_entry_by_NID, [ :pointer, :int, :int, :pointer, :int, :int, :int ], :int
  attach_function :X509_NAME_ENTRY_create_by_txt, [ :pointer, :string, :int, :pointer, :int ], :pointer
  attach_function :X509_NAME_ENTRY_create_by_NID, [ :pointer, :int, :int, :pointer, :int ], :pointer
  attach_function :X509_NAME_add_entry_by_txt, [ :pointer, :string, :int, :pointer, :int, :int, :int ], :int
  attach_function :X509_NAME_ENTRY_create_by_OBJ, [ :pointer, :pointer, :int, :pointer, :int ], :pointer
  attach_function :X509_NAME_ENTRY_set_object, [ :pointer, :pointer ], :int
  attach_function :X509_NAME_ENTRY_set_data, [ :pointer, :int, :pointer, :int ], :int
  attach_function :X509_NAME_ENTRY_get_object, [ :pointer ], :pointer
  attach_function :X509_NAME_ENTRY_get_data, [ :pointer ], :pointer
  attach_function :X509v3_get_ext_count, [ :pointer ], :int
  attach_function :X509v3_get_ext_by_NID, [ :pointer, :int, :int ], :int
  attach_function :X509v3_get_ext_by_OBJ, [ :pointer, :pointer, :int ], :int
  attach_function :X509v3_get_ext_by_critical, [ :pointer, :int, :int ], :int
  attach_function :X509v3_get_ext, [ :pointer, :int ], :pointer
  attach_function :X509v3_delete_ext, [ :pointer, :int ], :pointer
  attach_function :X509v3_add_ext, [ :pointer, :pointer, :int ], :pointer
  attach_function :X509_get_ext_count, [ :pointer ], :int
  attach_function :X509_get_ext_by_NID, [ :pointer, :int, :int ], :int
  attach_function :X509_get_ext_by_OBJ, [ :pointer, :pointer, :int ], :int
  attach_function :X509_get_ext_by_critical, [ :pointer, :int, :int ], :int
  attach_function :X509_get_ext, [ :pointer, :int ], :pointer
  attach_function :X509_delete_ext, [ :pointer, :int ], :pointer
  attach_function :X509_add_ext, [ :pointer, :pointer, :int ], :int
  attach_function :X509_get_ext_d2i, [ :pointer, :int, :pointer, :pointer ], :pointer
  attach_function :X509_add1_ext_i2d, [ :pointer, :int, :pointer, :int, :ulong ], :int
  attach_function :X509_CRL_get_ext_count, [ :pointer ], :int
  attach_function :X509_CRL_get_ext_by_NID, [ :pointer, :int, :int ], :int
  attach_function :X509_CRL_get_ext_by_OBJ, [ :pointer, :pointer, :int ], :int
  attach_function :X509_CRL_get_ext_by_critical, [ :pointer, :int, :int ], :int
  attach_function :X509_CRL_get_ext, [ :pointer, :int ], :pointer
  attach_function :X509_CRL_delete_ext, [ :pointer, :int ], :pointer
  attach_function :X509_CRL_add_ext, [ :pointer, :pointer, :int ], :int
  attach_function :X509_CRL_get_ext_d2i, [ :pointer, :int, :pointer, :pointer ], :pointer
  attach_function :X509_CRL_add1_ext_i2d, [ :pointer, :int, :pointer, :int, :ulong ], :int
  attach_function :X509_REVOKED_get_ext_count, [ :pointer ], :int
  attach_function :X509_REVOKED_get_ext_by_NID, [ :pointer, :int, :int ], :int
  attach_function :X509_REVOKED_get_ext_by_OBJ, [ :pointer, :pointer, :int ], :int
  attach_function :X509_REVOKED_get_ext_by_critical, [ :pointer, :int, :int ], :int
  attach_function :X509_REVOKED_get_ext, [ :pointer, :int ], :pointer
  attach_function :X509_REVOKED_delete_ext, [ :pointer, :int ], :pointer
  attach_function :X509_REVOKED_add_ext, [ :pointer, :pointer, :int ], :int
  attach_function :X509_REVOKED_get_ext_d2i, [ :pointer, :int, :pointer, :pointer ], :pointer
  attach_function :X509_REVOKED_add1_ext_i2d, [ :pointer, :int, :pointer, :int, :ulong ], :int
  attach_function :X509_EXTENSION_create_by_NID, [ :pointer, :int, :int, :pointer ], :pointer
  attach_function :X509_EXTENSION_create_by_OBJ, [ :pointer, :pointer, :int, :pointer ], :pointer
  attach_function :X509_EXTENSION_set_object, [ :pointer, :pointer ], :int
  attach_function :X509_EXTENSION_set_critical, [ :pointer, :int ], :int
  attach_function :X509_EXTENSION_set_data, [ :pointer, :pointer ], :int
  attach_function :X509_EXTENSION_get_object, [ :pointer ], :pointer
  attach_function :X509_EXTENSION_get_data, [ :pointer ], :pointer
  attach_function :X509_EXTENSION_get_critical, [ :pointer ], :int
  attach_function :X509at_get_attr_count, [ :pointer ], :int
  attach_function :X509at_get_attr_by_NID, [ :pointer, :int, :int ], :int
  attach_function :X509at_get_attr_by_OBJ, [ :pointer, :pointer, :int ], :int
  attach_function :X509at_get_attr, [ :pointer, :int ], :pointer
  attach_function :X509at_delete_attr, [ :pointer, :int ], :pointer
  attach_function :X509at_add1_attr, [ :pointer, :pointer ], :pointer
  attach_function :X509at_add1_attr_by_OBJ, [ :pointer, :pointer, :int, :pointer, :int ], :pointer
  attach_function :X509at_add1_attr_by_NID, [ :pointer, :int, :int, :pointer, :int ], :pointer
  attach_function :X509at_add1_attr_by_txt, [ :pointer, :string, :int, :pointer, :int ], :pointer
  attach_function :X509at_get0_data_by_OBJ, [ :pointer, :pointer, :int, :int ], :pointer
  attach_function :X509_ATTRIBUTE_create_by_NID, [ :pointer, :int, :int, :pointer, :int ], :pointer
  attach_function :X509_ATTRIBUTE_create_by_OBJ, [ :pointer, :pointer, :int, :pointer, :int ], :pointer
  attach_function :X509_ATTRIBUTE_create_by_txt, [ :pointer, :string, :int, :pointer, :int ], :pointer
  attach_function :X509_ATTRIBUTE_set1_object, [ :pointer, :pointer ], :int
  attach_function :X509_ATTRIBUTE_set1_data, [ :pointer, :int, :pointer, :int ], :int
  attach_function :X509_ATTRIBUTE_get0_data, [ :pointer, :int, :int, :pointer ], :pointer
  attach_function :X509_ATTRIBUTE_count, [ :pointer ], :int
  attach_function :X509_ATTRIBUTE_get0_object, [ :pointer ], :pointer
  attach_function :X509_ATTRIBUTE_get0_type, [ :pointer, :int ], :pointer
  attach_function :EVP_PKEY_get_attr_count, [ :pointer ], :int
  attach_function :EVP_PKEY_get_attr_by_NID, [ :pointer, :int, :int ], :int
  attach_function :EVP_PKEY_get_attr_by_OBJ, [ :pointer, :pointer, :int ], :int
  attach_function :EVP_PKEY_get_attr, [ :pointer, :int ], :pointer
  attach_function :EVP_PKEY_delete_attr, [ :pointer, :int ], :pointer
  attach_function :EVP_PKEY_add1_attr, [ :pointer, :pointer ], :int
  attach_function :EVP_PKEY_add1_attr_by_OBJ, [ :pointer, :pointer, :int, :pointer, :int ], :int
  attach_function :EVP_PKEY_add1_attr_by_NID, [ :pointer, :int, :int, :pointer, :int ], :int
  attach_function :EVP_PKEY_add1_attr_by_txt, [ :pointer, :string, :int, :pointer, :int ], :int
  attach_function :X509_verify_cert, [ :pointer ], :int
  attach_function :X509_find_by_issuer_and_serial, [ :pointer, :pointer, :pointer ], :pointer
  attach_function :X509_find_by_subject, [ :pointer, :pointer ], :pointer
  attach_function :PBEPARAM_new, [  ], :pointer
  attach_function :PBEPARAM_free, [ :pointer ], :void
  attach_function :d2i_PBEPARAM, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_PBEPARAM, [ :pointer, :pointer ], :int
  attach_function :PBE2PARAM_new, [  ], :pointer
  attach_function :PBE2PARAM_free, [ :pointer ], :void
  attach_function :d2i_PBE2PARAM, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_PBE2PARAM, [ :pointer, :pointer ], :int
  attach_function :PBKDF2PARAM_new, [  ], :pointer
  attach_function :PBKDF2PARAM_free, [ :pointer ], :void
  attach_function :d2i_PBKDF2PARAM, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_PBKDF2PARAM, [ :pointer, :pointer ], :int
  attach_function :PKCS5_pbe_set, [ :int, :int, :pointer, :int ], :pointer
  attach_function :PKCS5_pbe2_set, [ :pointer, :int, :pointer, :int ], :pointer
  attach_function :PKCS8_PRIV_KEY_INFO_new, [  ], :pointer
  attach_function :PKCS8_PRIV_KEY_INFO_free, [ :pointer ], :void
  attach_function :d2i_PKCS8_PRIV_KEY_INFO, [ :pointer, :pointer, :long ], :pointer
  attach_function :i2d_PKCS8_PRIV_KEY_INFO, [ :pointer, :pointer ], :int
  attach_function :EVP_PKCS82PKEY, [ :pointer ], :pointer
  attach_function :EVP_PKEY2PKCS8, [ :pointer ], :pointer
  attach_function :EVP_PKEY2PKCS8_broken, [ :pointer, :int ], :pointer
  attach_function :PKCS8_set_broken, [ :pointer, :int ], :pointer
  attach_function :X509_check_trust, [ :pointer, :int, :int ], :int
  attach_function :X509_TRUST_get_count, [  ], :int
  attach_function :X509_TRUST_get0, [ :int ], :pointer
  attach_function :X509_TRUST_get_by_id, [ :int ], :int
  attach_function :X509_TRUST_add, [ :int, :int, callback([ :pointer, :pointer, :int ], :int), :string, :int, :pointer ], :int
  attach_function :X509_TRUST_cleanup, [  ], :void
  attach_function :X509_TRUST_get_flags, [ :pointer ], :int
  attach_function :X509_TRUST_get0_name, [ :pointer ], :string
  attach_function :X509_TRUST_get_trust, [ :pointer ], :int
  attach_function :ERR_load_X509_strings, [  ], :void
  X509_F_ADD_CERT_DIR = 100
  X509_F_BY_FILE_CTRL = 101
  X509_F_CHECK_POLICY = 145
  X509_F_DIR_CTRL = 102
  X509_F_GET_CERT_BY_SUBJECT = 103
  X509_F_NETSCAPE_SPKI_B64_DECODE = 129
  X509_F_NETSCAPE_SPKI_B64_ENCODE = 130
  X509_F_X509AT_ADD1_ATTR = 135
  X509_F_X509V3_ADD_EXT = 104
  X509_F_X509_ATTRIBUTE_CREATE_BY_NID = 136
  X509_F_X509_ATTRIBUTE_CREATE_BY_OBJ = 137
  X509_F_X509_ATTRIBUTE_CREATE_BY_TXT = 140
  X509_F_X509_ATTRIBUTE_GET0_DATA = 139
  X509_F_X509_ATTRIBUTE_SET1_DATA = 138
  X509_F_X509_CHECK_PRIVATE_KEY = 128
  X509_F_X509_CRL_PRINT_FP = 147
  X509_F_X509_EXTENSION_CREATE_BY_NID = 108
  X509_F_X509_EXTENSION_CREATE_BY_OBJ = 109
  X509_F_X509_GET_PUBKEY_PARAMETERS = 110
  X509_F_X509_LOAD_CERT_CRL_FILE = 132
  X509_F_X509_LOAD_CERT_FILE = 111
  X509_F_X509_LOAD_CRL_FILE = 112
  X509_F_X509_NAME_ADD_ENTRY = 113
  X509_F_X509_NAME_ENTRY_CREATE_BY_NID = 114
  X509_F_X509_NAME_ENTRY_CREATE_BY_TXT = 131
  X509_F_X509_NAME_ENTRY_SET_OBJECT = 115
  X509_F_X509_NAME_ONELINE = 116
  X509_F_X509_NAME_PRINT = 117
  X509_F_X509_PRINT_EX_FP = 118
  X509_F_X509_PUBKEY_GET = 119
  X509_F_X509_PUBKEY_SET = 120
  X509_F_X509_REQ_CHECK_PRIVATE_KEY = 144
  X509_F_X509_REQ_PRINT_EX = 121
  X509_F_X509_REQ_PRINT_FP = 122
  X509_F_X509_REQ_TO_X509 = 123
  X509_F_X509_STORE_ADD_CERT = 124
  X509_F_X509_STORE_ADD_CRL = 125
  X509_F_X509_STORE_CTX_GET1_ISSUER = 146
  X509_F_X509_STORE_CTX_INIT = 143
  X509_F_X509_STORE_CTX_NEW = 142
  X509_F_X509_STORE_CTX_PURPOSE_INHERIT = 134
  X509_F_X509_TO_X509_REQ = 126
  X509_F_X509_TRUST_ADD = 133
  X509_F_X509_TRUST_SET = 141
  X509_F_X509_VERIFY_CERT = 127
  X509_R_BAD_X509_FILETYPE = 100
  X509_R_BASE64_DECODE_ERROR = 118
  X509_R_CANT_CHECK_DH_KEY = 114
  X509_R_CERT_ALREADY_IN_HASH_TABLE = 101
  X509_R_ERR_ASN1_LIB = 102
  X509_R_INVALID_DIRECTORY = 113
  X509_R_INVALID_FIELD_NAME = 119
  X509_R_INVALID_TRUST = 123
  X509_R_KEY_TYPE_MISMATCH = 115
  X509_R_KEY_VALUES_MISMATCH = 116
  X509_R_LOADING_CERT_DIR = 103
  X509_R_LOADING_DEFAULTS = 104
  X509_R_NO_CERT_SET_FOR_US_TO_VERIFY = 105
  X509_R_SHOULD_RETRY = 106
  X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN = 107
  X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY = 108
  X509_R_UNKNOWN_KEY_TYPE = 117
  X509_R_UNKNOWN_NID = 109
  X509_R_UNKNOWN_PURPOSE_ID = 121
  X509_R_UNKNOWN_TRUST_ID = 120
  X509_R_UNSUPPORTED_ALGORITHM = 111
  X509_R_WRONG_LOOKUP_TYPE = 112
  X509_R_WRONG_TYPE = 122
  attach_function :STORE_new_method, [ :pointer ], :pointer
  attach_function :STORE_new_engine, [ :pointer ], :pointer
  attach_function :STORE_free, [ :pointer ], :void
  attach_function :STORE_ctrl, [ :pointer, :int, :long, :pointer, callback([  ], :void) ], :int
  STORE_CTRL_SET_DIRECTORY = 0x0001
  STORE_CTRL_SET_FILE = 0x0002
  STORE_CTRL_SET_CONF_FILE = 0x0003
  STORE_CTRL_SET_CONF_SECTION = 0x0004
  attach_function :STORE_get_ex_new_index, [ :long, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :STORE_set_ex_data, [ :pointer, :int, :pointer ], :int
  attach_function :STORE_get_ex_data, [ :pointer, :int ], :pointer
  attach_function :STORE_get_method, [ :pointer ], :pointer
  attach_function :STORE_set_method, [ :pointer, :pointer ], :pointer
  attach_function :STORE_Memory, [  ], :pointer
  STORE_OBJECT_TYPE_X509_CERTIFICATE = 0x01
  STORE_OBJECT_TYPE_X509_CRL = 0x02
  STORE_OBJECT_TYPE_PRIVATE_KEY = 0x03
  STORE_OBJECT_TYPE_PUBLIC_KEY = 0x04
  STORE_OBJECT_TYPE_NUMBER = 0x05
  STORE_OBJECT_TYPE_ARBITRARY = 0x06
  STORE_OBJECT_TYPE_NUM = 0x06

  STORE_PARAM_EVP_TYPE = 0x01
  STORE_PARAM_BITS = 0x02
  STORE_PARAM_KEY_PARAMETERS = 0x03
  STORE_PARAM_KEY_NO_PARAMETERS = 0x04
  STORE_PARAM_AUTH_PASSPHRASE = 0x05
  STORE_PARAM_TYPE_NUM = 0x06
  STORE_PARAM_AUTH_KRB5_TICKET = 0x06

  STORE_ATTR_END = 0x00
  STORE_ATTR_FRIENDLYNAME = 0x01
  STORE_ATTR_KEYID = 0x02
  STORE_ATTR_ISSUERKEYID = 0x03
  STORE_ATTR_SUBJECTKEYID = 0x04
  STORE_ATTR_ISSUERSERIALHASH = 0x05
  STORE_ATTR_ISSUER = 0x06
  STORE_ATTR_SERIAL = 0x07
  STORE_ATTR_SUBJECT = 0x08
  STORE_ATTR_CERTHASH = 0x09
  STORE_ATTR_EMAIL = 0x0a
  STORE_ATTR_FILENAME = 0x0b
  STORE_ATTR_TYPE_NUM = 0x0b
  STORE_ATTR_OR = 0xff

  STORE_X509_VALID = 0x00
  STORE_X509_EXPIRED = 0x01
  STORE_X509_SUSPENDED = 0x02
  STORE_X509_REVOKED = 0x03

  class STOREOBJECTSt < FFI::Struct
    layout(
           :type, :int,
           :data, STOREOBJECTData
    )
  end
  attach_function :STORE_OBJECT_new, [  ], :pointer
  attach_function :STORE_OBJECT_free, [ :pointer ], :void
  attach_function :STORE_get_certificate, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :pointer
  attach_function :STORE_store_certificate, [ :pointer, :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int
  attach_function :STORE_modify_certificate, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM, a().OPENSSL_ITEM, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int
  attach_function :STORE_revoke_certificate, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int
  attach_function :STORE_delete_certificate, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int
  attach_function :STORE_list_certificate_start, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :pointer
  attach_function :STORE_list_certificate_next, [ :pointer, :pointer ], :pointer
  attach_function :STORE_list_certificate_end, [ :pointer, :pointer ], :int
  attach_function :STORE_list_certificate_endp, [ :pointer, :pointer ], :int
  attach_function :STORE_generate_key, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :pointer
  attach_function :STORE_get_private_key, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :pointer
  attach_function :STORE_store_private_key, [ :pointer, :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int
  attach_function :STORE_modify_private_key, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM, a().OPENSSL_ITEM, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int
  attach_function :STORE_revoke_private_key, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int
  attach_function :STORE_delete_private_key, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int
  attach_function :STORE_list_private_key_start, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :pointer
  attach_function :STORE_list_private_key_next, [ :pointer, :pointer ], :pointer
  attach_function :STORE_list_private_key_end, [ :pointer, :pointer ], :int
  attach_function :STORE_list_private_key_endp, [ :pointer, :pointer ], :int
  attach_function :STORE_get_public_key, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :pointer
  attach_function :STORE_store_public_key, [ :pointer, :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int
  attach_function :STORE_modify_public_key, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM, a().OPENSSL_ITEM, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int
  attach_function :STORE_revoke_public_key, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int
  attach_function :STORE_delete_public_key, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int
  attach_function :STORE_list_public_key_start, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :pointer
  attach_function :STORE_list_public_key_next, [ :pointer, :pointer ], :pointer
  attach_function :STORE_list_public_key_end, [ :pointer, :pointer ], :int
  attach_function :STORE_list_public_key_endp, [ :pointer, :pointer ], :int
  attach_function :STORE_generate_crl, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :pointer
  attach_function :STORE_get_crl, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :pointer
  attach_function :STORE_store_crl, [ :pointer, :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int
  attach_function :STORE_modify_crl, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM, a().OPENSSL_ITEM, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int
  attach_function :STORE_delete_crl, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int
  attach_function :STORE_list_crl_start, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :pointer
  attach_function :STORE_list_crl_next, [ :pointer, :pointer ], :pointer
  attach_function :STORE_list_crl_end, [ :pointer, :pointer ], :int
  attach_function :STORE_list_crl_endp, [ :pointer, :pointer ], :int
  attach_function :STORE_store_number, [ :pointer, :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int
  attach_function :STORE_modify_number, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM, a().OPENSSL_ITEM, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int
  attach_function :STORE_get_number, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :pointer
  attach_function :STORE_delete_number, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int
  attach_function :STORE_store_arbitrary, [ :pointer, :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int
  attach_function :STORE_modify_arbitrary, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM, a().OPENSSL_ITEM, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int
  attach_function :STORE_get_arbitrary, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :pointer
  attach_function :STORE_delete_arbitrary, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int
  attach_function :STORE_create_method, [ :string ], :pointer
  attach_function :STORE_destroy_method, [ :pointer ], :void
  callback(:STORE_INITIALISE_FUNC_PTR, [ :pointer ], :int)
  callback(:STORE_CLEANUP_FUNC_PTR, [ :pointer ], :void)
  callback(:STORE_GENERATE_OBJECT_FUNC_PTR, [ :pointer, :int, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :pointer)
  callback(:STORE_GET_OBJECT_FUNC_PTR, [ :pointer, :int, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :pointer)
  callback(:STORE_START_OBJECT_FUNC_PTR, [ :pointer, :int, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :pointer)
  callback(:STORE_NEXT_OBJECT_FUNC_PTR, [ :pointer, :pointer ], :pointer)
  callback(:STORE_END_OBJECT_FUNC_PTR, [ :pointer, :pointer ], :int)
  callback(:STORE_HANDLE_OBJECT_FUNC_PTR, [ :pointer, :int, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int)
  callback(:STORE_STORE_OBJECT_FUNC_PTR, [ :pointer, :int, :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int)
  callback(:STORE_MODIFY_OBJECT_FUNC_PTR, [ :pointer, :int, a().OPENSSL_ITEM, a().OPENSSL_ITEM, a().OPENSSL_ITEM, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int)
  callback(:STORE_GENERIC_FUNC_PTR, [ :pointer, a().OPENSSL_ITEM, a().OPENSSL_ITEM ], :int)
  callback(:STORE_CTRL_FUNC_PTR, [ :pointer, :int, :long, :pointer, callback([  ], :void) ], :int)
  attach_function :STORE_method_set_initialise_function, [ :pointer, :STORE_INITIALISE_FUNC_PTR ], :int
  attach_function :STORE_method_set_cleanup_function, [ :pointer, :STORE_CLEANUP_FUNC_PTR ], :int
  attach_function :STORE_method_set_generate_function, [ :pointer, :STORE_GENERATE_OBJECT_FUNC_PTR ], :int
  attach_function :STORE_method_set_get_function, [ :pointer, :STORE_GET_OBJECT_FUNC_PTR ], :int
  attach_function :STORE_method_set_store_function, [ :pointer, :STORE_STORE_OBJECT_FUNC_PTR ], :int
  attach_function :STORE_method_set_modify_function, [ :pointer, :STORE_MODIFY_OBJECT_FUNC_PTR ], :int
  attach_function :STORE_method_set_revoke_function, [ :pointer, :STORE_HANDLE_OBJECT_FUNC_PTR ], :int
  attach_function :STORE_method_set_delete_function, [ :pointer, :STORE_HANDLE_OBJECT_FUNC_PTR ], :int
  attach_function :STORE_method_set_list_start_function, [ :pointer, :STORE_START_OBJECT_FUNC_PTR ], :int
  attach_function :STORE_method_set_list_next_function, [ :pointer, :STORE_NEXT_OBJECT_FUNC_PTR ], :int
  attach_function :STORE_method_set_list_end_function, [ :pointer, :STORE_END_OBJECT_FUNC_PTR ], :int
  attach_function :STORE_method_set_update_store_function, [ :pointer, :STORE_GENERIC_FUNC_PTR ], :int
  attach_function :STORE_method_set_lock_store_function, [ :pointer, :STORE_GENERIC_FUNC_PTR ], :int
  attach_function :STORE_method_set_unlock_store_function, [ :pointer, :STORE_GENERIC_FUNC_PTR ], :int
  attach_function :STORE_method_set_ctrl_function, [ :pointer, :STORE_CTRL_FUNC_PTR ], :int
  attach_function :STORE_method_get_initialise_function, [ :pointer ], :STORE_INITIALISE_FUNC_PTR
  attach_function :STORE_method_get_cleanup_function, [ :pointer ], :STORE_CLEANUP_FUNC_PTR
  attach_function :STORE_method_get_generate_function, [ :pointer ], :STORE_GENERATE_OBJECT_FUNC_PTR
  attach_function :STORE_method_get_get_function, [ :pointer ], :STORE_GET_OBJECT_FUNC_PTR
  attach_function :STORE_method_get_store_function, [ :pointer ], :STORE_STORE_OBJECT_FUNC_PTR
  attach_function :STORE_method_get_modify_function, [ :pointer ], :STORE_MODIFY_OBJECT_FUNC_PTR
  attach_function :STORE_method_get_revoke_function, [ :pointer ], :STORE_HANDLE_OBJECT_FUNC_PTR
  attach_function :STORE_method_get_delete_function, [ :pointer ], :STORE_HANDLE_OBJECT_FUNC_PTR
  attach_function :STORE_method_get_list_start_function, [ :pointer ], :STORE_START_OBJECT_FUNC_PTR
  attach_function :STORE_method_get_list_next_function, [ :pointer ], :STORE_NEXT_OBJECT_FUNC_PTR
  attach_function :STORE_method_get_list_end_function, [ :pointer ], :STORE_END_OBJECT_FUNC_PTR
  attach_function :STORE_method_get_update_store_function, [ :pointer ], :STORE_GENERIC_FUNC_PTR
  attach_function :STORE_method_get_lock_store_function, [ :pointer ], :STORE_GENERIC_FUNC_PTR
  attach_function :STORE_method_get_unlock_store_function, [ :pointer ], :STORE_GENERIC_FUNC_PTR
  attach_function :STORE_method_get_ctrl_function, [ :pointer ], :STORE_CTRL_FUNC_PTR
  attach_function :STORE_parse_attrs_start, [ :pointer ], :pointer
  attach_function :STORE_parse_attrs_next, [ :pointer ], :pointer
  attach_function :STORE_parse_attrs_end, [ :pointer ], :int
  attach_function :STORE_parse_attrs_endp, [ :pointer ], :int
  attach_function :STORE_ATTR_INFO_new, [  ], :pointer
  attach_function :STORE_ATTR_INFO_free, [ :pointer ], :int
  attach_function :STORE_ATTR_INFO_get0_cstr, [ :pointer, :int ], :string
  attach_function :STORE_ATTR_INFO_get0_sha1str, [ :pointer, :int ], :pointer
  attach_function :STORE_ATTR_INFO_get0_dn, [ :pointer, :int ], :pointer
  attach_function :STORE_ATTR_INFO_get0_number, [ :pointer, :int ], :pointer
  attach_function :STORE_ATTR_INFO_set_cstr, [ :pointer, :int, :string, :uint ], :int
  attach_function :STORE_ATTR_INFO_set_sha1str, [ :pointer, :int, :pointer, :uint ], :int
  attach_function :STORE_ATTR_INFO_set_dn, [ :pointer, :int, :pointer ], :int
  attach_function :STORE_ATTR_INFO_set_number, [ :pointer, :int, :pointer ], :int
  attach_function :STORE_ATTR_INFO_modify_cstr, [ :pointer, :int, :string, :uint ], :int
  attach_function :STORE_ATTR_INFO_modify_sha1str, [ :pointer, :int, :pointer, :uint ], :int
  attach_function :STORE_ATTR_INFO_modify_dn, [ :pointer, :int, :pointer ], :int
  attach_function :STORE_ATTR_INFO_modify_number, [ :pointer, :int, :pointer ], :int
  attach_function :STORE_ATTR_INFO_compare, [ :pointer, :pointer ], :int
  attach_function :STORE_ATTR_INFO_in_range, [ :pointer, :pointer ], :int
  attach_function :STORE_ATTR_INFO_in, [ :pointer, :pointer ], :int
  attach_function :STORE_ATTR_INFO_in_ex, [ :pointer, :pointer ], :int
  attach_function :ERR_load_STORE_strings, [  ], :void
  STORE_F_MEM_DELETE = 134
  STORE_F_MEM_GENERATE = 135
  STORE_F_MEM_LIST_END = 168
  STORE_F_MEM_LIST_NEXT = 136
  STORE_F_MEM_LIST_START = 137
  STORE_F_MEM_MODIFY = 169
  STORE_F_MEM_STORE = 138
  STORE_F_STORE_ATTR_INFO_GET0_CSTR = 139
  STORE_F_STORE_ATTR_INFO_GET0_DN = 140
  STORE_F_STORE_ATTR_INFO_GET0_NUMBER = 141
  STORE_F_STORE_ATTR_INFO_GET0_SHA1STR = 142
  STORE_F_STORE_ATTR_INFO_MODIFY_CSTR = 143
  STORE_F_STORE_ATTR_INFO_MODIFY_DN = 144
  STORE_F_STORE_ATTR_INFO_MODIFY_NUMBER = 145
  STORE_F_STORE_ATTR_INFO_MODIFY_SHA1STR = 146
  STORE_F_STORE_ATTR_INFO_SET_CSTR = 147
  STORE_F_STORE_ATTR_INFO_SET_DN = 148
  STORE_F_STORE_ATTR_INFO_SET_NUMBER = 149
  STORE_F_STORE_ATTR_INFO_SET_SHA1STR = 150
  STORE_F_STORE_CERTIFICATE = 170
  STORE_F_STORE_CTRL = 161
  STORE_F_STORE_DELETE_ARBITRARY = 158
  STORE_F_STORE_DELETE_CERTIFICATE = 102
  STORE_F_STORE_DELETE_CRL = 103
  STORE_F_STORE_DELETE_NUMBER = 104
  STORE_F_STORE_DELETE_PRIVATE_KEY = 105
  STORE_F_STORE_DELETE_PUBLIC_KEY = 106
  STORE_F_STORE_GENERATE_CRL = 107
  STORE_F_STORE_GENERATE_KEY = 108
  STORE_F_STORE_GET_ARBITRARY = 159
  STORE_F_STORE_GET_CERTIFICATE = 109
  STORE_F_STORE_GET_CRL = 110
  STORE_F_STORE_GET_NUMBER = 111
  STORE_F_STORE_GET_PRIVATE_KEY = 112
  STORE_F_STORE_GET_PUBLIC_KEY = 113
  STORE_F_STORE_LIST_CERTIFICATE_END = 114
  STORE_F_STORE_LIST_CERTIFICATE_ENDP = 153
  STORE_F_STORE_LIST_CERTIFICATE_NEXT = 115
  STORE_F_STORE_LIST_CERTIFICATE_START = 116
  STORE_F_STORE_LIST_CRL_END = 117
  STORE_F_STORE_LIST_CRL_ENDP = 154
  STORE_F_STORE_LIST_CRL_NEXT = 118
  STORE_F_STORE_LIST_CRL_START = 119
  STORE_F_STORE_LIST_PRIVATE_KEY_END = 120
  STORE_F_STORE_LIST_PRIVATE_KEY_ENDP = 155
  STORE_F_STORE_LIST_PRIVATE_KEY_NEXT = 121
  STORE_F_STORE_LIST_PRIVATE_KEY_START = 122
  STORE_F_STORE_LIST_PUBLIC_KEY_END = 123
  STORE_F_STORE_LIST_PUBLIC_KEY_ENDP = 156
  STORE_F_STORE_LIST_PUBLIC_KEY_NEXT = 124
  STORE_F_STORE_LIST_PUBLIC_KEY_START = 125
  STORE_F_STORE_MODIFY_ARBITRARY = 162
  STORE_F_STORE_MODIFY_CERTIFICATE = 163
  STORE_F_STORE_MODIFY_CRL = 164
  STORE_F_STORE_MODIFY_NUMBER = 165
  STORE_F_STORE_MODIFY_PRIVATE_KEY = 166
  STORE_F_STORE_MODIFY_PUBLIC_KEY = 167
  STORE_F_STORE_NEW_ENGINE = 133
  STORE_F_STORE_NEW_METHOD = 132
  STORE_F_STORE_PARSE_ATTRS_END = 151
  STORE_F_STORE_PARSE_ATTRS_ENDP = 172
  STORE_F_STORE_PARSE_ATTRS_NEXT = 152
  STORE_F_STORE_PARSE_ATTRS_START = 171
  STORE_F_STORE_REVOKE_CERTIFICATE = 129
  STORE_F_STORE_REVOKE_PRIVATE_KEY = 130
  STORE_F_STORE_REVOKE_PUBLIC_KEY = 131
  STORE_F_STORE_STORE_ARBITRARY = 157
  STORE_F_STORE_STORE_CERTIFICATE = 100
  STORE_F_STORE_STORE_CRL = 101
  STORE_F_STORE_STORE_NUMBER = 126
  STORE_F_STORE_STORE_PRIVATE_KEY = 127
  STORE_F_STORE_STORE_PUBLIC_KEY = 128
  STORE_R_ALREADY_HAS_A_VALUE = 127
  STORE_R_FAILED_DELETING_ARBITRARY = 132
  STORE_R_FAILED_DELETING_CERTIFICATE = 100
  STORE_R_FAILED_DELETING_KEY = 101
  STORE_R_FAILED_DELETING_NUMBER = 102
  STORE_R_FAILED_GENERATING_CRL = 103
  STORE_R_FAILED_GENERATING_KEY = 104
  STORE_R_FAILED_GETTING_ARBITRARY = 133
  STORE_R_FAILED_GETTING_CERTIFICATE = 105
  STORE_R_FAILED_GETTING_KEY = 106
  STORE_R_FAILED_GETTING_NUMBER = 107
  STORE_R_FAILED_LISTING_CERTIFICATES = 108
  STORE_R_FAILED_LISTING_KEYS = 109
  STORE_R_FAILED_MODIFYING_ARBITRARY = 138
  STORE_R_FAILED_MODIFYING_CERTIFICATE = 139
  STORE_R_FAILED_MODIFYING_CRL = 140
  STORE_R_FAILED_MODIFYING_NUMBER = 141
  STORE_R_FAILED_MODIFYING_PRIVATE_KEY = 142
  STORE_R_FAILED_MODIFYING_PUBLIC_KEY = 143
  STORE_R_FAILED_REVOKING_CERTIFICATE = 110
  STORE_R_FAILED_REVOKING_KEY = 111
  STORE_R_FAILED_STORING_ARBITRARY = 134
  STORE_R_FAILED_STORING_CERTIFICATE = 112
  STORE_R_FAILED_STORING_KEY = 113
  STORE_R_FAILED_STORING_NUMBER = 114
  STORE_R_NOT_IMPLEMENTED = 128
  STORE_R_NO_CONTROL_FUNCTION = 144
  STORE_R_NO_DELETE_ARBITRARY_FUNCTION = 135
  STORE_R_NO_DELETE_NUMBER_FUNCTION = 115
  STORE_R_NO_DELETE_OBJECT_FUNCTION = 116
  STORE_R_NO_GENERATE_CRL_FUNCTION = 117
  STORE_R_NO_GENERATE_OBJECT_FUNCTION = 118
  STORE_R_NO_GET_OBJECT_ARBITRARY_FUNCTION = 136
  STORE_R_NO_GET_OBJECT_FUNCTION = 119
  STORE_R_NO_GET_OBJECT_NUMBER_FUNCTION = 120
  STORE_R_NO_LIST_OBJECT_ENDP_FUNCTION = 131
  STORE_R_NO_LIST_OBJECT_END_FUNCTION = 121
  STORE_R_NO_LIST_OBJECT_NEXT_FUNCTION = 122
  STORE_R_NO_LIST_OBJECT_START_FUNCTION = 123
  STORE_R_NO_MODIFY_OBJECT_FUNCTION = 145
  STORE_R_NO_REVOKE_OBJECT_FUNCTION = 124
  STORE_R_NO_STORE = 129
  STORE_R_NO_STORE_OBJECT_ARBITRARY_FUNCTION = 137
  STORE_R_NO_STORE_OBJECT_FUNCTION = 125
  STORE_R_NO_STORE_OBJECT_NUMBER_FUNCTION = 126
  STORE_R_NO_VALUE = 130
  _ERRNO_H = 1
  EPERM = 1
  ENOENT = 2
  ESRCH = 3
  EINTR = 4
  EIO = 5
  ENXIO = 6
  E2BIG = 7
  ENOEXEC = 8
  EBADF = 9
  ECHILD = 10
  EAGAIN = 11
  ENOMEM = 12
  EACCES = 13
  EFAULT = 14
  ENOTBLK = 15
  EBUSY = 16
  EEXIST = 17
  EXDEV = 18
  ENODEV = 19
  ENOTDIR = 20
  EISDIR = 21
  EINVAL = 22
  ENFILE = 23
  EMFILE = 24
  ENOTTY = 25
  ETXTBSY = 26
  EFBIG = 27
  ENOSPC = 28
  ESPIPE = 29
  EROFS = 30
  EMLINK = 31
  EPIPE = 32
  EDOM = 33
  ERANGE = 34
  EDEADLK = 35
  ENAMETOOLONG = 36
  ENOLCK = 37
  ENOSYS = 38
  ENOTEMPTY = 39
  ELOOP = 40
  EWOULDBLOCK = 11
  ENOMSG = 42
  EIDRM = 43
  ECHRNG = 44
  EL2NSYNC = 45
  EL3HLT = 46
  EL3RST = 47
  ELNRNG = 48
  EUNATCH = 49
  ENOCSI = 50
  EL2HLT = 51
  EBADE = 52
  EBADR = 53
  EXFULL = 54
  ENOANO = 55
  EBADRQC = 56
  EBADSLT = 57
  EDEADLOCK = 35
  EBFONT = 59
  ENOSTR = 60
  ENODATA = 61
  ETIME = 62
  ENOSR = 63
  ENONET = 64
  ENOPKG = 65
  EREMOTE = 66
  ENOLINK = 67
  EADV = 68
  ESRMNT = 69
  ECOMM = 70
  EPROTO = 71
  EMULTIHOP = 72
  EDOTDOT = 73
  EBADMSG = 74
  EOVERFLOW = 75
  ENOTUNIQ = 76
  EBADFD = 77
  EREMCHG = 78
  ELIBACC = 79
  ELIBBAD = 80
  ELIBSCN = 81
  ELIBMAX = 82
  ELIBEXEC = 83
  EILSEQ = 84
  ERESTART = 85
  ESTRPIPE = 86
  EUSERS = 87
  ENOTSOCK = 88
  EDESTADDRREQ = 89
  EMSGSIZE = 90
  EPROTOTYPE = 91
  ENOPROTOOPT = 92
  EPROTONOSUPPORT = 93
  ESOCKTNOSUPPORT = 94
  EOPNOTSUPP = 95
  EPFNOSUPPORT = 96
  EAFNOSUPPORT = 97
  EADDRINUSE = 98
  EADDRNOTAVAIL = 99
  ENETDOWN = 100
  ENETUNREACH = 101
  ENETRESET = 102
  ECONNABORTED = 103
  ECONNRESET = 104
  ENOBUFS = 105
  EISCONN = 106
  ENOTCONN = 107
  ESHUTDOWN = 108
  ETOOMANYREFS = 109
  ETIMEDOUT = 110
  ECONNREFUSED = 111
  EHOSTDOWN = 112
  EHOSTUNREACH = 113
  EALREADY = 114
  EINPROGRESS = 115
  ESTALE = 116
  EUCLEAN = 117
  ENOTNAM = 118
  ENAVAIL = 119
  EISNAM = 120
  EREMOTEIO = 121
  EDQUOT = 122
  ENOMEDIUM = 123
  EMEDIUMTYPE = 124
  ECANCELED = 125
  ENOKEY = 126
  EKEYEXPIRED = 127
  EKEYREVOKED = 128
  EKEYREJECTED = 129
  EOWNERDEAD = 130
  ENOTRECOVERABLE = 131
  ERFKILL = 132
  ENOTSUP = 95
  attach_function :__errno_location, [  ], :pointer
  ERR_TXT_MALLOCED = 0x01
  ERR_TXT_STRING = 0x02
  ERR_FLAG_MARK = 0x01
  ERR_NUM_ERRORS = 16
  class ErrStateSt < FFI::Struct
    layout(
           :pid, :ulong,
           :err_flags, [:int, 16],
           :err_buffer, [:ulong, 16],
           :err_data, [:string, 16],
           :err_data_flags, [:int, 16],
           :err_file, [:string, 16],
           :err_line, [:int, 16],
           :top, :int,
           :bottom, :int
    )
  end
  ERR_LIB_NONE = 1
  ERR_LIB_SYS = 2
  ERR_LIB_BN = 3
  ERR_LIB_RSA = 4
  ERR_LIB_DH = 5
  ERR_LIB_EVP = 6
  ERR_LIB_BUF = 7
  ERR_LIB_OBJ = 8
  ERR_LIB_PEM = 9
  ERR_LIB_DSA = 10
  ERR_LIB_X509 = 11
  ERR_LIB_ASN1 = 13
  ERR_LIB_CONF = 14
  ERR_LIB_CRYPTO = 15
  ERR_LIB_EC = 16
  ERR_LIB_SSL = 20
  ERR_LIB_BIO = 32
  ERR_LIB_PKCS7 = 33
  ERR_LIB_X509V3 = 34
  ERR_LIB_PKCS12 = 35
  ERR_LIB_RAND = 36
  ERR_LIB_DSO = 37
  ERR_LIB_ENGINE = 38
  ERR_LIB_OCSP = 39
  ERR_LIB_UI = 40
  ERR_LIB_COMP = 41
  ERR_LIB_ECDSA = 42
  ERR_LIB_ECDH = 43
  ERR_LIB_STORE = 44
  ERR_LIB_FIPS = 45
  ERR_LIB_CMS = 46
  ERR_LIB_JPAKE = 47
  ERR_LIB_USER = 128
  SYS_F_FOPEN = 1
  SYS_F_CONNECT = 2
  SYS_F_GETSERVBYNAME = 3
  SYS_F_SOCKET = 4
  SYS_F_IOCTLSOCKET = 5
  SYS_F_BIND = 6
  SYS_F_LISTEN = 7
  SYS_F_ACCEPT = 8
  SYS_F_WSASTARTUP = 9
  SYS_F_OPENDIR = 10
  SYS_F_FREAD = 11
  ERR_R_SYS_LIB = 2
  ERR_R_BN_LIB = 3
  ERR_R_RSA_LIB = 4
  ERR_R_DH_LIB = 5
  ERR_R_EVP_LIB = 6
  ERR_R_BUF_LIB = 7
  ERR_R_OBJ_LIB = 8
  ERR_R_PEM_LIB = 9
  ERR_R_DSA_LIB = 10
  ERR_R_X509_LIB = 11
  ERR_R_ASN1_LIB = 13
  ERR_R_CONF_LIB = 14
  ERR_R_CRYPTO_LIB = 15
  ERR_R_EC_LIB = 16
  ERR_R_SSL_LIB = 20
  ERR_R_BIO_LIB = 32
  ERR_R_PKCS7_LIB = 33
  ERR_R_X509V3_LIB = 34
  ERR_R_PKCS12_LIB = 35
  ERR_R_RAND_LIB = 36
  ERR_R_DSO_LIB = 37
  ERR_R_ENGINE_LIB = 38
  ERR_R_OCSP_LIB = 39
  ERR_R_UI_LIB = 40
  ERR_R_COMP_LIB = 41
  ERR_R_ECDSA_LIB = 42
  ERR_R_ECDH_LIB = 43
  ERR_R_STORE_LIB = 44
  ERR_R_NESTED_ASN1_ERROR = 58
  ERR_R_BAD_ASN1_OBJECT_HEADER = 59
  ERR_R_BAD_GET_ASN1_OBJECT_CALL = 60
  ERR_R_EXPECTING_AN_ASN1_SEQUENCE = 61
  ERR_R_ASN1_LENGTH_MISMATCH = 62
  ERR_R_MISSING_ASN1_EOS = 63
  ERR_R_FATAL = 64
  ERR_R_MALLOC_FAILURE = (1|64)
  ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED = (2|64)
  ERR_R_PASSED_NULL_PARAMETER = (3|64)
  ERR_R_INTERNAL_ERROR = (4|64)
  ERR_R_DISABLED = (5|64)
  class ERRStringDataSt < FFI::Struct
    layout(
           :error, :ulong,
           :string, :pointer
    )
    def string=(str)
      @string = FFI::MemoryPointer.from_string(str)
      self[:string] = @string
    end
    def string
      @string.get_string(0)
    end

  end
  attach_function :ERR_put_error, [ :int, :int, :int, :string, :int ], :void
  attach_function :ERR_set_error_data, [ :string, :int ], :void
  attach_function :ERR_get_error, [  ], :ulong
  attach_function :ERR_get_error_line, [ :pointer, :pointer ], :ulong
  attach_function :ERR_get_error_line_data, [ :pointer, :pointer, :pointer, :pointer ], :ulong
  attach_function :ERR_peek_error, [  ], :ulong
  attach_function :ERR_peek_error_line, [ :pointer, :pointer ], :ulong
  attach_function :ERR_peek_error_line_data, [ :pointer, :pointer, :pointer, :pointer ], :ulong
  attach_function :ERR_peek_last_error, [  ], :ulong
  attach_function :ERR_peek_last_error_line, [ :pointer, :pointer ], :ulong
  attach_function :ERR_peek_last_error_line_data, [ :pointer, :pointer, :pointer, :pointer ], :ulong
  attach_function :ERR_clear_error, [  ], :void
  attach_function :ERR_error_string, [ :ulong, :string ], :string
  attach_function :ERR_error_string_n, [ :ulong, :string, :uint ], :void
  attach_function :ERR_lib_error_string, [ :ulong ], :string
  attach_function :ERR_func_error_string, [ :ulong ], :string
  attach_function :ERR_reason_error_string, [ :ulong ], :string
  attach_function :ERR_print_errors_cb, [ callback([ :string, :uint, :pointer ], :int), :pointer ], :void
  attach_function :ERR_print_errors_fp, [ :pointer ], :void
  attach_function :ERR_print_errors, [ :pointer ], :void
  attach_function :ERR_add_error_data, [ :int, :varargs ], :void
  attach_function :ERR_load_strings, [ :int, a().ERR_STRING_DATA ], :void
  attach_function :ERR_unload_strings, [ :int, a().ERR_STRING_DATA ], :void
  attach_function :ERR_load_ERR_strings, [  ], :void
  attach_function :ERR_load_crypto_strings, [  ], :void
  attach_function :ERR_free_strings, [  ], :void
  attach_function :ERR_remove_state, [ :ulong ], :void
  attach_function :ERR_get_state, [  ], :pointer
  attach_function :ERR_get_string_table, [  ], :pointer
  attach_function :ERR_get_err_state_table, [  ], :pointer
  attach_function :ERR_release_err_state_table, [ :pointer ], :void
  attach_function :ERR_get_next_error_library, [  ], :int
  attach_function :ERR_set_mark, [  ], :int
  attach_function :ERR_pop_to_mark, [  ], :int
  attach_function :ERR_get_implementation, [  ], :pointer
  attach_function :ERR_set_implementation, [ :pointer ], :int
  ENGINE_CTRL_SET_LOGSTREAM = 1
  ENGINE_CTRL_SET_PASSWORD_CALLBACK = 2
  ENGINE_CTRL_HUP = 3
  ENGINE_CTRL_SET_USER_INTERFACE = 4
  ENGINE_CTRL_SET_CALLBACK_DATA = 5
  ENGINE_CTRL_LOAD_CONFIGURATION = 6
  ENGINE_CTRL_LOAD_SECTION = 7
  ENGINE_CTRL_HAS_CTRL_FUNCTION = 10
  ENGINE_CTRL_GET_FIRST_CMD_TYPE = 11
  ENGINE_CTRL_GET_NEXT_CMD_TYPE = 12
  ENGINE_CTRL_GET_CMD_FROM_NAME = 13
  ENGINE_CTRL_GET_NAME_LEN_FROM_CMD = 14
  ENGINE_CTRL_GET_NAME_FROM_CMD = 15
  ENGINE_CTRL_GET_DESC_LEN_FROM_CMD = 16
  ENGINE_CTRL_GET_DESC_FROM_CMD = 17
  ENGINE_CTRL_GET_CMD_FLAGS = 18
  ENGINE_CMD_BASE = 200
  ENGINE_CTRL_CHIL_SET_FORKCHECK = 100
  ENGINE_CTRL_CHIL_NO_LOCKING = 101
  class ENGINECMDDEFNSt < FFI::Struct
    layout(
           :cmd_num, :uint,
           :cmd_name, :pointer,
           :cmd_desc, :pointer,
           :cmd_flags, :uint
    )
    def cmd_name=(str)
      @cmd_name = FFI::MemoryPointer.from_string(str)
      self[:cmd_name] = @cmd_name
    end
    def cmd_name
      @cmd_name.get_string(0)
    end
    def cmd_desc=(str)
      @cmd_desc = FFI::MemoryPointer.from_string(str)
      self[:cmd_desc] = @cmd_desc
    end
    def cmd_desc
      @cmd_desc.get_string(0)
    end

  end
  callback(:ENGINE_GEN_FUNC_PTR, [  ], :int)
  callback(:ENGINE_GEN_INT_FUNC_PTR, [ :pointer ], :int)
  callback(:ENGINE_CTRL_FUNC_PTR, [ :pointer, :int, :long, :pointer, callback([  ], :void) ], :int)
  callback(:ENGINE_LOAD_KEY_PTR, [ :pointer, :string, :pointer, :pointer ], :pointer)
  callback(:ENGINE_SSL_CLIENT_CERT_PTR, [ :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer ], :int)
  callback(:ENGINE_CIPHERS_PTR, [ :pointer, :pointer, :pointer, :int ], :int)
  callback(:ENGINE_DIGESTS_PTR, [ :pointer, :pointer, :pointer, :int ], :int)
  attach_function :ENGINE_get_first, [  ], :pointer
  attach_function :ENGINE_get_last, [  ], :pointer
  attach_function :ENGINE_get_next, [ :pointer ], :pointer
  attach_function :ENGINE_get_prev, [ :pointer ], :pointer
  attach_function :ENGINE_add, [ :pointer ], :int
  attach_function :ENGINE_remove, [ :pointer ], :int
  attach_function :ENGINE_by_id, [ :string ], :pointer
  attach_function :ENGINE_load_openssl, [  ], :void
  attach_function :ENGINE_load_dynamic, [  ], :void
  attach_function :ENGINE_load_cryptodev, [  ], :void
  attach_function :ENGINE_load_aesni, [  ], :void
  attach_function :ENGINE_load_padlock, [  ], :void
  attach_function :ENGINE_load_builtin_engines, [  ], :void
  attach_function :ENGINE_get_table_flags, [  ], :uint
  attach_function :ENGINE_set_table_flags, [ :uint ], :void
  attach_function :ENGINE_register_RSA, [ :pointer ], :int
  attach_function :ENGINE_unregister_RSA, [ :pointer ], :void
  attach_function :ENGINE_register_all_RSA, [  ], :void
  attach_function :ENGINE_register_DSA, [ :pointer ], :int
  attach_function :ENGINE_unregister_DSA, [ :pointer ], :void
  attach_function :ENGINE_register_all_DSA, [  ], :void
  attach_function :ENGINE_register_ECDH, [ :pointer ], :int
  attach_function :ENGINE_unregister_ECDH, [ :pointer ], :void
  attach_function :ENGINE_register_all_ECDH, [  ], :void
  attach_function :ENGINE_register_ECDSA, [ :pointer ], :int
  attach_function :ENGINE_unregister_ECDSA, [ :pointer ], :void
  attach_function :ENGINE_register_all_ECDSA, [  ], :void
  attach_function :ENGINE_register_DH, [ :pointer ], :int
  attach_function :ENGINE_unregister_DH, [ :pointer ], :void
  attach_function :ENGINE_register_all_DH, [  ], :void
  attach_function :ENGINE_register_RAND, [ :pointer ], :int
  attach_function :ENGINE_unregister_RAND, [ :pointer ], :void
  attach_function :ENGINE_register_all_RAND, [  ], :void
  attach_function :ENGINE_register_STORE, [ :pointer ], :int
  attach_function :ENGINE_unregister_STORE, [ :pointer ], :void
  attach_function :ENGINE_register_all_STORE, [  ], :void
  attach_function :ENGINE_register_ciphers, [ :pointer ], :int
  attach_function :ENGINE_unregister_ciphers, [ :pointer ], :void
  attach_function :ENGINE_register_all_ciphers, [  ], :void
  attach_function :ENGINE_register_digests, [ :pointer ], :int
  attach_function :ENGINE_unregister_digests, [ :pointer ], :void
  attach_function :ENGINE_register_all_digests, [  ], :void
  attach_function :ENGINE_register_complete, [ :pointer ], :int
  attach_function :ENGINE_register_all_complete, [  ], :int
  attach_function :ENGINE_ctrl, [ :pointer, :int, :long, :pointer, callback([  ], :void) ], :int
  attach_function :ENGINE_cmd_is_executable, [ :pointer, :int ], :int
  attach_function :ENGINE_ctrl_cmd, [ :pointer, :string, :long, :pointer, callback([  ], :void), :int ], :int
  attach_function :ENGINE_ctrl_cmd_string, [ :pointer, :string, :string, :int ], :int
  attach_function :ENGINE_new, [  ], :pointer
  attach_function :ENGINE_free, [ :pointer ], :int
  attach_function :ENGINE_up_ref, [ :pointer ], :int
  attach_function :ENGINE_set_id, [ :pointer, :string ], :int
  attach_function :ENGINE_set_name, [ :pointer, :string ], :int
  attach_function :ENGINE_set_RSA, [ :pointer, :pointer ], :int
  attach_function :ENGINE_set_DSA, [ :pointer, :pointer ], :int
  attach_function :ENGINE_set_ECDH, [ :pointer, :pointer ], :int
  attach_function :ENGINE_set_ECDSA, [ :pointer, :pointer ], :int
  attach_function :ENGINE_set_DH, [ :pointer, :pointer ], :int
  attach_function :ENGINE_set_RAND, [ :pointer, :pointer ], :int
  attach_function :ENGINE_set_STORE, [ :pointer, :pointer ], :int
  attach_function :ENGINE_set_destroy_function, [ :pointer, :ENGINE_GEN_INT_FUNC_PTR ], :int
  attach_function :ENGINE_set_init_function, [ :pointer, :ENGINE_GEN_INT_FUNC_PTR ], :int
  attach_function :ENGINE_set_finish_function, [ :pointer, :ENGINE_GEN_INT_FUNC_PTR ], :int
  attach_function :ENGINE_set_ctrl_function, [ :pointer, :ENGINE_CTRL_FUNC_PTR ], :int
  attach_function :ENGINE_set_load_privkey_function, [ :pointer, :ENGINE_LOAD_KEY_PTR ], :int
  attach_function :ENGINE_set_load_pubkey_function, [ :pointer, :ENGINE_LOAD_KEY_PTR ], :int
  attach_function :ENGINE_set_load_ssl_client_cert_function, [ :pointer, :ENGINE_SSL_CLIENT_CERT_PTR ], :int
  attach_function :ENGINE_set_ciphers, [ :pointer, :ENGINE_CIPHERS_PTR ], :int
  attach_function :ENGINE_set_digests, [ :pointer, :ENGINE_DIGESTS_PTR ], :int
  attach_function :ENGINE_set_flags, [ :pointer, :int ], :int
  attach_function :ENGINE_set_cmd_defns, [ :pointer, :pointer ], :int
  attach_function :ENGINE_get_ex_new_index, [ :long, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :ENGINE_set_ex_data, [ :pointer, :int, :pointer ], :int
  attach_function :ENGINE_get_ex_data, [ :pointer, :int ], :pointer
  attach_function :ENGINE_cleanup, [  ], :void
  attach_function :ENGINE_get_id, [ :pointer ], :string
  attach_function :ENGINE_get_name, [ :pointer ], :string
  attach_function :ENGINE_get_RSA, [ :pointer ], :pointer
  attach_function :ENGINE_get_DSA, [ :pointer ], :pointer
  attach_function :ENGINE_get_ECDH, [ :pointer ], :pointer
  attach_function :ENGINE_get_ECDSA, [ :pointer ], :pointer
  attach_function :ENGINE_get_DH, [ :pointer ], :pointer
  attach_function :ENGINE_get_RAND, [ :pointer ], :pointer
  attach_function :ENGINE_get_STORE, [ :pointer ], :pointer
  attach_function :ENGINE_get_destroy_function, [ :pointer ], :ENGINE_GEN_INT_FUNC_PTR
  attach_function :ENGINE_get_init_function, [ :pointer ], :ENGINE_GEN_INT_FUNC_PTR
  attach_function :ENGINE_get_finish_function, [ :pointer ], :ENGINE_GEN_INT_FUNC_PTR
  attach_function :ENGINE_get_ctrl_function, [ :pointer ], :ENGINE_CTRL_FUNC_PTR
  attach_function :ENGINE_get_load_privkey_function, [ :pointer ], :ENGINE_LOAD_KEY_PTR
  attach_function :ENGINE_get_load_pubkey_function, [ :pointer ], :ENGINE_LOAD_KEY_PTR
  attach_function :ENGINE_get_ssl_client_cert_function, [ :pointer ], :ENGINE_SSL_CLIENT_CERT_PTR
  attach_function :ENGINE_get_ciphers, [ :pointer ], :ENGINE_CIPHERS_PTR
  attach_function :ENGINE_get_digests, [ :pointer ], :ENGINE_DIGESTS_PTR
  attach_function :ENGINE_get_cipher, [ :pointer, :int ], :pointer
  attach_function :ENGINE_get_digest, [ :pointer, :int ], :pointer
  attach_function :ENGINE_get_cmd_defns, [ :pointer ], :pointer
  attach_function :ENGINE_get_flags, [ :pointer ], :int
  attach_function :ENGINE_init, [ :pointer ], :int
  attach_function :ENGINE_finish, [ :pointer ], :int
  attach_function :ENGINE_load_private_key, [ :pointer, :string, :pointer, :pointer ], :pointer
  attach_function :ENGINE_load_public_key, [ :pointer, :string, :pointer, :pointer ], :pointer
  attach_function :ENGINE_load_ssl_client_cert, [ :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer ], :int
  attach_function :ENGINE_get_default_RSA, [  ], :pointer
  attach_function :ENGINE_get_default_DSA, [  ], :pointer
  attach_function :ENGINE_get_default_ECDH, [  ], :pointer
  attach_function :ENGINE_get_default_ECDSA, [  ], :pointer
  attach_function :ENGINE_get_default_DH, [  ], :pointer
  attach_function :ENGINE_get_default_RAND, [  ], :pointer
  attach_function :ENGINE_get_cipher_engine, [ :int ], :pointer
  attach_function :ENGINE_get_digest_engine, [ :int ], :pointer
  attach_function :ENGINE_set_default_RSA, [ :pointer ], :int
  attach_function :ENGINE_set_default_string, [ :pointer, :string ], :int
  attach_function :ENGINE_set_default_DSA, [ :pointer ], :int
  attach_function :ENGINE_set_default_ECDH, [ :pointer ], :int
  attach_function :ENGINE_set_default_ECDSA, [ :pointer ], :int
  attach_function :ENGINE_set_default_DH, [ :pointer ], :int
  attach_function :ENGINE_set_default_RAND, [ :pointer ], :int
  attach_function :ENGINE_set_default_ciphers, [ :pointer ], :int
  attach_function :ENGINE_set_default_digests, [ :pointer ], :int
  attach_function :ENGINE_set_default, [ :pointer, :uint ], :int
  attach_function :ENGINE_add_conf_module, [  ], :void
  callback(:dyn_MEM_malloc_cb, [ :uint ], :pointer)
  callback(:dyn_MEM_realloc_cb, [ :pointer, :uint ], :pointer)
  callback(:dyn_MEM_free_cb, [ :pointer ], :void)
  class StDynamicMEMFns < FFI::Struct
    layout(
           :malloc_cb, :dyn_MEM_malloc_cb,
           :realloc_cb, :dyn_MEM_realloc_cb,
           :free_cb, :dyn_MEM_free_cb
    )
    def malloc_cb=(cb)
      @malloc_cb = cb
      self[:malloc_cb] = @malloc_cb
    end
    def malloc_cb
      @malloc_cb
    end
    def realloc_cb=(cb)
      @realloc_cb = cb
      self[:realloc_cb] = @realloc_cb
    end
    def realloc_cb
      @realloc_cb
    end
    def free_cb=(cb)
      @free_cb = cb
      self[:free_cb] = @free_cb
    end
    def free_cb
      @free_cb
    end

  end
  callback(:dyn_lock_locking_cb, [ :int, :int, :string, :int ], :void)
  callback(:dyn_lock_add_lock_cb, [ :pointer, :int, :int, :string, :int ], :int)
  callback(:dyn_dynlock_create_cb, [ :string, :int ], :pointer)
  callback(:dyn_dynlock_lock_cb, [ :int, :pointer, :string, :int ], :void)
  callback(:dyn_dynlock_destroy_cb, [ :pointer, :string, :int ], :void)
  class StDynamicLOCKFns < FFI::Struct
    layout(
           :lock_locking_cb, :dyn_lock_locking_cb,
           :lock_add_lock_cb, :dyn_lock_add_lock_cb,
           :dynlock_create_cb, :dyn_dynlock_create_cb,
           :dynlock_lock_cb, :dyn_dynlock_lock_cb,
           :dynlock_destroy_cb, :dyn_dynlock_destroy_cb
    )
    def lock_locking_cb=(cb)
      @lock_locking_cb = cb
      self[:lock_locking_cb] = @lock_locking_cb
    end
    def lock_locking_cb
      @lock_locking_cb
    end
    def lock_add_lock_cb=(cb)
      @lock_add_lock_cb = cb
      self[:lock_add_lock_cb] = @lock_add_lock_cb
    end
    def lock_add_lock_cb
      @lock_add_lock_cb
    end
    def dynlock_create_cb=(cb)
      @dynlock_create_cb = cb
      self[:dynlock_create_cb] = @dynlock_create_cb
    end
    def dynlock_create_cb
      @dynlock_create_cb
    end
    def dynlock_lock_cb=(cb)
      @dynlock_lock_cb = cb
      self[:dynlock_lock_cb] = @dynlock_lock_cb
    end
    def dynlock_lock_cb
      @dynlock_lock_cb
    end
    def dynlock_destroy_cb=(cb)
      @dynlock_destroy_cb = cb
      self[:dynlock_destroy_cb] = @dynlock_destroy_cb
    end
    def dynlock_destroy_cb
      @dynlock_destroy_cb
    end

  end
  class StDynamicFns < FFI::Struct
    layout(
           :static_state, :pointer,
           :err_fns, :pointer,
           :ex_data_fns, :pointer,
           :mem_fns, StDynamicMEMFns,
           :lock_fns, StDynamicLOCKFns
    )
  end
  callback(:dynamic_v_check_fn, [ :ulong ], :ulong)
  callback(:dynamic_bind_engine, [ :pointer, :string, :pointer ], :int)
  attach_function :ENGINE_get_static_state, [  ], :pointer
  attach_function :ERR_load_ENGINE_strings, [  ], :void
  ENGINE_F_DYNAMIC_CTRL = 180
  ENGINE_F_DYNAMIC_GET_DATA_CTX = 181
  ENGINE_F_DYNAMIC_LOAD = 182
  ENGINE_F_DYNAMIC_SET_DATA_CTX = 183
  ENGINE_F_ENGINE_ADD = 105
  ENGINE_F_ENGINE_BY_ID = 106
  ENGINE_F_ENGINE_CMD_IS_EXECUTABLE = 170
  ENGINE_F_ENGINE_CTRL = 142
  ENGINE_F_ENGINE_CTRL_CMD = 178
  ENGINE_F_ENGINE_CTRL_CMD_STRING = 171
  ENGINE_F_ENGINE_FINISH = 107
  ENGINE_F_ENGINE_FREE_UTIL = 108
  ENGINE_F_ENGINE_GET_CIPHER = 185
  ENGINE_F_ENGINE_GET_DEFAULT_TYPE = 177
  ENGINE_F_ENGINE_GET_DIGEST = 186
  ENGINE_F_ENGINE_GET_NEXT = 115
  ENGINE_F_ENGINE_GET_PREV = 116
  ENGINE_F_ENGINE_INIT = 119
  ENGINE_F_ENGINE_LIST_ADD = 120
  ENGINE_F_ENGINE_LIST_REMOVE = 121
  ENGINE_F_ENGINE_LOAD_PRIVATE_KEY = 150
  ENGINE_F_ENGINE_LOAD_PUBLIC_KEY = 151
  ENGINE_F_ENGINE_LOAD_SSL_CLIENT_CERT = 192
  ENGINE_F_ENGINE_NEW = 122
  ENGINE_F_ENGINE_REMOVE = 123
  ENGINE_F_ENGINE_SET_DEFAULT_STRING = 189
  ENGINE_F_ENGINE_SET_DEFAULT_TYPE = 126
  ENGINE_F_ENGINE_SET_ID = 129
  ENGINE_F_ENGINE_SET_NAME = 130
  ENGINE_F_ENGINE_TABLE_REGISTER = 184
  ENGINE_F_ENGINE_UNLOAD_KEY = 152
  ENGINE_F_ENGINE_UNLOCKED_FINISH = 191
  ENGINE_F_ENGINE_UP_REF = 190
  ENGINE_F_INT_CTRL_HELPER = 172
  ENGINE_F_INT_ENGINE_CONFIGURE = 188
  ENGINE_F_INT_ENGINE_MODULE_INIT = 187
  ENGINE_F_LOG_MESSAGE = 141
  ENGINE_R_ALREADY_LOADED = 100
  ENGINE_R_ARGUMENT_IS_NOT_A_NUMBER = 133
  ENGINE_R_CMD_NOT_EXECUTABLE = 134
  ENGINE_R_COMMAND_TAKES_INPUT = 135
  ENGINE_R_COMMAND_TAKES_NO_INPUT = 136
  ENGINE_R_CONFLICTING_ENGINE_ID = 103
  ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED = 119
  ENGINE_R_DH_NOT_IMPLEMENTED = 139
  ENGINE_R_DSA_NOT_IMPLEMENTED = 140
  ENGINE_R_DSO_FAILURE = 104
  ENGINE_R_DSO_NOT_FOUND = 132
  ENGINE_R_ENGINES_SECTION_ERROR = 148
  ENGINE_R_ENGINE_CONFIGURATION_ERROR = 101
  ENGINE_R_ENGINE_IS_NOT_IN_LIST = 105
  ENGINE_R_ENGINE_SECTION_ERROR = 149
  ENGINE_R_FAILED_LOADING_PRIVATE_KEY = 128
  ENGINE_R_FAILED_LOADING_PUBLIC_KEY = 129
  ENGINE_R_FINISH_FAILED = 106
  ENGINE_R_GET_HANDLE_FAILED = 107
  ENGINE_R_ID_OR_NAME_MISSING = 108
  ENGINE_R_INIT_FAILED = 109
  ENGINE_R_INTERNAL_LIST_ERROR = 110
  ENGINE_R_INVALID_ARGUMENT = 143
  ENGINE_R_INVALID_CMD_NAME = 137
  ENGINE_R_INVALID_CMD_NUMBER = 138
  ENGINE_R_INVALID_INIT_VALUE = 151
  ENGINE_R_INVALID_STRING = 150
  ENGINE_R_NOT_INITIALISED = 117
  ENGINE_R_NOT_LOADED = 112
  ENGINE_R_NO_CONTROL_FUNCTION = 120
  ENGINE_R_NO_INDEX = 144
  ENGINE_R_NO_LOAD_FUNCTION = 125
  ENGINE_R_NO_REFERENCE = 130
  ENGINE_R_NO_SUCH_ENGINE = 116
  ENGINE_R_NO_UNLOAD_FUNCTION = 126
  ENGINE_R_PROVIDE_PARAMETERS = 113
  ENGINE_R_RSA_NOT_IMPLEMENTED = 141
  ENGINE_R_UNIMPLEMENTED_CIPHER = 146
  ENGINE_R_UNIMPLEMENTED_DIGEST = 147
  ENGINE_R_VERSION_INCOMPATIBILITY = 145

end
