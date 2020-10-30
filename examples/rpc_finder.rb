require 'turborex'
require 'optparse'


options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: rpc_finder.rb [options]"

  opts.on("-f", "--file FILE", "File") do |f|
    options[:file] = f
  end

  opts.on("-d", "--directory DIRECTORY", "Specify search directory") do |d|
    options[:directory] = d
  end

  opts.on("-e", "--extension EXTENSION", "Specify extension") do |e|
    options[:extension] = e
  end

  opts.on("", "--only-client", "Search client only") do |o|
    options[:only_client] = o
  end

  opts.on("", "--find-client", "Finding client") do |f|
    options[:find_client] = f
  end

  opts.on("", "--only-server", "Search server only") do |s|
    options[:only_server] = s
  end

  opts.on("-csx", "--csx", "Search cross-server xrefs") do |x|
    options[:csx] = x
  end
end.parse!

def solve_cross_server_xrefs(finder)
  finder.draw_ifs_xrefs
  finder.server_interfaces.each do |si|
    si.xrefs_from.each do |xref|
      ci = xref[0]
      call_info = xref[1]
      
      puts "Server Interface Id: #{si.interface_id}"
      puts "Client Interface Id: #{ci.interface_id}"

      call_info.each do |c|
        puts "Found path:"
        puts "   From: #{c[:caller].map{|r|'0x'+r.addr.to_s(16)}.join(', ')}"
        puts "   To: 0x#{c[:called].addr.to_s(16)}"
        puts "   Proc Number: #{c[:called].proc_num}"
        puts "------------------------------------------------------------"
        puts
      end
    end
  end
end

#pelist = TurboRex::MSRPC::RPCFinder::ImageFinder.glob('C://windows/system32', ['.dll'])
if options[:file]
  pelist = [options[:file]]
elsif options[:directory] && options[:extension]
  pelist = TurboRex::MSRPC::RPCFinder::ImageFinder.glob(options[:directory], options[:extension].split(',').map {|e| e.strip})
else
  raise "The file path must be specified"
end


c  = TurboRex::MSRPC::RPCFinder::Collection.new
pelist.each do |pe|
  f = File.new(pe)

  begin
    finder = TurboRex::MSRPC::RPCFinder::ImageFinder.new pe, collection_proxy: c
  rescue StandardError => e
    next
  end

  res = finder.auto_find do
    if options[:only_client]
      only_client
    elsif options[:only_server]
      only_server
    else
      only_server
    end

    if options[:find_client]
      find_client_routines
    end
  end

  finder.server_interfaces.each do |si|
    puts "Server Interface ID: #{si.interface_id}"
    puts "Server Routines: "
    si.routines.each_with_index do |r, i|
      puts "Index: #{i} - 0x#{r.addr.to_s(16)}"
    end
    puts
  end

  finder.client_interfaces.each do |ci|
    puts "Client Interface ID: #{ci.interface_id}"
    if options[:find_client]
      puts "Client Routines: "
      ci.routines.each do |r|
        puts "Procedure Number: #{r.proc_num} - 0x#{r.addr.to_s(16)}"
      end
    end
    puts
  end

  if options[:csx]
    solve_cross_server_xrefs(finder)
  end
end