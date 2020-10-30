require 'optparse'
require 'turborex'
require 'turborex/windows/com'

options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: com_finder.rb [options]"

  opts.on("-c", "--clsid CLSID", "CoClass ID") do |c|
    options[:clsid] = c
  end

  opts.on("-i", "--iid IID", "Interface ID") do |i|
    options[:iid] = i
  end

  opts.on("-oop", "--out-of-process", "Using out-of-process finder") do |o|
    options[:oop] = true
  end

  opts.on("-r", "--relative", "Specify whether the output address is rva") do |o|
    options[:relative] = true
  end
end.parse!

if options[:oop]
  finder = TurboRex::Windows::COM::OutOfProcFinder.new(options[:clsid])
else
  finder = TurboRex::Windows::COM::InProcFinder.new(options[:clsid])
end

methods = finder.locate_interface_methods(options[:iid], options[:relative])
puts "Module: #{methods[:module]}"

methods[:methods].each do |m|
  puts "index: #{m[:index]}"
  puts "Address: 0x#{(m[:va] || m[:rva]).to_s(16)}"
  puts
end