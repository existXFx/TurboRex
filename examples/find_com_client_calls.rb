require 'turborex'

file = ARGV[0]
finder = TurboRex::Windows::COM::ClientFinder.new(file)
res = finder.find_client_call

if res
  res.each do |r|
    puts "Class ID: #{r[:clsid]}"
    puts "Interface ID: #{r[:iid]}"
    puts "Context: #{r[:context]}"
    puts "Method index: #{r[:method_index]}"
    puts "Call site: 0x#{r[:call_site].to_s(16)}"
    puts
  end
end
