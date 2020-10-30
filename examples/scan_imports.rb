require 'turborex'

pelist = TurboRex::MSRPC::RPCFinder::ImageFinder.glob('C://windows/system32', ['.dll'])
res = TurboRex::Windows::Utils.find_import_func('CoCreateInstance', pelist)
puts res