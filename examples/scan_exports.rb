require 'turborex'

pelist = TurboRex::MSRPC::RPCFinder::ImageFinder.glob('C://windows/system32', ['.dll'])
res = TurboRex::Windows::Utils.find_export_func('GetProxyDllInfo', pelist)
puts res