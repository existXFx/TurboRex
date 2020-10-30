require 'turborex'

sdk = TurboRex::Windows::TinySDK.instance
sdk.load

sdk.np.parse <<-EOS
  typedef struct tagBIND_OPTS {
    DWORD cbStruct;
    DWORD grfFlags;
    DWORD grfMode;
    DWORD dwTickCountDeadline;
  } BIND_OPTS, *LPBIND_OPTS;
EOS

bind_opts = sdk.np.alloc_c_struct('BIND_OPTS')
bind_opts.grfMode = 1
puts bind_opts.str