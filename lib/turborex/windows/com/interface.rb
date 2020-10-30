module TurboRex
  class Windows < Metasm::WinOS
    module COM
      class Interface
        include WellKnownIID

        attr_accessor :this
        attr_reader :iid
        attr_reader :vtbl
        attr_reader :pvtbl
        attr_reader :parent
        attr_reader :methods

        class IUnknown < Interface
          METHOD_DEFS =<<-EOS
            HRESULT STDMETHODCALLTYPE QueryInterface( 
                    IUnknown * This,
                    REFIID riid,
                    void **ppvObject);
          
            ULONG STDMETHODCALLTYPE AddRef(IUnknown * This);
        
            ULONG STDMETHODCALLTYPE Release(IUnknown * This);
          EOS

          apiproxy = Windows::Win32API.dup
          apiproxy.parse_c(METHOD_DEFS)
          _symbol = apiproxy.cp.toplevel.symbol

          METHODS = [
                     _symbol['QueryInterface'],
                     _symbol['AddRef'],                    
                     _symbol['Release'] 
                    ]

          def initialize
            methods = METHODS
            parent = nil
            super(IID_IUnknown, methods, parent)
          end

          def name
            self.class.to_s
          end
        end

        class IClassFactory < Interface
          METHOD_DEFS =<<-EOS
            HRESULT STDMETHODCALLTYPE QueryInterface( 
                    IClassFactory * This,
                    REFIID riid,
                    void **ppvObject);
          
            ULONG STDMETHODCALLTYPE AddRef(IClassFactory * This);
        
            ULONG STDMETHODCALLTYPE Release(IClassFactory * This);

            HRESULT STDMETHODCALLTYPE CreateInstance( 
              IClassFactory * This,
              void *pUnkOuter,
                REFIID riid,
                void **ppvObject);
          
            HRESULT STDMETHODCALLTYPE LockServer( 
              IClassFactory * This,
              BOOL fLock);
          EOS

          apiproxy = Windows::Win32API.dup
          apiproxy.parse_c(METHOD_DEFS)
          _symbol = apiproxy.cp.toplevel.symbol
          METHODS = [
                     _symbol['QueryInterface'],
                     _symbol['AddRef'],                    
                     _symbol['Release'],
                     _symbol['CreateInstance'],
                     _symbol['LockServer']
                    ]

          def initialize
            methods = METHODS
            parent = nil
            super(IID_IClassFactory, methods, parent)
          end

          def name
            self.class.to_s
          end
        end

        class IRpcStubBuffer < Interface
          METHOD_DEFS =<<-EOS
            HRESULT STDMETHODCALLTYPE QueryInterface( 
                IRpcStubBuffer * This,
                REFIID riid,
                void **ppvObject);
            
            ULONG  STDMETHODCALLTYPE AddRef( 
                IRpcStubBuffer * This);
            
            ULONG STDMETHODCALLTYPE Release( 
                IRpcStubBuffer * This);
            
            HRESULT STDMETHODCALLTYPE Connect( 
                IRpcStubBuffer * This,
                IUnknown *pUnkServer);
            
            void STDMETHODCALLTYPE Disconnect( 
                IRpcStubBuffer * This);
            
            HRESULT STDMETHODCALLTYPE Invoke ( 
                IRpcStubBuffer * This,
                RPCOLEMESSAGE *_prpcmsg,
                IRpcChannelBuffer *_pRpcChannelBuffer);
            
            IRpcStubBuffer * STDMETHODCALLTYPE IsIIDSupported( 
                IRpcStubBuffer * This,
                REFIID riid);
            
            ULONG STDMETHODCALLTYPE CountRefs( 
                IRpcStubBuffer * This);
            
            HRESULT STDMETHODCALLTYPE DebugServerQueryInterface( 
                IRpcStubBuffer * This,
                void **ppv);
            
            void STDMETHODCALLTYPE DebugServerRelease( 
                IRpcStubBuffer * This,
                void *pv);
          EOS

          def initialize
            methods = METHODS
            parent = nil
            super(IID_IRpcStubBuffer, methods, parent)
          end
        end

        class IRpcProxyBuffer < Interface
          METHOD_DEFS = <<-EOS
            HRESULT STDMETHODCALLTYPE QueryInterface( 
                IRpcProxyBuffer * This,
                REFIID riid,
                void **ppvObject);
            
            ULONG STDMETHODCALLTYPE AddRef( 
                IRpcProxyBuffer * This);
            
            ULONG STDMETHODCALLTYPE Release( 
                IRpcProxyBuffer * This);
            
            HRESULT STDMETHODCALLTYPE Connect( 
                IRpcProxyBuffer * This,
                IRpcChannelBuffer *pRpcChannelBuffer);
            
            void STDMETHODCALLTYPE Disconnect( 
                IRpcProxyBuffer * This);
          EOS

          apiproxy = Windows::Win32API.dup
          apiproxy.parse_c(METHOD_DEFS)
          _symbol = apiproxy.cp.toplevel.symbol
          METHODS = [
                     _symbol['QueryInterface'],
                     _symbol['AddRef'],                    
                     _symbol['Release'],
                     _symbol['Connect'],
                     _symbol['Disconnect']
          ]

          def initialize
            methods = METHODS
            parent = nil
            super(IID_IRpcProxyBuffer, methods, parent)
          end

          def name
            self.class.to_s
          end
        end

        class IPSFactoryBuffer < Interface
          METHOD_DEFS = <<-EOS
            HRESULT STDMETHODCALLTYPE QueryInterface( 
                IPSFactoryBuffer * This,
                REFIID riid,
                void **ppvObject);
            
            ULONG STDMETHODCALLTYPE AddRef( 
                IPSFactoryBuffer * This);
            
            ULONG STDMETHODCALLTYPE Release( 
                IPSFactoryBuffer * This);
            
            HRESULT STDMETHODCALLTYPE CreateProxy( 
                IPSFactoryBuffer * This,
                IUnknown *pUnkOuter,
                REFIID riid,
                IRpcProxyBuffer **ppProxy,
                void **ppv);
            
            HRESULT STDMETHODCALLTYPE CreateStub( 
                IPSFactoryBuffer * This,
                REFIID riid,
                IUnknown *pUnkServer,
                IRpcStubBuffer **ppStub);
          EOS

          apiproxy = Windows::Win32API.dup
          apiproxy.parse_c(METHOD_DEFS)
          _symbol = apiproxy.cp.toplevel.symbol
          METHODS = [
                     _symbol['QueryInterface'],
                     _symbol['AddRef'],                    
                     _symbol['Release'],
                     _symbol['CreateProxy'],
                     _symbol['CreateStub']
          ]

          def initialize
            methods = METHODS
            parent = nil
            super(IID_IPSFactoryBuffer, methods, parent)
          end

          def name
            self.class.to_s
          end
        end

        class IStream < Interface
          METHOD_DEFS =<<-EOS
            HRESULT STDMETHODCALLTYPE QueryInterface( 
                    IStream * This,
                    REFIID riid,
                    void **ppvObject);
          
            ULONG STDMETHODCALLTYPE AddRef(IStream * This);
        
            ULONG STDMETHODCALLTYPE Release(IStream * This);

            HRESULT STDMETHODCALLTYPE Read( 
              IStream * This,
              void *pv,
              ULONG cb,
              ULONG *pcbRead);
          
            HRESULT STDMETHODCALLTYPE Write( 
              IStream * This,
              const void *pv,
              ULONG cb,
              ULONG *pcbWritten);
          
            HRESULT STDMETHODCALLTYPE Seek( 
              IStream * This,
              LARGE_INTEGER dlibMove,
              DWORD dwOrigin,
              ULARGE_INTEGER *plibNewPosition);
          
            HRESULT STDMETHODCALLTYPE SetSize( 
              IStream * This,
              ULARGE_INTEGER libNewSize);
          
            HRESULT STDMETHODCALLTYPE CopyTo( 
              IStream * This,
              void *pstm,
              ULARGE_INTEGER cb,
              ULARGE_INTEGER *pcbRead,
              ULARGE_INTEGER *pcbWritten);
          
            HRESULT STDMETHODCALLTYPE Commit( 
              IStream * This,
              DWORD grfCommitFlags);
          
            HRESULT STDMETHODCALLTYPE Revert( 
              IStream * This);
          
            HRESULT STDMETHODCALLTYPE LockRegion( 
              IStream * This,
              ULARGE_INTEGER libOffset,
              ULARGE_INTEGER cb,
              DWORD dwLockType);
          
            HRESULT STDMETHODCALLTYPE UnlockRegion( 
              IStream * This,
              ULARGE_INTEGER libOffset,
              ULARGE_INTEGER cb,
              DWORD dwLockType);
          
            HRESULT STDMETHODCALLTYPE Stat( 
              IStream * This,
              STATSTG *pstatstg,
              DWORD grfStatFlag);
          
            HRESULT STDMETHODCALLTYPE Clone( 
              IStream * This,
              void **ppstm);
          EOS

          apiproxy = Windows::Win32API.dup
          apiproxy.parse_c(METHOD_DEFS)
          _symbol = apiproxy.cp.toplevel.symbol
          METHODS = [_symbol['QueryInterface'],
                     _symbol['AddRef'],                    
                     _symbol['Release'],
                     _symbol['Read'],
                     _symbol['Write'],
                     _symbol['Seek'],
                     _symbol['SetSize'],
                     _symbol['CopyTo'],
                     _symbol['Commit'],
                     _symbol['Revert'],
                     _symbol['LockRegion'],
                     _symbol['UnlockRegion'],
                     _symbol['Stat'],
                     _symbol['Clone']
                    ]

          def initialize
            methods = METHODS
            parent = nil
            super(IID_IStream, methods, parent)
          end

          def name
            self.class.to_s
          end
        end

        class IStorage < Interface
          METHOD_DEFS =<<-EOS
            HRESULT STDMETHODCALLTYPE QueryInterface( 
                    IUnknown * This,
                    REFIID riid,
                    void **ppvObject);
          
            ULONG STDMETHODCALLTYPE AddRef(IUnknown * This);
        
            ULONG STDMETHODCALLTYPE Release(IUnknown * This);

            HRESULT STDMETHODCALLTYPE CreateStream( 
              IStorage * This,
              const OLECHAR *pwcsName,
              DWORD grfMode,
              DWORD reserved1,
              DWORD reserved2,
              IStream **ppstm);
          
            HRESULT STDMETHODCALLTYPE OpenStream( 
              IStorage * This,
              const OLECHAR *pwcsName,
              void *reserved1,
              DWORD grfMode,
              DWORD reserved2,
              IStream **ppstm);
          
            HRESULT STDMETHODCALLTYPE CreateStorage( 
              IStorage * This,
              const OLECHAR *pwcsName,
              DWORD grfMode,
              DWORD reserved1,
              DWORD reserved2,
              IStorage **ppstg);
          
            HRESULT STDMETHODCALLTYPE OpenStorage( 
              IStorage * This,
              const OLECHAR *pwcsName,
              IStorage *pstgPriority,
              DWORD grfMode,
              SNB snbExclude,
              DWORD reserved,
              IStorage **ppstg);
          
            HRESULT STDMETHODCALLTYPE CopyTo( 
              IStorage * This,
              DWORD ciidExclude,
              const IID *rgiidExclude,
              SNB snbExclude,
              IStorage *pstgDest);
          
            HRESULT STDMETHODCALLTYPE MoveElementTo ( 
              IStorage * This,
              const OLECHAR *pwcsName,
              IStorage *pstgDest,
              const OLECHAR *pwcsNewName,
              DWORD grfFlags);
          
            HRESULT STDMETHODCALLTYPE Commit( 
              IStorage * This,
              DWORD grfCommitFlags);
          
            HRESULT STDMETHODCALLTYPE Revert( 
              IStorage * This);
          
            HRESULT STDMETHODCALLTYPE EnumElements( 
              IStorage * This,
              DWORD reserved1,
              void *reserved2,
              DWORD reserved3,
              IEnumSTATSTG **ppenum);
          
            HRESULT STDMETHODCALLTYPE DestroyElement( 
              IStorage * This,
              const OLECHAR *pwcsName);
          
            HRESULT STDMETHODCALLTYPE RenameElement( 
              IStorage * This,
              const OLECHAR *pwcsOldName,
              const OLECHAR *pwcsNewName);
          
            HRESULT STDMETHODCALLTYPE SetElementTimes( 
              IStorage * This,
              const OLECHAR *pwcsName,
              const FILETIME *pctime,
              const FILETIME *patime,
              const FILETIME *pmtime);
          
            HRESULT STDMETHODCALLTYPE SetClass( 
              IStorage * This,
              REFCLSID clsid);
          
            HRESULT STDMETHODCALLTYPE SetStateBits( 
              IStorage * This,
              DWORD grfStateBits,
              DWORD grfMask);
          
            HRESULT STDMETHODCALLTYPE Stat( 
              IStorage * This,
              STATSTG *pstatstg,
              DWORD grfStatFlag);
          EOS

          apiproxy = Windows::Win32API.dup
          apiproxy.parse_c(METHOD_DEFS)
          _symbol = apiproxy.cp.toplevel.symbol

          METHODS = [
                     _symbol['QueryInterface'],
                     _symbol['AddRef'],                    
                     _symbol['Release'],
                     _symbol['CreateStream'],
                     _symbol['OpenStream'],
                     _symbol['CreateStorage'],
                     _symbol['OpenStorage'],
                     _symbol['CopyTo'],
                     _symbol['MoveElementTo'],
                     _symbol['Commit'],
                     _symbol['Revert'],
                     _symbol['EnumElements'],
                     _symbol['DestroyElement'],
                     _symbol['RenameElement'],
                     _symbol['SetElementTimes'],
                     _symbol['SetClass'],
                     _symbol['SetStateBits'],
                     _symbol['Stat']
                    ]

          def initialize
            methods = METHODS
            parent = nil
            super(IID_IStorage, methods, parent)
          end

          def name
            self.class.to_s
          end
        end

        def initialize(iid, methods, parent=IUnknown)
          @iid = iid
          @methods = methods
          @parent = parent
          @api_proxy = Win32API.dup

          @methods.freeze
          definie_rb_proxy
        end

        def this=(ptr)
          @this = ptr
          ptr_len = @api_proxy.host_cpu.size / 8
          format = ptr_len == 8 ? 'Q' : 'L'

          pvtbl = @api_proxy.memory_read(@this, ptr_len).unpack(format).first
          vtbl = @api_proxy.memory_read(pvtbl, ptr_len*@methods.count).unpack(format*@methods.count)
          @pvtbl = pvtbl
          @vtbl = vtbl

          @vtbl.each_with_index {|addr, i| @api_proxy.new_caller_for(@methods[i], @methods[i].name, addr)}
        end

        def marshal_to_string(mshctx=MSHCTX_DIFFERENTMACHINE, mshlflags=MSHLFLAGS_NORMAL)
          Utils.marshal_interface_to_string(self, mshctx, mshlflags)
        end

        def self.define_interface(iid, method_defs={}, parent=IUnknown)
          api_proxy = Win32API.dup
          methods = [*parent::METHODS]
          method_defs.each_value {|v| api_proxy.parse_c(v) }
          method_defs.each_key {|k| methods<<api_proxy.cp.toplevel.symbol[k.to_s]}
          methods.compact!

          new(iid, methods, parent)
        end

        def name
          self.class.to_s
        end

        private

        def definie_rb_proxy
          @methods.each do |m|
            self.define_singleton_method(m.name) do |*args|
              @api_proxy.send m.name, @this, *args
            end
          end
        end
      end
    end
  end
end