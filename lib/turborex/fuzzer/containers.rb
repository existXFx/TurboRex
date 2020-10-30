require 'turborex/windows'

module TurboRex
  module Fuzzer
    module Container
      class ContainerBase
        attr_reader :buf

        def fixed=(v)
          @fixed = true
          set_data v
        end

        def mutate(mutator)
          return @buf if @fixed
          set_data mutator.mutate(@buf)
        end
      end

      class BooleanContainer

      end

      class ByteContainer

      end

      class SmallContainer

      end

      class ShortContainer

      end

      class LongContainer

      end

      class HyperContainer

      end

      class FloatContainer

      end

      class DoubleContainer

      end

      class CharContainer

      end

      class WchartContainer

      end

      class OLESTRContainer < ContainerBase
        def set_data(data)
          wchar = TurboRex::Windows::Utils.multibyte_to_widechar(data)
          @buf = TurboRex::Windows::Win32API.alloc_c_ary('WCHAR', @length / 2)
          @buf.str = wchar
          @buf
        end
      end

      class BSTRContainer
        def set_data(data)
          if data.is_a? OLESTRContainer

          else

          end
        end
      end

      class FixedSizeBufferContainer < ContainerBase
        def initialize(size, opts = {})
          @size = size
          @offset = @opts[:offset]
          @buf = TurboRex::Windows::Win32API.alloc_c_ary('BYTE', @size)
        end

        def set_data(data)
          @offset ? @buf.str[@offset] = data : @buf.str = data
        end
      end

      class VariantSizeBufferContainer < ContainerBase
        def set_data(data)
          @buf = TurboRex::Windows::Win32API.alloc_c_ary('BYTE', data.bytesize)
          @buf.str = data
          @buf
        end
      end

      class StructureContainer < ContainerBase
        def initialize(name, typedef=nil, opts = {})
          if typedef
            TurboRex::Windows::Win32API.parse_c(typedef)
          end

          @buf = TurboRex::Windows::Win32API.alloc_c_struct(name)
          @member = opts[:member]
        end

        def set_data(data)
          @member ? @buf.send("#{@member}=", data) : @buf.str = data
        end
      end
    end
  end
end