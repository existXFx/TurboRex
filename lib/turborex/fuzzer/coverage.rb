module TurboRex
  module Fuzzer
    class CoverageClient
      def initialize(mapping_name, buf_size=65536)
        setting_mapping(mapping_name, buf_size)
        @virgin_bits = [0xFF] * buf_size
        @view_size = buf_size
        @bitmap_size = 0
      end

      def trace_bits
        page = [0].pack('C')*@view_size
        return if TurboRex::Windows::Win32API.readprocessmemory(-1, @buf, page, @view_size, 0) == 0
        page
      end

      # def has_new_bits?(trace_bits=trace_bits, virgin_bits=@virgin_bits)
      #   ret = false
      #   trace_bits.bytes.to_a.each do |b, i|
      #     virgin_bit = virgin_bits[i]
      #     unless (b & virgin_bit).zero?
      #       unless ret
      #         if virgin_bit == 0xFF
      #           ret = true
      #           @bitmap_size += 1
      #         else
      #           ret = :new_hit
      #         end
      #       end

      #       virgin_byte = virgin_byte & ~b
      #       virgin_bits[i] = virgin_bit
      #     end
      #   end

      #   ret
      # end

      private

      def setting_mapping(mapping_name, buf_size)
        @mapping_name = mapping_name

        @hmap = TurboRex::Windows::Win32API.openfilemappinga(
          TurboRex::Windows::Win32API::FILE_MAP_ALL_ACCESS,
          false,
          mapping_name
        )

        raise "Error opening file mapping" unless @hmap

        @buf = TurboRex::Windows::Win32API.mapviewoffile(
          @hmap,
          TurboRex::Windows::Win32API::FILE_MAP_ALL_ACCESS,
          0,
          0,
          buf_size
        )

        unless @buf
          TurboRex::Windows::Win32API.closehandle(@hmap)
          raise "Error mapping view of file"
        end
      end
    end
  end
end