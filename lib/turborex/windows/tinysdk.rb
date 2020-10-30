require 'singleton'

module TurboRex
  class Windows < Metasm::WinOS
    def self.tinysdk
      TurboRex::Windows::TinySDK.instance
    end

    class TinySDK
      DEFAULT_LOAD_FILE = TurboRex.root + '/resources/headers/tinysdk/tinysdk.h'

      include Singleton

      attr_reader :include_path
      attr_reader :loaded_files
      attr_reader :np

      def initialize
        @loaded = false
        @loaded_files = []
        set_include_path
      end

      def load(opts = {})
        return true if loaded?
        load!(opts)
      end

      def load!(opts)
        opts[:cpu] ||= ::Metasm::Ia32

        opts[:visual_studio] = true
        opts[:data_model] = 'llp64' if opts[:cpu] == Metasm::X86_64
        opts[:predefined] = true

        @np = TurboRex::CStruct::NativeParser.new(nil, opts)
        @cp = @np.parser

        if opts[:files]
          opts[:files].each {|f| @cp.parse_file(f)}
          @loaded_files = opts[:files]
        else
          @cp.parse_file(DEFAULT_LOAD_FILE)
          @loaded_files << DEFAULT_LOAD_FILE
        end

        true
      end

      def loaded?
        @loaded
      end

      ## https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/using-ntstatus-values
      def self.nt_success?(ntstatus)
        (0..0x3FFFFFFF).include?(ntstatus) || (0x40000000..0x7FFFFFFF).include?(ntstatus) || ntstatus.nil?
      end

      def self.nt_information?(ntstatus)
        (0x40000000..0x7FFFFFFF).include?(ntstatus)
      end

      def self.nt_warning?(ntstatus)
        (0x80000000..0xBFFFFFFF).include?(ntstatus)
      end

      def self.nt_error?(ntstatus)
        (0xC0000000..0xFFFFFFFF).include?(ntstatus)
      end

      def self.format_hex_ntstatus(integer, opts = {})
        integer = 0 unless integer
        unpacked = [integer].pack('V').unpack('V')[0]
        if opts[:hex_str]
          '0x' + unpacked.to_s(16).upcase
        else
          unpacked
        end
      end

      private

      def set_include_path
        root = TurboRex.root + '/resources/headers'
        @include_path = TurboRex::Utils.get_all_subdir(root)
      end
    end
  end
end
