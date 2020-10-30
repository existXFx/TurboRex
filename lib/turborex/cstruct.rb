require 'turborex/cstruct/struct_helper'
require 'docile'
require 'rex/struct2'

module RefineAllocCStruct
  refine Metasm::C::AllocCStruct do
    def to_string # Warning: must be changed
      self.str[self.stroff, self.sizeof]
    end
  end
end

module TurboRex
  module CStruct
    extend TurboRex::CStruct::Helper

    Docile::FallbackContextProxy.class_eval do # Monkey patch
      NON_FALLBACK_METHODS = Set[:class, :self, :respond_to?, :instance_of?]

      def initialize(receiver, fallback)
        @__receiver__ = receiver
        @__fallback__ = fallback

        # Enables calling DSL methods from helper methods in the block's context
        unless fallback.respond_to?(:method_missing)
          # NOTE: There's no {#define_singleton_method} on Ruby 1.8.x
          singleton_class = (
          class << fallback;
            self;
          end)

          # instrument {#method_missing} on the block's context to fallback to
          # the DSL object. This allows helper methods in the block's context to
          # contain calls to methods on the DSL object.
          singleton_class.
              send(:define_method, :method_missing) do |method, *args, &block|
            m = method.to_sym
            if !NON_FALLBACK_METHODS.include?(m) && !fallback.respond_to?(m) && receiver.respond_to?(m) || receiver.respond_to?(:method_missing)
              receiver.__send__(method.to_sym, *args, &block)
            else
              super(method, *args, &block)
            end
          end

          # instrument a helper method to remove the above instrumentation
          singleton_class.
              send(:define_method, :__docile_undo_fallback__) do
            singleton_class.send(:remove_method, :method_missing)
            singleton_class.send(:remove_method, :__docile_undo_fallback__)
          end
        end
      end
    end

    ::Rex::Struct2::CStruct.class_eval do
      attr_reader :name_table

      def offset(struct, index, base_offset = 0)
        if index == 0
          return index
        end

        offset = 0

        (0...index).each do |i|
          offset += struct[i].slength
        end

        base_offset + offset
      end

      def padding_align(base_offset = 0, pack = nil)
        i = 0

        loop do
          current_offset = offset(self, i, base_offset)
          if self[i].is_a? Rex::Struct2::CStruct

            self[i].pack(@pack)
            self[i].padding_align(@pack)
            #break if self[i + 1] == nil
            #binding.pry if @pack == 8

            padding = calc_padding(self[i].self_align, current_offset, @pack)
          else
            padding = calc_padding(self[i].slength, current_offset, @pack)
          end

          if padding == 0
            break if self[i + 1] == nil

            i += 1
            next
          end

          s = Rex::Struct2::CStructTemplate.new
          padding.times do
            s.template << ['uint8', 'padding', 0]
          end

          insert(i, s.make_struct)

          i += 1
          break if self[i + 1] == nil
          i += 1
        end

        self.trailing_padding(@pack)
      end

      def trailing_padding(pack = nil)
        pack ||= @pack
        trailing = self.slength % effective_align(pack)
        if trailing != 0
          s = Rex::Struct2::CStructTemplate.new
          trailing.times do
            s.template << ['uint8', 'padding', 0]
          end

          append(s.make_struct)
        end

        self
      end

      def get_member_length(arr = [])
        self.each do |member|
          #if member.is_a? Rex::Struct2::CStruct
          #  member.get_member_length(arr)
          #else
          arr << member.slength
          #end
        end

        arr
      end

      def self_align
        arr = []

        self.each do |member|
          if member.is_a? Rex::Struct2::CStruct
            arr << member.get_member_self_align.max
          else
            arr << member.slength
          end
        end

        arr.max
      end

      def get_member_self_align
        arr = []
        self.each do |member|
          if member.is_a? Rex::Struct2::CStruct
            arr << member.self_align
          else
            arr << member.slength
          end
        end

        arr
      end

      def effective_align(pack = nil)
        pack ||= @pack
        effective_value = get_member_self_align.max
        unless pack.nil?
          effective_value = [effective_value, pack].min
        end

        return effective_value
      end

      def pack(n)
        @pack = n
      end

      private def insert(index, obj)
        elements.insert(index, obj)
        @name_table.insert(index, 'padding')
      end

      private def append(obj)
        elements.push(obj)
        @name_table.push('padding')
      end

      private def calc_padding(length, offset, pack = nil)
        if pack != nil && pack < length
          length = pack
        end

        (length - (offset % length)) % length
      end
    end

    ::Rex::Struct2::CStructTemplate.class_eval do
      def initialize(*tem)
        self.template = tem
        self.template_create_restraints = []
        self.template_apply_restraint = []
        @natural_align = nil
        @pack = nil
      end

      def natural_align(align = true)
        @natural_align = align

        self
      end

      def pack(n)
        @pack = n

        self
      end

      def make_struct(pack = nil, natural_align = nil)
        s = ::Rex::Struct2::CStruct.new(*self.template).
            create_restraints(*self.template_create_restraints).
            apply_restraint(*self.template_apply_restraint)

        pack ||= @pack
        natural_align ||= @natural_align

        if pack
          s.pack(pack)
        end

        if natural_align
          s.padding_align
        end

        s
      end
    end

    def define_structs(opts = {}, str = nil, &block)
      if block_given?
        Docile.dsl_eval(StructMgr.new(opts), &block)
      elsif opts[:native_parse] # parse with Metasm::C::Parser
        opts.delete[:native_parse]
        NativeParser.new(str, opts)
      end
    end

    class StructMgr
      attr_reader :structs_table

      def initialize(opts)
        @structs_table = {}
        @opts = opts
      end

      def [](name)
        @structs_table[name.to_sym]
      end

      def build
        self
      end

      def struct(obj)
        @structs_table[obj.struct_name.to_sym] = obj
        TurboRex::CStruct::CStructBuilder.create_method(obj.struct_name.to_sym) do |name|
          self.s.template << ['template', name.to_s, obj.s]
        end

        self
      end

      def method_missing(m, *args, &block)
        if block
          arch = @opts[:arch] || 'x86'
          return Docile.dsl_eval(CStructBuilder.new(arch), &block).build(m.to_s)
        end

        FieldsProxy.new m.to_s
      end
    end

    class FieldsProxy
      attr_reader :count
      attr_reader :name

      def initialize(name)
        @name = name
        @count = 1
        @point_to = nil
      end

      def [](count)
        @count = count.to_i

        self
      end

      def to_s
        @name.to_s
      end

      def point_to(cstruct)
        @point_to = cstruct
      end
    end

    class CStructBuilder
      attr_reader :struct_name
      attr_reader :s

      def initialize(arch = 'x86')
        @s = ::Rex::Struct2::CStructTemplate.new
        @arch = arch
        define_variable_length_type
      end

      def char(field, init_value = 0)
        add_object('int8', field, init_value)
      end

      def uchar(field, init_value = 0)
        add_object('uint8', field, init_value)
      end

      def short(field, init_value = 0, endian = 'v') #  'v' is little-endian, 'n' is big-endian
        add_object('int16' + endian, field, init_value)
      end

      def ushort(field, init_value = 0, endian = 'v')
        add_object('uint16' + endian, field, init_value)
      end

      def int(field, init_value = 0, endian = 'v')
        add_object('int32' + endian, field, init_value)
      end

      def uint(field, init_value = 0, endian = 'v')
        add_object('uint32' + endian, field, init_value)
      end

      def word(field, init_value = 0, endian = 'v')
        add_object('uint16' + endian, field, init_value)
      end

      def dword(field, init_value = 0, endian = 'v')
        add_object('uint32' + endian, field, init_value)
      end

      def int64(field, init_value = 0, endian = 'v')
        add_object('int64' + endian, field, init_value)
      end

      def __int64(field, init_value = 0, endian = 'v')
        add_object('int64' + endian, field, init_value)
      end

      def uint64(field, init_value = 0, endian = 'v')
        add_object('uint64' + endian, field, init_value)
      end

      def pvoid(field, init_value = 0, endian = 'v')
        case @arch
        when 'x86'
          add_object('uint32' + endian, field, init_value)
        when 'x64'
          add_object('uint64' + endian, field, init_value)
        end
      end

      # https://docs.microsoft.com/en-us/windows/win32/winprog/windows-data-types
      # https://docs.microsoft.com/en-us/cpp/cpp/data-type-ranges?redirectedfrom=MSDN&view=vs-2019
      # The data type range follows Microsoft VC/C++ compiler
      # data model llp64 on 64-bit arch
      alias ATOM word
      alias WORD word
      alias DWORD dword
      alias SHORT short
      alias QWORD uint64
      alias BYTE uchar
      alias BOOLEAN BYTE
      alias BOOL int
      alias CCHAR char
      alias CHAR char
      alias UCHAR uchar
      alias COLORREF DWORD
      alias DWORDLONG uint64
      alias DWORD32 uint
      alias DWORD64 uint64
      alias HFILE int
      alias UINT uint
      alias INT int
      alias INT8 char
      alias INT16 short
      alias INT32 int
      alias INT64 int64
      alias UINT8 uchar
      alias UINT16 ushort
      alias UINT32 uint
      alias UINT64 uint64
      alias LANGID WORD
      alias LCID DWORD
      alias LCTYPE DWORD
      alias LGRPID DWORD
      alias LONG32 int
      alias LONG64 int64
      alias LONG int
      alias ULONG uint
      alias ULONG32 uint
      alias ULONG64 uint64
      alias USHORT ushort
      alias PVOID pvoid
      alias HANDLE PVOID


      def alias_singleton_method(alias_sym, method)
        self.singleton_class.send(:alias_method, alias_sym, method)
      end

      def define_variable_length_type
        arch_32? ? alias_singleton_method(:ULONG_PTR, :uint) : alias_singleton_method(:ULONG_PTR, :uint64)
        arch_32? ? alias_singleton_method(:ULONG_PTR_T, :uint) : alias_singleton_method(:ULONG_PTR_T, :uint64)
      end

      def struct(&block)
        yield
      end

      def add_object(type, field, init_value)
        if field.count == 1
          @s.template << [type, field.to_s, init_value]
        else
          struct_temp = ::Rex::Struct2::CStructTemplate.new
          field.count.times do |i|
            struct_temp.template << [type, field.to_s + '_' + i.to_s, init_value]
          end

          @s.template << ['template', field.to_s, struct_temp]
        end
      end

      def build(name)
        set_struct_name(name)

        self
      end

      def self.create_method(method_name, &block)
        define_method(method_name, &block)
      end

      def set_struct_name(name)
        @struct_name = name
      end

      def make(opts = {})
        @s.make_struct(opts[:pack], opts[:align])
      end

      def from_str(s)
        struct = @s.make_struct
        struct.from_s(s)
        struct
      end

      private

      def arch_32?
        @arch == 'x86'
      end

      def arch_64?
        !arch_32?
      end
    end

    class NativeParser
      attr_reader :parser
      attr_reader :cpu

      def initialize(str, opts={})
        @cpu = opts[:cpu].new rescue nil || Metasm::Ia32.new
        @parser = @cpu.new_cparser

        if opts[:predefined] # TODO: more Predefined macros
          if opts[:cpu] == Metasm::Ia32
            @parser.lexer.define("_WIN32")
          elsif opts[:cpu] == Metasm::X86_64
            @parser.lexer.define("_WIN64")
            @parser.llp64
          end
        end

        @parser.send(opts[:data_model].to_s) if opts[:data_model]
        
        if opts[:visual_studio]
          @parser.prepare_visualstudio
        end

        if opts[:gcc]
          @parser.prepare_gcc
        end

        @include_path = opts[:include_path] || []
        perform_include_path
        @parser.lexer.warn_redefinition = false
        @parser.lexer.include_search_path = @include_path
        if opts[:file]
          @parser.parse_file opts[:file]
        elsif str
          @parser.parse str
        end
      end

      def find_c_struct(name)
        @parser.find_c_struct(name)
      end

      def find_c_type(name)
        @parser.find_c_type(name)
      end

      def [](name)
        NativeStructProxy.new(@parser, name)
      end

      def method_missing(m, *args, &block)
        @parser.send(m, *args, &block)
      end

      private

      def perform_include_path
        @include_path += TurboRex::Windows.tinysdk.include_path
        @include_path.uniq!
      end
    end

    class NativeStructProxy
      attr_reader :size
      attr_reader :sizeof
      attr_reader :name
      attr_reader :struct

      def initialize(parser, name)
        @parser = parser
        @name = name
        @size = @sizeof = parser.sizeof(parser.find_c_struct(name))
      end

      def from_str(str, offset = 0)
        struct = @parser.find_c_struct(@name)
        @struct = ::Metasm::C::AllocCStruct.new(@parser, struct, str, offset)
      end

      def to_s
        @struct.str
      end

      def method_missing(m, *args, &block)
        @struct.send(m, *args, &block)
      end
    end
  end
end