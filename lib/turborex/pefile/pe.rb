require 'rex/peparsey'
require 'pathname'
require 'rgl/adjacency'

module TurboRex
  module PEFile
    class PE < Rex::PeParsey::Pe
      attr_accessor :image_path
      attr_reader :data_sections
      attr_reader :executable_sections

      def initialize(isource)
        super(isource)

        get_data_sections
        get_executable_sections
      end

      def data_section_names
        unless @data_sections.empty?
          names = []
          @data_sections.each do |section|
            names << section.name
          end

          return names
        end

        nil
      end

      private

      def get_data_sections
        @data_sections = []
        self.all_sections.each do |section|
          next if section.flags.nil?
          if section.flags & 0x20000000 != 0 #IMAGE_SCN_MEM_EXECUTE
            next
          end

          unless section.flags & 0x40000000 != 0 #IMAGE_SCN_MEM_READ
            next
          end

          @data_sections << section
        end
      end

      def get_executable_sections
        @executable_sections = []
        self.all_sections.each do |section|
          next if section.flags.nil?
          if section.flags & 0x20000000 != 0 #IMAGE_SCN_MEM_EXECUTE
            @executable_sections << section
          end
        end
      end
    end
  end
end