module TurboRex
  module PEFile
    module Scanner
      require 'rgl/path'

      def self.scan_section(section, regex)
        index = 0

        hits = []

        while index < section.size && (index = section.index(regex, index)) != nil

          idx = index
          buf = ''
          mat = nil

          while (!(mat = buf.match(regex)))
            buf << section.read(idx, 1)
            idx += 1
          end

          rva = section.offset_to_rva(index)

          hits << [rva, buf.unpack("H*")]
          index += buf.length
        end

        return hits
      end

      def self.scan_all_sections(pe, regex)
        result = []

        pe.all_sections.each do |section|
          Scanner.scan_section(section, regex).each do |r|
            result << r
          end
        end
      end

      def self.data_section?(section)
        if section.flags & 0x20000000 != 0 #IMAGE_SCN_MEM_EXECUTE
          return false
        end

        unless section.flags & 0x40000000 != 0 #IMAGE_SCN_MEM_READ
          return false
        end

        return true
      end

      def has_path?(dasm, addr1, addr2, dg=nil)
        dg = draw_xrefs_dg(dasm, addr1) unless dg

        v1 = dasm.get_label_at(addr1) || addr1.to_s
        v2 = dasm.get_label_at(addr2) || addr2.to_s
        dg.path?(v1, v2)
      end

      def draw_xrefs_dg(dasm, addr1)
        g = dasm.function_graph_from(addr1)
        dg = RGL::DirectedAdjacencyGraph.new

        (g.keys + g.values).flatten.uniq.each do |e|
          label = dasm.get_label_at(e) || e.to_s
          dg.add_vertex label
        end
  
        g.each do |k, v|
          kl = dasm.get_label_at(k) || k.to_s
          v.each do |e|
            el = dasm.get_label_at(e) || e.to_s
            dg.add_edge(kl, el)
          end
        end

        dg
      end
    end
  end
end