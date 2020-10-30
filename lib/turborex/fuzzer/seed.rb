module TurboRex
  module Fuzzer
    class Seed
      attr_reader :seed

      def initialize(seed)
        @seed = seed
      end

      def container=(c)
        
      end

      def self.from_file(path, separator="\n")
        File.read(path).split(separator).map {|s| new(s)}
      end
    end

    class SeedGroup
      attr_reader :seeds
      attr_accessor :energy

      def initialize(seeds, energy)
        @seeds = seeds
        @energy = energy
      end
    end
  end
end

