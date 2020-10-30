module TurboRex
  module Fuzzer
    module Mutators
      class CharlieMillerMutator
        attr_accessor :factor

        def initialize(factor=100)
          @factor = factor
        end

        def mutate(buf)
          numwrites = rand(buf.bytesize.to_f / @factor)+1
          numwrites.to_i.times do |i|
            rbytes = rand(256)
            rn = rand(buf.bytesize)
            buf[rn] = rbytes.chr
          end

          buf
        end
      end
    end
  end
end

