require 'turborex/windows/com'
require 'turborex/fuzzer/containers'
require 'turborex/fuzzer/mutators'
require 'turborex/fuzzer/coverage'
require 'turborex/fuzzer/seed'

module TurboRex
  module Fuzzer
    class InputBase

    end

    class FuzzerBase

    end

    class COMFuzzer < FuzzerBase
      class Config
        attr_reader :target

        def new_target(&block)
          @target = Docile.dsl_eval(TargetBuilder.new, &block).build
        end

        def build
          self
        end
      end
      
      Target = Struct.new(:clsid, :interface, :method, :params, :context)
      Parameter = Struct.new(:index, :container, :mutator, :fixed, :seed, :depends_on, :relationship)

      class ParamBuilder
        def initialize(index, args)
          @args = args
          @struct = Parameter.new
          @struct.index = index
        end

        def container(c)
          @struct.container = c
        end

        def seed(s, opts = {})

          if s.is_a?(Array)
          elsif s.is_a?(TurboRex::Fuzzer::Seed)
            s = [s]
          else
            raise "Invalid seed type: #{s.class}"
          end

          @struct.seed = s

          if opts[:depends_on] && opts[:relationship]
            depends_arg = @args.find {|a| a.name == opts[:depends_on].to_s}
            unless depends_arg
              raise "No such parameter: #{opts[:depends_on]}"
            end

            @struct.depends_on = opts[:depends_on]
            @struct.relationship = opts[:relationship]
          end
        end

        def mutator(m)
          @struct.mutator = m
        end

        def fixed(value)
          @struct.fixed = value
        end

        def build
          @struct
        end
      end

      class TargetBuilder
        def initialize
          @params = []
        end

        def interface(iface)
          @interface = iface
        end

        def clsid(clsid)
          @clsid = clsid
        end

        def context(context)
          @context = context
        end

        def method(name)
          method = @interface.methods.find {|m| m.name == name.to_s}
          raise "No such method #{name}" unless method

          @method = method
        end

        def build
          Target.new(@clsid, @interface, @method, @params, @context)
        end

        def method_missing(m, *args, &block)
          if m.to_s.start_with?('param_')
            name = m.to_s.split('param_')[-1]

            index = @method.type.args.index {|a| a.name == name}
            raise "No such parameter #{name}" unless index
            arg = @method.type.args[index]
            raise "The THIS pointer can't be specified." if index == 0
            @params[index-1] = Docile.dsl_eval(ParamBuilder.new(index-1, @method.type.args), &block).build
          else
            super(m, *args, &block)
          end
        end
      end

      class Input < InputBase
        def initialize(config)
          configure = config.fuzzer_configure
          target = configure.target
          @clsid = target.clsid
          @interface = target.interface
          @method = target.method
          @method_name = @method.name.to_sym

          @client = TurboRex::Windows::COM::Client.new(@clsid)
          @client.create_instance cls_context: target.context, interface: @interface
        end

        def feed(*args)
          #raw_args = args.map {|a| a.buf}
          #feed_raw(*raw_args)
          @interface.send(@method_name, *args)
        end

        # def feed_raw(*args)
        #   @interface.send(@method_name, *args)
        # end
      end

      attr_reader :input
      attr_reader :config

      def initialize(config)
        @config = config
        @input = Input.new(config)
        @growth_medium = []

        params = config.fuzzer_configure.target.params
        params.each do |p|
          if p.fixed
            p.container.fixed = p.fixed
          end

          TurboRex::Fuzzer::SeedGroup.new()
          @growth_medium << p.container
        end

        params.map {|p| p.seed }
      end

      def generate
        @growth_medium.map {|c| c.padding }
      end

    end

    class Config
      attr_reader :mechanism
      attr_reader :fuzzer_configure

      def mechanism=(m)
        raise "Should be one of these values: 'rpc', 'com'" unless [:com, :rpc].include?(m.to_sym)
        @mechanism = m
      end

      def configure(&block)
        case mechanism.to_sym
        when :rpc
          raise NotImplementedError
        when :com
          @fuzzer_configure = Docile.dsl_eval(COMFuzzer::Config.new, &block).build
        end
      end
    end

    def self.create_fuzzer(&block)
      config = Config.new
      yield(config)

      case config.mechanism.to_sym
      when :com
        COMFuzzer.new(config)
      when :rpc
        #RPCFuzzer.new(config)
      end
    end
  end
end