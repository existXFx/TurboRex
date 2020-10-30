require 'turborex/windows/security/ace.rb'

module TurboRex
  class Windows < Metasm::WinOS
    module Security
      class ACL
        class DACL < ACL
          attr_reader :revision
          attr_reader :count
          attr_reader :ace_list

          def initialize(revision, count, ace_list=[])
            @revision = revision
            @count = count
            @ace_list = ace_list.freeze
          end

          def self.from_raw(raw)
            raise NotImplementedError
          end
        end
      end
    end
  end
end