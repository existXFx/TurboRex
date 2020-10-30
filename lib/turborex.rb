module TurboRex
  def self.root
    File.expand_path('../..', __FILE__)
  end

  require 'os'
  require 'securerandom'
  require 'parallel' unless ::OS.windows?
  require 'metasm'
  require 'turborex/monkey'
  require 'turborex/utils'
  require 'turborex/exception'
  require 'turborex/windows'
  require 'turborex/fuzzer'
  require 'turborex/pefile'
  require 'turborex/msrpc'
  require 'turborex/cstruct'


  include TurboRex::Utils
end