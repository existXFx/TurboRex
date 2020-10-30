# Monkey patches

module Metasm
  class COFF < ExeFormat
    class LoadConfig < SerialStruct
      # For CFG fields
      xwords :guard_check_icall, :guard_dispatch_icall, :guard_fids_table, :cffunc_count
      word :guard_flags
    end
  end
end