module TurboRex
  module Exception

    module ALPC
      include Exception

      class BufferTooSmall < RuntimeError
        def to_s
          "The length of Buffer is too small."
        end
      end

      class TooManyRetries < RuntimeError
        def to_s
          "Too many retries."
        end
      end

      class UnknownPayloadType < RuntimeError
        def to_s
          "The payload type is invalid."
        end
      end

      class ReplyMessageMismatch < RuntimeError
        def to_s
          "An attempt was made to reply to an LPC message, but the thread specified by the client ID in the message was not waiting on that message."
        end
      end

      class UnableToAcceptConnection < RuntimeError

      end
    end

    module MSRPC
      class InvalidParamDescriptor < StandardError
      end

      class InvalidTypeFormatString < StandardError

      end

      class UnknownSymbolName < StandardError

      end
    end

    class UnknownError < StandardError
      def to_s
        "An unknown error occurred."
      end
    end

    class NotNTSuccess < StandardError
      def initialize(ntstatus='')
        @message = "The return value isn't one of NT_SUCCESS： #{ntstatus}"
      end

      def to_s
        @message
      end
    end
  end
end
