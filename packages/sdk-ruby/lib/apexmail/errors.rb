# frozen_string_literal: true

module ApexMail
  class Error < StandardError
    attr_reader :status_code, :code, :details

    def initialize(message, status_code: nil, code: nil, details: nil)
      super(message)
      @status_code = status_code
      @code        = code
      @details     = details
    end
  end

  class AuthenticationError < Error; end
  class ForbiddenError      < Error; end
  class ConflictError       < Error; end
  class NotFoundError       < Error; end
  class ValidationError     < Error; end
  class RateLimitError < Error
    attr_reader :retry_after

    def initialize(message, status_code: nil, code: nil, details: nil, retry_after: nil)
      super(message, status_code: status_code, code: code, details: details)
      @retry_after = retry_after
    end
  end
  class NetworkError        < Error; end
end
