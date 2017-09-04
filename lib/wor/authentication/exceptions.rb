module Wor
  module Authentication
    module Exceptions
      class BaseError < StandardError
        def message
          exception_name = self.class.to_s.split('::').last
          camel_case_splitted = exception_name.split(/(?=[A-Z])/)
          camel_case_splitted.join(' ')
        end

        def status_code
          401
        end
      end

      class InvalidExpirationDays < BaseError; end
      class InvalidMaximumUsefulDays < BaseError; end
      class SubclassMustImplement < BaseError; end
      class NoKeyProvided < BaseError; end
      class InvalidAuthorizationToken < BaseError; end

      class ExpiredToken < BaseError
        def message
          "Token's maximum_useful_date reached."
        end
      end

      class NotRenewableToken < BaseError
        def message
          "Token's expiration_date reached."
        end
      end

      class NoEntityPresent < BaseError
        def message
          "Token's owner not found."
        end
      end

      class MissingAuthorizationHeader < BaseError
        def message
          'Token not found in "Authorization" header.'
        end
      end
    end
  end
end
