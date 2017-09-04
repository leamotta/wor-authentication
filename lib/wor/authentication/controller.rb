module Wor
  module Authentication
    module Controller
      def authenticate_request
        raise Wor::Authentication::Exceptions::NoKeyProvided
        decoded_token.validate!(current_entity, entity_custom_validation_value)
      end

      def decoded_token
        @decoded_token ||= Wor::Authentication::TokenManager.new(
          token_key
        ).decode(authentication_token)
      end

      def current_entity
        @current_entity ||= find_authenticable_entity(decoded_token)
      end

      alias_method :current_user, :current_entity

      def authentication_token
        if request.headers['Authorization'].blank?
          raise Wor::Authentication::Exceptions::MissingAuthorizationHeader
        end
        request.headers.fetch('Authorization', '').split(' ').last
      end

      ##########################################################################################
      #                   DEFAULT METHOD IMPLEMENTATIONS, USER SHOULD CHANGE                   #
      ##########################################################################################
      def entity_custom_validation_value
        current_entity.try(:entity_custom_validation)
      end

      def token_key
        raise Wor::Authentication::Exceptions::SubclassMustImplement unless defined?(Rails)
        if Rails.application.secrets.secret_key_base.blank?
          raise Wor::Authentication::Exceptions::NoKeyProvided
        end
        Rails.application.secrets.secret_key_base
      end

      def find_authenticable_entity(decoded_token)
        User.find_by(id: decoded_token[:id])
      end

      ##########################################################################################
      #                               DEFAULT EXCEPTION HANDLERS                               #
      ##########################################################################################
      def self.included(controller)
        Exceptions.constants.select do |e|
          break unless Exceptions.const_get(e).is_a?(Class)
          controller.rescue_from Exceptions.const_get(e), with: :default_wor_error
        end
      end

      private

      def default_wor_error(exception)
        render json: { error: exception.message }, status: exception.status_code
      end
    end
  end
end
