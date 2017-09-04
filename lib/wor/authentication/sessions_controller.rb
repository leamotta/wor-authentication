module Wor
  module Authentication
    module SessionsController
      def create
        entity = authenticate_entity(authenticate_params)
        if entity
          token_data = generate_access_token(entity)
          render json: {
            access_token: token_data[:token], renew_id: token_data[:renew_id]
          }, status: :ok
        else
          render_error('Invalid authentication credentials', :unauthorized)
        end
      end

      def renew
        if !decoded_token.valid_renew_id?(renew_token_params[:renew_id])
          render_error('Invalid renew_id', :unauthorized)
        else
          render json: { access_token: renew_access_token(current_entity) }, status: :ok
        end
      end

      def invalidate_all
        # should we rescue anything here ?
        # if invalidating uses db and fails, or something like that
        entity_custom_validation_invalidate_all_value(current_entity)
        head :ok
      end

      def generate_access_token(entity)
        renew_id = token_renew_id
        payload = entity_payload(entity).merge(
          entity_custom_validation: entity_custom_validation_value(entity),
          expiration_date: new_token_expiration_date,
          maximum_useful_date: token_maximum_useful_date,
          renew_id: renew_id
        )
        access_token_object(token_key, payload, renew_id)
      end

      def renew_access_token(entity)
        payload = decoded_token.payload
        payload[:expiration_date] = new_token_expiration_date
        payload[:entity_custom_validation] = entity_custom_validation_renew_value(entity)
        Wor::Authentication::TokenManager.new(token_key).encode(payload)
      end

      def new_token_expiration_date
        Wor::Authentication.expiration_days.days.from_now.to_i
      end

      def token_maximum_useful_date
        Wor::Authentication.maximum_useful_days.days.from_now.to_i
      end

      def token_renew_id
        SecureRandom.hex(32)
      end

      def entity_custom_validation_renew_value(entity)
        entity_custom_validation_value(entity)
      end

      def entity_custom_validation_invalidate_all_value(_entity)
        nil
      end

      ##########################################################################################
      #                   DEFAULT METHOD IMPLEMENTATIONS, USER SHOULD CHANGE                   #
      ##########################################################################################
      def authenticate_entity(params)
        entity = User.find_by(email: params[:email])
        return nil unless entity.present? && entity.valid_password?(params[:password])
        entity
      end

      def entity_payload(entity)
        { id: entity.id }
      end

      def entity_custom_validation_value(entity)
        SecureRandom.hex(32).tap do |random_value|
          begin
            entity.update!(entity_custom_validation: random_value)
          rescue
            Rails.logger.info('User does not have a entity_custom_validation attribute')
          end
        end
      end

      private

      def access_token_object(token_key, payload, renew_id)
        {
          token: Wor::Authentication::TokenManager.new(token_key).encode(payload),
          renew_id: renew_id
        }
      end

      def current_entity
        @current_entity ||= find_authenticable_entity(decoded_token)
      end

      def render_error(error_message, status)
        render json: { error: error_message }, status: status
      end

      def authenticate_params
        params.require(:session)
      end

      def renew_token_params
        params.require(:session).permit(:renew_id)
      end

      def render_missing_authorization_token
        render_error('You must pass an Authorization Header with the access token', :unauthorized)
      end

      def render_invalid_authorization_token
        render_error('Invalid authorization token', :unauthorized)
      end

      def render_not_renewable_token
        render_error('Access token is not valid anymore', :unauthorized)
      end

      def render_expired_token
        render_error('Expired token', :unauthorized)
      end

      def render_entity_invalid_custom_validation
        render_error('Entity invalid custom validation', :unauthorized)
      end
    end
  end
end
