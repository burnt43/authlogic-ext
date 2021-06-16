module Authlogic
  module Ext
    module ActsAsAuthentic
      module Controller
        #
        # Include Hook
        #

        class << self
          def included(klass)
            klass.class_eval do
              extend ClassMethods
            end
          end
        end

        #
        # Instance Methods
        #

        def should_redirect_to_two_factor_auth_code_entry?
          !(
            self.is_a?(Sandbox::WebUser::SessionsController) &&
            (
              action_name == 'two_factor_auth_code_entry' ||
              action_name == 'validate_two_factor_auth_code_entry'
            )
          )
        end

        #
        # Class Methods
        #

        module ClassMethods
        end
      end
    end
  end
end
