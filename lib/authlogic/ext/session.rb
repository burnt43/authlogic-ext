module Authlogic
  module Ext
    module Session
      # --------------------------------------------------
      # Include Hook
      # --------------------------------------------------

      class << self
        def included(klass)
          klass.class_eval do
            extend ClassMethods

            attr_accessor :two_factor_auth_code

            validate :two_factor_auth_code_valid?, if: :should_check_for_two_factor_auth_code_validity?

            before_save :update_ext_info

            before_destroy :unset_two_factor_auth_completed_flag
          end
        end

        # This is my own version of delegation that ActiveRecord uses.
        def define_ext_method_proxy(method_name, prefix: nil, on:)
          effective_prefix =
            if prefix == true
              "#{on}_"
            elsif prefix
              "#{prefix}_"
            else
              ''
            end

          my_method_name = "#{effective_prefix}#{method_name}"

          define_method my_method_name do |*args|
            send(on)&.send(method_name, *args)
          end
        end
      end

      # def set_two_factor_auth_completed
      define_ext_method_proxy :set_two_factor_auth_completed, prefix: true, on: :record
      # def get_two_factor_auth_enabled
      define_ext_method_proxy :get_two_factor_auth_enabled,   prefix: true, on: :record
      # def get_two_factor_auth_completed
      define_ext_method_proxy :get_two_factor_auth_completed, prefix: true, on: :record
      
      # --------------------------------------------------
      # Callback Instance Methods
      # --------------------------------------------------

      # Check to see if the code entered matches what the current code is
      # at this moment in time.
      def two_factor_auth_code_valid?
        unless two_factor_auth_code == record&.two_factor_auth_otp_code
          errors.add(:two_factor_auth_code, 'does not match')
        end
      end

      # Update an additional info here. This method is a 'before_save' callback.
      # This will happen if a login is successful or a 2FA code entry is
      # successful.
      def update_ext_info
        if two_factor_auth_code_provided?
          record_set_two_factor_auth_completed(true)
        end
      end

      # This is a 'before_destroy' callback. When destroying an Authlogic
      # session, this will be called. When destroying a session(logging out),
      # we need to unset the 'two_factor_auth_completed' flag.
      def unset_two_factor_auth_completed_flag
        record_set_two_factor_auth_completed(false)
      end

      # --------------------------------------------------
      # Callback Conditional Instance Methods
      # --------------------------------------------------

      # Method that is a companion to the 'two_factor_auth_code_valid?'
      # validation method. This is called to even see if we should be 
      # calling that validation.
      def should_check_for_two_factor_auth_code_validity?
        two_factor_auth_enabled? && record_get_two_factor_auth_enabled
      end

      # We have set the two_factor_auth_code attr to something, therefore
      # we consider this to mean that we want to validate that the input
      # that was given matches what is generated with the OTP.
      def two_factor_auth_code_provided?
        !two_factor_auth_code.blank?
      end

      # --------------------------------------------------
      # Question Instance Methods
      # --------------------------------------------------

      # Is 2FA enabled on the Authlogic Session via the 'two_factor_auth' config
      # option?
      def two_factor_auth_enabled?
        self.class.authlogic_ext_config[:two_factor_auth]
      end

      # Does the record associated with this session have their personal
      # 2FA setting enabled, but they have not completed the 2FA code
      # entry successfully? This basically means the user logged in OK
      # with a username/password, but did not enter a good 2FA code yet.
      def record_has_two_factor_auth_required_and_uncompleted?
        record_get_two_factor_auth_enabled && !record_get_two_factor_auth_completed
      end

      # --------------------------------------------------
      # Class Methods
      # --------------------------------------------------

      module ClassMethods
        # Return all the configured options as a hash.
        def authlogic_ext_config
          @authlogic_ext_config ||= {}
        end

        # Config method for enabling/disabling two_factor_auth feature.
        def two_factor_auth(value)
          @authlogic_ext_config ||= {}
          @authlogic_ext_config[:two_factor_auth] = value
        end

        def ignore_two_factor_auth_redirection_on(controller_action_name)
          @authlogic_ext_config ||= {}
          (@authlogic_ext_config[:ignore_two_factor_auth_redirection_on] ||= []).push(controller_action_name)
        end

        def should_redirect_to_two_factor_auth_code_entry?
          c = Authlogic::Session::Base.controller
          current_controller_action_name = "#{c.controller_path}##{c.action_name}"

          (authlogic_ext_config[:ignore_two_factor_auth_redirection_on] || []).none? do |controller_action_name|
            current_controller_action_name == controller_action_name
          end
        end
      end
    end
  end
end
