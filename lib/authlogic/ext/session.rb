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
            validate :increment_two_factor_auth_failure_count
            validate :two_factor_auth_failure_threshold_reached

            after_persisting :check_two_factor_auth_persistence_token

            before_save :update_ext_info

            after_save :save_two_factor_auth_cookie, if: :should_call_save_two_factor_auth_cookie_callback?

            before_destroy :unset_two_factor_auth_completed_flag

            after_destroy :destroy_two_factor_auth_cookie
          end
        end
      end

      # --------------------------------------------------
      # Instance Methods
      # --------------------------------------------------

      def reset_two_factor_auth_failure_count
        record.set_two_factor_auth_failure_count(0)
      end

      # --------------------------------------------------
      # 2FA Completion Methods
      # --------------------------------------------------

      def set_two_factor_auth_completed_flag
        @two_factor_auth_completed = true
      end

      def unset_two_factor_auth_completed_flag
        @two_factor_auth_completed = false
      end

      def two_factor_auth_completed?
        @two_factor_auth_completed
      end

      # --------------------------------------------------
      # 2FA Persistence Token Methods
      # --------------------------------------------------

      def reset_two_factor_auth_persistence_token
        record.set_two_factor_auth_persistence_token(Authlogic::Random.hex_token)
      end

      def should_reset_two_factor_auth_persistence_token?
        return false unless record

        record.get_two_factor_auth_persistence_token.nil?
      end

      # --------------------------------------------------
      # 2FA Cookie Methods
      # --------------------------------------------------

      # REVIEW: This might be better as a configurable option, instead of
      #   hard-coded.
      def two_factor_auth_cookie_key
        'two_factor_auth_credentials'
      end

      def generate_two_factor_auth_cookie_for_saving
        {
          value:    "#{record.get_two_factor_auth_persistence_token}",
          expires:  nil,
          secure:   secure,
          httponly: httponly,
          domain:   controller.cookie_domain
        }
      end

      def save_two_factor_auth_cookie
        if sign_cookie?
          controller.cookies.signed[two_factor_auth_cookie_key] = generate_two_factor_auth_cookie_for_saving
        else
          controller.cookies[two_factor_auth_cookie_key] = generate_two_factor_auth_cookie_for_saving
        end
      end

      def two_factor_auth_cookie_credentials
        if self.class.sign_cookie
          cookie = controller.cookies.signed[two_factor_auth_cookie_key]
        else
          cookie = controller.cookies[two_factor_auth_cookie_key]
        end

        return {} unless cookie

        data = cookie.split('::')
        {
          two_factor_auth_persistence_token: data[0]
        }
      end

      def should_call_save_two_factor_auth_cookie_callback?
        two_factor_auth_code_provided?
      end

      def destroy_two_factor_auth_cookie
        controller.cookies.delete two_factor_auth_cookie_key, :domain => controller.cookie_domain
      end

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

      def increment_two_factor_auth_failure_count
        if errors.key?(:two_factor_auth_code) && attempted_record
          old_count = attempted_record.get_two_factor_auth_failure_count
          return unless old_count

          new_count = old_count + 1
          attempted_record.set_two_factor_auth_failure_count(new_count)
        end
      end

      def two_factor_auth_failure_threshold_reached
        threshold = self.class.authlogic_ext_config[:two_factor_auth_threshold]
        return unless threshold && attempted_record && attempted_record.get_two_factor_auth_failure_count >= threshold

        reset_two_factor_auth_failure_count

				# NOTE: This callback will be called in the validation phase and this will
				#   only execute on a validation failure. I would like to destroy this
        #   very session, but its still in the validation phase so if I call
        #   destroy directly it will clear ALL data including errors and it
        #   will make change the return value of the save or valid? method
        #   to true even though it is false. So to get around this, I just
        #   took only the lines I need from the destroy method to make it
        #   so the user has to log in from the start again instead of being
        #   stuck on the 2FA code entry part of the authentication pipeline.
				before_destroy
				@record = nil
				after_destroy
      end

      def check_two_factor_auth_persistence_token
        if record
          two_factor_auth_persistence_token_from_cookie = two_factor_auth_cookie_credentials[:two_factor_auth_persistence_token]

          if !record.get_two_factor_auth_persistence_token.blank? &&
             record.get_two_factor_auth_persistence_token == two_factor_auth_persistence_token_from_cookie
          then
            set_two_factor_auth_completed_flag
          else
            unset_two_factor_auth_completed_flag
          end
        else
          unset_two_factor_auth_completed_flag
        end
      end

      # Update an additional info here. This method is a 'before_save' callback.
      # This will happen if a login is successful or a 2FA code entry is
      # successful.
      def update_ext_info
        # If a 2FA code was provided and a record exists, then we consider
        # this to mean that the Session object was saved successfully with
        # a 2FA code.
        if two_factor_auth_code_provided? && record
          if should_reset_two_factor_auth_persistence_token?
            reset_two_factor_auth_persistence_token
          end

          # Reset the failure count.
          reset_two_factor_auth_failure_count

          # Set last_successful_auth to right now!
          record.set_two_factor_auth_last_successful_auth(Time.now)
        end
      end

      # --------------------------------------------------
      # Callback Conditional Instance Methods
      # --------------------------------------------------

      # Method that is a companion to the 'two_factor_auth_code_valid?'
      # validation method. This is called to even see if we should be 
      # calling that validation.
      def should_check_for_two_factor_auth_code_validity?
        two_factor_auth_enabled? && record&.get_two_factor_auth_enabled
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
        record&.get_two_factor_auth_enabled && !two_factor_auth_completed?
      end

      # --------------------------------------------------
      # Class Methods
      # --------------------------------------------------

      module ClassMethods

        # Config method for enabling/disabling two_factor_auth feature.
        def two_factor_auth(value)
          @authlogic_ext_config ||= {}
          @authlogic_ext_config[__method__.to_sym] = value
        end

        def two_factor_auth_threshold(value)
          @authlogic_ext_config ||= {}
          @authlogic_ext_config[__method__.to_sym] = value
        end

        def ignore_two_factor_auth_redirection_on(controller_action_name)
          @authlogic_ext_config ||= {}
          (@authlogic_ext_config[__method__.to_sym] ||= []).push(controller_action_name)
        end

        # Return all the configured options as a hash.
        def authlogic_ext_config
          @authlogic_ext_config ||= {}
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
