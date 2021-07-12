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

            after_persisting :check_two_factor_auth_persistence_token, if: :should_check_two_factor_auth_persistence_token?

            after_two_factor_auth_failed :increment_two_factor_auth_failure_count

            # NOTE: I think this callback should be last in the
            #   after_two_factor_auth_failed group. If you add more, then it
            #   should be defined before this one, unless you have a good
            #   reason to add it afterwards.
            after_two_factor_auth_failed :check_two_factor_auth_failure_threshold_reached

            after_two_factor_auth_succeeded :reset_two_factor_auth_persistence_token, if: :should_reset_two_factor_auth_persistence_token?
            after_two_factor_auth_succeeded :reset_two_factor_auth_failure_count
            after_two_factor_auth_succeeded :update_two_factor_auth_last_successful_auth
            after_two_factor_auth_succeeded :set_two_factor_auth_confirmed

            after_two_factor_auth_failure_threshold_reached :reset_two_factor_auth_failure_count
            after_two_factor_auth_failure_threshold_reached :disable_two_factor_auth_on_record, if: :should_disable_two_factor_auth_on_record?
            after_two_factor_auth_failure_threshold_reached :destroy_self

            before_save :run_after_two_factor_auth_succeeded_callbacks, if: :should_run_after_two_factor_auth_succeeded_callbacks?

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

      def run_after_two_factor_auth_succeeded_callbacks
        run_authlogc_ext_callbacks(:after, :two_factor_auth_succeeded)
      end

      def should_run_after_two_factor_auth_succeeded_callbacks?
        two_factor_auth_enabled? &&
        two_factor_auth_code_provided? &&
        record &&
        record.get_two_factor_auth_enabled
      end

      def update_two_factor_auth_last_successful_auth
        record.set_two_factor_auth_last_successful_auth(Time.now)
      end

      def set_two_factor_auth_confirmed
        record.set_two_factor_auth_confirmed(true)
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
          run_authlogc_ext_callbacks(:after, :two_factor_auth_failed)
        end
      end

      def increment_two_factor_auth_failure_count
        old_count = attempted_record.get_two_factor_auth_failure_count
        return unless old_count

        new_count = old_count + 1
        attempted_record.set_two_factor_auth_failure_count(new_count)
      end

      def check_two_factor_auth_failure_threshold_reached
        threshold = self.class.authlogic_ext_config[:two_factor_auth_threshold]
        return unless threshold && attempted_record && attempted_record.get_two_factor_auth_failure_count >= threshold

        run_authlogc_ext_callbacks(:after, :two_factor_auth_failure_threshold_reached)
      end

      def disable_two_factor_auth_on_record
        record&.set_two_factor_auth_enabled(false)
      end

      def should_disable_two_factor_auth_on_record?
        record && !record.get_two_factor_auth_confirmed
      end

      def destroy_self
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

      # This is an 'after_persisting' callback. 'after_persisting' is a special
      # callback defined in the real Authlogic library. It basically means that
      # we've found a Session using some means of persistence. From MTT's
      # perspective, this means that we've found the session using the
      # persistence token in the cookies. In our design, we also have a
      # persistence token that represents that 2FA was completed. In this method
      # we are checking the existence of the 2FA persistence token and whether
      # or not it matches what the record has in the database. If it does match,
      # then we set a flag saying that this Session must have completed 2FA at
      # some point, if it does not match, then we make sure the flag is unset.
      # This means that the Session is still expecting a 2FA code to complete
      # authentication.
      def check_two_factor_auth_persistence_token
        if record
          two_factor_auth_persistence_token_from_cookie = two_factor_auth_cookie_credentials[:two_factor_auth_persistence_token]

          if !record.get_two_factor_auth_persistence_token.blank? &&
             record.get_two_factor_auth_persistence_token == two_factor_auth_persistence_token_from_cookie
          then
            # The cookie matches, so we'll set the flag.
            set_two_factor_auth_completed_flag
          else
            if single_access
              # If we couldn't match based on the cookie, but we authenticated
              # with the single access token, then we'll just set the flag
              # here without needing to actually send the 2FA code.
              set_two_factor_auth_completed_flag
            else
              # No single access given and cookie doesn't match so unset the
              # flag.
              unset_two_factor_auth_completed_flag
            end
          end
        else
          # No record was even found, so unset the flag.
          unset_two_factor_auth_completed_flag
        end
      end

      def should_check_two_factor_auth_persistence_token?
        two_factor_auth_enabled?
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
      # Authlogic::Ext Callback Methods
      # --------------------------------------------------

      def run_authlogc_ext_callbacks(callback_when, callback_type)
        callbacks = self.class.authlogic_ext_callbacks.dig(callback_type.to_sym, callback_when.to_sym)
        return unless callbacks

        callbacks.each do |callback_config|
          callback_object = callback_config[:callback_object]
          next unless callback_object

          if_condition = callback_config.dig(:options, :if)
          next if if_condition && !execute_authlogic_ext_callback_object(if_condition)

          execute_authlogic_ext_callback_object(callback_object)
        end
      end

      def execute_authlogic_ext_callback_object(callback_object)
        if callback_object.is_a?(Proc)
          instance_exec(&callback_object)
        else
          send(callback_object)
        end
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

        # REVIEW: I should probably figure out how to utilize ActiveRecord's
        #   callback system, but I can quickly just write my own.

        # NOTE: This is meta-programming to basically define the following
        #   methods. (Including, but not limited to):
        #   - def after_two_factor_auth_succeeded
        #   - def after_two_factor_auth_failed
        callbacks = {
          two_factor_auth_succeeded: %i[after],
          two_factor_auth_failed: %i[after],
          two_factor_auth_failure_threshold_reached: %i[after]
        }

        callbacks.each do |callback_type, callback_whens|
          callback_whens.each do |callback_when|
            define_callback_method_name = "#{callback_when}_#{callback_type}"

            define_method define_callback_method_name do |method_or_proc, **options|
              @authlogic_ext_callbacks ||= {}
              @authlogic_ext_callbacks[callback_type] ||= {}
              @authlogic_ext_callbacks[callback_type][callback_when] ||= []
              @authlogic_ext_callbacks[callback_type][callback_when].push({
                callback_object: method_or_proc,
                options: options
              })
            end
          end
        end

        def authlogic_ext_callbacks
          @authlogic_ext_callbacks || {}
        end
      end
    end
  end
end
