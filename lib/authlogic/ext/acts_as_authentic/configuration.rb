module Authlogic
  module Ext
    module ActsAsAuthentic
      class Configuration
        class << self
          def define_option(name, default_value=nil)
            option_setter_method = "#{name}="
            option_getter_method = "#{name}"
            instance_variable_name = "@#{name}"

            define_method option_setter_method do |value|
              instance_variable_set(instance_variable_name, value)
            end

            define_method option_getter_method do
              instance_variable_get(instance_variable_name) || default_value
            end
          end
        end

        define_option :two_factor_auth, false
        alias_method :two_factor_auth_required?, :two_factor_auth

        #
        # v1 2FA Options (Base Feature with Authenticator Support)
        #

        define_option :two_factor_auth_key_attr_name, :two_factor_auth_key
        define_option :two_factor_auth_enabled_attr_name, :two_factor_auth_enabled
        define_option :two_factor_auth_persistence_token_attr_name, :two_factor_auth_persistence_token
        define_option :two_factor_auth_confirmed_attr_name, :two_factor_auth_confirmed
        define_option :two_factor_auth_failure_count_attr_name, :two_factor_auth_failure_count
        define_option :two_factor_auth_last_successful_auth_attr_name, :two_factor_auth_last_successful_auth
        define_option :two_factor_auth_otp_class
        define_option :two_factor_auth_otp_code_method
        define_option :two_factor_auth_uri_method
        define_option :two_factor_auth_uri_input_method
        define_option :two_factor_auth_uri_qr_code_class

        #
        # v2 2FA Options (Email Support)
        #
        
        # Option for what kind of 2FA you want: authenticator app or email code.
        define_option :two_factor_auth_method_attr_name

        # Email related options.
        define_option :two_factor_auth_email_code_attr_name
        define_option :two_factor_auth_email_code_sent_at_attr_name
        define_option :two_factor_auth_email_code_expiry, 600
        define_option :two_factor_auth_email_code_deliver_proc

        # Nil auth method options.
        define_option :allow_new_records_auth_method_nil, false
        alias_method :allow_new_records_auth_method_nil?, :allow_new_records_auth_method_nil

        define_option :allow_pre_existing_auth_method_nil, false
        alias_method :allow_pre_existing_auth_method_nil?, :allow_pre_existing_auth_method_nil

        define_option :new_records_auth_method_set_to_nil, false
        alias_method :new_records_auth_method_set_to_nil?, :new_records_auth_method_set_to_nil

        # --------------------------------------------------
        # Instance Methods
        # --------------------------------------------------

        # Temporarily override one or more options for the duration of the
        # given block, then restore each option back to whatever value it
        # had before the block ran (even if the block raises).
        #
        # Example:
        #   config.with_temporary_options(allow_new_records_auth_method_nil: true) do
        #     # ... allow_new_records_auth_method_nil is true in here ...
        #   end
        def with_temporary_options(overrides)
          original_values = overrides.each_key.each_with_object({}) do |name, memo|
            memo[name] = send(name)
          end

          overrides.each { |name, value| send("#{name}=", value) }

          yield
        ensure
          original_values.each { |name, value| send("#{name}=", value) }
        end
      end
    end
  end
end
