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

        define_option :two_factor_auth_key_attr_name, :two_factor_auth_key
        define_option :two_factor_auth_enabled_attr_name, :two_factor_auth_enabled
        define_option :two_factor_auth_completed_attr_name, :two_factor_auth_completed
        define_option :two_factor_auth_otp_class
        define_option :two_factor_auth_otp_code_method
        define_option :act_like_two_factor_auth_completed_on_enable, true
      end
    end
  end
end
