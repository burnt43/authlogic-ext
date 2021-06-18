module Authlogic
  module Ext
    module ActsAsAuthentic
      module Model
        # --------------------------------------------------
        # Include Hook
        # --------------------------------------------------

        class << self
          def included(klass)
            klass.class_eval do
              extend ClassMethods

              # Try and make a new 2FA key.
              before_save :generate_two_factor_auth_key, if: :two_factor_auth_has_changed_to_enabled?
              before_save :set_two_factor_auth_completed_flag, if: :should_set_two_factor_auth_completed_flag?
              before_save :unset_two_factor_auth_completed_flag, if: :should_unset_two_factor_auth_completed_flag?
            end
          end
        end

        # --------------------------------------------------
        # Instance Methods
        # --------------------------------------------------

        # Define getter/setters for attributes that can have whatever actual
        # columns names you want in your table.
        %i[
          two_factor_auth_key
          two_factor_auth_enabled
          two_factor_auth_completed
          two_factor_auth_failure_count
          two_factor_auth_last_successful_auth
        ].each do |virtual_attr_name|
          config_attr_name_method = "#{virtual_attr_name}_attr_name"

          getter_method_name = "get_#{virtual_attr_name}"
          setter_method_name = "set_#{virtual_attr_name}"
          change_method_name = "get_#{virtual_attr_name}_changes"


          define_method getter_method_name do
            actual_attr_name = acts_as_authentic_ext_config&.send(config_attr_name_method)
            return unless actual_attr_name && respond_to?(actual_attr_name)

            send(actual_attr_name)
          end

          define_method setter_method_name do |value|
            actual_attr_name = acts_as_authentic_ext_config&.send(config_attr_name_method)
            return unless actual_attr_name && respond_to?(actual_attr_name)

            send("#{actual_attr_name}=", value)
          end

          define_method change_method_name do
            actual_attr_name = acts_as_authentic_ext_config&.send(config_attr_name_method)
            return unless actual_attr_name && respond_to?(actual_attr_name)

            send("#{actual_attr_name}_change")
          end
        end

        # --------------------------------------------------
        # Callback Instance Methods
        # --------------------------------------------------

        # Generate the key that will be used for Time-Based OTP.
        # Options:
        #   force: Generate a new key even if 1 already exists. This is a
        #          dangerous option, because the user/customer will most
        #          likely already have a 2FA app configured with this key.
        #          Changing it will force the customer to also update the
        #          value in their app.
        def generate_two_factor_auth_key(force: false)
          return unless acts_as_authentic_ext_config&.two_factor_auth_required?

          if get_two_factor_auth_key.nil? || force
            set_two_factor_auth_key(ROTP::Base32.random)
          end
        end

        def set_two_factor_auth_completed_flag
          set_two_factor_auth_completed(true)
        end

        def unset_two_factor_auth_completed_flag
          set_two_factor_auth_completed(false)

          # Return true otherwise this will mess up ActiveRecord's before_save
          # callback system and abort the mission.
          true
        end

        # --------------------------------------------------
        # Callback Conditional Instance Methods
        # --------------------------------------------------

        # See if the value of the two_factor_auth_enabled column has changed
        # from false to true.
        def two_factor_auth_has_changed_to_enabled?
          return false unless acts_as_authentic_ext_config.two_factor_auth_required?

          get_two_factor_auth_enabled_changes == [false, true]
        end

        def should_set_two_factor_auth_completed_flag?
          acts_as_authentic_ext_config.act_like_two_factor_auth_completed_on_enable &&
          two_factor_auth_has_changed_to_enabled?
        end


        def should_unset_two_factor_auth_completed_flag?
          two_factor_auth_has_changed_to_disabled?
        end

        def two_factor_auth_has_changed_to_disabled?
          return false unless acts_as_authentic_ext_config.two_factor_auth_required?

          get_two_factor_auth_enabled_changes == [true, false]
        end

        # --------------------------------------------------
        # 2FA Instance Methods
        # --------------------------------------------------

        # Get the instance the OTP class that will be used for generating
        # codes.
        def two_factor_auth_otp
          return @two_factor_auth_otp if defined?(@two_factor_auth_otp)

          if !get_two_factor_auth_key.blank? &&
             acts_as_authentic_ext_config.two_factor_auth_otp_class
          then
            @two_factor_auth_otp = acts_as_authentic_ext_config.two_factor_auth_otp_class.new(get_two_factor_auth_key)
          end
        end

        # Return a generated code.
        def two_factor_auth_otp_code
          two_factor_auth_otp&.send(acts_as_authentic_ext_config.two_factor_auth_otp_code_method)
        end

        # --------------------------------------------------
        # Config Methods
        # --------------------------------------------------

        # Access the config that was created for the class of this object.
        def acts_as_authentic_ext_config
          self.class.acts_as_authentic_ext_config
        end

        # --------------------------------------------------
        # Class Methods
        # --------------------------------------------------

        module ClassMethods
          # This is my version of 'acts_as_authentic'. I tried to make it
          # just like the real one. Instead of patching in my own config
          # in the existing 'acts_as_authentic', I just made a entirely
          # new one that separates the new config that I've added.
          def acts_as_authentic_ext(&block)
            return unless block

            config = Authlogic::Ext::ActsAsAuthentic::Configuration.new
            block.call(config)

            @acts_as_authentic_ext_config = config
          end

          def acts_as_authentic_ext_config
            @acts_as_authentic_ext_config
          end
        end
      end
    end
  end
end
