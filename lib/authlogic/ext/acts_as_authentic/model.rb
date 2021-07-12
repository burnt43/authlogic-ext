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
              before_save :remove_two_factor_auth_confirmation, if: :two_factor_auth_has_changed_to_disabled?
              after_save :destroy_two_factor_auth_cookie, if: :two_factor_auth_has_changed_to_disabled?
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
          two_factor_auth_confirmed
          two_factor_auth_persistence_token
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

        def remove_two_factor_auth_confirmation
          true.tap { set_two_factor_auth_confirmed(false) }
        end

        # REVIEW: I'm not sure this should actually be in here. Maybe the app
        #   that uses this gem should be responsible for this I'm not sure.
        # REVIEW: There is some hard-coded repitition here. I'm essentially
        #   calling the Authlogic::Ext::Session#destroy_two_factor_auth_cookie
        #   method without calling it, because I don't have the session object
        #   here. I could probably do a Session.find(), but I don't know the
        #   Session class in this part of the code. I could add it as a config
        #   option maybe. This works, but its a bad smell.
        def destroy_two_factor_auth_cookie
          return unless Authlogic::Session::Base.controller

          Authlogic::Session::Base.controller.cookies.delete 'two_factor_auth_credentials', :domain => Authlogic::Session::Base.controller.cookie_domain
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

        def two_factor_auth_otp_uri
          return unless two_factor_auth_otp &&
                        acts_as_authentic_ext_config.two_factor_auth_uri_method &&
                        two_factor_auth_otp.respond_to?(acts_as_authentic_ext_config.two_factor_auth_uri_method) &&
                        acts_as_authentic_ext_config.two_factor_auth_uri_input_method

          two_factor_auth_otp.send(
            acts_as_authentic_ext_config.two_factor_auth_uri_method,
            send(acts_as_authentic_ext_config.two_factor_auth_uri_input_method)
          )
        end

        def two_factor_auth_qr_code
          uri = two_factor_auth_otp_uri
          return unless uri && acts_as_authentic_ext_config.two_factor_auth_uri_qr_code_class

          acts_as_authentic_ext_config.two_factor_auth_uri_qr_code_class.new(uri)
        end

        def two_factor_auth_qr_code_svg(width: 500, height: 500, module_size: 8)
          qr_code = two_factor_auth_qr_code
          return unless qr_code

          StringIO.new.tap do |s|
            s.print(%Q(<svg version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:ev="http://www.w3.org/2001/xml-events" width="#{width}" height="#{height}" shape-rendering="crispEdges">))
            s.print(
              qr_code.as_svg({
                color: '000',
                shape_rendering: 'crispEdges',
                standalone: false,
                use_path: true
              }.merge({
                module_size: module_size
              }))
            )
            s.print("</svg>")
          end.string
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
