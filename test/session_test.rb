module Authlogic
  module Ext
    module Testing
      class SessionTest < Authlogic::Ext::Testing::Test
        def test_should_redirect_to_two_factor_auth_code_entry
          user_class = Authlogic::Ext::Testing.generate_acts_as_authentic_class('Authlogic::Ext::Testing::User') do
            acts_as_authentic do |config|
              config.perishable_token_valid_for = 3600
              config.validate_email_field = false
              config.crypto_provider = Authlogic::CryptoProviders::Sha512
              config.merge_validates_length_of_password_field_options(minimum: 8)
            end

            acts_as_authentic_ext do |config|
              config.two_factor_auth = true
              config.two_factor_auth_otp_class = ROTP::TOTP
              config.two_factor_auth_otp_code_method = :now
              config.act_like_two_factor_auth_completed_on_enable = true
            end
          end

          session_class = Authlogic::Ext::Testing.generate_session_class('Authlogic::Ext::Testing::Session', acts_as_authentic_class: user_class) do
            generalize_credentials_error_messages true
            allow_http_basic_auth false
            find_by_login_method :find_by_username
            login_field :username
            two_factor_auth true
            two_factor_auth_threshold 1
            ignore_two_factor_auth_redirection_on "namespace1/namespace2/foos#action1"
            ignore_two_factor_auth_redirection_on "bars#action2"
          end

          controller01 = Authlogic::Ext::Testing::DummyController.new(
            controller_path: 'widgets',
            action_name: 'action1'
          )
          controller02 = Authlogic::Ext::Testing::DummyController.new(
            controller_path: 'namespace1/namespace2/foos',
            action_name: 'action1'
          )
          controller03 = Authlogic::Ext::Testing::DummyController.new(
            controller_path: 'bars',
            action_name: 'action2'
          )

          Authlogic::Session::Base.controller = controller01
          assert(session_class.should_redirect_to_two_factor_auth_code_entry?)

          Authlogic::Session::Base.controller = controller02
          refute(session_class.should_redirect_to_two_factor_auth_code_entry?)

          Authlogic::Session::Base.controller = controller03
          refute(session_class.should_redirect_to_two_factor_auth_code_entry?)
        end
      end
    end
  end
end
