require './test/init'

module Authlogic
  module Ext
    module Testing
      class ActsAsAuthenticModelTest < Authlogic::Ext::Testing::Test
        def test_something
          user_class =
            Authlogic::Ext::Testing.generate_acts_as_authentic_class('Authlogic::Ext::Test::UserClass01') do
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

          session_class =
            Authlogic::Ext::Testing.generate_session_class(
              'Authlogic::Ext::Test::SessionClass',
              acts_as_authentic_class: user_class
            ) do
              generalize_credentials_error_messages true
              allow_http_basic_auth false
              find_by_login_method :find_by_username
              login_field :username
              two_factor_auth true
            end

          assert(true)
        end
      end
    end
  end
end
