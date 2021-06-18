require './test/init'

module Authlogic
  module Ext
    module Testing
      class ActsAsAuthenticModelTest < Authlogic::Ext::Testing::Test
        def test_basic_2fa_setup
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
              config.two_factor_auth_uri_method = :provisioning_uri
              config.two_factor_auth_uri_input_method = :username
              config.two_factor_auth_uri_qr_code_class = RQRCode::QRCode
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
          end

          # --------------------------------------------------
          # Create a basic user with a username and password. Leave 2FA
          # disabled on this user.
          # --------------------------------------------------
          user = user_class.new(
            username: 'user01',
            password: 'my*pass*word',
            password_confirmation: 'my*pass*word'
          )
          user.save

          # No 2FA columns should have been changed.
          assert_nil(user.two_factor_auth_key)
          refute(user.two_factor_auth_enabled?)
          refute(user.two_factor_auth_completed?)

          # 2FA methods should not return anything.
          assert_nil(user.two_factor_auth_otp)
          assert_nil(user.two_factor_auth_otp_code)
          assert_nil(user.two_factor_auth_otp_uri)
          assert_nil(user.two_factor_auth_qr_code)
          assert_nil(user.two_factor_auth_qr_code_svg)

          # --------------------------------------------------
          # Login (With 2FA disabled and wrong password)
          # --------------------------------------------------
          session_class.within_request do |session, record|
            assert_nil(session)

            new_session = session_class.new(
              username: 'user01',
              password: 'not_the_password'
            )
            save_result = new_session.save
            refute(save_result)
          end

          # --------------------------------------------------
          # Login (With 2FA disabled and the right password)
          # --------------------------------------------------
          session_class.within_request do |session, record|
            assert_nil(session)

            new_session = session_class.new(
              username: 'user01',
              password: 'my*pass*word'
            )
            save_result = new_session.save
            assert(save_result)
          end

          # --------------------------------------------------
          # We're logged in so find the session!
          # --------------------------------------------------
          session_class.within_request do |session, record|
            refute_nil(session)

            # This method should be false since the record doesn't even have
            # 2FA enabled.
            refute(session.record_has_two_factor_auth_required_and_uncompleted?)

            # No 2FA columns should have been changed.
            assert_nil(record.two_factor_auth_key)
            refute(record.two_factor_auth_enabled?)
            refute(record.two_factor_auth_completed?)

            # 2FA methods should not return anything.
            assert_nil(record.two_factor_auth_otp)
            assert_nil(record.two_factor_auth_otp_code)
            assert_nil(record.two_factor_auth_otp_uri)
            assert_nil(record.two_factor_auth_qr_code)
            assert_nil(record.two_factor_auth_qr_code_svg)
          end

          # --------------------------------------------------
          # Enable 2FA on the user
          # --------------------------------------------------
          session_class.within_request do |session, record|
            update_result = record.update_attributes(two_factor_auth_enabled: true)
            assert(update_result)

            # We should see this as true since we just set it.
            assert(record.two_factor_auth_enabled?)
            # A key should have automatically been generated.
            refute_nil(record.two_factor_auth_key)
            # act_like_two_factor_auth_completed_on_enable=true, so this will
            # get set to true.
            assert(record.two_factor_auth_completed)
            # The OTP methods should now give some data.
            refute_nil(record.two_factor_auth_otp)
            refute_nil(record.two_factor_auth_otp_code)
            refute_nil(record.two_factor_auth_otp_uri)
            refute_nil(record.two_factor_auth_qr_code)
            refute_nil(record.two_factor_auth_qr_code_svg)
          end

          # --------------------------------------------------
          # Logout the User
          # --------------------------------------------------
          session_class.within_request do |session, record|
            # Logout by destroying the session.
            session.destroy

            # The user should have its completed flag unset. Which will require
            # the user to enter 2FA on its next login.
            refute(record.two_factor_auth_completed?)
          end

          # --------------------------------------------------
          # Login (With 2FA enabled)
          # --------------------------------------------------
          session_class.within_request do |session, record|
            assert_nil(session)

            new_session = session_class.new(
              username: 'user01',
              password: 'my*pass*word'
            )
            save_result = new_session.save
            assert(save_result)
          end

          # --------------------------------------------------
          # After logging in, the session should recognize we
          # need to enter a 2FA code
          # --------------------------------------------------
          session_class.within_request do |session, record|
            # The session should be in a state where it is expecting to receive
            # a 2FA code to complete authentication.
            assert(session.record_has_two_factor_auth_required_and_uncompleted?)
            assert_equal(0, record.two_factor_auth_failure_count)
            assert_nil(record.two_factor_auth_last_successful_auth)
          end

          # --------------------------------------------------
          # Simulate user entering a 2FA code (Incorrect Code)
          # --------------------------------------------------
          session_class.within_request do |session, record|
            session.two_factor_auth_code = 'xxxyyy'
            save_result = session.save
            refute(save_result)
            assert(session.errors.messages.key?(:two_factor_auth_code))
            assert_equal(1, record.two_factor_auth_failure_count)
            assert_nil(record.two_factor_auth_last_successful_auth)
          end

          # --------------------------------------------------
          # Login again because we failed to enter a code and
          # reached the configured threshold of 1. This means
          # the session gets killed and the user has to log
          # in again from the start.
          # --------------------------------------------------
          session_class.within_request do |session, record|
            assert_nil(session)

            new_session = session_class.new(
              username: 'user01',
              password: 'my*pass*word'
            )
            save_result = new_session.save
            assert(save_result)
          end

          # --------------------------------------------------
          # Simulate user entering a 2FA code (Correct Code)
          # --------------------------------------------------
          session_class.within_request do |session, record|
            session.two_factor_auth_code = record.two_factor_auth_otp_code
            save_result = session.save
            assert(save_result)
            assert_equal(0, record.two_factor_auth_failure_count)
            refute_nil(record.two_factor_auth_last_successful_auth)
          end

          # --------------------------------------------------
          # We should now be fully authenticated with both
          # username/password and the 2FA code.
          # --------------------------------------------------
          session_class.within_request do |session, record|
            refute(session.record_has_two_factor_auth_required_and_uncompleted?)
          end

          # --------------------------------------------------
          # Logout
          # --------------------------------------------------
          session_class.within_request do |session, record|
            session.destroy
            refute(record.two_factor_auth_completed?)
          end

          # --------------------------------------------------
          # Session is gone
          # --------------------------------------------------
          session_class.within_request do |session, record|
            assert_nil(session)
          end
        end
      end
    end
  end
end
