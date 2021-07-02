require './test/init'

module Authlogic
  module Ext
    module Testing
      class ActsAsAuthenticModelTest < Authlogic::Ext::Testing::Test
        # {{{ def test_simulate_2fa_failures
        def test_simulate_2fa_failures
          user_class = Authlogic::Ext::Testing.generate_acts_as_authentic_class('Authlogic::Ext::Testing::User') do
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
            two_factor_auth true
            two_factor_auth_threshold 2
          end

          # TODO:
          #   1. set off threshold before 2FA is confirmed and test that 2fa gets disabled
          #   2. set off threshold after 2FA is confirmed and test that 2fa remains enabled
          #   3. clean up the methods in session/models to put them in the right categories
        end
        # }}}

        # {{{ def test_simulate_log_in_and_out_for_user_with_2fa_enabled
        def test_simulate_log_in_and_out_for_user_with_2fa_enabled
          user_class = Authlogic::Ext::Testing.generate_acts_as_authentic_class('Authlogic::Ext::Testing::User') do
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
            two_factor_auth true
          end

          # --------------------------------------------------
          # Create a User
          # --------------------------------------------------
          user = user_class.new(
            username: 'user01',
            password: 'some*password',
            password_confirmation: 'some*password',
            two_factor_auth_enabled: true
          )
          result = user.save
          assert(result)

          # Some 2FA columns should have beeen initialized
          assert(user.two_factor_auth_enabled?)
          refute(user.two_factor_auth_confirmed)
          assert_nil(user.two_factor_auth_persistence_token)
          assert_nil(user.two_factor_auth_last_successful_auth)
          refute_nil(user.two_factor_auth_key)
          assert_equal(0, user.two_factor_auth_failure_count)

          # --------------------------------------------------
          # Fail to Login
          # --------------------------------------------------
          session_class.within_request do |session, record|
            assert_nil(session)
            assert_nil(record)

            new_session = session_class.new(
              username: 'user01',
              password: 'not_the_password'
            )
            save_result = new_session.save
            refute(save_result)

            record = new_session.attempted_record
            refute_nil(record)

            # The failure count for 2FA should not have increased since we
            # did not fail entering the 2FA code, we failed to enter the
            # password.
            assert_equal(0, user.two_factor_auth_failure_count)
          end

          # --------------------------------------------------
          # Login Successfully
          # --------------------------------------------------
          session_class.within_request do |session, record|
            assert_nil(session)
            assert_nil(record)

            new_session = session_class.new(
              username: 'user01',
              password: 'some*password'
            )
            save_result = new_session.save
            assert(save_result)

            # 2FA is required, so this should be true.
            assert(new_session.record_has_two_factor_auth_required_and_uncompleted?)

            record = new_session.record

            # Check 2FA columns. 
            refute(record.two_factor_auth_confirmed)
            assert_nil(record.two_factor_auth_persistence_token)
            assert_nil(record.two_factor_auth_last_successful_auth)
            refute_nil(record.two_factor_auth_key)
            assert_equal(0, record.two_factor_auth_failure_count)
          end

          # --------------------------------------------------
          # Enter 2FA Code Successfully
          # --------------------------------------------------
          session_class.within_request do |session, record|
            refute_nil(session)
            refute_nil(record)

            assert(session.record_has_two_factor_auth_required_and_uncompleted?)

            # Enter the correct code should successfully save the session.
            session.two_factor_auth_code = record.two_factor_auth_otp_code
            result = session.save
            assert(result)

            # Check 2FA columns. 
            refute_nil(record.two_factor_auth_persistence_token)
            refute_nil(record.two_factor_auth_last_successful_auth)
            assert(record.two_factor_auth_confirmed)
            assert_equal(0, record.two_factor_auth_failure_count)
          end

          # --------------------------------------------------
          # Logout
          # --------------------------------------------------
          session_class.within_request do |session, record|
            refute_nil(session)
            refute_nil(record)

            session.destroy

            # Check 2FA columns. 
            assert(record.two_factor_auth_enabled)
            assert(record.two_factor_auth_confirmed)
            assert_equal(0, record.two_factor_auth_failure_count)
            refute_nil(record.two_factor_auth_key)
            refute_nil(record.two_factor_auth_persistence_token)
            refute_nil(record.two_factor_auth_last_successful_auth)
          end

          # --------------------------------------------------
          # Post Logout Request
          # --------------------------------------------------
          session_class.within_request do |session, record|
            assert_nil(session)
            assert_nil(record)
          end
        end
        # }}}

        # {{{ def test_simulate_log_in_and_out_for_user_without_2fa_enabled
        def test_simulate_log_in_and_out_for_user_without_2fa_enabled
          user_class = Authlogic::Ext::Testing.generate_acts_as_authentic_class('Authlogic::Ext::Testing::User') do
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
            two_factor_auth true
          end

          # --------------------------------------------------
          # Create a User
          # --------------------------------------------------
          user = user_class.new(
            username: 'user01',
            password: 'some*password',
            password_confirmation: 'some*password'
          )
          result = user.save
          assert(result)

          # --------------------------------------------------
          # Fail to Login
          # --------------------------------------------------
          session_class.within_request do |session, record|
            assert_nil(session)
            assert_nil(record)

            new_session = session_class.new(
              username: 'user01',
              password: 'not_the_password'
            )
            save_result = new_session.save
            refute(save_result)
          end

          # --------------------------------------------------
          # Login Successfully
          # --------------------------------------------------
          session_class.within_request do |session, record|
            assert_nil(session)
            assert_nil(record)

            new_session = session_class.new(
              username: 'user01',
              password: 'some*password'
            )
            save_result = new_session.save
            assert(save_result)

            # 2FA is not required, so this should be false.
            refute(new_session.record_has_two_factor_auth_required_and_uncompleted?)

            record = new_session.record

            # No 2FA columns should be set.
            assert_nil(record.two_factor_auth_key)
            assert_nil(record.two_factor_auth_persistence_token)
            assert_nil(record.two_factor_auth_last_successful_auth)
            assert_equal(0, record.two_factor_auth_failure_count)
            refute(record.two_factor_auth_enabled?)
            refute(record.two_factor_auth_confirmed?)
          end

          # --------------------------------------------------
          # Attempt 2FA (Feature not Enabled)
          # --------------------------------------------------
          session_class.within_request do |session, record|
            refute_nil(session)
            refute_nil(record)

            session.two_factor_auth_code = '111111111111'
            result = session.save

            # Even though we entered a bogus 2FA code, the session should
            # still save, because the feature is not even enabled. It
            # will never check the code we gave it.
            assert(result)

            # No 2FA columns should be set.
            assert_nil(record.two_factor_auth_key)
            assert_nil(record.two_factor_auth_persistence_token)
            assert_nil(record.two_factor_auth_last_successful_auth)
            assert_equal(0, record.two_factor_auth_failure_count)
            refute(record.two_factor_auth_enabled?)
            refute(record.two_factor_auth_confirmed?)
          end

          # --------------------------------------------------
          # Logout
          # --------------------------------------------------
          session_class.within_request do |session, record|
            session.destroy

            # No 2FA columns should be set.
            assert_nil(record.two_factor_auth_key)
            assert_nil(record.two_factor_auth_persistence_token)
            assert_nil(record.two_factor_auth_last_successful_auth)
            assert_equal(0, record.two_factor_auth_failure_count)
            refute(record.two_factor_auth_enabled?)
            refute(record.two_factor_auth_confirmed?)
          end
        end
        # }}}

        # {{{ def test_simulate_log_in_and_out_with_2fa_option_disabled_on_session
        def test_simulate_log_in_and_out_with_2fa_option_disabled_on_session
          user_class = Authlogic::Ext::Testing.generate_acts_as_authentic_class('Authlogic::Ext::Testing::User') do
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
            two_factor_auth false
          end

          # --------------------------------------------------
          # Create a User
          # --------------------------------------------------
          user = user_class.new(
            username: 'user01',
            password: 'some*password',
            password_confirmation: 'some*password'
          )
          result = user.save
          assert(result)

          # --------------------------------------------------
          # Fail to Login
          # --------------------------------------------------
          session_class.within_request do |session, record|
            assert_nil(session)
            assert_nil(record)

            new_session = session_class.new(
              username: 'user01',
              password: 'not_the_password'
            )
            save_result = new_session.save
            refute(save_result)
          end

          # --------------------------------------------------
          # Login Successfully
          # --------------------------------------------------
          session_class.within_request do |session, record|
            assert_nil(session)
            assert_nil(record)

            new_session = session_class.new(
              username: 'user01',
              password: 'some*password'
            )
            save_result = new_session.save
            assert(save_result)

            # 2FA is not required, so this should be false.
            refute(new_session.record_has_two_factor_auth_required_and_uncompleted?)

            record = new_session.record

            # No 2FA columns should be set.
            assert_nil(record.two_factor_auth_key)
            assert_nil(record.two_factor_auth_persistence_token)
            assert_nil(record.two_factor_auth_last_successful_auth)
            assert_equal(0, record.two_factor_auth_failure_count)
            refute(record.two_factor_auth_enabled?)
            refute(record.two_factor_auth_confirmed?)
          end

          # --------------------------------------------------
          # Attempt 2FA (Feature not Enabled)
          # --------------------------------------------------
          session_class.within_request do |session, record|
            refute_nil(session)
            refute_nil(record)

            session.two_factor_auth_code = '111111111111'
            result = session.save

            # Even though we entered a bogus 2FA code, the session should
            # still save, because the feature is not even enabled. It
            # will never check the code we gave it.
            assert(result)

            # No 2FA columns should be set.
            assert_nil(record.two_factor_auth_key)
            assert_nil(record.two_factor_auth_persistence_token)
            assert_nil(record.two_factor_auth_last_successful_auth)
            assert_equal(0, record.two_factor_auth_failure_count)
            refute(record.two_factor_auth_enabled?)
            refute(record.two_factor_auth_confirmed?)
          end

          # --------------------------------------------------
          # Logout
          # --------------------------------------------------
          session_class.within_request do |session, record|
            session.destroy

            # No 2FA columns should be set.
            assert_nil(record.two_factor_auth_key)
            assert_nil(record.two_factor_auth_persistence_token)
            assert_nil(record.two_factor_auth_last_successful_auth)
            assert_equal(0, record.two_factor_auth_failure_count)
            refute(record.two_factor_auth_enabled?)
            refute(record.two_factor_auth_confirmed?)
          end
        end
        # }}}

        # {{{ def test_basic_2fa_setup
        def test_basic_2fa_setup
          user_class = Authlogic::Ext::Testing.generate_acts_as_authentic_class('Authlogic::Ext::Testing::User') do
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
            two_factor_auth true
            two_factor_auth_threshold 2
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
            refute(session.two_factor_auth_completed?)

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
            # # act_like_two_factor_auth_completed_on_enable=true, so this will
            # # get set to true.
            # assert(session.two_factor_auth_completed?)
            # # The OTP methods should now give some data.
            # refute_nil(record.two_factor_auth_otp)
            # refute_nil(record.two_factor_auth_otp_code)
            # refute_nil(record.two_factor_auth_otp_uri)
            # refute_nil(record.two_factor_auth_qr_code)
            # refute_nil(record.two_factor_auth_qr_code_svg)
          end

          # --------------------------------------------------
          # Logout the User
          # --------------------------------------------------
          session_class.within_request do |session, record|
            # Logout by destroying the session.
            session.destroy

            refute(session.two_factor_auth_completed?)
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
          # Simulate user entering a 2FA code
          # (Incorrect Code 1st Time)
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
          # Simulate user entering a 2FA code
          # (Incorrect Code 2nd time in a row) 
          # This should put us at the configured max of 2
          # which will destroy the session and reset the
          # failure count back to 0.
          # --------------------------------------------------
          session_class.within_request do |session, record|
            session.two_factor_auth_code = 'xxxyyy'
            save_result = session.save
            refute(save_result)
            assert(session.errors.messages.key?(:two_factor_auth_code))
            assert_equal(0, record.two_factor_auth_failure_count)
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
            refute(session.two_factor_auth_completed?)
          end

          # --------------------------------------------------
          # Session is gone
          # --------------------------------------------------
          session_class.within_request do |session, record|
            assert_nil(session)
          end
        end
        # }}}
      end
    end
  end
end
