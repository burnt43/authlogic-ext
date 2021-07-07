require './test/init'

module Authlogic
  module Ext
    module Testing
      class ActsAsAuthenticModelTest < Authlogic::Ext::Testing::Test
        # {{{ test_remove_two_factor_auth_confirmation
        def test_remove_two_factor_auth_confirmation
          user_class = Authlogic::Ext::Testing.generate_acts_as_authentic_class('Authlogic::Ext::Testing::User') do
            acts_as_authentic_ext do |config|
              config.two_factor_auth = true
              config.two_factor_auth_otp_class = ROTP::TOTP
              config.two_factor_auth_otp_code_method = :now
              config.two_factor_auth_uri_method = :provisioning_uri
              config.two_factor_auth_uri_input_method = :username
              config.two_factor_auth_uri_qr_code_class = RQRCode::QRCode
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
            two_factor_auth_enabled: true,
            two_factor_auth_confirmed: true
          )
          result = user.save
          assert(result)
          assert(user.two_factor_auth_confirmed?)

          # --------------------------------------------------
          # Disable 2FA on User
          # --------------------------------------------------
          user.update_attributes(two_factor_auth_enabled: false)
          refute(user.two_factor_auth_confirmed?)
        end
        # }}}

        # {{{ test_destroy_cookie_on_2fa_disable_without_simulated_gui
        def test_destroy_cookie_on_2fa_disable_without_simulated_gui
          Authlogic::Session::Base.controller = nil

          user_class = Authlogic::Ext::Testing.generate_acts_as_authentic_class('Authlogic::Ext::Testing::User') do
            acts_as_authentic_ext do |config|
              config.two_factor_auth = true
              config.two_factor_auth_otp_class = ROTP::TOTP
              config.two_factor_auth_otp_code_method = :now
              config.two_factor_auth_uri_method = :provisioning_uri
              config.two_factor_auth_uri_input_method = :username
              config.two_factor_auth_uri_qr_code_class = RQRCode::QRCode
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

          # --------------------------------------------------
          # Disable 2FA on User
          # --------------------------------------------------
          user.update_attributes(two_factor_auth_enabled: false)
        end
        # }}}

        # {{{ test_destroy_cookie_on_2fa_disable_in_simulated_gui
        def test_destroy_cookie_on_2fa_disable_in_simulated_gui
          user_class = Authlogic::Ext::Testing.generate_acts_as_authentic_class('Authlogic::Ext::Testing::User') do
            acts_as_authentic_ext do |config|
              config.two_factor_auth = true
              config.two_factor_auth_otp_class = ROTP::TOTP
              config.two_factor_auth_otp_code_method = :now
              config.two_factor_auth_uri_method = :provisioning_uri
              config.two_factor_auth_uri_input_method = :username
              config.two_factor_auth_uri_qr_code_class = RQRCode::QRCode
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

          assert_nil(Authlogic::Session::Base.controller.cookies['two_factor_auth_credentials'])

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

            assert_nil(Authlogic::Session::Base.controller.cookies['two_factor_auth_credentials'])
          end

          # --------------------------------------------------
          # Enter 2FA Code Successfully
          # --------------------------------------------------
          session_class.within_request do |session, record|
            refute_nil(session)
            refute_nil(record)

            session.two_factor_auth_code = record.two_factor_auth_otp_code
            result = session.save
            assert(result)

            refute_nil(Authlogic::Session::Base.controller.cookies['two_factor_auth_credentials'])
          end

          # --------------------------------------------------
          # Disable 2FA on User
          # --------------------------------------------------
          session_class.within_request do |session, record|
            refute_nil(session)
            refute_nil(record)

            result = record.update_attributes(two_factor_auth_enabled: false)
            assert(result)

            assert_nil(Authlogic::Session::Base.controller.cookies['two_factor_auth_credentials'])
          end
        end
        # }}}

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
            end
          end

          session_class = Authlogic::Ext::Testing.generate_session_class('Authlogic::Ext::Testing::Session', acts_as_authentic_class: user_class) do
            two_factor_auth true
            two_factor_auth_threshold 2
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

            record = new_session.record

            # 2FA is required, so this should be true.
            assert(new_session.record_has_two_factor_auth_required_and_uncompleted?)
            assert_equal(0, record.two_factor_auth_failure_count)
            refute(record.two_factor_auth_confirmed?)
          end

          # --------------------------------------------------
          # Enter 2FA Wrong Code (2x)
          # --------------------------------------------------
          session_class.within_request do |session, record|
            refute_nil(session)
            refute_nil(record)

            session.two_factor_auth_code = 'abcdef'
            result = session.save
            refute(result)

            # 2FA still enabled, failure count incremented.
            assert(record.two_factor_auth_enabled?)
            assert_equal(1, record.two_factor_auth_failure_count)
          end

          session_class.within_request do |session, record|
            refute_nil(session)
            refute_nil(record)

            session.two_factor_auth_code = 'uvwxyz'
            result = session.save
            refute(result)

            # 2FA becomes disabled, because the user never entered a correct
            # 2FA code ever in its history, therefore the confirmed flag never
            # gets set to true. The failure count reset, because we hit the
            # threshold of 2.
            refute(record.two_factor_auth_enabled?)
            assert_equal(0, record.two_factor_auth_failure_count)
          end

          # --------------------------------------------------
          # Renable 2FA
          # --------------------------------------------------
          user.reload
          result = user.update_attributes(two_factor_auth_enabled: true)
          assert(result)

          # --------------------------------------------------
          # Login Again Successfully
          # --------------------------------------------------
          session_class.within_request do |session, record|
            # These should be nil, because the session should have been
            # destroyed when we failed to enter the 2FA code past the
            # the threshold.
            assert_nil(session)
            assert_nil(record)

            new_session = session_class.new(
              username: 'user01',
              password: 'some*password'
            )
            save_result = new_session.save
            assert(save_result)

            record = new_session.record

            # 2FA is required, so this should be true.
            assert(new_session.record_has_two_factor_auth_required_and_uncompleted?)
            assert_equal(0, record.two_factor_auth_failure_count)
            refute(record.two_factor_auth_confirmed?)
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
          end

          # --------------------------------------------------
          # Login Again Again Successfully
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

            record = new_session.record

            # 2FA is required, so this should be true.
            assert(new_session.record_has_two_factor_auth_required_and_uncompleted?)
            assert_equal(0, record.two_factor_auth_failure_count)
            assert(record.two_factor_auth_confirmed?)
          end

          # --------------------------------------------------
          # Enter 2FA Wrong Code (2x)
          # --------------------------------------------------
          session_class.within_request do |session, record|
            refute_nil(session)
            refute_nil(record)

            session.two_factor_auth_code = 'abcdef'
            result = session.save
            refute(result)

            # 2FA still enabled, failure count incremented.
            assert(record.two_factor_auth_enabled?)
            assert_equal(1, record.two_factor_auth_failure_count)
          end

          session_class.within_request do |session, record|
            refute_nil(session)
            refute_nil(record)

            session.two_factor_auth_code = 'uvwxyz'
            result = session.save
            refute(result)

            # 2FA STILL enabled, because this user has logged in fully with
            # 2FA code in the past. The failure count reset, because we hit the
            # threshold of 2.
            assert(record.two_factor_auth_enabled?)
            assert_equal(0, record.two_factor_auth_failure_count)
          end

          # TODO:
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
      end
    end
  end
end
