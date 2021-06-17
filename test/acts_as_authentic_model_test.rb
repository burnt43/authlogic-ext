require './test/init'

module Authlogic
  module Ext
    module Testing
      class ActsAsAuthenticModelTest < Authlogic::Ext::Testing::Test
        def test_basic_2fa_setup
          Authlogic::Session::Base.controller = Authlogic::Ext::Testing::DummyController.new

          # --------------------------------------------------
          # Create a basic user with a username and password. Leave 2FA
          # disabled on this user.
          # --------------------------------------------------
          user = Authlogic::Ext::Testing::Models::TwoFactorAuthEnabled::WebUser.new(
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

          # --------------------------------------------------
          # Login (With 2FA disabled)
          # --------------------------------------------------
          Authlogic::Ext::Testing::Models::TwoFactorAuthEnabled::WebUser::Session.within_request do |session, record|
            assert_nil(session)

            new_session = Authlogic::Ext::Testing::Models::TwoFactorAuthEnabled::WebUser::Session.new(
              username: 'user01',
              password: 'my*pass*word'
            )
            save_result = new_session.save
            assert(save_result)
          end

          # --------------------------------------------------
          # We're logged in so find the session!
          # --------------------------------------------------
          Authlogic::Ext::Testing::Models::TwoFactorAuthEnabled::WebUser::Session.within_request do |session, record|
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
          end

          # --------------------------------------------------
          # Enable 2FA on the user
          # --------------------------------------------------
          Authlogic::Ext::Testing::Models::TwoFactorAuthEnabled::WebUser::Session.within_request do |session, record|
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
          end

          # --------------------------------------------------
          # Logout the User
          # --------------------------------------------------
          Authlogic::Ext::Testing::Models::TwoFactorAuthEnabled::WebUser::Session.within_request do |session, record|
            # Logout by destroying the session.
            session.destroy

            # The user should have its completed flag unset. Which will require
            # the user to enter 2FA on its next login.
            refute(record.two_factor_auth_completed?)
          end

          # --------------------------------------------------
          # Login (With 2FA enabled)
          # --------------------------------------------------
          Authlogic::Ext::Testing::Models::TwoFactorAuthEnabled::WebUser::Session.within_request do |session, record|
            assert_nil(session)

            new_session = Authlogic::Ext::Testing::Models::TwoFactorAuthEnabled::WebUser::Session.new(
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
          Authlogic::Ext::Testing::Models::TwoFactorAuthEnabled::WebUser::Session.within_request do |session, record|
            # The session should be in a state where it is expecting to receive
            # a 2FA code to complete authentication.
            assert(session.record_has_two_factor_auth_required_and_uncompleted?)
          end

          # --------------------------------------------------
          # Simulate user entering a 2FA code (Incorrect Code)
          # --------------------------------------------------
          Authlogic::Ext::Testing::Models::TwoFactorAuthEnabled::WebUser::Session.within_request do |session, record|
            session.two_factor_auth_code = 'xxxyyy'
            save_result = session.save
            refute(save_result)
            assert(session.errors.messages.key?(:two_factor_auth_code))
          end

          # --------------------------------------------------
          # Simulate user entering a 2FA code (Correct Code)
          # --------------------------------------------------
          Authlogic::Ext::Testing::Models::TwoFactorAuthEnabled::WebUser::Session.within_request do |session, record|
            session.two_factor_auth_code = record.two_factor_auth_otp_code
            save_result = session.save
            assert(save_result)
          end

          # --------------------------------------------------
          # We should now be fully authenticated with both
          # username/password and the 2FA code.
          # --------------------------------------------------
          Authlogic::Ext::Testing::Models::TwoFactorAuthEnabled::WebUser::Session.within_request do |session, record|
            refute(session.record_has_two_factor_auth_required_and_uncompleted?)
          end

          # --------------------------------------------------
          # Logout
          # --------------------------------------------------
          Authlogic::Ext::Testing::Models::TwoFactorAuthEnabled::WebUser::Session.within_request do |session, record|
            session.destroy
            refute(record.two_factor_auth_completed?)
          end

          # --------------------------------------------------
          # Session is gone
          # --------------------------------------------------
          Authlogic::Ext::Testing::Models::TwoFactorAuthEnabled::WebUser::Session.within_request do |session, record|
            assert_nil(session)
          end
        end
      end
    end
  end
end
