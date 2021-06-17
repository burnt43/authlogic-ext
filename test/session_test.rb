module Authlogic
  module Ext
    module Testing
      class SessionTest < Authlogic::Ext::Testing::Test
        def test_should_redirect_to_two_factor_auth_code_entry
          fake_widgets_action1_controller_instance = Object.new.tap do |o|
            def o.controller_path
              'widgets'
            end

            def o.action_name
              'action1'
            end
          end

          fake_namespace1_namespace2_foos_action1_controller_instance = Object.new.tap do |o|
            def o.controller_path
              'namespace1/namespace2/foos'
            end

            def o.action_name
              'action1'
            end
          end

          fake_bars_action2_controller_instance = Object.new.tap do |o|
            def o.controller_path
              'bars'
            end

            def o.action_name
              'action2'
            end
          end

          Authlogic::Session::Base.controller = fake_widgets_action1_controller_instance
          assert(Authlogic::Ext::Testing::Models::TwoFactorAuthEnabled::WebUser::Session.should_redirect_to_two_factor_auth_code_entry?)

          Authlogic::Session::Base.controller = fake_namespace1_namespace2_foos_action1_controller_instance
          refute(Authlogic::Ext::Testing::Models::TwoFactorAuthEnabled::WebUser::Session.should_redirect_to_two_factor_auth_code_entry?)

          Authlogic::Session::Base.controller = fake_bars_action2_controller_instance
          refute(Authlogic::Ext::Testing::Models::TwoFactorAuthEnabled::WebUser::Session.should_redirect_to_two_factor_auth_code_entry?)
        end
      end
    end
  end
end
