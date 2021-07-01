module Warning
  def warn(msg)
  end
end

unless $SKIP_MINITEST
  require 'minitest/pride'
  require 'minitest/autorun'

	MiniTest.after_run do
    Authlogic::Ext::Testing.clear_tables!
	end
end

require 'authlogic'
require './lib/authlogic-ext'
require 'rotp'
require 'rqrcode'
require 'stringio'

module Kernel
  def jcarson_debug(msg)
    puts "[\033[0;34mJCARSON\033[0;0m] - #{msg}"
  end
end

module Authlogic
  module Ext
    # Add a class method to Session classes that we can use in the tests to
    # simulate like you just made a controller request and this is the
    # session and record you would find in the before_filters.
    module Session
      module ClassMethods
        # Pretend like we're making a web request and yield to the given block
        # the session and record we've found.
        def within_request(&block)
          if block
            session = find
            block.call(session, session&.record)
          end
        end
      end
    end

    module Testing
      class << self
        def database_file
          @database_file ||= Pathname.new('test/assets/db/test.sqlite3')
        end

        def ensure_database_file_exists!
          return if database_file.exist?

          FileUtils.touch(database_file)
        end

        def destroy_database_file!
          return unless database_file.exist?

          FileUtils.rm(database_file)
        end

        def load_schema_into_database_file!
					schema_load = Class.new(ActiveRecord::Migration) do
						def up
							create_table :web_users do |t|
								# My Columns
								t.string :username, null: false

								# Authlogic::ActsAsAuthentic::Password
								t.string :crypted_password
								t.string :password_salt

								# Authlogic::ActsAsAuthentic::PersistenceToken
								t.string :persistence_token
								t.index :persistence_token, unique: true

								# Authlogic::ActsAsAuthentic::SingleAccessToken
								t.string :single_access_token
								t.index :single_access_token, unique: true

								# Authlogic::ActsAsAuthentic::PerishableToken
								t.string :perishable_token
								t.index :perishable_token, unique: true

								# See "Magic Columns" in Authlogic::Session::Base
								t.integer :login_count, default: 0, null: false
								t.integer :failed_login_count, default: 0, null: false
								t.datetime :current_login_at
								t.datetime :last_login_at
								t.string :current_login_ip
								t.string :last_login_ip

								# Authlogic::Ext (Necessary Columns)
								t.string :two_factor_auth_key, limit: 32
								t.boolean :two_factor_auth_enabled, null: false, default: false
								t.string :two_factor_auth_persistence_token
								t.index :two_factor_auth_persistence_token, unique: true

                # TODO: This should be removed
								t.boolean :two_factor_auth_completed, null: false, default: false

                # Authlogic::Ext (Optional Columns)
                t.integer :two_factor_auth_failure_count, null: false, default: 0
                t.datetime :two_factor_auth_last_successful_auth
							end
						end
					end

					schema_load.new.up
        end

        def clear_tables!
          ActiveRecord::Base.connection.execute('DELETE FROM web_users WHERE 1;')
        end

        # NOTE: These anonymous class generators are no longer used, but I'm
        #   keeping them because they are cool and I may need to look back
        #   at them in the future.

        def generate_acts_as_authentic_class(name, &block)
          Class.new(ActiveRecord::Base).tap do |c|
            c.table_name = 'web_users'

            c.class_eval do
              # We need to hack the name method for this class. Since this is
              # an 'anonymous class' it won't have a name. Authlogic relies
              # on the class having a name. Normally, we could just do:
              # def self.name
              #   'some_name'
              # end
              # However, we're taking in the name as an argument to the
              # 'generate_acts_as_authentic_class' method and using
              # 'class' or 'def' keywords starts a new scope and we would
              # not be able to access the name argument. Using 'class_eval'
              # and 'define_method' are equivalent and do not change the
              # scope which allows us to access the name arg.
              singleton_class.class_eval do
                define_method :name do
                  name
                end

                def model_name
                  @model_name ||= ActiveModel::Name.new(self)
                end
              end

              # Include the Ext functionality.
              include Authlogic::Ext::ActsAsAuthentic::Model
            end

            c.class_eval(&block) if block
          end
        end

        def generate_session_class(name, acts_as_authentic_class: nil, &block)
          Class.new(Authlogic::Session::Base).tap do |c|
            c.class_eval do
              # See 'generate_acts_as_authentic_class' for explanation.
              singleton_class.class_eval do
                define_method :name do
                  name
                end

                define_method :klass do
                  acts_as_authentic_class
                end

                define_method :klass_name do
                  name
                end
              end

              # Include the Ext functionality.
              include Authlogic::Ext::Session
            end

            c.class_eval(&block) if block
          end
        end
      end

      class DummyController
        attr_accessor :controller_path
        attr_accessor :action_name

        def initialize(controller_path: nil, action_name: nil)
          @controller_path = controller_path
          @action_name = action_name
        end

        def clear_cached_data!
          @cookies = nil
          @params = nil
          @session = nil
        end

        def request
          Object.new.tap do |o|
            def o.ip
              '127.0.0.1'
            end
          end
        end

        def cookies
          @cookies ||= Object.new.tap do |o|
            def o.backend_hash
              @backend_hash ||= {}
            end

            def o.[](key)
              backend_hash[key]
            end

            def o.[]=(key, value)
              backend_hash[key] = value[:value]
            end

            def o.delete(key, options={})
              backend_hash.delete(key)
            end
          end
        end

        def cookie_domain
        end

        def params
          @params ||= {}
        end

        def session
          @session ||= {}
        end
      end

      unless $SKIP_MINITEST
        class Test < Minitest::Test
          def setup
            Authlogic::Session::Base.controller = Authlogic::Ext::Testing::DummyController.new
          end

          def teardown
            current_controller = Authlogic::Session::Base.controller
            if current_controller.respond_to?(:clear_cached_data!)
              current_controller.clear_cached_data!
            end

            Authlogic::Ext::Testing.clear_tables!
          end
        end
      end
    end
  end
end

ActiveRecord::Base.configurations = {
  'test' => {
    adapter: 'sqlite3',
    pool:     5,
    timeout:  5000,
    database: Authlogic::Ext::Testing.database_file.to_s
  }
}
ActiveRecord::Base.establish_connection(:test)
