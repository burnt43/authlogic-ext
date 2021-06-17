require 'rake/testtask'

namespace :authlogic_ext do
  namespace :test do
    namespace :db do
      task :init do
        $SKIP_MINITEST = true
        require './test/init'
      end

      task :create => [:init] do
        Authlogic::Ext::Testing.ensure_database_file_exists!
      end

      task :destroy => [:init] do
        Authlogic::Ext::Testing.destroy_database_file!
      end

      task :load_schema => [:init] do
        schema_load = Class.new(ActiveRecord::Migration[4.2]) do
          def up
            create_table :web_users do |t|
              # My Columns
              t.string :username, null: false

              # Authlogic::ActsAsAuthentic::Password
              add_column :web_users, :crypted_password, :string    
              add_column :web_users, :password_salt, :string    

              # Authlogic::ActsAsAuthentic::PersistenceToken
              add_column :web_users, :persistence_token, :string    
              add_index :web_users, :persistence_token, unique: true

              # Authlogic::ActsAsAuthentic::SingleAccessToken
              add_column :web_users, :single_access_token, :string    
              add_index :web_users, :single_access_token, unique: true

              # Authlogic::ActsAsAuthentic::PerishableToken
              add_column :web_users, :perishable_token, :string    
              add_index :web_users, :perishable_token, unique: true

              # See "Magic Columns" in Authlogic::Session::Base
              add_column :web_users, :login_count, :integer, default: 0, null: false
              add_column :web_users, :failed_login_count, :integer, default: 0, null: false
              add_column :web_users, :current_login_at, :datetime
              add_column :web_users, :last_login_at, :datetime
              add_column :web_users, :current_login_ip, :string
              add_column :web_users, :last_login_ip, :string

              # Authlogic::Ext
              add_column :web_users, :two_factor_auth_key, :string, limit: 32
              add_column :web_users, :two_factor_auth_enabled, :boolean, null: false, default: false
              add_column :web_users, :two_factor_auth_completed, :boolean, null: false, default: false
            end
          end
        end

        schema_load.new.up
      end

      task :setup => [:init, :destroy, :create, :load_schema]
    end

    Rake::TestTask.new(:run) do |t|
      t.test_files = FileList['./test/*_test.rb']
      t.verbose = false
    end
  end
end
