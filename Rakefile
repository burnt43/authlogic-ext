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
        Authlogic::Ext::Testing.load_schema_into_database_file!
      end

      task :setup => [:init, :destroy, :create, :load_schema]
    end

    Rake::TestTask.new(:run) do |t|
      t.test_files = FileList['./test/*_test.rb']
      t.verbose = false
    end
  end
end
