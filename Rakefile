require 'rake/testtask'

namespace :authlogic_ext do
  namespace :test do
    Rake::TestTask.new(:run) do |t|
      t.test_files = FileList['./test/*_test.rb']
      t.verbose = false
    end
  end
end
