module Warning
  def warn(msg)
  end
end

unless $SKIP_MINITEST
  require 'minitest/pride'
  require 'minitest/autorun'
end

require 'authlogic'
require 'rotp'
require './lib/authlogic-ext'

module Authlogic
  module Ext
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
        end

        def generate_acts_as_authentic_class(name, &block)
          Class.new(ActiveRecord::Base).tap do |c|
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
                  @hacked_name ||= name
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
                  @hacked_name ||= name
                end

                define_method :klass do
                  acts_as_authentic_class
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
      end

      unless $SKIP_MINITEST
        class Test < Minitest::Test
        end
      end
    end
  end
end

ActiveRecord::Base.configurations = {
  test: {
    adapter: 'sqlite3',
    pool:     5,
    timeout:  5000,
    database: Authlogic::Ext::Testing.database_file.to_s
  }
}
ActiveRecord::Base.establish_connection(:test)
