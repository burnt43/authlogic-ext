module Warning
  def warn(msg)
  end
end

require 'minitest/pride'
require 'minitest/autorun'

require 'authlogic'
require 'rotp'
require './lib/authlogic-ext'

module Authlogic
  module Ext
    module Testing
      class << self
        def generate_acts_as_authentic_class(name)
          Class.new(ActiveRecord::Base).tap do |c|
            c.class_eval do
              # We need to hack the name method for this class. Normally, we
              # could just do:
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
          end
        end

        def generate_session_class(name, acts_as_authentic_class: nil)
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
          end
        end
      end

      class DummyController
      end

      class Test < Minitest::Test
      end
    end
  end
end
