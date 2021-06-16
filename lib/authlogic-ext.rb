# This is the 'entry-point' for the gem. We'll just require all our
# stuff right here.

# Ensure that there is an Authlogic module. Since this gem is an extension
# of authlogic most likely you have already included it in your application.
module Authlogic
end

require 'authlogic/ext'
require 'authlogic/ext/session'
require 'authlogic/ext/acts_as_authentic'
require 'authlogic/ext/acts_as_authentic/configuration'
require 'authlogic/ext/acts_as_authentic/model'
require 'authlogic/ext/acts_as_authentic/controller'
