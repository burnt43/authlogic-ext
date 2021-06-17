require 'pathname'

# This is the 'entry-point' for the gem. We'll just require all our
# stuff right here.

# Ensure that there is an Authlogic module. Since this gem is an extension
# of authlogic most likely you have already included it in your application.
module Authlogic
end

pathname = Pathname.new(__FILE__)

require pathname.parent.join('authlogic', 'ext')
require pathname.parent.join('authlogic', 'ext', 'session')
require pathname.parent.join('authlogic', 'ext', 'acts_as_authentic')
require pathname.parent.join('authlogic', 'ext', 'acts_as_authentic', 'configuration')
require pathname.parent.join('authlogic', 'ext', 'acts_as_authentic', 'model')
