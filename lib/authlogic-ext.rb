require 'pathname'

# This is the 'entry-point' for the gem. We'll just require all our
# stuff right here.

# Ensure that there is an Authlogic module. Since this gem is an extension
# of authlogic most likely you have already included it in your application.
module Authlogic
end

pathname = Pathname.new(__FILE__)

require pathname.parent.join('authlogic', 'ext').to_s
require pathname.parent.join('authlogic', 'ext', 'session').to_s
require pathname.parent.join('authlogic', 'ext', 'acts_as_authentic').to_s
require pathname.parent.join('authlogic', 'ext', 'acts_as_authentic', 'configuration').to_s
require pathname.parent.join('authlogic', 'ext', 'acts_as_authentic', 'model').to_s
