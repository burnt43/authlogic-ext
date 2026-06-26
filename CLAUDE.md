### Code Style Info

- The methods should be in ABC order among groupings. Groupings include
  - Public Instance Methods
  - Private Instance Methods
  - Class Methods (in class << self blocks)

- Any collection like an Array or Hash should be ABC order too. So if I have
  an Array of valid values for an enum, for example, then I want those Array
  elements in order.

### Testing

- To run the tests you run the following command:
  bundle exec rake authlogic_ext:test:run

- To setup the tests you run the following command:
  bundle exec rake authlogic_ext:test:db:setup
  You only have to setup the tests' database if it doesn't already exist.
