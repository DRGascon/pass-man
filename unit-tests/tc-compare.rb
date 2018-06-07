require 'minitest/autorun'
require './utils/compare'

class TC_CompareTest < MiniTest::Test

    def test_valid_compare
        str1 = "Hello world"
        str2 = "Hello world"
        assert_equal true, Utils.equal_time_compare(str1, str2), 'Equal compare failed'
    end
end
