################################################################################
# Unit tests for the user class
################################################################################
#
#

require './user.rb'
require 'minitest/autorun'

class TC_UserTest < MiniTest::Test

    def test_locked_init
        new_user = User.new "dgascon", 1234, "this is some special secret"
        assert new_user.unlocked == false
    end

    def test_locking_user
        new_user = User.new "dgascon", 1234, "this is some special secret"
        new_user.lock("password1234")
        assert new_user.unlocked == false
    end

    def test_unlocking_user
        new_user = User.new "dgascon", 1234, "this some special secret"
        new_user.lock("password1234")
        new_user.unlock("password1234")
        assert new_user.unlocked == true
    end

    def test_back_unlock
        new_user = User.new "dgascon", 1234, "this some special secret"
        new_user.lock("password1234")
        new_user.unlock("password1235")
        assert new_user.unlocked == false
    end
end
