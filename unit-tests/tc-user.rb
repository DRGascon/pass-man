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

    def test_adding_entry
        new_user = User.new "dgascon", 1234, "this is some special secret"

        assert new_user.entries.length == 0
        # Lock and unlock the user so we can add an entry
        new_user.lock("23423490hasdfasldvn01243")
        new_user.unlock("23423490hasdfasldvn01243")
        # Add the entry
        new_user.add_new_entry("www.google.ca", "dgascon", "password1234") 
        assert new_user.entries.length == 1
    end

    def test_adding_locked_user
        new_user = User.new "dgascon", 1234, "this is some special secret"
        new_user.lock("23423490hasdfasldvn01243")
        assert_raises(LockedError) { new_user.add_new_entry("www.google.ca", "dgascon", "password1234") }
        # Nothing should've been added
        assert new_user.entries.length == 0
    end
end
