################################################################################
# Unit tests for the user class
################################################################################
#
#

require './user.rb'
require 'minitest/autorun'

class TC_UserTest < MiniTest::Test

    def setup
        digest = OpenSSL::Digest::SHA512.new
        password = "password1234"
        @password_key = OpenSSL::PKCS5.pbkdf2_hmac(password, "1234", 20000, 32, digest)
    end

    def test_locked_init
        new_user = User.new "dgascon", 1234, @password_key
        assert new_user.unlocked == false
    end

    def test_unlocking_user
        new_user = User.new "dgascon", 1234, @password_key
        new_user.unlock("password1234")
        assert new_user.unlocked == true
    end
end
