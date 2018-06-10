
require './pass-entry'
require './user'
require 'minitest/autorun'

class TC_PasswordEntry < MiniTest::Test

    def test_init_state
        new_entry = PasswordEntry.new "www.google.ca" , "test_user"
        assert new_entry.password == nil
    end

    def test_lock_lock
        new_entry = PasswordEntry.new "www.google.ca", "test_user"
        new_user = User.new "master_user", 1234, "some secret here"
        assert new_entry.iv.nil?
        assert new_entry.auth_tag.nil?
        new_entry.lock_password(new_user.secret, new_user, "password1234")

        assert !new_entry.encrypted_password.nil?
        assert !new_entry.auth_tag.nil?
        assert new_entry.auth_tag.length == 16
        assert !new_entry.iv.nil?
        assert new_entry.iv.length == 12
    end
end
