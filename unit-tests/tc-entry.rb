
require './pass-entry'
require './user'
require 'minitest/autorun'

class TC_PasswordEntry < MiniTest::Test

    ############################################################################
    # Test our initial status contains what we think
    ############################################################################
    def test_init_state
        new_entry = PasswordEntry.new "www.google.ca" , "test_user"
        assert new_entry.password == nil
    end

    ############################################################################
    # Test that our lock works the way we expect
    ############################################################################
    def test_entry_lock
        new_entry = PasswordEntry.new "www.google.ca", "test_user"
        new_user = User.new "master_user", 1234, "some secret here"
        assert new_entry.iv.nil?
        assert new_entry.auth_tag.nil?

        # This will do util users have encrypted secrets by default
        new_user.lock("fake_pass")
        new_user.unlock("fake_pass")

        new_entry.lock_password(new_user, "password1234")

        assert !new_entry.encrypted_password.nil?
        assert !new_entry.auth_tag.nil?
        assert new_entry.auth_tag.length == 16
        assert !new_entry.iv.nil?
        assert new_entry.iv.length == 12
    end

    ############################################################################
    # Test to make sure we can lock then unlock a password
    ############################################################################
    def test_entry_unlock
        new_entry = PasswordEntry.new "www.google.ca", "test_user"
        new_user = User.new "master_user", 1234, "some secret here"

        # This will do util users have encrypted secrets by default
        new_user.lock("fake_pass")
        new_user.unlock("fake_pass")

        new_entry.lock_password(new_user, "password1234")

        decrypted_password = new_entry.unlock_password(new_user)
        assert decrypted_password == "password1234"
    end

    ############################################################################
    # Test to make sure we can't unlock with the same user name, secret, but different
    # id
    ############################################################################
    def test_different_user_entry_unlock
        new_entry = PasswordEntry.new "www.google.ca", "test_user"
        new_user = User.new "master_user", 1234, "some secret here"

        # This will do util users have encrypted secrets by default
        new_user.lock("fake_pass")
        new_user.unlock("fake_pass")

        new_entry.lock_password(new_user, "password1234")

        different_user = User.new "master_user", 1235, "some secret here"

        # This will do util users have encrypted secrets by default
        different_user.lock("fake_pass")
        different_user.unlock("fake_pass")

        decrypted_password = new_entry.unlock_password(different_user)

        assert decrypted_password.nil?
    end

    ############################################################################
    # Test to make sure we can't unlock with the same user name, id, but different
    # secret
    ############################################################################
    def test_different_secret_entry_unlock
        new_entry = PasswordEntry.new "www.google.ca", "test_user"
        new_user = User.new "master_user", 1234, "some secret here"

        # This will do util users have encrypted secrets by default
        new_user.lock("fake_pass")
        new_user.unlock("fake_pass")

        new_entry.lock_password(new_user, "password1234")

        different_user = User.new "master_user", 1234, "Some secret here"

        # This will do util users have encrypted secrets by default
        different_user.lock("fake_pass")
        different_user.unlock("fake_pass")

        decrypted_password = new_entry.unlock_password(different_user)

        assert decrypted_password.nil?
    end

    ############################################################################
    # Test to make sure we can't unlock with a locked user
    ############################################################################
    def test_locked_user
        new_entry = PasswordEntry.new "www.google.ca", "test_user"
        new_user = User.new "master_user", 1234, "some secret here"

        # This will do util users have encrypted secrets by default
        new_user.lock("fake_pass")

        assert_raises(LockedError) { new_entry.lock_password(new_user, "password1234") }
    end

    ############################################################################
    # Test serializing a new entry
    ############################################################################
    def test_json_empty_entry
        new_entry = PasswordEntry.new "www.google.ca", "test_user"

        entry_json = new_entry.to_json

        assert entry_json == '{"json_class":"PasswordEntry","iv":null,"user_name":"test_user","site_name":"www.google.ca","encrypted_password":null,"auth_tag":null}'
    end

    ############################################################################
    # Test serializing a locked entry
    ############################################################################
    def test_json_locked_entry
        new_entry = PasswordEntry.new "www.google.ca", "test_user"
        new_user = User.new "master_user", 1234, "Some secret here"

        new_user.lock("fake_pass")
        new_user.unlock("fake_pass")

        new_entry.lock_password(new_user, "password1234")

        entry_json = new_entry.to_json

        assert entry_json = {"json_class":"PasswordEntry","iv":"3ad76fe5685e8f53a7bbb523","user_name":"test_user","site_name":"www.google.ca","encrypted_password":"98f2fa2d672cb4fda1d539ae","auth_tag":"66e897aab622386dd30b2c4ae1c1c5e7"}
    end
end
