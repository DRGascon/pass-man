
require './entry-crypto/pass-entry'
require './entry-crypto/user'
require 'minitest/autorun'

class TC_PasswordEntry < MiniTest::Test

    ############################################################################
    # Test our initial status contains what we think
    ############################################################################
    def test_init_state
        new_entry = EntryCrypto::PasswordEntry.new "www.google.ca" , "test_user"
        assert new_entry.password == nil
    end

    ############################################################################
    # Test that our lock works the way we expect
    ############################################################################
    def test_entry_lock
        new_entry = EntryCrypto::PasswordEntry.new "www.google.ca", "test_user"
        new_user = EntryCrypto::User.new "master_user", 1234, "some secret here"
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
        new_entry = EntryCrypto::PasswordEntry.new "www.google.ca", "test_user"
        new_user = EntryCrypto::User.new "master_user", 1234, "some secret here"

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
        new_entry = EntryCrypto::PasswordEntry.new "www.google.ca", "test_user"
        new_user = EntryCrypto::User.new "master_user", 1234, "12345678901234567890123456789012"

        # This will do util users have encrypted secrets by default
        new_user.lock("fake_pass")
        new_user.unlock("fake_pass")

        new_entry.lock_password(new_user, "password1234")

        different_user = EntryCrypto::User.new "master_user", 1235, "some secret here"

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
        new_entry = EntryCrypto::PasswordEntry.new "www.google.ca", "test_user"
        new_user = EntryCrypto::User.new "master_user", 1234, "some secret here"

        # This will do util users have encrypted secrets by default
        new_user.lock("fake_pass")
        new_user.unlock("fake_pass")

        new_entry.lock_password(new_user, "password1234")

        different_user = EntryCrypto::User.new "master_user", 1234, "Some secret here"

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
        new_entry = EntryCrypto::PasswordEntry.new "www.google.ca", "test_user"
        new_user = EntryCrypto::User.new "master_user", 1234, "some secret here"

        # This will do util users have encrypted secrets by default
        new_user.lock("fake_pass")

        assert_raises(EntryCrypto::LockedError) { new_entry.lock_password(new_user, "password1234") }
    end

    ############################################################################
    # Test serializing a new entry
    ############################################################################
    def test_json_empty_entry
        new_entry = EntryCrypto::PasswordEntry.new "www.google.ca", "test_user"

        entry_json = new_entry.to_json

        assert entry_json == '{"json_class":"PasswordEntry","iv":null,"user_name":"test_user","site_name":"www.google.ca","encrypted_password":null,"auth_tag":null,"salt":null}'
    end

    ############################################################################
    # Test serializing a locked entry
    ############################################################################
    def test_json_locked_entry
        new_entry = EntryCrypto::PasswordEntry.new "www.google.ca", "test_user"
        new_user = EntryCrypto::User.new "master_user", 1234, "12345678901234567890123456789012"

        new_user.lock("fake_pass")
        new_user.unlock("fake_pass")

        new_entry.lock_password(new_user, "password1234")

        entry_json = new_entry.to_json

        parsed = JSON.parse entry_json

        assert parsed["json_class"] == "PasswordEntry"
        assert parsed["iv"].length == 24
        assert parsed["user_name"] == "test_user"
        assert parsed["site_name"] == "www.google.ca"
        # Double length since the stored string is a byte string
        assert parsed["encrypted_password"].length == "password1234".length * 2
        assert parsed["auth_tag"].length == 32

    end

    ############################################################################
    # Test de-serializing a locked entry properly
    ############################################################################
    def test_json_deserialize
        new_entry = EntryCrypto::PasswordEntry.new
        new_user = EntryCrypto::User.new "master_user", 1234, "12345678901234567890123456789012"

        new_user.lock("fake_pass")
        new_user.unlock("fake_pass")

        result = new_entry.from_json '{"json_class":"PasswordEntry","iv":"f28ac40a30d46674a34c8b9c","user_name":"test_user","site_name":"www.google.ca","encrypted_password":"e536c732d1d1785c157e079d","auth_tag":"0a117b90b082a633285e569b2f0f7606","salt":"bafb2053f8eba9a34a1019a47096424da985620fa169d9d7bef1e1adb788b51bbb356fa171ec8bba62b3acb1baa414773706124619bf8c8ac414594a1e440f56"}'

        assert result == true
        assert new_entry.site_name == "www.google.ca"
        assert new_entry.user_name == "test_user"

        decrypted_password = new_entry.unlock_password(new_user)

        assert decrypted_password == "password1234"
    end

    ############################################################################
    # Test de-serializing a locked entry with a changed tag
    ############################################################################
    def test_json_deserialize_bad_tag
        new_entry = EntryCrypto::PasswordEntry.new
        new_user = EntryCrypto::User.new "master_user", 1234, "Some secret here"

        new_user.lock("fake_pass")
        new_user.unlock("fake_pass")

        result = new_entry.from_json '{"json_class":"PasswordEntry","iv":"f28ac40a30d46674a34c8b9c","user_name":"test_user","site_name":"www.google.ca","encrypted_password":"e536c732d1d1785c157e079d","auth_tag":"1a117b90b082a633285e569b2f0f7606","salt":"bafb2053f8eba9a34a1019a47096424da985620fa169d9d7bef1e1adb788b51bbb356fa171ec8bba62b3acb1baa414773706124619bf8c8ac414594a1e440f56"}'

        assert result == true
        assert new_entry.site_name == "www.google.ca"
        assert new_entry.user_name == "test_user"

        decrypted_password = new_entry.unlock_password(new_user)

        assert decrypted_password != "password1234"
    end

    ############################################################################
    # Test de-serializing a locked entry with a too short IV
    ############################################################################
    def test_json_deserialize_short_iv
        new_entry = EntryCrypto::PasswordEntry.new
        new_user = EntryCrypto::User.new "master_user", 1234, "Some secret here"

        new_user.lock("fake_pass")
        new_user.unlock("fake_pass")

        result = new_entry.from_json '{"json_class":"PasswordEntry","iv":"4d2c2617dd3cb9c716571f9","user_name":"test_user","site_name":"www.google.ca","encrypted_password":"201894205d3f112fefa1e7f7","auth_tag":"a7a81df2c35c28ca5a345230b0392793"}'

        assert result == false
        assert new_entry.user_name.nil?
        assert new_entry.site_name.nil?
        assert new_entry.encrypted_password.nil?
        assert new_entry.iv.nil?
        assert new_entry.auth_tag.nil?

    end
    ############################################################################
    # Test de-serializing a locked entry with a too short tag
    ############################################################################
    def test_json_deserialize_short_tag
        new_entry = EntryCrypto::PasswordEntry.new
        new_user = EntryCrypto::User.new "master_user", 1234, "Some secret here"

        new_user.lock("fake_pass")
        new_user.unlock("fake_pass")

        result = new_entry.from_json '{"json_class":"PasswordEntry","iv":"d4d2c2617dd3cb9c716571f9","user_name":"test_user","site_name":"www.google.ca","encrypted_password":"201894205d3f112fefa1e7f7","auth_tag":"a7a81df2c3528a5a345230b0392793"}'

        assert result == false
        assert new_entry.user_name.nil?
        assert new_entry.site_name.nil?
        assert new_entry.encrypted_password.nil?
        assert new_entry.iv.nil?
        assert new_entry.auth_tag.nil?
    end

    ############################################################################
    # Test de-serializing a locked entry with a changed encrypted password
    ############################################################################
    def test_json_deserialize_changed_pass
        new_entry = EntryCrypto::PasswordEntry.new
        new_user = EntryCrypto::User.new "master_user", 1234, "12345678901234567890123456789012"

        new_user.lock("fake_pass")
        new_user.unlock("fake_pass")

        result = new_entry.from_json '{"json_class":"PasswordEntry","iv":"f28ac40a30d46674a34c8b9c","user_name":"test_user","site_name":"www.google.ca","encrypted_password":"f536c732d1d1785c157e079d","auth_tag":"0a117b90b082a633285e569b2f0f7606","salt":"bafb2053f8eba9a34a1019a47096424da985620fa169d9d7bef1e1adb788b51bbb356fa171ec8bba62b3acb1baa414773706124619bf8c8ac414594a1e440f56"}'

        assert result == true

        decrypted_password = new_entry.unlock_password(new_user)

        assert decrypted_password.nil?
    end

end
