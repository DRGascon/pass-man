
module Utils

    ############################################################################
    # Give a website entry and password, derive a new key
    ############################################################################
    def self.make_entry_key(password, entry)
        # Use SHA-512
        digest = OpenSSL::Digest::SHA512.new
        # First create our key through PBKDF2
        password_key = OpenSSL::PKCS5.pbkdf2_hmac(password, entry[:user_id].to_s + entry[:website].to_s, 10000, 32, digest)
    end
end
