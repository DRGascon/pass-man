require 'OpenSSL'

module Utils

    ############################################################################
    # Give a website entry and secret, derive a new key
    ############################################################################
    def self.make_entry_key(secret, site_name, user_name)
        # Use SHA-512
        digest = OpenSSL::Digest::SHA512.new
        # First create our key through PBKDF2
        password_key = OpenSSL::PKCS5.pbkdf2_hmac(secret, site_name + user_name, 10000, 32, digest)
    end

    ############################################################################
    # Generate pseudo random bytes of a specific length
    ############################################################################
    def self.generate_random_bytes(length)
        # Check to see if we have enough entropy
        if OpenSSL::Random.status?
            OpenSSL::Random.pseudo_bytes(length)
        else
            nil
        end
    end
end
