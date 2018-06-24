require 'openssl'
require 'securerandom'

module Utils

    ############################################################################
    # Give a website entry and secret, derive a new key
    ############################################################################
    def self.make_entry_key(secret, site_name, user_name, salt = nil)
        if salt.nil? or salt.length != 64
            salt = generate_random_bytes(64)
        end
        {:salt => salt, :key => Crypto.hkdf(salt, secret, site_name + user_name, 32) }
    end

    ############################################################################
    # Generate pseudo random bytes of a specific length
    ############################################################################
    def self.generate_random_bytes(length)
        SecureRandom.random_bytes(length)
    end
end
