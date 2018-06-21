################################################################################
# A module to implement HKDF according to RFC5869
################################################################################
require 'openssl'

module Crypto

    def self.hkdf_extract(salt, ikm)
        prk = OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, salt, ikm)
    end

    def self.hkdf_expand(prk, info, output_length)
        # Digest is 512bits long
        total_length = output_length/(512/8).ceil
        generated_values = [""]
        generated_length = 0
        itr = 1
        while generated_length < output_length
            generated_values << OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, prk, generated_values[-1] + info + itr)
            generated_length += 512/8
        end
    end
end
