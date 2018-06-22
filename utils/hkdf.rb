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
        okm = ""
        total_length = (output_length.to_f/(256/8)).ceil
        generated_values = []
        generated_values << ""
        generated_values[0].force_encoding "ASCII-8BIT"
        itr = 1
        info.force_encoding "ASCII-8BIT"
        while itr <= total_length
            test =generated_values[itr - 1] + info + [itr].pack("C*") 
            result = OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, prk, generated_values[itr - 1] + info + [itr].pack("C*"))
            result.force_encoding "ASCII-8BIT"
            generated_values << result
            # Append to the OKM
            okm << result
            itr += 1
        end
        okm[0..output_length-1]
    end
end
