################################################################################
# A module to implement HKDF according to RFC5869
################################################################################
require 'openssl'

module Crypto

    ############################################################################
    # The HDFK extrack step using SHA-256 as the hard coded hashing algorithm
    ############################################################################
    def self.hkdf_extract(salt, ikm)
        # No explicit handling of empty salt case as HMAC by definition
        # will zero pat any key that isn't long enough
        OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, salt, ikm)
    end

    ############################################################################
    # The HDFK expand step using SHA-256 as the hard coded hashing algorithm
    ############################################################################
    def self.hkdf_expand(prk, info, output_length)
        okm = ""
        total_length = (output_length.to_f/(256/8)).ceil
        previous_value = ""
        # Force the encodings to make OpenSSL happy
        previous_value.force_encoding "ASCII-8BIT"
        itr = 1
        info.force_encoding "ASCII-8BIT"
        while itr <= total_length
            previous_value = OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new,
                prk, previous_value + info + [itr].pack("C*"))
            previous_value.force_encoding "ASCII-8BIT"
            # Append to the OKM
            okm << previous_value
            itr += 1
        end
        # Return the L bytes of the OKM
        okm[0..output_length-1]
    end
end
