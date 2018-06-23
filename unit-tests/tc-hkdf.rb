################################################################################
# Unit tests for the HKDF, KATs are from RFC5869
# https://tools.ietf.org/html/rfc5869
################################################################################


require './utils/hkdf'
require 'minitest/autorun'

class TC_HKDFTest < MiniTest::Test

    def test_hkdf_kat1

        ikm = Array.new(22, 0x0B).pack("C*")
        salt = (0x00..0x0C).to_a.pack("C*")
        prk = Crypto.hkdf_extract(salt, ikm)
        # Check the extract step
        assert prk.unpack("H*")[0] == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"

        info = (0xF0..0xF9).to_a.pack("C*")
        # Now that the ikm is good, call the expand step
        okm = Crypto.hkdf_expand(prk, info, 42)

        # Check the keying material
        assert okm.unpack("H*")[0] == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    end
end
