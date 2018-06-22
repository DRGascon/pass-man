################################################################################
# Unit tests for the HKDF
################################################################################


require './utils/hkdf'
require 'minitest/autorun'

class TC_HKDFTest < MiniTest::Test

    def test_hkdf_kat1

        ikm = "\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B"
        salt = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C"
        prk = Crypto.hkdf_extract(salt, ikm)
        assert prk.unpack("H*")[0] == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"

        info = "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9"
        # Now that the ikm is good, call the expand step
        okm = Crypto.hkdf_expand(prk, info, 42)

        # Check the keying material
        assert okm.unpack("H*")[0] == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    end
end
