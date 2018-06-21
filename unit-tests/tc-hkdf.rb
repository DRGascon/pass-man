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
    end
end
