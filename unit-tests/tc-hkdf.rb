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
        info = (0xF0..0xF9).to_a.pack("C*")
        prk = Crypto.hkdf_extract(salt, ikm)
        # Check the extract step
        assert prk.unpack("H*")[0] == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"

        # Now that the ikm is good, call the expand step
        okm = Crypto.hkdf_expand(prk, info, 42)

        # Check the keying material
        assert okm.unpack("H*")[0] == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    end

    def test_hkdf_kat1_different_ikm

        ikm = Array.new(22, 0x0A).pack("C*")
        salt = (0x00..0x0C).to_a.pack("C*")
        info = (0xF0..0xF9).to_a.pack("C*")
        prk = Crypto.hkdf_extract(salt, ikm)
        # Check the extract step
        assert prk.unpack("H*")[0] != "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"

        # Now that the ikm is good, call the expand step
        okm = Crypto.hkdf_expand(prk, info, 42)

        # Check the keying material
        assert okm.unpack("H*")[0] != "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    end

    def test_hkdf_kat1_zero_salt

        ikm = Array.new(22, 0x0B).pack("C*")
        salt = ""
        info = (0xF0..0xF9).to_a.pack("C*")
        prk = Crypto.hkdf_extract(salt, ikm)
        # Check the extract step
        assert prk.unpack("H*")[0] != "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"

        # Now that the ikm is good, call the expand step
        okm = Crypto.hkdf_expand(prk, info, 42)

        # Check the keying material
        assert okm.unpack("H*")[0] != "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    end

    def test_hkdf_kat1_zero_info

        ikm = Array.new(22, 0x0B).pack("C*")
        salt = (0x00..0x0C).to_a.pack("C*")
        info = ""
        prk = Crypto.hkdf_extract(salt, ikm)
        # Check the extract step, which should still pass
        assert prk.unpack("H*")[0] == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"

        # Now that the ikm is good, call the expand step
        okm = Crypto.hkdf_expand(prk, info, 42)

        # Check the keying material
        assert okm.unpack("H*")[0] != "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    end

    def test_hkdf_kat2

        ikm = (0x00..0x4F).to_a.pack("C*")
        salt = (0x60..0xAF).to_a.pack("C*")
        info = (0xB0..0xFF).to_a.pack("C*")

        prk = Crypto.hkdf_extract(salt, ikm)

        # Check the extract step
        assert prk.unpack("H*")[0] == "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"

        okm = Crypto.hkdf_expand(prk, info, 82)

        assert okm.unpack("H*")[0] == "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
    end

    def test_hkdf_kat2_zero_info

        ikm = (0x00..0x4F).to_a.pack("C*")
        salt = (0x60..0xAF).to_a.pack("C*")
        info = ""

        prk = Crypto.hkdf_extract(salt, ikm)

        # Check the extract step
        assert prk.unpack("H*")[0] == "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"

        okm = Crypto.hkdf_expand(prk, info, 82)

        assert okm.unpack("H*")[0] != "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
    end

    def test_hkdf_kat2_zero_salt

        ikm = (0x00..0x4F).to_a.pack("C*")
        salt = ""
        info = (0xB0..0xFF).to_a.pack("C*")

        prk = Crypto.hkdf_extract(salt, ikm)

        # Check the extract step
        assert prk.unpack("H*")[0] != "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"

        okm = Crypto.hkdf_expand(prk, info, 82)

        assert okm.unpack("H*")[0] != "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
    end

    def test_hkdf_kat3

        ikm = Array.new(22, 0x0B).pack("C*")
        salt = ""
        info = ""

        prk = Crypto.hkdf_extract(salt, ikm)

        assert prk.unpack("H*")[0] == "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"

        okm = Crypto.hkdf_expand(prk, info, 42)

        assert okm.unpack("H*")[0] == "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    end

    def test_hkdf_kat3_different_ikm

        ikm = Array.new(22, 0x0C).pack("C*")
        salt = ""
        info = ""

        prk = Crypto.hkdf_extract(salt, ikm)

        assert prk.unpack("H*")[0] != "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"

        okm = Crypto.hkdf_expand(prk, info, 42)

        assert okm.unpack("H*")[0] != "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    end

end
