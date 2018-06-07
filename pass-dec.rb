# Include whatever modules we'll be using
require 'openssl'
require './utils/logging'

################################################################################
# DecPassword class
#
# This class will be initialized using an encrypted password entry and will
# decrypt it as part of its initialization
#
# Who knows if RAII is a good idea in Ruby...
#
################################################################################
class DecPassword
    attr_reader :decrypted_password, :tag_password
    ############################################################################
    # initialize method
    #
    # entry is expected to contain:
    #    user_id: The id of the user who's password we're decrypting
    #    webiste: The site the password is for (This is used as the phrase for the KDF
    #    password: The encrypted password to decrypt
    #    iv: The IV to decrypt with
    ############################################################################
    def initialize(entry, password)
        # Log what we're doing
        Logging.logger.info "Decrypting password for " + entry[:user_id].to_s + " site " + entry[:website]
        # Use SHA-512
        digest = OpenSSL::Digest::SHA512.new
        # First create our key through PBKDF2
        password_key = OpenSSL::PKCS5.pbkdf2_hmac(password, entry[:user_id].to_s + entry[:website].to_s, 10000, 32, digest)
        # Now lets encrypt the password using GCM
        cipher = OpenSSL::Cipher::AES.new(256, :GCM)
        # Use decrypt mode
        cipher.decrypt
        # Use the KDF key
        cipher.key = password_key
        # Use the IV
        cipher.iv = entry[:iv]
        # Our AEAD is Website + user_id
        cipher.auth_data = entry[:website] + entry[:user_id].to_s
        cipher.auth_tag = entry[:tag]
        # Do the decryption
        @decrypted_password = cipher.update(entry[:pass]) + cipher.final
        Logging.logger.info "Decrypted password for " + entry[:user_id].to_s + " site " + entry[:website]
    end
end
