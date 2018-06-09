# Include whatever modules we'll be using
require 'openssl'
require './utils/logging'
require './utils/key_gen'

################################################################################
# EncPassword class
#
# This class will be initialized using a password entry and will always contain
# an encrypted password through its lifetime.
#
# Who knows if RAII is a good idea in Ruby...
#
################################################################################
class EncPassword
    # Let anyone read the encrypted password
    attr_reader :encrypted_password, :tag_password, :iv

    ############################################################################
    # initialize method
    #
    # entry is expected to contain:
    #   user_id: The id of the user who's password we're encrypting
    #   website: The site the password is for (This is used as the phrase for the KDF
    #   password: The actual password to encrypt
    #
    ############################################################################
    def initialize(entry, password)
        # Log what we're doing
        Logging.logger.info "Encrypting password for " + entry[:user_id].to_s + " site " + entry[:website]
        # Use SHA-512
        digest = OpenSSL::Digest::SHA512.new
        # First create our key through PBKDF2
	password_key = Utils.make_entry_key(password, entry)
        # Now lets encrypt the password using GCM
        cipher = OpenSSL::Cipher::AES.new(256, :GCM)
        # Use encrypt mode
        cipher.encrypt
        # Take 256 bits of the KDF return
        cipher.key = password_key
        # Always use a random IV
        @iv = cipher.random_iv
        cipher.iv = @iv
        # Our AEAD is Website + user_id
        cipher.auth_data = entry[:website] + entry[:user_id].to_s
        # Do the encryption
        @encrypted_password = cipher.update(entry[:pass]) + cipher.final
        # Get the auth tag
        @tag_password = cipher.auth_tag
        Logging.logger.info "Encrypted password for " + entry[:user_id].to_s + " site " + entry[:website] + " tag_password " + @tag_password.unpack('H*').first
    end

end
