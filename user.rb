require './utils/logging'
require './utils/compare'
require 'openssl'

################################################################################
# Custom exception for trying to use a locked user
################################################################################
class LockedError < StandardError
    def initialize(user)
        super("Tried to use locked user")
        Logging.logger.error "Trying to use locked user " + user.name
    end
end

################################################################################
# User class
#
# Represents a user with a unique ID, and secret.
#
# Secrets remain encrypted until the user is authenticated
################################################################################
class User
    attr_accessor :name, :id, :iv, :auth_tag
    attr_reader :secret, :unlocked

    ############################################################################
    # Initialize a new user
    #
    # name - the username
    # id - the user id
    # secret - the user's secret
    ############################################################################
    def initialize(name, id, secret)
        @name = name
        @id = id
        @secret = secret
        @unlocked = false
        Logging.logger.info "Initialized new user " + name + " id " + id.to_s
    end

    ############################################################################
    # Unlock the user's secret based on a password
    ############################################################################
    def unlock(password)
        Logging.logger.info "Trying to unlock user " + @name
        secret_key = generate_key(password)
        # Now try to decrypt the secret
        decrypted_secret = decrypt_secret(secret_key, @iv, @auth_tag)
        # Did we successfully get the secret?
        if !decrypted_secret.nil?
            @secret = decrypted_secret
        end
        @unlocked = !decrypted_secret.nil?
    end

    ############################################################################
    # Generate a key based off a password, using parts of the user for a salt
    ############################################################################
    def generate_key(password)
        digest = OpenSSL::Digest::SHA512.new
        # Generate the key based on the password
        secret_key = OpenSSL::PKCS5.pbkdf2_hmac(password, @id.to_s, 20000, 32, digest)
    end

    ############################################################################
    # Decrypt the user's secret key
    ############################################################################
    def decrypt_secret(key, iv, auth_tag)
        # Get the cipher
        cipher = OpenSSL::Cipher::AES.new(256, :GCM)
        # Set to decrypt
        cipher.decrypt
        # Setup the cipher parameters
        cipher.iv = iv
        cipher.key = key
        cipher.auth_tag = auth_tag
        cipher.auth_data = @name + @id.to_s
        # Try to do the decryption, if the tags fail to verify we'll get a
        # CipherError thrown
        begin
            decrypted_secret = cipher.update(@secret) + cipher.final
        rescue OpenSSL::Cipher::CipherError
            Logging.logger.error "Failed to decrypt secret for user " + @name + " tag " + @auth_tag.unpack('H*').first
            decrypted_secret = nil
        end
    end

    ############################################################################
    # Lock the user's secret with a password
    ############################################################################
    def lock(password)
        cipher = OpenSSL::Cipher::AES.new(256, :GCM)
        # If there's no IV, generate one
        @iv = @iv.nil? ? cipher.random_iv : @iv
        key = generate_key(password)
        @auth_tag = encrypt_secret(key, @iv)
        @unlocked = false
    end

    ############################################################################
    # Encrypt the user's secret key
    ############################################################################
    def encrypt_secret(key, iv)
        # Get the cipher
        cipher = OpenSSL::Cipher::AES.new(256, :GCM)
        # Set to decrypt
        cipher.encrypt
        # Setup the cipher parameters
        cipher.iv = iv
        cipher.key = key
        cipher.auth_data = @name + @id.to_s
        # Try to do the decryption, if the tags fail to verify we'll get a
        # CipherError thrown
        begin
            @secret = cipher.update(@secret) + cipher.final
        rescue OpenSSL::Cipher::CipherError
            Logging.logger.error "Failed to encrypt secret for user " + @name
        end
        Logging.logger.error "Encrypted secret for user " + @name + " tag " + cipher.auth_tag.unpack('H*').first
        cipher.auth_tag
    end

    ############################################################################
    # Overriden accessor to prevent returning the secret if the user is locked
    ############################################################################
    def secret
        if @unlocked
            @secret
        else
            raise LockedError.new self
        end
    end
    private :decrypt_secret, :encrypt_secret
end
