require './utils/logging'
require './utils/compare'
require 'openssl'

################################################################################
# User class
#
# Represents a user with a unique ID, and secret.
#
# Secrets remain encrypted until the user is authenticated
################################################################################
class User
    attr_accessor :name, :id
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
        digest = OpenSSL::Digest::SHA512.new
        # First generate the key based on the password
        secret_key = OpenSSL::PKCS5.pbkdf2_hmac(password, @id.to_s, 20000, 32, digest)
        # Is this our expected secret?
        @unlocked = Utils.equal_time_compare(secret_key, @secret)
        Logging.logger.info "Unlock attempt for " + @name + " result " + @unlocked.to_s
    end

    ############################################################################
    # Lock the user's secret with a password
    ############################################################################
    def lock(password)
        @unlocked = false
    end
end
