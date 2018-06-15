################################################################################
# An entry for everthing stored with a password
################################################################################

require './utils/logging'
require './utils/key_gen'
require './user'
require 'json'

class PasswordEntry

    attr_accessor :site_name, :user_name
    attr_reader :password, :encrypted_password, :auth_tag, :iv

    ############################################################################
    # Initialize the entry
    ############################################################################
    def initialize(site_name, user_name)
        Logging.logger.info "Creating password entry for site " + site_name + " user " + user_name
        @site_name = site_name
        @user_name = user_name
    end

    ############################################################################
    # Unlock a password with the secret it was locked with
    ############################################################################
    def unlock_password(user)
        Logging.logger.info "Trying to unlock website " + @site_name + " user name " + @user_name + " for user " + user.name
        password_key = Utils.make_entry_key(user.secret, @site_name, @user_name)

        # Now decrypt the password
        cipher = OpenSSL::Cipher::AES.new(256, :GCM)
        cipher.decrypt
        cipher.iv = @iv
        cipher.key = password_key
        cipher.auth_tag = @auth_tag
        cipher.auth_data = user.name + user.id.to_s

        begin
            decrypted_password = cipher.update(@encrypted_password) + cipher.final
        rescue OpenSSL::Cipher::CipherError
            Logging.logger.error "Failed to unlock website " + @site_name + " user name " + @user_name
            decrypted_password = nil
        else
            Logging.logger.info "Unlocked website " + @site_name + " user name " + @user_name
        end
        decrypted_password
    end

    ############################################################################
    # Lock a password with a secret
    ############################################################################
    def lock_password(user, password)
        Logging.logger.info "Trying to lock website " + @site_name + " user name " + @user_name + " for user " + user.name
        password_key = Utils.make_entry_key(user.secret, @site_name, @user_name)
        # Now decrypt the password
        cipher = OpenSSL::Cipher::AES.new(256, :GCM)
        cipher.encrypt
        @iv = @iv.nil? ? cipher.random_iv : @iv
        cipher.iv = @iv
        cipher.key = password_key
        cipher.auth_data = user.name + user.id.to_s
        begin
            @encrypted_password = cipher.update(password) + cipher.final
        rescue OpenSSL::Cipher::CipherError
            Logging.logger.error "Failed to lock website " + @site_name + " user name " + @user_name + " for user " + user.name
            @encrypted_password = nil
        else
            Logging.logger.info "Locked website " + @site_name + " user name " + @user_name
        end
        @auth_tag = cipher.auth_tag
        @encrypted_password
    end

    def array_to_str(array)
        array.nil? ? nil : array.unpack("H*").first.force_encoding('UTF-8')


    end

    def to_json
        JSON.generate({
            :json_class => "PasswordEntry",
            :iv => array_to_str(@iv),
            :user_name => @user_name,
            :site_name => @site_name,
            :encrypted_password => array_to_str(@encrypted_password),
            :auth_tag => array_to_str(@auth_tag)
        })
    end

end
