################################################################################
# An entry for everthing stored with a password
################################################################################

require './utils/logging'
require './utils/key_gen'
require './utils/string'
require './entry-crypto/user'
require 'json'

class PasswordEntry

    attr_accessor :site_name, :user_name, :salt
    attr_reader :password, :encrypted_password, :auth_tag, :iv

    ############################################################################
    # Initialize the entry
    ############################################################################
    def initialize(site_name = "", user_name = "")
        Logging.logger.info "Creating password entry for site " + site_name + " user " + user_name
        @site_name = site_name
        @user_name = user_name
        @iv = nil
        @encrypted_password = nil
        @auth_tag = nil
        @salt = nil
    end

    ############################################################################
    # Unlock a password with the secret it was locked with
    ############################################################################
    def unlock_password(user)
        Logging.logger.info "Trying to unlock website " + @site_name + " user name " + @user_name + " for user " + user.name
        password_key = Utils.make_entry_key(user.secret, @site_name, @user_name, @salt)

        # Now decrypt the password
        cipher = OpenSSL::Cipher::AES.new(256, :GCM)
        cipher.decrypt
        cipher.iv = @iv
        cipher.key = password_key[:key]
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
        password_key = Utils.make_entry_key(user.secret, @site_name, @user_name, @salt)
        # Now decrypt the password
        cipher = OpenSSL::Cipher::AES.new(256, :GCM)
        cipher.encrypt
        @iv = @iv.nil? ? cipher.random_iv : @iv
        @salt = password_key[:salt]
        cipher.iv = @iv
        cipher.key = password_key[:key]
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

    ############################################################################
    # Convert the object to JSON representation
    ############################################################################
    def to_json
        Logging.logger.info "Serializing PasswordEntry for website " + @site_name + " user name " + @user_name
        JSON.generate({
            :json_class => "PasswordEntry",
            :iv => Utils.array_to_str(@iv),
            :user_name => @user_name,
            :site_name => @site_name,
            :encrypted_password => Utils.array_to_str(@encrypted_password),
            :auth_tag => Utils.array_to_str(@auth_tag),
            :salt => Utils.array_to_str(@salt)
        })
    end

    ############################################################################
    # Retrieve an object from JSON representation
    ############################################################################
    def from_json(json_string)
        result = false
        parsed_json = JSON.parse(json_string)
        Logging.logger.info "Trying to deserialize PasswordEntry"
        # Make sure this is for this class
        if parsed_json["json_class"] == "PasswordEntry"
            @user_name = parsed_json["user_name"]
            @site_name = parsed_json["site_name"]
            # Only accept sensitive information if all pieces are present
            if parsed_json["iv"] and parsed_json["iv"].length == 24 and
                    parsed_json["encrypted_password"] and
                    parsed_json["auth_tag"] and parsed_json["auth_tag"].length == 32 and
                    parsed_json["salt"] and parsed_json["salt"].length == 128

                    @iv = parsed_json["iv"].split.pack("H*")
                    @encrypted_password = parsed_json["encrypted_password"].split.pack("H*")
                    @auth_tag = parsed_json["auth_tag"].split.pack("H*")
                    @salt = parsed_json["salt"].split.pack("H*")
                    result = true
            else
                # Clear out anything we might've set
                @user_name = nil
                @site_name = nil
            end
        end
        if result == false
            Logging.logger.error "Failed to deserialize"
        end
        result
    end

end
