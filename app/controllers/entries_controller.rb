require './entry-crypto/pass-entry'
require './entry-crypto/user'

class EntriesController < ApplicationController
    def new
    end

    def create
        encrypted_entry = PasswordEntry.new params[:entry][:site_name], params[:entry][:user_name]
        dummy_user = get_unlocked_dummy_user
        
        # Lock the password
        encrypted_entry.lock_password dummy_user, params[:entry][:password]

        # Update the entry with everything needed to decrypt, stored as strings for now
        params[:entry][:encrypted_password] = Utils.array_to_str(encrypted_entry.encrypted_password)
        params[:entry][:iv] = Utils.array_to_str(encrypted_entry.iv)
        params[:entry][:auth_tag] = Utils.array_to_str(encrypted_entry.auth_tag)
        params[:entry][:salt] = Utils.array_to_str(encrypted_entry.salt)

        puts params
        @entry = Entry.new entry_params

        @entry.save
        redirect_to @entry
    end

    def show
        @entry = Entry.find(params[:id])

        decrypted_entry = PasswordEntry.new @entry.site_name, @entry.user_name
        decrypted_entry.set_crypto_values @entry.encrypted_password.split.pack("H*"), @entry.iv.split.pack("H*"), @entry.auth_tag.split.pack("H*"), @entry.salt.split.pack("H*")
        dummy_user = get_unlocked_dummy_user

        @entry.encrypted_password = decrypted_entry.unlock_password(dummy_user)
    end

    def index
        @entries = []
        user = get_unlocked_dummy_user
        # Iterate through each entry, decrypting if possible
        Entry.all.each do |entry|
            decrypted_entry = PasswordEntry.new entry.site_name, entry.user_name
            decrypted_entry.set_crypto_values entry.encrypted_password.split.pack("H*"), entry.iv.split.pack("H*"), entry.auth_tag.split.pack("H*"), entry.salt.split.pack("H*")
            decrypted_password = decrypted_entry.unlock_password user
            # If decryption was successful, append the entry
            if !decrypted_password.nil?
                entry.encrypted_password = decrypted_password
                @entries << entry
            # Otherwise show a hidden field
            else
                entry.encrypted_password = "********"
                @entries << entry
            end
        end

        
    end

    private
        def entry_params
            params.require(:entry).permit(:site_name, :user_name, :encrypted_password, :iv, :auth_tag, :salt)
        end

        ############################################################################
        # Generate, unlock, and return a dummy user.
        #
        # This is for getting ramped on rails, once real user auth is in place this
        # should go away
        ############################################################################
        def get_unlocked_dummy_user
            dummy_user = User.new "dgascon", 1, "12345678901234567890123456789012"
            # Here until we have proper user authentication
            dummy_user.lock("123912840913750sadfjahsdfkasehruiw")
            dummy_user.unlock("123912840913750sadfjahsdfkasehruiw")

            dummy_user
        end

end
