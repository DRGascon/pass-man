require './entry-crypto/pass-entry'
require './entry-crypto/user'

class EntriesController < ApplicationController
    def new
        @entry = Entry.new
    end

    def edit
        @entry = Entry.find(params[:id])

        @entry.encrypted_password = get_displayable_decrypted_password @entry
    end

    def create
        encrypted_entry = EntryCrypto::PasswordEntry.new params[:entry][:site_name], params[:entry][:user_name]
        dummy_user = get_unlocked_dummy_user
        
        # Lock the password
        encrypted_entry.lock_password dummy_user, params[:entry][:password]

        # Update the entry with everything needed to decrypt, stored as strings for now
        params[:entry][:encrypted_password] = Utils.array_to_str(encrypted_entry.encrypted_password)
        params[:entry][:iv] = Utils.array_to_str(encrypted_entry.iv)
        params[:entry][:auth_tag] = Utils.array_to_str(encrypted_entry.auth_tag)
        params[:entry][:salt] = Utils.array_to_str(encrypted_entry.salt)

        @entry = Entry.new entry_params

        if @entry.save
            redirect_to @entry
        else
            render 'new'
        end
    end

    def update
        # Pull the existing entry
        @entry = Entry.find(params[:id])

        # Encrypt the new password
        encrypted_entry = EntryCrypto::PasswordEntry.new @entry.site_name, @entry.user_name
        # Use a dummy user for now
        dummy_user = get_unlocked_dummy_user
        
        # Lock the password, because we haven't set crypto attributes a new set
        # will be generated for this update
        encrypted_entry.lock_password dummy_user, params[:entry][:encrypted_password]

        # Update the entry with everything needed to decrypt, stored as strings for now
        params[:entry][:encrypted_password] = Utils.array_to_str(encrypted_entry.encrypted_password)
        params[:entry][:iv] = Utils.array_to_str(encrypted_entry.iv)
        params[:entry][:auth_tag] = Utils.array_to_str(encrypted_entry.auth_tag)
        params[:entry][:salt] = Utils.array_to_str(encrypted_entry.salt)

        if @entry.update(entry_params)
            redirect_to @entry
        else
            render 'edit'
        end
    end

    def destroy
        @entry = Entry.find(params[:id])

        # We own this password, we can delete it
        if !(get_decrypted_password @entry).nil?
            @entry.destroy
        end

        redirect_to entries_path
    end

    def show
        @entry = Entry.find(params[:id])

        @entry.encrypted_password = get_displayable_decrypted_password @entry
    end

    def index
        @entries = []
        # Iterate through each entry, decrypting if possible
        Entry.all.each do |entry|
            entry.encrypted_password = get_displayable_decrypted_password entry
            @entries << entry
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
            dummy_user = EntryCrypto::User.new "dgascon", 1, "12345678901234567890123456789012"
            # Here until we have proper user authentication
            dummy_user.lock("123912840913750sadfjahsdfkasehruiw")
            dummy_user.unlock("123912840913750sadfjahsdfkasehruiw")

            dummy_user
        end

        ########################################################################
        # Take an entry, and return it's decrypted password as a string
        # If decryption can't be done, nil will be returned
        ########################################################################
        def get_decrypted_password(entry)
            # Use a dummy user until we have valid authentication
            user = get_unlocked_dummy_user
            # Create our entry
            decrypted_entry = EntryCrypto::PasswordEntry.new entry.site_name, entry.user_name
            decrypted_entry.set_crypto_values entry.encrypted_password.split.pack("H*"), entry.iv.split.pack("H*"), entry.auth_tag.split.pack("H*"), entry.salt.split.pack("H*")
            decrypted_entry.unlock_password user
        end

        ########################################################################
        # A wrapped around get_decrypted_password which will return a masked
        # entry if decryption failed
        ########################################################################
        def get_displayable_decrypted_password(entry)
            decrypted_password = get_decrypted_password entry

            if decrypted_password.nil?
                decrypted_password = "********"
            end
            decrypted_password
        end
end
