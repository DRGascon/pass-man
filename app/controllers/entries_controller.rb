require './entry-crypto/pass-entry'
require './entry-crypto/user'

class EntriesController < ApplicationController
    def new
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
    def create
        encrypted_entry = PasswordEntry.new params[:entry][:site_name], params[:entry][:user_name]
        dummy_user = get_unlocked_dummy_user
        
        # Lock the password
        encrypted_entry.lock_password dummy_user, params[:entry][:password]

        # Update the entry with everything needed to decrypt
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

        puts @entry.encrypted_password
    end

    private
        def entry_params
            params.require(:entry).permit(:site_name, :user_name, :encrypted_password, :iv, :auth_tag, :salt)
        end
end
