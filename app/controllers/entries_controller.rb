require './entry-crypto/pass-entry'
require './entry-crypto/user'

class EntriesController < ApplicationController
    def new
    end

    def create
        # For now we'll use a dummy user
        dummy_user = User.new "dgascon", 1, "12345678901234567890123456789012"
        encrypted_entry = PasswordEntry.new params[:entry][:site_name], params[:entry][:user_name]

        dummy_user.lock("123912840913750sadfjahsdfkasehruiw")
        dummy_user.unlock("123912840913750sadfjahsdfkasehruiw")

        encrypted_entry.lock_password dummy_user, params[:entry][:password]

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
