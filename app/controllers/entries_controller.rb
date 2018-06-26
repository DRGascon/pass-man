require './entry-crypto/pass-entry'
require './entry-crypto/user'

class EntriesController < ApplicationController
    def new
    end

    def create
        # For now we'll use a dummy user
        dummy_user = User.new "dgascon", 1, "12345678901234567890123456789012"
        encrypted_entry = PasswordEntry.new params[:entry][:website], params[:entry][:user_name]

        dummy_user.lock("123912840913750sadfjahsdfkasehruiw")
        dummy_user.unlock("123912840913750sadfjahsdfkasehruiw")

        encrypted_entry.lock_password dummy_user, params[:entry][:password]

        @entry = Entry.new encrypted_entry.site_name, encrypted_entry.user_name, encrypted_entry.encrypted_password, encrypted_entry.auth_tag, encrypted_entry.iv
        params[:entry]
    end
end
