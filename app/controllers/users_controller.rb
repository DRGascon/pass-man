require './entry-crypto/user'
require './utils/string'

class UsersController < ApplicationController

    def new
        @user = User.new

    end

    def create
        crypto_user = EntryCrypto::User.new params[:user][:user_name], params[:user][:id]

        encrypted_secret = crypto_user.lock(params[:user][:password])

        params[:user][:iv] = Utils.array_to_str(crypto_user.iv)
        params[:user][:auth_tag] = Utils.array_to_str(crypto_user.auth_tag)
        params[:user][:secret] = Utils.array_to_str(encrypted_secret)

        @user = User.new user_params

        if @user.save
            redirect_to @user
        else
            render 'new'
        end
    end

    private
        def user_params
            params.require(:user).permit(:user_name, :email, :secret, :iv, :auth_tag)
        end
end
