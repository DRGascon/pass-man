class EntriesController < ApplicationController
    def new
    end

    def create
        render plain: params[:entry].inspect
    end
end
