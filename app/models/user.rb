class User < ApplicationRecord
    validates :user_name, presence: true
    validates :email, presence: true, format: { with: URI::MailTo::EMAIL_REGEXP }
    has_many :entries
end
