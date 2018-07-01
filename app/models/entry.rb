class Entry < ApplicationRecord
    validates :user_name, presence: true
    validates :site_name, presence: true
    validates :encrypted_password, presence: true
    belongs_to :user
end
