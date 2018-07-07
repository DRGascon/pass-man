class AddCryptoToUsers < ActiveRecord::Migration[5.2]
  def change
    add_column :users, :auth_tag, :string
    add_column :users, :iv, :string
  end
end
