class CreateEntries < ActiveRecord::Migration[5.2]
  def change
    create_table :entries do |t|
      t.string :site_name
      t.string :user_name
      t.string :encrypted_password
      t.string :auth_tag
      t.string :iv

      t.timestamps
    end
  end
end
