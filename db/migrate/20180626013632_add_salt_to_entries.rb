class AddSaltToEntries < ActiveRecord::Migration[5.2]
  def change
    add_column :entries, :salt, :string
  end
end
