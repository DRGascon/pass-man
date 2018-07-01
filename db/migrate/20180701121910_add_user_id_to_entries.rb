class AddUserIdToEntries < ActiveRecord::Migration[5.2]
  def change
    add_reference :entries, :user_id, foreign_key: true
  end
end
