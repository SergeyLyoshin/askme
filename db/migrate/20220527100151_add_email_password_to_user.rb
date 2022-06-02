class AddEmailPasswordToUser < ActiveRecord::Migration[6.1]
  def change
    # Команды, добавляющие к таблице users поля email, password_hash, password_salt
    add_column :users, :email, :string
    add_column :users, :password_hash, :string
    add_column :users, :password_salt, :string
  end

  # Эта строка добавит колонке юзера поле аватара
  add_column :users, :avatar_url, :string
end
