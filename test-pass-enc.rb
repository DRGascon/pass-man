require './pass-enc.rb'

# A dummy entry
entry = { :website => "www.google.ca", :pass => "password1234", :user_id => 5000 }

encPass = EncPassword.new entry

