require './pass-enc.rb'
require './pass-dec.rb'

# A dummy entry
entry = { :website => "www.google.ca", :pass => "password1234", :user_id => 5000 }
entry1 = { :website => "www.google.ca", :pass => "another_password", :user_id => 5000 }

encPass = EncPassword.new entry, "password_test"
encPass1 = EncPassword.new entry1, "password_test"

# Now lets try to decrypt

entry[:iv] = encPass.iv
entry[:pass] = encPass.encrypted_password
entry[:tag] = encPass.tag_password

entry1[:iv] = encPass1.iv
entry1[:pass] = encPass1.encrypted_password
entry1[:tag] = "test" 

decPass = DecPassword.new entry, "password_test"
decPass1 = DecPassword.new entry1, "password_test"

passPrint = Proc.new { | pass| !pass.nil? ? (print "Decrypted password " + pass + "\n") : (print "Decryption failure\n") }

passPrint.call decPass.decrypted_password
passPrint.call decPass1.decrypted_password
