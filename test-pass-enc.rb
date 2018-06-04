require './pass-enc.rb'
require './pass-dec.rb'

# A dummy entry
entry = { :website => "www.google.ca", :pass => "password1234", :user_id => 5000 }
entry1 = { :website => "www.google.ca", :pass => "another_password", :user_id => 5000 }

encPass = EncPassword.new entry
encPass1 = EncPassword.new entry1

# Now lets try to decrypt

entry[:iv] = encPass.iv
entry[:pass] = encPass.encrypted_password
entry[:tag] = encPass.tag_password

entry1[:iv] = encPass1.iv
entry1[:pass] = encPass1.encrypted_password
entry1[:tag] = encPass1.tag_password

decPass = DecPassword.new entry
decPass1 = DecPassword.new entry1


print "Decrypted password" + decPass.decrypted_password + "\n"
print "Decrypted password " + decPass1.decrypted_password + "\n"
