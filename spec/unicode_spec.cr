require "./spec_helper"

describe Argon2::Password do
  describe "unicode" do
    it "should work with utf16" do
      unstr = "Σὲ γνωρίζω ἀπὸ τὴν κό"
      hash = Argon2::Password.create(unstr)
      Argon2::Password.verify_password(unstr, hash).should eq(Argon2::Response::ARGON2_OK)
    end

    it "should work with null byte" do
      rawstr = "String has a\0NULL in it"
      hash = Argon2::Password.create(rawstr)
      Argon2::Password.verify_password(rawstr, hash).should eq(Argon2::Response::ARGON2_OK)
      # Asserts that no NULL byte truncation occurs
      expect_raises(Exception, "Error with return code: ARGON2_VERIFY_MISMATCH and value: -35") do
        Argon2::Password.verify_password("String has a", hash)
      end
    end

    it "should work with emoji" do
      rawstr = "😀 😬 😁 😂 😃 😄 💩 😈 👿"
      hash = Argon2::Password.create(rawstr)
      Argon2::Password.verify_password(rawstr, hash).should eq(Argon2::Response::ARGON2_OK)
      # Asserts not empty string
      expect_raises(Exception, "Error with return code: ARGON2_VERIFY_MISMATCH and value: -35") do
        Argon2::Password.verify_password("", hash)
      end
    end
  end
end
