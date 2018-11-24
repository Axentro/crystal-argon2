require "./spec_helper"

describe Argon2::Engine do
  password = "password"
  salt = "somesalt\0\0\0\0\0\0\0\0"

  describe "errors" do
    it "with 2 iterations and 16 cost" do
      Argon2::Engine.hash_argon2i_raw(password, salt, 2, 16).should eq("1c7eeef9e0e969b3024722fc864a1ca9f6ca20da73f9bf3f1731881beae2039e")
    end
  end
end
