require "./spec_helper"

describe Argon2::Engine do
  password = "password"
  salt = "somesalt\0\0\0\0\0\0\0\0"

  describe "errors" do
    describe "raw hash" do
      it "should raise ARGON2_MEMORY_TOO_LITTLE when m_cost is too small" do
        expect_raises(Exception, "Error with return code: ARGON2_MEMORY_TOO_LITTLE and value: -14") do
          Argon2::Engine.hash_argon2i_raw(password, salt, 1, 2).should eq("1c7eeef9e0e969b3024722fc864a1ca9f6ca20da73f9bf3f1731881beae2039e")
        end
      end
      it "should raise ARGON2_SALT_TOO_SHORT when salt size is too small" do
        expect_raises(Exception, "Error with return code: ARGON2_SALT_TOO_SHORT and value: -6") do
          Argon2::Engine.hash_argon2i_raw(password, "", 1, 2).should eq("1c7eeef9e0e969b3024722fc864a1ca9f6ca20da73f9bf3f1731881beae2039e")
        end
      end
    end

    describe "encoded hash" do
      it "should raise ARGON2_MEMORY_TOO_LITTLE when m_cost is too small" do
        expect_raises(Exception, "Error with return code: ARGON2_MEMORY_TOO_LITTLE and value: -14") do
          Argon2::Engine.hash_argon2i_encode(password, salt, 1, 2).should eq("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA$HH7u+eDpabMCRyL8hkocqfbKINpz+b8/FzGIG+riA54")
        end
      end
      it "should raise ARGON2_SALT_TOO_SHORT when salt size is too small" do
        expect_raises(Exception, "Error with return code: ARGON2_SALT_TOO_SHORT and value: -6") do
          Argon2::Engine.hash_argon2i_encode(password, "", 1, 2).should eq("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA$HH7u+eDpabMCRyL8hkocqfbKINpz+b8/FzGIG+riA54")
        end
      end
    end
  end
end
