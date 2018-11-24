require "./spec_helper"

describe Argon2::Engine do
  password = "password"
  salt = "somesalt\0\0\0\0\0\0\0\0"

  describe "hash_argon2i_raw" do
    it "with 2 iterations and 16 cost" do
      Argon2::Engine.hash_argon2i_raw(password, salt, 2, 16).should eq("1c7eeef9e0e969b3024722fc864a1ca9f6ca20da73f9bf3f1731881beae2039e")
    end

    it "with 2 iterations and 18 cost" do
      Argon2::Engine.hash_argon2i_raw(password, salt, 2, 18).should eq("5c6dfd2712110cf88f1426059b01d87f8210d5368da0e7ee68586e9d4af4954b")
    end

    it "with 2 iterations and 8 cost" do
      Argon2::Engine.hash_argon2i_raw(password, salt, 2, 8).should eq("dfebf9d4eadd6859f4cc6a9bb20043fd9da7e1e36bdacdbb05ca569f463269f8")
    end

    it "with 1 iterations and 16 cost" do
      Argon2::Engine.hash_argon2i_raw(password, salt, 1, 16).should eq("fabd1ddbd86a101d326ac2abe79660202b10192925d2fd2483085df94df0c91a")
    end

    it "with 4 iterations and 16 cost" do
      Argon2::Engine.hash_argon2i_raw(password, salt, 4, 16).should eq("b3b4cb3d6e2c1cb1e7bffdb966ab3ceafae701d6b7789c3f1e6c6b22d82d99d5")
    end

    it "with 2 iterations and 16 cost and different password" do
      Argon2::Engine.hash_argon2i_raw("differentpassword", salt, 2, 16).should eq("b2db9d7c0d1288951aec4b6e1cd3835ea29a7da2ac13e6f48554a26b127146f9")
    end

    it "with 2 iterations and 16 cost and different salt" do
      Argon2::Engine.hash_argon2i_raw(password, "diffsalt\0\0\0\0\0\0\0\0", 2, 16).should eq("bb6686865f2c1093f70f543c9535f807d5b42d5dc6d71f14a4a7a291913e05e0")
    end
  end

  describe "hasg_argon2i_encode" do
    it "with 2 iterations and 16 cost" do
      Argon2::Engine.hash_argon2i_encode(password, salt, 2, 16).should eq("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA$HH7u+eDpabMCRyL8hkocqfbKINpz+b8/FzGIG+riA54")
    end

    it "with 2 iterations and 8 cost" do
      Argon2::Engine.hash_argon2i_encode(password, salt, 2, 16).should eq("$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA$3+v51OrdaFn0zGqbsgBD/Z2n4eNr2s27BcpWn0Yyafg")
    end

    it "with 1 iterations and 16 cost" do
      Argon2::Engine.hash_argon2i_encode(password, salt, 1, 16).should eq("$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQAAAAAAAAAAA$+r0d29hqEB0yasKr55ZgICsQGSkl0v0kgwhd+U3wyRo")
    end

    it "with 2 iterations and 16 cost and different password" do
      Argon2::Engine.hash_argon2i_encode(password, salt, 1, 16).should eq("$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQAAAAAAAAAAA$+r0d29hqEB0yasKr55ZgICsQGSkl0v0kgwhd+U3wyRo")
    end

    it "with 2 iterations and 16 cost and different salt" do
      Argon2::Engine.hash_argon2i_encode(password, salt, 1, 16).should eq("$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQAAAAAAAAAAA$+r0d29hqEB0yasKr55ZgICsQGSkl0v0kgwhd+U3wyRo")
    end
  end
end
