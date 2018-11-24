require "./spec_helper"

describe Argon2::Engine do
  password = "password"
  salt = "somesalt\0\0\0\0\0\0\0\0"

  describe "argon2i" do
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

    describe "hash_argon2i_encode" do
      it "with 2 iterations and 16 cost" do
        Argon2::Engine.hash_argon2i_encode(password, salt, 2, 16).should eq("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA$HH7u+eDpabMCRyL8hkocqfbKINpz+b8/FzGIG+riA54")
      end

      it "with 2 iterations and 8 cost" do
        Argon2::Engine.hash_argon2i_encode(password, salt, 2, 8).should eq("$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA$3+v51OrdaFn0zGqbsgBD/Z2n4eNr2s27BcpWn0Yyafg")
      end

      it "with 1 iterations and 16 cost" do
        Argon2::Engine.hash_argon2i_encode(password, salt, 1, 16).should eq("$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQAAAAAAAAAAA$+r0d29hqEB0yasKr55ZgICsQGSkl0v0kgwhd+U3wyRo")
      end

      it "with 2 iterations and 16 cost and different password" do
        Argon2::Engine.hash_argon2i_encode("differentpassword", salt, 2, 16).should eq("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA$studfA0SiJUa7EtuHNODXqKafaKsE+b0hVSiaxJxRvk")
      end

      it "with 2 iterations and 16 cost and different salt" do
        Argon2::Engine.hash_argon2i_encode(password, "diffsalt\0\0\0\0\0\0\0\0", 2, 16).should eq("$argon2i$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQAAAAAAAAAAA$u2aGhl8sEJP3D1Q8lTX4B9W0LV3G1x8UpKeikZE+BeA")
      end
    end
  end

  describe "argon2d" do
    describe "hash_argon2d_raw" do
      it "with 2 iterations and 16 cost" do
        Argon2::Engine.hash_argon2d_raw(password, salt, 2, 16).should eq("aadb2bfc595ce2da52c554835d50154aa60d53ca3469230f9a3ac8dc623fa294")
      end
      it "with 2 iterations and 18 cost" do
        Argon2::Engine.hash_argon2d_raw(password, salt, 2, 18).should eq("5fe78c2c6dc09edba8a4d1571e4ec4b5c504c13fd0c47a69597f92385bd8c854")
      end

      it "with 2 iterations and 8 cost" do
        Argon2::Engine.hash_argon2d_raw(password, salt, 2, 8).should eq("5e8ecb8a10a8168b47583d639bf3e2264a9702884468ad4851b3ec2f81430167")
      end

      it "with 1 iterations and 16 cost" do
        Argon2::Engine.hash_argon2d_raw(password, salt, 1, 16).should eq("0b05fd22786e5b5973b40b633f741e5f6e95ae39b90bb1c54b0d41fc8b727ce5")
      end

      it "with 4 iterations and 16 cost" do
        Argon2::Engine.hash_argon2d_raw(password, salt, 4, 16).should eq("048a2a5f3db05f887c0e7fd4e4255a29a360cf9fec8891ddd26003c7bdf4d79f")
      end

      it "with 2 iterations and 16 cost and different password" do
        Argon2::Engine.hash_argon2d_raw("differentpassword", salt, 2, 16).should eq("1c43716a0317758fe69aea5d01629094fbeff1bf3107a161ffc24674d052f55f")
      end

      it "with 2 iterations and 16 cost and different salt" do
        Argon2::Engine.hash_argon2d_raw(password, "diffsalt\0\0\0\0\0\0\0\0", 2, 16).should eq("4d8f103781c305d52d2e690efcc6b96c3cfe218650962fe0ae9efc4f78eb9c1a")
      end
    end

    describe "hash_argon2d_encode" do
      it "with 2 iterations and 16 cost" do
        Argon2::Engine.hash_argon2d_encode(password, salt, 2, 16).should eq("$argon2d$v=19$m=65536,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA$qtsr/Flc4tpSxVSDXVAVSqYNU8o0aSMPmjrI3GI/opQ")
      end

      it "with 2 iterations and 8 cost" do
        Argon2::Engine.hash_argon2d_encode(password, salt, 2, 8).should eq("$argon2d$v=19$m=256,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA$Xo7LihCoFotHWD1jm/PiJkqXAohEaK1IUbPsL4FDAWc")
      end

      it "with 1 iterations and 16 cost" do
        Argon2::Engine.hash_argon2d_encode(password, salt, 1, 16).should eq("$argon2d$v=19$m=65536,t=1,p=1$c29tZXNhbHQAAAAAAAAAAA$CwX9InhuW1lztAtjP3QeX26Vrjm5C7HFSw1B/ItyfOU")
      end

      it "with 2 iterations and 16 cost and different password" do
        Argon2::Engine.hash_argon2d_encode("differentpassword", salt, 2, 16).should eq("$argon2d$v=19$m=65536,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA$HENxagMXdY/mmupdAWKQlPvv8b8xB6Fh/8JGdNBS9V8")
      end

      it "with 2 iterations and 16 cost and different salt" do
        Argon2::Engine.hash_argon2d_encode(password, "diffsalt\0\0\0\0\0\0\0\0", 2, 16).should eq("$argon2d$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQAAAAAAAAAAA$TY8QN4HDBdUtLmkO/Ma5bDz+IYZQli/grp78T3jrnBo")
      end
    end
  end

  describe "argon2id" do
    describe "hash_argon2id_raw" do
      it "with 2 iterations and 16 cost" do
        Argon2::Engine.hash_argon2id_raw(password, salt, 2, 16).should eq("b327fc4f307da6f3081ad161bd10131d6d675f8de23fe14b69a4d79eaa7232b6")
      end
      it "with 2 iterations and 18 cost" do
        Argon2::Engine.hash_argon2id_raw(password, salt, 2, 18).should eq("f14d2a35a2bfcb67d8da297e2e377e7673637c53ca04bd212622a2554278d5da")
      end

      it "with 2 iterations and 8 cost" do
        Argon2::Engine.hash_argon2id_raw(password, salt, 2, 8).should eq("4c2b0d52eb5682fde5a30b2d21ab0525b7626a62a2abca8f51dcf6c12bd0e2bc")
      end

      it "with 1 iterations and 16 cost" do
        Argon2::Engine.hash_argon2id_raw(password, salt, 1, 16).should eq("6fbb0b9812786068ffc8e8cc9d40d60b576faed66bec43dd313eb307d16ad299")
      end

      it "with 4 iterations and 16 cost" do
        Argon2::Engine.hash_argon2id_raw(password, salt, 4, 16).should eq("bd8091ea02d471a71407f48d4dee02a13e9ea44bf6b43c2ba77bff81613cd87c")
      end

      it "with 2 iterations and 16 cost and different password" do
        Argon2::Engine.hash_argon2id_raw("differentpassword", salt, 2, 16).should eq("d1b0d1d9fa6266eb628f3c65c6b8cb9ea9c24a6b46d7fade47840d71abdf28b9")
      end

      it "with 2 iterations and 16 cost and different salt" do
        Argon2::Engine.hash_argon2id_raw(password, "diffsalt\0\0\0\0\0\0\0\0", 2, 16).should eq("be6d6a417650fbf3204f663e1a8ed79f1b40f5d273df0a2d8df8348ad3a02a56")
      end
    end

    describe "hash_argon2id_encode" do
      it "with 2 iterations and 16 cost" do
        Argon2::Engine.hash_argon2id_encode(password, salt, 2, 16).should eq("$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA$syf8TzB9pvMIGtFhvRATHW1nX43iP+FLaaTXnqpyMrY")
      end

      it "with 2 iterations and 8 cost" do
        Argon2::Engine.hash_argon2id_encode(password, salt, 2, 8).should eq("$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA$TCsNUutWgv3lowstIasFJbdiamKiq8qPUdz2wSvQ4rw")
      end

      it "with 1 iterations and 16 cost" do
        Argon2::Engine.hash_argon2id_encode(password, salt, 1, 16).should eq("$argon2id$v=19$m=65536,t=1,p=1$c29tZXNhbHQAAAAAAAAAAA$b7sLmBJ4YGj/yOjMnUDWC1dvrtZr7EPdMT6zB9Fq0pk")
      end

      it "with 2 iterations and 16 cost and different password" do
        Argon2::Engine.hash_argon2id_encode("differentpassword", salt, 2, 16).should eq("$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA$0bDR2fpiZutijzxlxrjLnqnCSmtG1/reR4QNcavfKLk")
      end

      it "with 2 iterations and 16 cost and different salt" do
        Argon2::Engine.hash_argon2id_encode(password, "diffsalt\0\0\0\0\0\0\0\0", 2, 16).should eq("$argon2id$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQAAAAAAAAAAA$vm1qQXZQ+/MgT2Y+Go7XnxtA9dJz3wotjfg0itOgKlY")
      end
    end
  end
end
