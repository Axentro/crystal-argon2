require "./spec_helper"

describe Argon2::Password do

  it "should create new password instance with default values" do
    pass = Argon2::Password.new
    pass.@t_cost.should eq(2)
    pass.@m_cost.should eq(16)
  end

  it "should create new password instance with supplied args" do
    pass = Argon2::Password.new(4, 12)
    pass.@t_cost.should eq(4)
    pass.@m_cost.should eq(12)
  end

  it "should create a hash" do
    result = Argon2::Password.new.create("password")
    result.starts_with?("$argon2i").should be_true
  end

  describe "verify with long and short salt" do
    it "should verify an existing hash with a long salt" do
     result = Argon2::Password.verify_password("password", "$argon2i$v=19$m=65536,t=2,p=1$VG9vTG9uZ1NhbGVMZW5ndGg$mYleBHsG6N0+H4JGJ0xXoIRO6rWNZwN/eQQQ8eHIDmk")
     result.should eq(Argon2::Response::ARGON2_OK)
    end
    it "should verify an existing hash with a short salt" do
     result = Argon2::Password.verify_password("password", "$argon2i$v=19$m=65536,t=2,p=1$VG9vU2hvcnRTYWxlTGVu$i59ELgAm5G6J+9+oZwO+kkV48tJyocNh6bHdkj9J5lk")
     result.should eq(Argon2::Response::ARGON2_OK)
    end
  end
end
