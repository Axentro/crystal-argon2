require "random/secure"
require "./constants"
require "./lib_argon2"

module Argon2
  module Engine

    # Generate a random hex salt string - defaults to default length recommended by the argon2 spec
    def self.generate_salt(salt_size = DEFAULT_SALT_LEN)
      Random::Secure.hex(salt_size / 2)
    end

    # Hashes a password with Argon2i, producing a raw hash
    # @param password string
    # @param salt string
    # @param t_cost Number of iterations
    # @param m_cost Sets memory usage to m_cost kibibytes
    def self.hash_argon2i_raw(password : String, salt : String, t_cost : Int32, m_cost : Int32)
      iterations = t_cost
      memory = m_cost
      parallelism = 1
      password_len = password.bytesize
      salt_len = salt.bytesize
      hash = Slice(UInt8).new(OUT_LEN)
      hash_len = OUT_LEN
      LibArgon2.argon2i_hash_raw(iterations, 1 << memory, parallelism, password, password_len, salt, salt_len, hash, hash_len)
      hash.hexstring
    end

    def self.hash_argon2i_encode(password : String, salt : String, t_cost : Int32, m_cost : Int32)
      iterations = t_cost
      memory = m_cost
      parallelism = 1
      password_len = password.bytesize
      salt_len = salt.bytesize
      buffer = Slice(UInt8).new(ENCODE_LEN)
      hash_len = OUT_LEN
      encoded_len = ENCODE_LEN

      LibArgon2.argon2i_hash_encoded(iterations, 1 << memory, parallelism, password, password_len, salt, salt_len, hash_len, buffer, encoded_len)
      result = String.new(buffer)
      result.delete("\0")
    end

  end
end

# p Argon2::Engine.hash_argon2i_raw("password","somesalt\0\0\0\0\0\0\0\0", 2, 16)
# p Argon2::Engine.hash_argon2i_encode("password","somesalt\0\0\0\0\0\0\0\0", 2, 16)


# a =  "FLIHOaTUWps\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000"
# p a.hexbytes

# require "random/secure"
#
# iterations = 2
# memory = 1024
# parallelism = 4
# password = "password"
# password_len = password.bytesize
# salt = Random::Secure.hex(8)
# salt_len = salt.bytesize
# key_len = 32
# hash = Slice(UInt8).new(key_len)
# hash_len = key_len
# salt_slice = Slice(UInt8).new(salt.bytesize / 2)
#
# 1.step(to: salt.size, by: 2) do |i|
#   salt_slice[(i - 1) / 2] = salt[i - 1 .. i].to_u8(16)
# end
#
# p LibArgon2.argon2i_hash_raw(iterations, memory, parallelism, password, password_len, salt, salt_len, hash, hash_len)
# p hash.hexstring
