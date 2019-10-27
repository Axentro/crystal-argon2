require "random/secure"
require "./constants"
require "./lib_argon2"

module Argon2
  module Engine
    enum EngineType
      ARGON2I
      ARGON2D
      ARGON2ID
    end

    # Generate a random hex salt string - defaults to default length recommended by the argon2 spec
    def self.generate_salt(salt_size = DEFAULT_SALT_LEN)
      Random::Secure.hex((salt_size / 2).to_i)
    end

    # Hashes a password with Argon2i, producing a raw hash
    # @param password string
    # @param salt string
    # @param t_cost Number of iterations
    # @param m_cost Sets memory usage to m_cost kibibytes
    def self.hash_argon2i_raw(password : String, salt : String, t_cost : Int32, m_cost : Int32)
      raw_hash(EngineType::ARGON2I, password, salt, t_cost, m_cost)
    end

    # Hashes a password with Argon2i, producing an encoded hash
    # @param password string
    # @param salt string
    # @param t_cost Number of iterations
    # @param m_cost Sets memory usage to m_cost kibibytes
    def self.hash_argon2i_encode(password : String, salt : String, t_cost : Int32, m_cost : Int32)
      encoded_hash(EngineType::ARGON2I, password, salt, t_cost, m_cost)
    end

    # Hashes a password with Argon2d, producing a raw hash
    # @param password string
    # @param salt string
    # @param t_cost Number of iterations
    # @param m_cost Sets memory usage to m_cost kibibytes
    def self.hash_argon2d_raw(password : String, salt : String, t_cost : Int32, m_cost : Int32)
      raw_hash(EngineType::ARGON2D, password, salt, t_cost, m_cost)
    end

    # Hashes a password with Argon2d, producing an encoded hash
    # @param password string
    # @param salt string
    # @param t_cost Number of iterations
    # @param m_cost Sets memory usage to m_cost kibibytes
    def self.hash_argon2d_encode(password : String, salt : String, t_cost : Int32, m_cost : Int32)
      encoded_hash(EngineType::ARGON2D, password, salt, t_cost, m_cost)
    end

    # Hashes a password with Argon2id, producing a raw hash
    # @param password string
    # @param salt string
    # @param t_cost Number of iterations
    # @param m_cost Sets memory usage to m_cost kibibytes
    def self.hash_argon2id_raw(password : String, salt : String, t_cost : Int32, m_cost : Int32)
      raw_hash(EngineType::ARGON2ID, password, salt, t_cost, m_cost)
    end

    # Hashes a password with Argon2id, producing an encoded hash
    # @param password string
    # @param salt string
    # @param t_cost Number of iterations
    # @param m_cost Sets memory usage to m_cost kibibytes
    def self.hash_argon2id_encode(password : String, salt : String, t_cost : Int32, m_cost : Int32)
      encoded_hash(EngineType::ARGON2ID, password, salt, t_cost, m_cost)
    end

    # Verifies a password using Argon2i against an encoded string
    # @param password string
    # @param encoded string (output from has_argon2i_encode)
    # Returns ARGON2_OK if successful
    def self.argon2i_verify(password : String, encoded_string : String)
      encoded_verify(EngineType::ARGON2I, password, encoded_string)
    end

    # Verifies a password using Argon2d against an encoded string
    # @param password string
    # @param encoded string (output from has_argon2d_encode)
    # Returns ARGON2_OK if successful
    def self.argon2d_verify(password : String, encoded_string : String)
      encoded_verify(EngineType::ARGON2D, password, encoded_string)
    end

    # Verifies a password using Argon2id against an encoded string
    # @param password string
    # @param encoded string (output from has_argon2id_encode)
    # Returns ARGON2_OK if successful
    def self.argon2id_verify(password : String, encoded_string : String)
      encoded_verify(EngineType::ARGON2ID, password, encoded_string)
    end

    def self.raw_hash_buffer(engine_type : EngineType, password : String, salt : String, t_cost : Int32, m_cost : Int32, out_len : Int32 = OUT_LEN)
      iterations = t_cost
      memory = m_cost
      parallelism = 1
      password_len = password.bytesize
      salt_len = salt.bytesize
      hash = Slice(UInt8).new(out_len)
      hash_len = out_len

      case engine_type
      when EngineType::ARGON2I
        handle_error Argon2::Response.new(LibArgon2.argon2i_hash_raw(iterations, 1 << memory, parallelism, password, password_len, salt, salt_len, hash, hash_len))
      when EngineType::ARGON2D
        handle_error Argon2::Response.new(LibArgon2.argon2d_hash_raw(iterations, 1 << memory, parallelism, password, password_len, salt, salt_len, hash, hash_len))
      else
        handle_error Argon2::Response.new(LibArgon2.argon2id_hash_raw(iterations, 1 << memory, parallelism, password, password_len, salt, salt_len, hash, hash_len))
      end
      hash
    end

    def self.raw_hash(engine_type : EngineType, password : String, salt : String, t_cost : Int32, m_cost : Int32)
      raw_hash_buffer(engine_type, password, salt, t_cost, m_cost, OUT_LEN).hexstring
    end

    def self.encoded_hash(engine_type : EngineType, password : String, salt : String, t_cost : Int32, m_cost : Int32)
      iterations = t_cost
      memory = m_cost
      parallelism = 1
      password_len = password.bytesize
      salt_len = salt.bytesize
      buffer = Slice(UInt8).new(ENCODE_LEN)
      hash_len = OUT_LEN
      encoded_len = ENCODE_LEN

      case engine_type
      when EngineType::ARGON2I
        handle_error Argon2::Response.new(LibArgon2.argon2i_hash_encoded(iterations, 1 << memory, parallelism, password, password_len, salt, salt_len, hash_len, buffer, encoded_len))
      when EngineType::ARGON2D
        handle_error Argon2::Response.new(LibArgon2.argon2d_hash_encoded(iterations, 1 << memory, parallelism, password, password_len, salt, salt_len, hash_len, buffer, encoded_len))
      else
        handle_error Argon2::Response.new(LibArgon2.argon2id_hash_encoded(iterations, 1 << memory, parallelism, password, password_len, salt, salt_len, hash_len, buffer, encoded_len))
      end

      result = String.new(buffer)
      result.delete("\0")
    end

    def self.encoded_verify(engine_type : EngineType, password : String, encoded_string : String)
      case engine_type
      when EngineType::ARGON2I
        handle_error Argon2::Response.new(LibArgon2.argon2i_verify(encoded_string, password, password.bytesize))
      when EngineType::ARGON2D
        handle_error Argon2::Response.new(LibArgon2.argon2d_verify(encoded_string, password, password.bytesize))
      else
        handle_error Argon2::Response.new(LibArgon2.argon2id_verify(encoded_string, password, password.bytesize))
      end
    end

    private def self.handle_error(return_value : Argon2::Response)
      raise "Error with return code: #{return_value} and value: #{return_value.value}" if return_value != Argon2::Response::ARGON2_OK
      return_value
    end
  end
end
