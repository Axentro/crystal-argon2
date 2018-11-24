require "./engine"
require "./constants"
require "./lib_argon2"

module Argon2
  class Password
    def initialize(@t_cost : Int32 = 2, @m_cost : Int32 = 16)
      @salt = Engine.generate_salt
    end

    def create(password : String, engine_type : Engine::EngineType = Engine::EngineType::ARGON2I)
      case engine_type
      when Engine::EngineType::ARGON2I
        Argon2::Engine.hash_argon2i_encode(password, @salt, @t_cost, @m_cost)
      when Engine::EngineType::ARGON2D
        Argon2::Engine.hash_argon2d_encode(password, @salt, @t_cost, @m_cost)
      else
        Argon2::Engine.hash_argon2id_encode(password, @salt, @t_cost, @m_cost)
      end
    end

    def self.create(password : String)
      Argon2::Password.new.create(password)
    end

    def self.verify_password(password : String, hash : String, engine_type : Engine::EngineType = Engine::EngineType::ARGON2I)
      case engine_type
      when Engine::EngineType::ARGON2I
        Argon2::Engine.argon2i_verify(password, hash)
      when Engine::EngineType::ARGON2D
        Argon2::Engine.argon2d_verify(password, hash)
      else
        Argon2::Engine.argon2id_verify(password, hash)
      end
    end
  end
end
