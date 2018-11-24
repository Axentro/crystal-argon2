@[Link(ldflags: "-L#{__DIR__}/../ext/argon2 -largon2")]
lib LibArgon2
  # Hashes a password with Argon2i, producing a raw hash at @hash
  # @param t_cost Number of iterations
  # @param m_cost Sets memory usage to m_cost kibibytes
  # @param parallelism Number of threads and compute lanes
  # @param pwd Pointer to password
  # @param pwdlen Password size in bytes
  # @param salt Pointer to salt
  # @param saltlen Salt size in bytes
  # @param hash Buffer where to write the raw hash - updated by the function
  # @param hashlen Desired length of the hash in bytes
  # Different parallelism levels will give different results
  # Returns ARGON2_OK if successful
  fun argon2i_hash_raw(t_cost : LibC::Int, m_cost : LibC::Int, parallelism : LibC::Int, pwd : Void*, pwdlen : LibC::SizeT, salt : Void*, saltlen : LibC::SizeT, hash : Void*, hashlen : LibC::SizeT) : LibC::Int

  # Hashes a password with Argon2i, producing an encoded hash
  # @param t_cost Number of iterations
  # @param m_cost Sets memory usage to m_cost kibibytes
  # @param parallelism Number of threads and compute lanes
  # @param pwd Pointer to password
  # @param pwdlen Password size in bytes
  # @param salt Pointer to salt
  # @param saltlen Salt size in bytes
  # @param hashlen Desired length of the hash in bytes
  # @param encoded Buffer where to write the encoded hash
  # @param encodedlen Size of the buffer (thus max size of the encoded hash)
  # Different parallelism levels will give different results
  # Returns ARGON2_OK if successful
  fun argon2i_hash_encoded(t_cost : LibC::Int, m_cost : LibC::Int, parallelism : LibC::Int, pwd : Void*, pwdlen : LibC::SizeT, salt : Void*, saltlen : LibC::SizeT, hashlen : LibC::SizeT, encoded : LibC::Char*, encodedlen : LibC::SizeT) : LibC::Int

  # Hashes a password with Argon2d, producing a raw hash at @hash
  # same params as Argon2i
  fun argon2d_hash_raw(t_cost : LibC::Int, m_cost : LibC::Int, parallelism : LibC::Int, pwd : Void*, pwdlen : LibC::SizeT, salt : Void*, saltlen : LibC::SizeT, hash : Void*, hashlen : LibC::SizeT) : LibC::Int

  # Hashes a password with Argon2i, producing an encoded hash
  # same params as Argon2i
  fun argon2d_hash_encoded(t_cost : LibC::Int, m_cost : LibC::Int, parallelism : LibC::Int, pwd : Void*, pwdlen : LibC::SizeT, salt : Void*, saltlen : LibC::SizeT, hashlen : LibC::SizeT, encoded : LibC::Char*, encodedlen : LibC::SizeT) : LibC::Int

  # Hashes a password with Argon2id, producing a raw hash at @hash
  # same params as Argon2i
  fun argon2id_hash_raw(t_cost : LibC::Int, m_cost : LibC::Int, parallelism : LibC::Int, pwd : Void*, pwdlen : LibC::SizeT, salt : Void*, saltlen : LibC::SizeT, hash : Void*, hashlen : LibC::SizeT) : LibC::Int

  # Hashes a password with Argon2id, producing an encoded hash
  # same params as Argon2i
  fun argon2id_hash_encoded(t_cost : LibC::Int, m_cost : LibC::Int, parallelism : LibC::Int, pwd : Void*, pwdlen : LibC::SizeT, salt : Void*, saltlen : LibC::SizeT, hashlen : LibC::SizeT, encoded : LibC::Char*, encodedlen : LibC::SizeT) : LibC::Int

  fun argon2i_verify(encoded : LibC::Char*, pwd : Void*, pwdlen : LibC::SizeT) : LibC::Int
  fun argon2d_verify(encoded : LibC::Char*, pwd : Void*, pwdlen : LibC::SizeT) : LibC::Int
  fun argon2id_verify(encoded : LibC::Char*, pwd : Void*, pwdlen : LibC::SizeT) : LibC::Int
end
