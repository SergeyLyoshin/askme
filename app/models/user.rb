require 'openssl'

class User < ApplicationRecord
  ITERATIONS = 20_000
  DIGEST = OpenSSL::Digest::SHA256.new
  HEX_BACKGROUND_COLOR_REGEX = /\A#([\da-f]{3}){1,2}\z/
  DEFAULT_BACKGROUND_COLOR = '#005a55'
  
  has_many :questions, dependent: :destroy

  attr_accessor :password, :password_confirmation

  #Валидации из задания:
  validates :username, length: { maximum: 40 },
                       presence: true, uniqueness: true, format: {with: /\A\w+\z/}

  validates :email, presence: true, uniqueness: true, format: { with: URI::MailTo::EMAIL_REGEXP }

  validates :background_color, format: {with: HEX_BACKGROUND_COLOR_REGEX}, on: :update

  before_validation :downcase_username_and_email

  before_save :encrypt_password


  # Служебный метод, преобразующий бинарную строку в шестнадцатиричный формат,
  # для удобства хранения.
  def self.hash_to_string(password_hash)
    password_hash.unpack('H*')[0]
  end

  def self.authenticate(email, password)
    user = find_by(email: email)
    if user.present? && user.password_hash == User
       .hash_to_string(OpenSSL::PKCS5.pbkdf2_hmac(password, user.password_salt, ITERATIONS, DIGEST.length, DIGEST))
      user
    end
  end

  def bg_color
    background_color || DEFAULT_BACKGROUND_COLOR
  end

  private

  def downcase_username_and_email
    username&.downcase!
    email&.downcase!
  end

  def encrypt_password
    if password.present?
      self.password_salt = User.hash_to_string(OpenSSL::Random.random_bytes(16))

      self.password_hash = User.hash_to_string(
        OpenSSL::PKCS5.pbkdf2_hmac(
          password, password_salt, ITERATIONS, DIGEST.length, DIGEST
        )
      )

    end
  end
  
end
