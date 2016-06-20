require "jwt"
require "securerandom"

module Joken
  class Tokens
    MAX_DEVICES = 10
    EXP_DAYS = 14
    TOKEN_SIZE = 15


    def new_auth_token
      token = SecureRandom.urlsafe_base64(15)
      
      if self.auth_tokens
        self.auth_tokens[token] = { created_at: Time.now.to_i }
      else
        self.auth_tokens = { token => { created_at: Time.now.to_i } }
      end

      while self.auth_tokens.size > MAX_DEVICES
        exp_sort = self.auth_tokens.sort_by { |k, v| k["created_at"] }.first
        self.delete_token(exp_sort.first)
      end
      
      save
      
      # Should be returned and passed in header as:
      # 'Authorization: Bearer xxxxxxx.yyyyyyyyy.zzzzzzzzzzz'
      build_header(token)
    end

    def delete_token(token)
      self.auth_tokens.delete!(token)
    end

    def build_header(token)
      payload = {
        data: {
          id: id, 
          auth_token: token
        },
        exp: (DateTime.now + EXP_DAYS).to_i
      }
      
      # Could be Rails.application.secrets.secret_key_base....
      JWT.encode(payload, ENV["SECRET_KEY"])
    end
  end
end
