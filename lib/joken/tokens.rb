require "jwt"

module Joken
  class Tokens
    MAX_DEVICES = 10

    def new_auth_token
      token = SecureRandom.urlsafe_base64(15)

      auth_tokens << { token => { created_at: Time.now.to_i } }

      while auth_tokens.size > MAX_DEVICES
        exp_sort = auth_tokens.sort_by { |k, v| v["created_at"] }.first
        auth_tokens.delete!(exp_sort.first)
      end

      # Should be returned and passed in header as:
      # 'Authorization: Bearer xxxxxxx.yyyyyyyyy.zzzzzzzzzzz'
      build_header(token)
    end

    def delete_token(token)
      auth_tokens.delete!(token)
    end

    def build_header(token)
      payload = [{data: {id: id, auth_token: token}}, {typ: "JWT", alg: "HS256"}]
      # Could be Rails.application.secrets.secret_key_base....
      JWT.encode(payload, ENV["SECRET_KEY"], "HS256")
    end
  end
end
