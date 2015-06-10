local BaseDao = require "kong.dao.cassandra.base_dao"

local OAuth2Credentials = BaseDao:extend()

function OAuth2Credentials:new(properties)
  self._schema = {
    id = { type = "id" },
    consumer_id = { type = "id", required = true, foreign = true, queryable = true },
    name = { type = "string", required = true, queryable = true },
    client_id = { type = "string", required = true, unique = true, queryable = true },
    client_secret = { type = "string", required = true, unique = true, queryable = true },
    created_at = { type = "timestamp" }
  }

  self._queries = {
    insert = {
      args_keys = { "id", "consumer_id", "name", "client_id", "client_secret", "created_at" },
      query = [[
        INSERT INTO oauth2_credentials(id, consumer_id, name, client_id, client_secret, created_at)
          VALUES(?, ?, ?, ?, ?, ?);
      ]]
    },
    update = {
      args_keys = { "name", "created_at", "id" },
      query = [[ UPDATE oauth2_credentials SET name = ?, created_at = ? WHERE id = ?; ]]
    },
    select = {
      query = [[ SELECT * FROM oauth2_credentials %s; ]]
    },
    select_one = {
      args_keys = { "id" },
      query = [[ SELECT * FROM oauth2_credentials WHERE id = ?; ]]
    },
    delete = {
      args_keys = { "id" },
      query = [[ DELETE FROM oauth2_credentials WHERE id = ?; ]]
    },
    __foreign = {
      consumer_id = {
        args_keys = { "consumer_id" },
        query = [[ SELECT id FROM consumers WHERE id = ?; ]]
      }
    },
    __unique = {
      key = {
        args_keys = { "key" },
        query = [[ SELECT id FROM oauth2_credentials WHERE key = ?; ]]
      }
    },
    drop = "TRUNCATE oauth2_credentials;"
  }

  OAuth2Credentials.super.new(self, properties)
end

return { oauth2_credentials = OAuth2Credentials }
