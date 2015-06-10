local Migration = {
  name = "2015-06-09-170921_0.3.2",

  up = function(options)
    return [[
      CREATE TABLE IF NOT EXISTS oauth2_credentials(
        id uuid,
        consumer_id uuid,
        client_id text,
        client_secret text,
        created_at timestamp,
        PRIMARY KEY (id)
      );
    ]]
  end,

  down = function(options)
    return [[
      DROP TABLE oauth2_credentials;
    ]]
  end
}

return Migration