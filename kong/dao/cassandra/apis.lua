local BaseDao = require "kong.dao.cassandra.base_dao"
local apis_schema = require "kong.dao.schemas.apis"

local Apis = BaseDao:extend()

function Apis:new(properties)
  self._entity = "API"
  self._table = "apis"
  self._schema = apis_schema
  self._primary_key = {"id"}
  self._queries = {
    select = {
      query = [[ SELECT * FROM apis %s; ]]
    },
    __unique = {
      self = {
        args_keys = { "id" },
        query = [[ SELECT * FROM apis WHERE id = ?; ]]
      },
      name = {
        args_keys = { "name" },
        query = [[ SELECT id FROM apis WHERE name = ?; ]]
      },
      path = {
        args_keys = { "path" },
        query = [[ SELECT id FROM apis WHERE path = ?; ]]
      },
      public_dns = {
        args_keys = { "public_dns" },
        query = [[ SELECT id FROM apis WHERE public_dns = ?; ]]
      }
    },
    drop = "TRUNCATE apis;"
  }

  Apis.super.new(self, properties)
end

function Apis:find_all()
  local apis = {}
  for _, rows, page, err in Apis.super._execute_kong_query(self, self._queries.select.query, nil, {auto_paging=true}) do
    if err then
      return nil, err
    end

    for _, row in ipairs(rows) do
      table.insert(apis, row)
    end
  end

  return apis
end

-- @override
function Apis:delete(where_t)
  local ok, err = Apis.super.delete(self, {id = where_t.id})
  if not ok then
    return false, err
  end

  -- delete all related plugins configurations
  local plugins_dao = self._factory.plugins_configurations
  local query, args_keys, errors = plugins_dao:_build_where_query(plugins_dao._queries.select.query, {
    api_id = where_t.id
  })
  if errors then
    return nil, errors
  end

  for _, rows, page, err in plugins_dao:_execute_kong_query({query=query, args_keys=args_keys}, {api_id=where_t.id}, {auto_paging=true}) do
    if err then
      return nil, err
    end

    for _, row in ipairs(rows) do
      local ok_del_plugin, err = plugins_dao:delete({id = row.id})
      if not ok_del_plugin then
        return nil, err
      end
    end
  end

  return ok
end

return { apis = Apis }
