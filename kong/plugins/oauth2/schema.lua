local utils = require "kong.tools.utils"
local stringy = require "stringy"

local function generate_if_missing(v, t, column)
  if not v or stringy.strip(v) == "" then
    return true, nil, { [column] = utils.uuid(true)}
  end
  return true
end

local function check_mandatory_scope(v, t)
  if v and not t.scopes then
    return false, "To set a mandatory scope you also need to create available scopes"
  end
  return true
end

return {
  scopes = { required = false, type = "array" },
  mandatory_scope = { required = true, type = "boolean", default = false, func = check_mandatory_scope },
  provision_key = { required = false, unique = true, type = "string", func = generate_if_missing }
}
