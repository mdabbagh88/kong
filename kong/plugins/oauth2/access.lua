local stringy = require "stringy"
local utils = require "kong.tools.utils"
local cache = require "kong.tools.database_cache"
local responses = require "kong.tools.responses"

local _M = {}


local RESPONSE_TYPE = "response_type"
local STATE = "state"
local CODE = "code"
local TOKEN = "token"
local SCOPE = "scope"
local CLIENT_ID = "client_id"
local ERROR = "error"
local AUTHENTICATED_USERNAME = "authenticated_username"
local AUTHENTICATED_USERID = "authenticated_userid"

local AUTHORIZE_URL = "^/oauth2/authorize/?$"
local TOKEN_URL = "^/oauth2/token/?$"

-- TODO: Expire token (using TTL ?)
local function generate_token(credential, authenticated_username, authenticated_userid, state)
  local token, err = dao.oauth2_tokens:insert({
    credential_id = credential.id,
    authenticated_username = authenticated_username,
    authenticated_userid = authenticated_userid
  })
  return {
    access_token = token.access_token,
    token_type = "bearer",
    expires_in = token.expires_in,
    refresh_token = token.refresh_token,
    state = state -- If state is nil, this value won't be added
  }
end

local function get_redirect_uri(client_id)
  local client
  if client_id then
    client = cache.get_or_set(cache.oauth2_credential_key(client_id), function()
      local credentials, err = dao.oauth2_credentials:find_by_keys { client_id = client_id }
      local result
      if err then
        return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
      elseif #credentials > 0 then
        result = credentials[1]
      end
      return result
    end)
  end
  return client and client.redirect_uri or nil, client
end

local function authorize(conf)
  local response_params = {}

  ngx.req.read_body()
  -- OAuth2 parameters could be in both the querystring or body
  local parameters = utils.table_merge(ngx.req.get_uri_args(), ngx.req.get_post_args())

  local redirect_uri, client
  local state = parameters[STATE]

  if conf.provision_key ~= parameters.provision_key then
    response_params = {[ERROR] = "invalid_provision_key", error_description = "Invalid Kong provision_key"}
  else
    local response_type = parameters[RESPONSE_TYPE]
    -- Check response_type
    if not (response_type == CODE or response_type == TOKEN) then -- Authorization Code Grant (http://tools.ietf.org/html/rfc6749#section-4.1.1)
      response_params = {[ERROR] = "unsupported_response_type", error_description = "Invalid "..RESPONSE_TYPE}
    end

    -- Check scopes
    local scope = parameters[SCOPE]
    if conf.scopes and scope then
      local scopes = stringy.split(scope, " ")
      for _, v in ipairs(scopes) do
        if not utils.table_contains(conf.scopes, scope) then
          response_params = {[ERROR] = "invalid_scope", error_description = "\""..scope.."\" is an invalid "..SCOPE}
          break
        end
      end
    elseif not scope and conf.mandatory_scope then
      response_params = {[ERROR] = "invalid_scope", error_description = "You must specify a "..SCOPE}
    end

    -- Check client_id and redirect_uri
    redirect_uri, client = get_redirect_uri(parameters[CLIENT_ID])
    if not redirect_uri then
      response_params = {[ERROR] = "invalid_request", error_description = "Invalid "..CLIENT_ID}
    end

    -- If there are no errors, keep processing the request
    if not response_params[ERROR] then
      if response_type == CODE then
        local authorization_code, err = dao.oauth2_authorization_codes:insert({
          authenticated_username = parameters[AUTHENTICATED_USERNAME],
          authenticated_userid = parameters[AUTHENTICATED_USERID]
        })

        response_params = {
          code = authorization_code.code,
        }
      else
        response_params = generate_token(client, parameters[AUTHENTICATED_USERNAME], parameters[AUTHENTICATED_USERID], state)
      end
    end
  end

  -- Adding the state if it exists. If the state == nil then it won't be added
  response_params.state = state

  -- Sending response in JSON format
  responses.send(response_params[ERROR] and 400 or 200, redirect_uri and {
    redirect_uri = redirect_uri.."?"..ngx.encode_args(response_params)
  } or response_params)
end

--[[
local function retrieve_token()
  ngx.req.read_body()
  local args = ngx.req.get_post_args()
  
  local grant_type = args["grant_type"]
  if grant_type == "authorization_code" then
    local code = args["code"]

    local redirect_uri = get_redirect_uri(querystring["client_id"])
    if redirect_uri then
      local authorization_code = dao.oauth2_authorization_codes:find_one(code)

      if authorization_code then
        responses.send_HTTP_OK(generate_token())
      end

    end

  end
end
--]]

function _M.execute(conf)
  if ngx.req.get_method() == "POST" then
    if ngx.re.match(ngx.var.request_uri, AUTHORIZE_URL) then
      authorize(conf)
    elseif ngx.re.match(ngx.var.request_uri, TOKEN_URL) then
      --retrieve_token()
    end
  end

  local access_token = ngx.req.get_uri_args()["access_token"]

  local token
  if access_token then
    token = cache.get_or_set(cache.oauth2_token_key(access_token), function()
      local credentials, err = dao.oauth2_tokens:find_by_keys { access_token = access_token }
      local result
      if err then
        return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
      elseif #credentials > 0 then
        result = credentials[1]
      end
      return result
    end)
  end

  if not credential then
    ngx.ctx.stop_phases = true -- interrupt other phases of this request
    return responses.send_HTTP_FORBIDDEN("Invalid authentication credentials")
  end

  -- Retrieve consumer
  --[[
  local consumer = cache.get_or_set(cache.consumer_key(credential.consumer_id), function()
    local result, err = dao.consumers:find_one(credential.consumer_id)
    if err then
      return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
    end
    return result
  end)

  ngx.req.set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
  ngx.req.set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
  ngx.req.set_header(constants.HEADERS.CONSUMER_USERNAME, consumer.username)
  ngx.ctx.authenticated_entity = credential
  --]]
end

return _M