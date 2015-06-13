local spec_helper = require "spec.spec_helpers"
local utils = require "kong.tools.utils"
local http_client = require "kong.tools.http_client"
local cjson = require "cjson"
local rex = require "rex_pcre"

-- Load everything we need from the spec_helper
local env = spec_helper.get_env() -- test environment
local faker = env.faker
local dao_factory = env.dao_factory
local configuration = env.configuration
configuration.cassandra = configuration.databases_available[configuration.database].properties

local PROXY_URL = spec_helper.PROXY_URL

local function provision_code()
  local response, status = http_client.post(PROXY_URL.."/oauth2/authorize", { provision_key = "provision123", client_id = "clientid123", scope = "email", response_type = "code", state = "hello", authenticated_username = "user123", authenticated_userid = "userid123" }, {host = "oauth2.com"})
  local body = cjson.decode(response)
  local matches = rex.gmatch(body.redirect_uri, "^http://google\\.com/kong\\?code=([\\w]{32,32})&state=hello$")
  local code 
  for line in matches do 
    code = line
    break
  end
  local data = dao_factory.oauth2_authorization_codes:find_by_keys({code = code})
  return data[1].code
end

describe("Authentication Plugin", function()

  setup(function()
    spec_helper.prepare_db()
    spec_helper.insert_fixtures {
      api = {
        { name = "tests oauth2", public_dns = "oauth2.com", target_url = "http://mockbin.com" }
      },
      consumer = {
        { username = "auth_tests_consumer" }
      },
      plugin_configuration = {
        { name = "oauth2", value = { scopes = { "email", "profile" }, mandatory_scope = true, provision_key = "provision123" }, __api = 1 }
      },
      oauth2_credential = {
        { client_id = "clientid123", client_secret = "secret123", redirect_uri = "http://google.com/kong", name="testapp", __consumer = 1 }
      }
    }

    spec_helper.start_kong()
  end)

  teardown(function()
    spec_helper.stop_kong()
  end)

  describe("OAuth2 Authorization", function()

    describe("Code Grant", function()

      it("should return an error when no provision_key is being sent", function()
        local response, status, headers = http_client.post(PROXY_URL.."/oauth2/authorize", { }, {host = "oauth2.com"})
        local body = cjson.decode(response)
        assert.are.equal(400, status)
        assert.are.equal(2, utils.table_size(body))
        assert.are.equal("invalid_provision_key", body.error)
        assert.are.equal("Invalid Kong provision_key", body.error_description)

        -- Checking headers
        assert.are.equal("no-store", headers["cache-control"])
        assert.are.equal("no-cache", headers["pragma"])
      end)

      it("should return an error when no parameter is being sent", function()
        local response, status = http_client.post(PROXY_URL.."/oauth2/authorize", { provision_key = "provision123" }, {host = "oauth2.com"})
        local body = cjson.decode(response)
        assert.are.equal(400, status)
        assert.are.equal(2, utils.table_size(body))
        assert.are.equal("invalid_request", body.error)
        assert.are.equal("Invalid client_id", body.error_description)
      end)

      it("should return an error when only the client_is being sent", function()
        local response, status = http_client.post(PROXY_URL.."/oauth2/authorize", { provision_key = "provision123", client_id = "clientid123" }, {host = "oauth2.com"})
        local body = cjson.decode(response)
        assert.are.equal(400, status)
        assert.are.equal(1, utils.table_size(body))
        assert.are.equal("http://google.com/kong?error=invalid_scope&error_description=You%20must%20specify%20a%20scope", body.redirect_uri)
      end)

      it("should return an error when an invalid scope is being sent", function()
        local response, status = http_client.post(PROXY_URL.."/oauth2/authorize", { provision_key = "provision123", client_id = "clientid123", scope = "wot" }, {host = "oauth2.com"})
        local body = cjson.decode(response)
        assert.are.equal(400, status)
        assert.are.equal(1, utils.table_size(body))
        assert.are.equal("http://google.com/kong?error=invalid_scope&error_description=%22wot%22%20is%20an%20invalid%20scope", body.redirect_uri)
      end)

      it("should return an error when no response_type is being sent", function()
        local response, status = http_client.post(PROXY_URL.."/oauth2/authorize", { provision_key = "provision123", client_id = "clientid123", scope = "email" }, {host = "oauth2.com"})
        local body = cjson.decode(response)
        assert.are.equal(400, status)
        assert.are.equal(1, utils.table_size(body))
        assert.are.equal("http://google.com/kong?error=unsupported_response_type&error_description=Invalid%20response_type", body.redirect_uri)
      end)

      it("should return an error with a state when no response_type is being sent", function()
        local response, status = http_client.post(PROXY_URL.."/oauth2/authorize", { provision_key = "provision123", client_id = "clientid123", scope = "email", state = "somestate" }, {host = "oauth2.com"})
        local body = cjson.decode(response)
        assert.are.equal(400, status)
        assert.are.equal(1, utils.table_size(body))
        assert.are.equal("http://google.com/kong?error=unsupported_response_type&state=somestate&error_description=Invalid%20response_type", body.redirect_uri)
      end)

      it("should return error when the redirect_uri does not match", function()
        local response, status = http_client.post(PROXY_URL.."/oauth2/authorize", { provision_key = "provision123", client_id = "clientid123", scope = "email", response_type = "code", redirect_uri = "http://hello.com/" }, {host = "oauth2.com"})
        local body = cjson.decode(response)
        assert.are.equal(400, status)
        assert.are.equal(1, utils.table_size(body))
        assert.are.equal("http://google.com/kong?error=invalid_request&error_description=Invalid%20redirect_uri%20that%20does%20not%20match%20with%20the%20one%20created%20with%20the%20application", body.redirect_uri)
      end)

      it("should return success", function()
        local response, status = http_client.post(PROXY_URL.."/oauth2/authorize", { provision_key = "provision123", client_id = "clientid123", scope = "email", response_type = "code" }, {host = "oauth2.com"})
        local body = cjson.decode(response)
        assert.are.equal(200, status)
        assert.are.equal(1, utils.table_size(body))
        assert.truthy(rex.match(body.redirect_uri, "^http://google\\.com/kong\\?code=[\\w]{32,32}$"))
      end)

      it("should return success when requesting the url with final slash", function()
        local response, status = http_client.post(PROXY_URL.."/oauth2/authorize/", { provision_key = "provision123", client_id = "clientid123", scope = "email", response_type = "code" }, {host = "oauth2.com"})
        local body = cjson.decode(response)
        assert.are.equal(200, status)
        assert.are.equal(1, utils.table_size(body))
        assert.truthy(rex.match(body.redirect_uri, "^http://google\\.com/kong\\?code=[\\w]{32,32}$"))
      end)

      it("should return success with a state", function()
        local response, status, headers = http_client.post(PROXY_URL.."/oauth2/authorize", { provision_key = "provision123", client_id = "clientid123", scope = "email", response_type = "code", state = "hello" }, {host = "oauth2.com"})
        local body = cjson.decode(response)
        assert.are.equal(200, status)
        assert.are.equal(1, utils.table_size(body))
        assert.truthy(rex.match(body.redirect_uri, "^http://google\\.com/kong\\?code=[\\w]{32,32}&state=hello$"))

        -- Checking headers
        assert.are.equal("no-store", headers["cache-control"])
        assert.are.equal("no-cache", headers["pragma"])
      end)

      it("should return success and store authenticated user properties", function()
        local response, status = http_client.post(PROXY_URL.."/oauth2/authorize", { provision_key = "provision123", client_id = "clientid123", scope = "email", response_type = "code", state = "hello", authenticated_username = "user123", authenticated_userid = "userid123" }, {host = "oauth2.com"})
        local body = cjson.decode(response)
        assert.are.equal(200, status)
        assert.are.equal(1, utils.table_size(body))
        assert.truthy(rex.match(body.redirect_uri, "^http://google\\.com/kong\\?code=[\\w]{32,32}&state=hello$"))

        local matches = rex.gmatch(body.redirect_uri, "^http://google\\.com/kong\\?code=([\\w]{32,32})&state=hello$")
        local code 
        for line in matches do 
          code = line
          break
        end
        local data = dao_factory.oauth2_authorization_codes:find_by_keys({code = code})
        assert.are.equal(1, #data)
        assert.are.equal(code, data[1].code)

        assert.are.equal("user123", data[1].authenticated_username)
        assert.are.equal("userid123", data[1].authenticated_userid)
        assert.are.equal("email", data[1].scope)
      end)
    end)
  
    describe("Implicit Grant", function()
      it("should return success", function()
        local response, status, headers = http_client.post(PROXY_URL.."/oauth2/authorize", { provision_key = "provision123", client_id = "clientid123", scope = "email", response_type = "token" }, {host = "oauth2.com"})
        local body = cjson.decode(response)
        assert.are.equal(200, status)
        assert.are.equal(1, utils.table_size(body))
        assert.truthy(rex.match(body.redirect_uri, "^http://google\\.com/kong\\?refresh_token=[\\w]{32,32}&token_type=bearer&access_token=[\\w]{32,32}$"))

        -- Checking headers
        assert.are.equal("no-store", headers["cache-control"])
        assert.are.equal("no-cache", headers["pragma"])
      end)

      it("should return success and the state", function()
        local response, status = http_client.post(PROXY_URL.."/oauth2/authorize", { provision_key = "provision123", client_id = "clientid123", scope = "email", response_type = "token", state = "wot" }, {host = "oauth2.com"})
        local body = cjson.decode(response)
        assert.are.equal(200, status)
        assert.are.equal(1, utils.table_size(body))
        assert.truthy(rex.match(body.redirect_uri, "^http://google\\.com/kong\\?refresh_token=[\\w]{32,32}&token_type=bearer&state=wot&access_token=[\\w]{32,32}$"))
      end)

      it("should return success and store authenticated user properties", function()
        local response, status = http_client.post(PROXY_URL.."/oauth2/authorize", { provision_key = "provision123", client_id = "clientid123", scope = "email  profile", response_type = "token", authenticated_username = "user123", authenticated_userid = "userid123" }, {host = "oauth2.com"})
        local body = cjson.decode(response)
        assert.are.equal(200, status)
        assert.are.equal(1, utils.table_size(body))
        assert.truthy(rex.match(body.redirect_uri, "^http://google\\.com/kong\\?refresh_token=[\\w]{32,32}&token_type=bearer&access_token=[\\w]{32,32}$"))

        local matches = rex.gmatch(body.redirect_uri, "^http://google\\.com/kong\\?refresh_token=[\\w]{32,32}&token_type=bearer&access_token=([\\w]{32,32})$")
        local access_token 
        for line in matches do
          access_token = line
          break
        end
        local data = dao_factory.oauth2_tokens:find_by_keys({access_token = access_token})
        assert.are.equal(1, #data)
        assert.are.equal(access_token, data[1].access_token)

        assert.are.equal("user123", data[1].authenticated_username)
        assert.are.equal("userid123", data[1].authenticated_userid)
        assert.are.equal("email profile", data[1].scope)
      end)
    end)
  end)

  describe("OAuth2 Access Token", function()

    it("should return an error when nothing is being sent", function()
      local response, status, headers = http_client.post(PROXY_URL.."/oauth2/token", { }, {host = "oauth2.com"})
      local body = cjson.decode(response)
      assert.are.equal(400, status)
      assert.are.equal(2, utils.table_size(body))
      assert.are.equal("invalid_request", body.error)
      assert.are.equal("Invalid code", body.error_description)

      -- Checking headers
      assert.are.equal("no-store", headers["cache-control"])
      assert.are.equal("no-cache", headers["pragma"])
    end)

    it("should return an error when only the code is being sent", function()
      local code = provision_code()

      local response, status, headers = http_client.post(PROXY_URL.."/oauth2/token", { code = code }, {host = "oauth2.com"})
      local body = cjson.decode(response)
      assert.are.equal(400, status)
      assert.are.equal(2, utils.table_size(body))
      assert.are.equal("invalid_request", body.error)
      assert.are.equal("Invalid client_secret", body.error_description)

      -- Checking headers
      assert.are.equal("no-store", headers["cache-control"])
      assert.are.equal("no-cache", headers["pragma"])
    end)

    it("should return an error when only the code and client_secret are being sent", function()
      local code = provision_code()

      local response, status, headers = http_client.post(PROXY_URL.."/oauth2/token", { code = code, client_secret = "secret123" }, {host = "oauth2.com"})
      local body = cjson.decode(response)
      assert.are.equal(400, status)
      assert.are.equal(2, utils.table_size(body))
      assert.are.equal("invalid_request", body.error)
      assert.are.equal("Invalid client_id", body.error_description)

      -- Checking headers
      assert.are.equal("no-store", headers["cache-control"])
      assert.are.equal("no-cache", headers["pragma"])
    end)

    it("should return an error when only the code and client_secret and client_id are being sent", function()
      local code = provision_code()

      local response, status, headers = http_client.post(PROXY_URL.."/oauth2/token", { code = code, client_id = "clientid123", client_secret = "secret123" }, {host = "oauth2.com"})
      local body = cjson.decode(response)
      assert.are.equal(400, status)
      assert.are.equal(1, utils.table_size(body))
      assert.are.equal("http://google.com/kong?error=invalid_request&error_description=Invalid%20grant_type", body.redirect_uri)
    end)

    it("should return success without state", function()
      local code = provision_code()

      local response, status, headers = http_client.post(PROXY_URL.."/oauth2/token", { code = code, client_id = "clientid123", client_secret = "secret123", grant_type = "authorization_code" }, {host = "oauth2.com"})
      local body = cjson.decode(response)
        assert.are.equal(200, status)
        assert.are.equal(1, utils.table_size(body))
        assert.truthy(rex.match(body.redirect_uri, "^http://google\\.com/kong\\?refresh_token=[\\w]{32,32}&token_type=bearer&access_token=[\\w]{32,32}$"))
    end)

    it("should return success with state", function()
      local code = provision_code()

      local response, status, headers = http_client.post(PROXY_URL.."/oauth2/token", { code = code, client_id = "clientid123", client_secret = "secret123", grant_type = "authorization_code", state = "wot" }, {host = "oauth2.com"})
      local body = cjson.decode(response)
        assert.are.equal(200, status)
        assert.are.equal(1, utils.table_size(body))
        assert.truthy(rex.match(body.redirect_uri, "^http://google\\.com/kong\\?refresh_token=[\\w]{32,32}&token_type=bearer&state=wot&access_token=[\\w]{32,32}$"))
    end)
  end)
end)
