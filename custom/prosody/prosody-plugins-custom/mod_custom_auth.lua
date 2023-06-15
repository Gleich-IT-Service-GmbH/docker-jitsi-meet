-- Customized authentication
-- Copyright (C) 2022 Gleich-IT GmbH

local mod_custom_auth = {
    ["host"] = (module.host),
    ["http"] = (require "net.http"),
    ["util_http"] = (require "util.http"),
    ["stanza"] = (require "util.stanza"),
    ["json"] = (require "util.json"),
    ["hashes"] = (require "util.hashes"),
    ["base64"] = (require "util.encodings".base64),
    ["um_is_admin"] = (require "core.usermanager".is_admin),
    ["dbi"] = (require "DBI"),
    ["jwt"] = (require "luajwtjitsi"),
    ["b64url_rep"] = { ["+"] = "-", ["/"] = "_", ["="] = "", ["-"] = "+", ["_"] = "/" },

    ["db"] = nil,
    
    ["CFG_JWT_APP_SECRET"] = nil,
    ["CFG_REQUIRE_TOKEN_FOR_MODS"] = nil,
    ["HMAC_ALGO"] = "HS256"
};

function mod_custom_auth.load_config(self)
    self.CFG_JWT_APP_SECRET = module:get_option_string("app_secret");
    self.CFG_REQUIRE_TOKEN_FOR_MODS = module:get_option_boolean("token_verification_require_token_for_moderation");

    module:log("debug", "Config loaded");
end

-- Function for validating a token
-- raw_token: string - Token string to validate.
--
-- Returns true if valid, false otherwise
function mod_custom_auth.validate_token(self, raw_token)
    local token = self:split_token(raw_token, true);

    local hashes = self.hashes;

    if token == nil then
        token = {}
    end

    local new_signature = self:sign_token(token["header"], token["payload"]);

    return hashes.equals(token["signature"], new_signature);
end

-- Splits JWT token into its parts as table.
-- token: string - The base64 encoded token.
-- as_string: boolean - Return as encoded strings.
--
-- Returns table with parts - ["header", "payload", "signature"]
--         or nil on error.
function mod_custom_auth.split_token(self, token, as_string)
    as_string = as_string or false;

    local tmp = {};
    for str in string.gmatch(token, "([^\\.]+)") do
        table.insert(tmp, str);
    end

    if table.getn(tmp) ~= 3 then
        module:log("error", "split_token: JWT does not contain three parts.")
        return nil;
    end

    local result = nil;
    if (not as_string) then
        result = {
            ["header"] = json_to_table(tmp[1], true),
            ["payload"] = json_to_table(tmp[2], true),
            ["signature"] = tmp[3]
        };
    else
        result = {
            ["header"] = tmp[1],
            ["payload"] = tmp[2],
            ["signature"] = tmp[3]
        }
    end

    return result;
end

-- Signs jwt token.
-- header: string - Encoded header string.
-- payload: string - Encoded payload string.
--
-- Returns signature.
function mod_custom_auth.sign_token(self, header, payload)
    local hashes = self.hashes;

    return hashes.hmac_sha256(self.CFG_JWT_APP_SECRET, (header .. "." .. payload), true);
end

-- Converts a table into a json string.
-- table: table - Table to convert.
-- do_encode: boolean - Also encode json.
--
-- Returns table as json string.
function mod_custom_auth.table_to_json(self, table, do_encode)
    do_encode = do_encode or false;

    local json = self.json;

    local new_json = json.encode(table);

    if do_encode then
        new_json = self:base64url_encode(new_json);
    end

    return new_json;
end

-- Converts a json string into a table.
-- raw_json: string - Raw json string.
-- is_encoded: boolean - Decode string if is encoded.
--
-- Returns table from json string.
function mod_custom_auth.json_to_table(self, raw_json, is_encoded)
    is_encoded = is_encoded or false;

    local json = self.json;

    if is_encoded then
        raw_json = self:base64url_decode(raw_json);
    end

    local new_table = json.decode(raw_json);
    return new_table;
end

function mod_custom_auth.create_jwt(self, msg)
    local json = self.json;
    local hashes = self.hashes;

    local header = {
        typ = "JWT";
        alg = self.HMAC_ALGO;
    };

    local payload = {
        add = msg;
        aud = "Abschlussprüfung";
        iss = module:get_option_string("app_id");
        room = "*";
        sub = "*";
        exp = (os.time() + (3 * 60 * 60)); -- 3h
        nbf = os.time();

        context = {
            user = {
                id = "NO-ID";
                name = msg.user.name;
                email = msg.user.email;
            };

            features = {
                ["screen-sharing"] = true;
            };
        };
    }

    local jwt = self.jwt;
    local result, err = jwt.encode(payload, self.CFG_JWT_APP_SECRET, self.HMAC_ALGO);

    if (result == nil) then
        module:log("debug", err);
        result = "";
    end

    return result
end

function mod_custom_auth.base64url_encode(self, data)
    local b64url_rep = self.b64url_rep;
    local base64 = self.base64;

    return (string.gsub(base64.encode(data), "[+/=]", b64url_rep));
end

function mod_custom_auth.base64url_decode(self, data)
    local b64url_rep = self.b64url_rep;
    local base64 = self.base64;

    return base64.decode(string.gsub(data, "[-_]", b64url_rep).."==");
end

function mod_custom_auth.default_response_body(self)
    local default_response_body = {
        status_code = 200;
        headers = {
            content_type = "application/json; charset=utf8";

            access_control_allow_origin = "*";
            access_control_allow_methods = "POST";
        };
    };

    return default_response_body; 
end

-- Open database on startup
module:hook_global("server-started",
    function(event)
        mod_custom_auth:load_config();

        local db_ec = nil; -- Error code
        local db_em = nil; -- Error message

        module:log("info", "Auth module loaded");
        module:log("debug", "Creating database connection");
        
        mod_custom_auth.db, db_em = mod_custom_auth.dbi.Connect("PostgreSQL", os.getenv("DATABASE_DB"), os.getenv("DATABASE_USER"), os.getenv("DATABASE_PASSWORD"), "postgres", 5432);
        if (db_em ~= nil) then
            mod_custom_auth = nil;

            module:log("error", db_em);
        end
        
        mod_custom_auth.db:autocommit(true);
    end
);

-- Close database on shutdown
module:hook_global("server-stopped",
    function(event)
        module:log("debug", "Closing database connection");

        local db = mod_custom_auth.db;
        db:close();
    end
);

module:hook("config-reload",
    function(event)
        mod_custom_auth:load_config();
    end
);

function handle_token_req(event)
    local http = mod_custom_auth.http;
    local db = mod_custom_auth.db;
    local hashes = mod_custom_auth.hashes;
    local json = mod_custom_auth.json;

    local request = event.request;
    local body = request.body;
    local response = mod_custom_auth:default_response_body();

    if (body == nil) then
        response.body = json.encode({ error = "No body was sent" });
        response.status_code = 400;
        return response;
    end;

    local parsed_body = json.decode(body);
    
    if (parsed_body == nil) then
        response.body = json.encode({ error = "Was a JSON sent?" });
        response.status_code = 400;
        return response;
    end

    if (parsed_body.email == nil or parsed_body.email == "" or parsed_body.email == "\0") 
        or (parsed_body.password == nil or parsed_body.password == "" or parsed_body.password == "\0") then 
        
        response.body = json.encode({ error = "A part of the JSON is missing?" });
        response.status_code = 400;
        return response;
    end

    local stmt = db:prepare([[
        SELECT u.uuid AS user_id, concat_ws(' ', jitsi_decrypt(u.first_name), jitsi_decrypt(u.last_name)) AS name, jitsi_decrypt(u.email) AS email, u.is_admin
        FROM jitsi_user u
        WHERE u.email=jitsi_encrypt(?) AND u.password_hash=crypt(?, u.password_hash)
    ]]);

    local user_email = parsed_body.email;
    local user_password = parsed_body.password;
    stmt:execute(user_email, user_password);

    local msg = stmt:fetch(true);
    if (msg == nil) then
        response.status_code = 403;
        response.body = json.encode({ error = "No user found" });
        return response;
    else
        msg = {
            user = {
                id = msg.user_id;
                name = msg.name;
                email = msg.email;
                isModerator = msg.is_admin;
            };
        };

        if (msg.user.isModerator) then
            msg.group = "moderator";
        else
            msg.group = "party";
        end
    end

    msg = mod_custom_auth:create_jwt(msg);

    response.body = json.encode({ data = msg });
    return response;
end

function handle_add_user_req(event)
    local http = mod_custom_auth.http;
    local db = mod_custom_auth.db;
    local hashes = mod_custom_auth.hashes;
    local json = mod_custom_auth.json;
    local jwt = mod_custom_auth.jwt;

    local request = event.request;
    local body = request.body;
    local response = mod_custom_auth:default_response_body();

    if (body == nil) then
        response.body = json.encode({ error = "No body was sent" });
        response.status_code = 400;
        return response;
    end;

    local parsed_body = json.decode(body);
    
    if (parsed_body == nil) then
        response.body = json.encode({ error = "Was a JSON sent?" });
        response.status_code = 400;
        return response;
    end

    parsed_body.jwt = jwt.verify(parsed_body.jwt, mod_custom_auth.HMAC_ALGO, mod_custom_auth.CFG_JWT_APP_SECRET);
    if (parsed_body.jwt == nil or parsed_body.jwt == "" or parsed_body.jwt == "\0")
        or (parsed_body.firstName == nil or parsed_body.firstName == "" or parsed_body.firstName == "\0")
        or (parsed_body.lastName == nil or parsed_body.lastName == "" or parsed_body.lastName == "\0")
        or (parsed_body.email == nil or parsed_body.email == "" or parsed_body.email == "\0") 
        or (parsed_body.password == nil or parsed_body.password == "" or parsed_body.password == "\0") then 
        
        response.body = json.encode({ error = "Missing data" });
        response.status_code = 400;
        return response;
    end

    parsed_body.isModerator = parsed_body.isModerator or false;

    if (parsed_body.jwt == nil or (parsed_body.jwt ~= nil and parsed_body.jwt.add.user.isModerator == 0)) then
        module:log("debug", err);

        response.body = json.encode({ error = "JWT is not valid or unsufficent permission" });
        response.status_code = 403;
        return response;
    end

    local stmt = db:prepare([[
        INSERT INTO jitsi_user(first_name, last_name, email, password_hash, is_admin)
        SELECT jitsi_encrypt(?), jitsi_encrypt(?), jitsi_encrypt(?), jitsi_new_password(?), ?
    ]]);

    local stmt_result, stmt_err = stmt:execute(parsed_body.firstName, parsed_body.lastName, parsed_body.email, parsed_body.password, parsed_body.isModerator);

    if (stmt_result == false or stmt_err ~= nil) then
        module:log("debug", stmt_err);

        response.body = json.encode({ error = "Unable to add user" });
        response.status_code = 409;
        return response;
    end

    return response;
end

function handle_update_user_req(event)
    local db = mod_custom_auth.db;
    local hashes = mod_custom_auth.hashes;
    local json = mod_custom_auth.json;
    local jwt = mod_custom_auth.jwt;

    local request = event.request;
    local body = request.body;
    local response = mod_custom_auth:default_response_body();

    if (body == nil) then
        response.body = json.encode({ error = "No body was sent" });
        response.status_code = 400;
        return response;
    end;

    local parsed_body = json.decode(body);
    
    if (parsed_body == nil) then
        response.body = json.encode({ error = "Was a JSON sent?" });
        response.status_code = 400;
        return response;
    end

    parsed_body.jwt = jwt.verify(parsed_body.jwt, mod_custom_auth.HMAC_ALGO, mod_custom_auth.CFG_JWT_APP_SECRET);
    if (parsed_body.jwt == nil or parsed_body.jwt == "" or parsed_body.jwt == "\0")
        or (parsed_body.id == nil or parsed_body.id == "" or parsed_body.id == "\0")
        or (parsed_body.firstName == nil or parsed_body.firstName == "" or parsed_body.firstName == "\0")
        or (parsed_body.lastName == nil or parsed_body.lastName == "" or parsed_body.lastName == "\0")
        or (parsed_body.email == nil or parsed_body.email == "" or parsed_body.email == "\0") then 
        
        response.body = json.encode({ error = "Missing data" });
        response.status_code = 400;
        return response;
    end

    local jwt_user_uuid = parsed_body.jwt.add.user.id;

    parsed_body.isModerator = parsed_body.isModerator or false;
    parsed_body.password = parsed_body.password or nil;

    -- Fetch number of admins.
    local stmt = db:prepare[[
        SELECT COUNT(id) AS num_admins
        FROM jitsi_user
        WHERE is_admin=TRUE
    ]];
    stmt:execute();
    local tmp_row = stmt:fetch(true);
    local num_admins = tmp_row.num_admins;
    stmt:close();

    -- Fetch if user is admin (used for later if admin is added/removed or changing data on other users)
    stmt = db:prepare[[
        SELECT is_admin
        FROM jitsi_user
        WHERE uuid=?
    ]];
    stmt:execute(jwt_user_uuid);
    tmp_row = stmt:fetch(true);
    local jwt_user_is_admin = tmp_row.is_admin;
    stmt:close();

    if (parsed_body.id == jwt_user_uuid) then
        -- User changes his own data.
        if (jwt_user_is_admin == false) then
            parsed_body.isModerator = false;
        end
    else
        -- User tries to change other users data.
        if (jwt_user_is_admin == false) then
            response.body = json.encode({ error = "User not authorized" });
            response.status_code = 403;
            return response;
        end

        -- Preventing last admin to remove admin privileges.
        if (num_admins <= 1 and jwt_user_is_admin and jwt_user_uuid == parsed_body.id) then
            response.body = json.encode({ error = "Unable to update user" });
            response.status_code = 409;
            return response;
        end
    end

    local sql = [[
        UPDATE jitsi_user
        SET first_name=jitsi_encrypt(?), last_name=jitsi_encrypt(?), email=jitsi_encrypt(?), is_admin=?
    ]];

    if (parsed_body.password ~= nil) then
        sql = sql .. ", password_hash=jitsi_new_password(?)";
    end

    sql = sql .. " WHERE uuid=?";

    stmt = db:prepare(sql);
    local stmt_result = false;
    local stmt_err = nil;

    if (parsed_body.password ~= nil) then
        stmt_result, stmt_err = stmt:execute(parsed_body.firstName, parsed_body.lastName, parsed_body.email, parsed_body.isModerator, parsed_body.password, parsed_body.id);
    else
        stmt_result, stmt_err = stmt:execute(parsed_body.firstName, parsed_body.lastName, parsed_body.email, parsed_body.isModerator, parsed_body.id);
    end

    if (stmt_result) then
        response.status_code = 200;
    else
        module:log("debug", stmt_err);

        response.body = json.encode({ error = "Internal server error" });
        response.status_code = 500;
    end

    return response;
end

function handle_delete_user_req(event)
    local db = mod_custom_auth.db;
    local hashes = mod_custom_auth.hashes;
    local json = mod_custom_auth.json;
    local jwt = mod_custom_auth.jwt;

    local request = event.request;
    local body = request.body;
    local response = mod_custom_auth:default_response_body();

    local parsed_body = json.decode(body);
    
    if (parsed_body == nil) then
        response.body = json.encode({ error = "Was a JSON sent?" });
        response.status_code = 400;
        return response;
    end

    parsed_body.jwt = jwt.verify(parsed_body.jwt, mod_custom_auth.HMAC_ALGO, mod_custom_auth.CFG_JWT_APP_SECRET);
    if (parsed_body.jwt == nil or parsed_body.jwt == "" or parsed_body.jwt == "\0")
        or (parsed_body.id == nil or parsed_body.id == "" or parsed_body.id == "\0")
        or (parsed_body.email == nil or parsed_body.email == "" or parsed_body.email == "\0") then 
        
        response.body = json.encode({ error = "Missing data" });
        response.status_code = 400;
        return response;
    end

    local jwt_user_uuid = parsed_body.jwt.add.user.id;

    -- Fetch number of admins.
    local stmt = db:prepare[[
        SELECT COUNT(id) AS num_admins
        FROM jitsi_user
        WHERE is_admin=TRUE
    ]];
    stmt:execute();
    local tmp_row = stmt:fetch(true);
    local num_admins = tmp_row.num_admins;
    stmt:close();

    -- Fetch if user is admin.
    stmt = db:prepare[[
        SELECT is_admin
        FROM jitsi_user
        WHERE uuid=?
    ]];
    stmt:execute(jwt_user_uuid);
    tmp_row = stmt:fetch(true);
    local jwt_user_is_admin = tmp_row.is_admin;
    stmt:close();

    -- Allow only admins to delete users.
    if (jwt_user_is_admin == false) then
        response.body = json.encode({ error = "Unable to delete user" });
        response.status_code = 403;
        return response;
    end

    -- Prevent deletion of last admin.
    if (num_admins <= 1 and jwt_user_uuid == parsed_body.id) then
        response.body = json.encode({ error = "Unable to delete user" });
        response.status_code = 403;
        return response;
    end

    stmt = db:prepare[[
        DELETE FROM jitsi_user
        WHERE uuid=? AND email=jitsi_encrypt(?)
    ]];
    stmt:execute(parsed_body.id, parsed_body.email);

    if (stmt:affected() <= 0) then
        response.body = json.encode({ error = "Failed to delete user" });
        response.status_code = 500;
    end

    stmt:close();

    return response;
end

function handle_get_user_req(event)
    local db = mod_custom_auth.db;
    local hashes = mod_custom_auth.hashes;
    local json = mod_custom_auth.json;
    local jwt = mod_custom_auth.jwt;

    local request = event.request;
    local body = request.body;
    local response = mod_custom_auth:default_response_body();

    local parsed_body = json.decode(body);
    
    if (parsed_body == nil) then
        response.body = json.encode({ error = "Was a JSON sent?" });
        response.status_code = 400;
        return response;
    end

    parsed_body.jwt = jwt.verify(parsed_body.jwt, mod_custom_auth.HMAC_ALGO, mod_custom_auth.CFG_JWT_APP_SECRET);
    if (parsed_body.jwt == nil or parsed_body.jwt == "" or parsed_body.jwt == "\0") then 
        
        response.body = json.encode({ error = "Missing data" });
        response.status_code = 400;
        return response;
    end

    local jwt_user_uuid = parsed_body.jwt.add.user.id;

    -- Fetch if user is admin.
    stmt = db:prepare[[
        SELECT is_admin
        FROM jitsi_user
        WHERE uuid=?
    ]];
    stmt:execute(jwt_user_uuid);
    tmp_row = stmt:fetch(true);
    local jwt_user_is_admin = tmp_row.is_admin;
    stmt:close();

    if (jwt_user_is_admin) then
        stmt = db:prepare[[
            SELECT uuid AS id, jitsi_decrypt(first_name) AS "firstName", jitsi_decrypt(last_name) AS "lastName", jitsi_decrypt(email) AS email, is_admin AS "isModerator"
            FROM jitsi_user
        ]];
        stmt:execute();
    else
        stmt = db:prepare[[
            SELECT uuid AS id, jitsi_decrypt(first_name) AS "firstName", jitsi_decrypt(last_name) AS "lastName", jitsi_decrypt(email) AS email, is_admin AS "isModerator"
            FROM jitsi_user
            WHERE uuid=?
        ]];
        stmt:execute(jwt_user_uuid);
    end

    local return_data = {};
    for row in stmt:rows(true) do
        table.insert(return_data, row);
    end

    response.body = json.encode({ data = return_data });
    return response;
end

function handle_get_spectator_settings_req(event)
    local hashes = mod_custom_auth.hashes;
    local json = mod_custom_auth.json;
    local jwt = mod_custom_auth.jwt;

    local request = event.request;
    local body = request.body;
    local response = mod_custom_auth:default_response_body();

    local parsed_body = json.decode(body);
    
    if (parsed_body == nil) then
        response.body = json.encode({ error = "Was a JSON sent?" });
        response.status_code = 400;
        return response;
    end

    parsed_body.jwt = jwt.verify(parsed_body.jwt, mod_custom_auth.HMAC_ALGO, mod_custom_auth.CFG_JWT_APP_SECRET);
    if (parsed_body.jwt == nil or parsed_body.jwt == "" or parsed_body.jwt == "\0")
        or (parsed_body.jwt.add == nil or parsed_body.jwt.add.user == nil or parsed_body.jwt.add.user.isModerator == nil or parsed_body.jwt.add.user.isModerator != true) then 
        
        response.body = json.encode({ error = "Missing data" });
        response.status_code = 400;
        return response;
    end

    local configFile = "/config-web/config.js";
    local file = io.open(configFile, "r");
    local fileContent = file:read("*all");
    file:close();

    local result = false
    if string.match(fileContent, "config.custom.allowViewerToSpeak%s*=%s*true") then
        result = true
    end

    response.body = json.encode({ data = { spectator = result } });
    return response;
end

function handle_update_spectator_settings_req(event)
    local hashes = mod_custom_auth.hashes;
    local json = mod_custom_auth.json;
    local jwt = mod_custom_auth.jwt;

    local request = event.request;
    local body = request.body;
    local response = mod_custom_auth:default_response_body();

    local parsed_body = json.decode(body);
    
    if (parsed_body == nil) then
        response.body = json.encode({ error = "Was a JSON sent?" });
        response.status_code = 400;
        return response;
    end

    parsed_body.jwt = jwt.verify(parsed_body.jwt, mod_custom_auth.HMAC_ALGO, mod_custom_auth.CFG_JWT_APP_SECRET);
    if (parsed_body.jwt == nil or parsed_body.jwt == "" or parsed_body.jwt == "\0")
        or (parsed_body.spectator == nil or parsed_body.spectator == "" or parsed_body.spectator == "\0" or type(parsed_body.spectator) ~= "boolean")
        or (parsed_body.jwt.add == nil or parsed_body.jwt.add.user == nil or parsed_body.jwt.add.user.isModerator == nil or parsed_body.jwt.add.user.isModerator != true) then 
        
        response.body = json.encode({ error = "Missing data" });
        response.status_code = 400;
        return response;
    end

    local configFiles = { "/config-web/config.js", "/config-web/custom-config.js" };
    for _, file in ipairs(configFiles) do
        local fh, err = io.open(file, "r");
        if fh == nil then
            module:log("error", err);
        end

        local fh_lines = {}
        for line in fh:lines() do
            if string.match(line, "config.custom.allowViewerToSpeak") then
                line = string.gsub(line, "config.custom.allowViewerToSpeak.*", "config.custom.allowViewerToSpeak = " .. (tostring(parsed_body.spectator)))
            end
            table.insert(fh_lines, line);
        end
        fh:close();
        fh = nil;

        local fh, err = io.open(file, "w+");

        if fh == nil then
            module:log("error", err);
        end

        fh:write(table.concat(fh_lines, "\n"));
        fh:close();
    end

    return response;
end

module:depends("http");
module:provides("http", {
    default_path = "/token";
    route = {
        ["POST"] = handle_token_req;
        ["POST /"] = handle_token_req;

        ["POST /user/add"] = handle_add_user_req;
        ["POST /user/add/"] = handle_add_user_req;

        ["POST /user/update"] = handle_update_user_req;
        ["POST /user/update/"] = handle_update_user_req;

        ["POST /user/delete"] = handle_delete_user_req;
        ["POST /user/delete/"] = handle_delete_user_req;

        ["POST /user"] = handle_get_user_req;
        ["POST /user/"] = handle_get_user_req;

        ["POST /spectator"] = handle_get_spectator_settings_req;
        ["POST /spectator/"] = handle_get_spectator_settings_req;

        ["POST /spectator/update"] = handle_update_spectator_settings_req;
        ["POST /spectator/update/"] = handle_update_spectator_settings_req;
    };
});

return mod_custom_auth;
