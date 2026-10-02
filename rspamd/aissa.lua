-- AISSA: bounded live scoring plus asynchronous reputation collection.
local http = require "rspamd_http"
local util = require "rspamd_util"
local logger = require "rspamd_logger"
local ucl = require "ucl"
local cfg = rspamd_config:get_all_opt('aissa') or {}
if not cfg.enabled then return end

local percent = tonumber(cfg.sample_percent or 0.2)
assert(percent and percent >= 0 and percent <= 100, 'invalid aissa sample_percent')
assert(cfg.combine == nil or cfg.combine == 'all' or cfg.combine == 'any', 'invalid aissa combine')
assert(cfg.unknown_country == nil or cfg.unknown_country == 'skip' or cfg.unknown_country == 'match', 'invalid unknown_country')
for _, key in ipairs({'min_rspamd_score', 'account_min_10m', 'ip_min_10m',
  'account_ai_suspect_min', 'ip_ai_suspect_min', 'account_confirmed_min', 'ip_confirmed_min'}) do
  assert(cfg[key] == nil or type(cfg[key]) == 'number', 'invalid numeric criterion: ' .. key)
end
for _, key in ipairs({'country_not_in', 'symbols_any'}) do
  if cfg[key] then
    assert(type(cfg[key]) == 'table', 'invalid list criterion: ' .. key)
    for _, value in ipairs(cfg[key]) do assert(type(value) == 'string', 'invalid criterion entry') end
  end
end
local f = assert(io.open(cfg.token_file or '/etc/rspamd/local.d/aissa.token', 'r'), 'cannot read aissa token')
local token = f:read('*a'):gsub('%s+$', '')
f:close()
assert(#token >= 32, 'invalid aissa token')
local endpoint = 'http://127.0.0.1:8765'
local size_limit = tonumber(cfg.max_message_bytes or 2097152)
assert(size_limit and size_limit > 0 and size_limit <= 2097152, 'invalid message size limit')

-- Separate selection, live waiting, and weights. No direct MTA actions.
local scoring = cfg.scoring_enabled == true
assert(cfg.scoring_enabled == nil or type(cfg.scoring_enabled) == 'boolean',
       'invalid scoring_enabled')
local wait_seconds = tonumber(cfg.score_wait_seconds or 10)
assert(wait_seconds and wait_seconds >= 1 and wait_seconds <= 30,
       'invalid score_wait_seconds (1..30)')
local weights = cfg.scores or {}
assert(type(weights) == 'table', 'invalid aissa scores')
local defaults = {phishing=3, spam=1, bulk=0, ham=0, uncertain=0}
local symbols = {
  phishing='AISSA_PHISHING', spam='AISSA_SPAM', bulk='AISSA_BULK',
  ham='AISSA_HAM', uncertain='AISSA_UNCERTAIN',
}
for class, default in pairs(defaults) do
  if weights[class] == nil then weights[class] = default end
  assert(type(weights[class]) == 'number' and weights[class] >= -100
         and weights[class] <= 100, 'invalid AISSA weight: ' .. class)
end

local function mark(task, reason)
  task:insert_result('AISSA_STATUS', 1, reason)
end

-- Polling keeps the serial Python HTTP server free for /results and /ack.
-- Timers and HTTP requests belong to this task's asynchronous session.
local function await_verdict(task, meta, deadline)
  local ended = false
  local function finish(reason)
    if ended then return end
    ended = true
    mark(task, reason)
  end
  local poll
  poll = function()
    if ended then return end
    local remaining = deadline - util.get_ticks()
    if remaining <= 0 then finish('score_timeout'); return end
    local started = http.request({
      task = task, url = endpoint .. '/verdict', method = 'POST',
      body = ucl.to_json({event_id=meta.event_id}), mime_type='application/json',
      headers = {Authorization='Bearer ' .. token},
      timeout = math.min(0.5, remaining), max_size=4096,
      callback = function(err, code, body)
        if ended then return end
        if util.get_ticks() >= deadline then finish('score_timeout'); return end
        if err or code ~= 200 then finish('verdict_unavailable'); return end
        local parser = ucl.parser()
        if not parser:parse_string(tostring(body)) then
          finish('invalid_verdict'); return
        end
        local verdict = parser:get_object()
        if type(verdict) ~= 'table' then finish('invalid_verdict'); return end
        if verdict.status == 'pending' then
          local delay = math.min(0.25, deadline - util.get_ticks())
          if delay <= 0 then finish('score_timeout'); return end
          task:add_timer(delay, function() poll(); return false end)
        elseif verdict.status == 'ok' then
          local symbol = symbols[verdict.classification]
          local confidence = verdict.confidence
          if not symbol or type(confidence) ~= 'number'
              or not (confidence >= 0 and confidence <= 1) then
            finish('invalid_verdict'); return
          end
          task:insert_result(symbol, 1, string.format('confidence=%.3f', confidence))
          finish('scored')
        elseif verdict.status == 'error' then
          finish('inference_error')
        else
          finish('verdict_unavailable')
        end
      end,
    })
    if started == false then finish('verdict_unavailable') end
  end
  poll()
end

local function conditions(task, country, counts)
  local checks = {}
  if cfg.country_not_in and #cfg.country_not_in > 0 then
    local match = cfg.unknown_country == 'match'
    if country ~= '' then
      match = true
      for _, excluded in ipairs(cfg.country_not_in) do
        if country == excluded:upper() then match = false end
      end
    end
    checks[#checks+1] = match
  end
  if cfg.require_url then checks[#checks+1] = #(task:get_urls() or {}) > 0 end
  if cfg.min_rspamd_score then
    local score = task:get_metric_score() or {}
    checks[#checks+1] = (score[1] or 0) >= cfg.min_rspamd_score
  end
  if cfg.symbols_any and #cfg.symbols_any > 0 then
    local found = false
    for _, sym in ipairs(cfg.symbols_any) do
      if task:has_symbol(sym) then found = true end
    end
    checks[#checks+1] = found
  end
  if cfg.account_min_10m then
    checks[#checks+1] = (counts.account_600 or 0) >= cfg.account_min_10m
  end
  if cfg.ip_min_10m then
    checks[#checks+1] = (counts.ip_600 or 0) >= cfg.ip_min_10m
  end
  for _, key in ipairs({'account_ai_suspect', 'ip_ai_suspect', 'account_confirmed', 'ip_confirmed'}) do
    if cfg[key .. '_min'] then
      checks[#checks+1] = (counts[key] or 0) >= cfg[key .. '_min']
    end
  end
  if #checks == 0 then return true end
  if cfg.combine == 'any' then
    for _, ok in ipairs(checks) do if ok then return true end end
    return false
  end
  for _, ok in ipairs(checks) do if not ok then return false end end
  return true
end


local redis = require "lua_redis"
local inherited = assert(redis.parse_redis_server('aissa'), 'AISSA: no Redis configuration')
local rp = {}
for k, v in pairs(inherited) do rp[k] = v end

-- Only AISSA gets this shorter timeout. Global rspamd settings are unchanged.
rp.timeout = tonumber(cfg.redis_timeout or 0.2)
assert(rp.timeout and rp.timeout > 0 and rp.timeout <= 1, 'invalid redis_timeout')
-- Keys are constructed explicitly; no task-variable expansion is needed.
rp.expand_keys = false

local prefix = 'aissa:v2:'
local node = cfg.node_id or 'manta'
assert(type(node) == 'string' and #node <= 40 and node:match('^[%w_.-]+$'),
       'invalid AISSA node_id')

local function b64(value)
  return tostring(util.encode_base64(value, 0))
end

local function identity(kind, value)
  if not value or value == '' then return '' end
  return prefix .. kind .. ':' .. b64(value)
end

-- Atomic observation, fixed time buckets and reputation snapshot.
-- One Redis writer/shard is used for all AISSA keys.
local observe_script = [[
local fresh = redis.call('SET', KEYS[1], '1', 'NX', 'EX', 172800)
local now = tonumber(ARGV[1])
local day = math.floor(now / 86400)
local out = {}
for i=2,3 do
  local base = KEYS[i]
  if base == '' then
    for j=1,5 do out[#out+1] = 0 end
  else
    for _,seconds in ipairs({60,600,3600}) do
      local key = base .. ':count:' .. seconds .. ':' .. math.floor(now/seconds)
      if fresh then
        redis.call('INCR',key)
        redis.call('EXPIRE',key,seconds*2)
      end
      out[#out+1] = tonumber(redis.call('GET',key) or '0')
    end
    for _,lane in ipairs({'ai_suspect','confirmed'}) do
      local a = tonumber(redis.call('GET',base..':'..lane..':'..day) or '0')
      local b = tonumber(redis.call('GET',base..':'..lane..':'..(day-1)) or '0')
      out[#out+1] = a+b
    end
  end
end
return out
]]

-- Idempotent result application. Repeated collection is harmless.
local result_script = [[
if not redis.call('SET',KEYS[1],'1','NX','EX',172800) then return 0 end
local day = math.floor(tonumber(ARGV[1])/86400)
local class = ARGV[2]
for i=2,3 do
  if KEYS[i] ~= '' then
    local base = KEYS[i]
    local function inc(lane)
      local key=base..':'..lane..':'..day
      redis.call('INCR',key)
      redis.call('EXPIRE',key,172800)
    end
    if class == 'confirmed' then
      inc('confirmed')
    else
      inc('ai_checked')
      if class == 'spam' or class == 'phishing' then inc('ai_suspect') end
    end
  end
end
return 1
]]

local function scan(task)
  local deadline = util.get_ticks() + wait_seconds
  local ip = task:get_from_ip()
  local country = task:get_mempool():get_variable('country', 'string') or ''
  local qid = task:get_queue_id() or ''
  local score = task:get_metric_score() or {}
  local meta = {
    event_id = node .. ':' .. qid .. ':' .. (task:get_digest() or ''),
    queue_id = qid,
    account = task:get_user() or '',
    ip = ip and ip:is_valid() and tostring(ip) or '',
    country = country:upper(),
    rspamd_score = score[1] or 0,
  }
  local args = {
    observe_script, 3,
    prefix .. 'observed:' .. b64(meta.event_id),
    identity('account', meta.account), identity('ip', meta.ip),
    tostring(os.time()),
  }
  local finished = false
  local function observed(err, data)
    if finished then return end
    finished = true
    if err or type(data) ~= 'table' or #data ~= 10 then
      mark(task, 'state_unavailable')
      return
    end
    local counts = {
      account_60 = tonumber(data[1]) or 0,
      account_600 = tonumber(data[2]) or 0,
      account_3600 = tonumber(data[3]) or 0,
      account_ai_suspect = tonumber(data[4]) or 0,
      account_confirmed = tonumber(data[5]) or 0,
      ip_60 = tonumber(data[6]) or 0,
      ip_600 = tonumber(data[7]) or 0,
      ip_3600 = tonumber(data[8]) or 0,
      ip_ai_suspect = tonumber(data[9]) or 0,
      ip_confirmed = tonumber(data[10]) or 0,
    }
    if not conditions(task, meta.country, counts) then mark(task, 'criteria'); return end
    if math.random()*100 >= percent then mark(task, 'sample'); return end
    if task:get_size() > size_limit then mark(task, 'size'); return end

    local started = http.request({
      task = task, url = endpoint .. '/submit', method = 'POST',
      body = task:get_content(), mime_type = 'message/rfc822',
      timeout = scoring and math.min(0.5, math.max(0.001, deadline - util.get_ticks())) or 0.5,
      max_size = 4096,
      headers = {
        Authorization = 'Bearer ' .. token,
        ['X-Aissa-Meta'] = b64(ucl.to_json(meta)),
      },
      callback = function(err2, code)
        if err2 then mark(task, 'submit_error')
        elseif code == 202 or code == 200 then
          if scoring then await_verdict(task, meta, deadline)
          else mark(task, code == 202 and 'queued' or 'duplicate') end
        elseif code == 429 then mark(task, 'capacity')
        else mark(task, 'submit_error') end
      end,
    })
    if started == false then mark(task, 'submit_error') end
  end
  local started = redis.redis_make_request(
    task, rp, prefix, true, observed, 'EVAL', args)
  if started == false then observed('schedule_failed') end
end

-- Controller workers collect results independently of incoming mail.
-- Multiple collectors are safe because Redis application is idempotent.
rspamd_config:add_on_load(function(rcfg, ev_base, worker)
  if worker:get_name() ~= 'controller' then return end
  local interval = tonumber(cfg.result_poll_seconds or 2)
  assert(interval and interval >= 1, 'invalid result_poll_seconds')
  local busy = false

  rcfg:add_periodic(ev_base, interval, function()
    if busy then return true end
    busy = true

    local function done()
      busy = false
    end

    local function acknowledge(ids)
      if #ids == 0 then done(); return end
      local started = http.request({
        config = rcfg, ev_base = ev_base,
        url = endpoint .. '/ack', method = 'POST',
        body = ucl.to_json({ids = ids}), mime_type = 'application/json',
        headers = {Authorization = 'Bearer ' .. token},
        timeout = 1, max_size = 4096,
        callback = function()
          -- On failure the service retains results; next poll retries.
          done()
        end,
      })
      if started == false then done() end
    end

    local function collected(err, code, body)
      if err or code ~= 200 then done(); return end
      local parser = ucl.parser()
      if not parser:parse_string(tostring(body)) then done(); return end
      local payload = parser:get_object()
      if type(payload) ~= 'table' or type(payload.results) ~= 'table' then
        done(); return
      end
      local rows, ids = payload.results, {}

      local function apply(index)
        local row = rows[index]
        if not row then acknowledge(ids); return end
        if type(row) ~= 'table' or type(row.id) ~= 'string'
            or type(row.meta) ~= 'table'
            or type(row.meta.event_id) ~= 'string' then
          done(); return
        end
        if row.status == 'error' then
          -- Inference errors are terminal observations, never ham.
          ids[#ids+1] = row.id
          apply(index+1)
          return
        end
        local allowed = {
          ham=true, bulk=true, spam=true, phishing=true,
          uncertain=true, confirmed=true,
        }
        if not allowed[row.classification] or not tonumber(row.completed_at) then
          done(); return
        end
        local lane = row.classification == 'confirmed' and 'confirmed' or 'ai'
        local args = {
          result_script, 3,
          prefix .. 'applied:' .. lane .. ':' .. b64(row.meta.event_id),
          identity('account', row.meta.account),
          identity('ip', row.meta.ip),
          tostring(row.completed_at), row.classification,
        }
        local called = false
        local function applied(redis_err)
          if called then return end
          called = true
          if redis_err then
            logger.warnx(rcfg, 'AISSA: result retained after Redis write failure')
            acknowledge(ids)
            return
          end
          ids[#ids+1] = row.id
          apply(index+1)
        end
        local started = redis.redis_make_request_taskless(
          ev_base, rcfg, rp, prefix, true, applied, 'EVAL', args)
        if started == false then applied('schedule_failed') end
      end
      apply(1)
    end

    local started = http.request({
      config = rcfg, ev_base = ev_base,
      url = endpoint .. '/results', method = 'GET',
      headers = {Authorization = 'Bearer ' .. token},
      timeout = 1, max_size = 65536, callback = collected,
    })
    if started == false then done() end
    return true
  end)
end)

local id = rspamd_config:register_symbol({
  name = 'AISSA_OBSERVE', type = 'postfilter', score = 0.0, callback = scan,
})
rspamd_config:register_symbol({name = 'AISSA_STATUS', type = 'virtual', parent = id, score = 0.0})
for class, symbol in pairs(symbols) do
  rspamd_config:register_symbol({
    name=symbol, type='virtual', parent=id, score=weights[class], group='aissa',
  })
end
logger.infox(rspamd_config, 'AISSA enabled; sample_percent=%s; scoring=%s; wait=%s',
             percent, scoring, wait_seconds)
