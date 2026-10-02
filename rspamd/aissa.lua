-- AISSA observe-only postfilter; deliberately never sets MTA actions.
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
local f = assert(io.open(cfg.token_file or '/etc/aissa/token', 'r'), 'cannot read aissa token')
local token = f:read('*a'):gsub('%s+$', '')
f:close()
assert(#token >= 32, 'invalid aissa token')
local endpoint = 'http://127.0.0.1:8765'
local size_limit = tonumber(cfg.max_message_bytes or 2097152)
assert(size_limit and size_limit > 0 and size_limit <= 2097152, 'invalid message size limit')

local function mark(task, reason)
  task:insert_result('AISSA_STATUS', 1, reason)
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

local function scan(task)
  local ip = task:get_from_ip()
  local country = task:get_mempool():get_variable('country', 'string') or ''
  local qid = task:get_queue_id() or ''
  local digest = task:get_digest() or ''
  local score = task:get_metric_score() or {}
  local meta = {
    event_id = qid .. ':' .. digest,
    queue_id = qid,
    account = task:get_user() or '',
    ip = ip and tostring(ip) or '',
    country = country:upper(),
    rspamd_score = score[1] or 0,
  }
  local metadata_json = ucl.to_json(meta)
  local started = http.request({
    task = task, url = endpoint .. '/observe', method = 'POST',
    body = metadata_json, mime_type = 'application/json',
    headers = {Authorization = 'Bearer ' .. token}, timeout = 0.5, max_size = 8192,
    callback = function(err, code, body)
      if err or code ~= 200 then mark(task, 'state_unavailable'); return end
      local parser = ucl.parser()
      if not parser:parse_string(tostring(body)) then mark(task, 'invalid_state'); return end
      local state = parser:get_object()
      if type(state) ~= 'table' or type(state.counts) ~= 'table' then mark(task, 'invalid_state'); return end
      if not conditions(task, meta.country, state.counts or {}) then mark(task, 'criteria'); return end
      if math.random() * 100 >= percent then mark(task, 'sample'); return end
      if task:get_size() > size_limit then mark(task, 'size'); return end
      local accepted = http.request({
        task = task, url = endpoint .. '/submit', method = 'POST', body = task:get_content(),
        mime_type = 'message/rfc822', timeout = 0.5, max_size = 4096,
        headers = {Authorization = 'Bearer ' .. token,
          ['X-Aissa-Meta'] = util.encode_base64(metadata_json):gsub('%s', '')},
        callback = function(suberr, subcode)
          if suberr then mark(task, 'submit_error')
          elseif subcode == 202 then mark(task, 'queued')
          elseif subcode == 200 then mark(task, 'duplicate')
          elseif subcode == 429 then mark(task, 'capacity')
          else mark(task, 'submit_error') end
        end,
      })
      if not accepted then mark(task, 'submit_error') end
    end,
  })
  if not started then mark(task, 'state_unavailable') end
end

local id = rspamd_config:register_symbol({
  name = 'AISSA_OBSERVE', type = 'postfilter', score = 0.0, callback = scan,
})
rspamd_config:register_symbol({name = 'AISSA_STATUS', type = 'virtual', parent = id, score = 0.0})
logger.infox(rspamd_config, 'AISSA observation enabled; sample_percent=%s', percent)
