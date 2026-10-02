-- Contract tests with a deterministic event loop; not a substitute for rspamadm.
local function run(opts)
  local now, events, marks, registered, payload = 0, {}, {}, {}, nil
  local attempts = 0
  local cfg = {
    enabled=true, scoring_enabled=opts.scoring ~= false, sample_percent=100,
    score_wait_seconds=opts.wait or 1, scores={phishing=3, spam=1, ham=0},
  }
  local function schedule(delay, fn) events[#events+1]={at=now+delay,fn=fn} end
  local http = {}
  function http.request(req)
    if req.url:match('/submit$') then
      schedule(.01, function() req.callback(nil, opts.submit_code or 202, '') end)
    elseif req.url:match('/verdict$') then
      attempts = attempts+1
      if opts.schedule_failure then return false end
      local verdict = opts.verdict or {status='ok',classification='phishing',confidence=.95}
      if opts.pending_forever or (opts.pending_once and attempts == 1) then
        verdict={status='pending'}
      end
      schedule(opts.late and req.timeout or .01, function()
        payload=verdict
        req.callback(opts.http_error and 'error' or nil, 200, 'json')
      end)
    else error('Unexpected HTTP request') end
    return true
  end
  package.loaded.rspamd_http = http
  package.loaded.rspamd_util = {get_ticks=function() return now end,
    encode_base64=function(value) return value end}
  package.loaded.rspamd_logger = {infox=function() end, warnx=function() end}
  package.loaded.ucl = {to_json=function() return '{}' end,
    parser=function() return {
      parse_string=function() return not opts.bad_json end,
      get_object=function() return payload end,
    } end}
  package.loaded.lua_redis = {
    parse_redis_server=function() return {} end,
    redis_make_request=function(_,_,_,_,cb)
      schedule(.01,function() cb(nil,{0,0,0,0,0,0,0,0,0,0}) end)
      return true
    end,
  }
  rspamd_config = {
    get_all_opt=function() return cfg end,
    add_on_load=function() end,
    register_symbol=function(_, symbol)
      registered[symbol.name]=symbol
      return symbol.name
    end,
  }
  local real_open=io.open
  io.open=function() return {read=function() return string.rep('x',64) end,close=function() end} end
  local ok, err=pcall(dofile, AISSA_LUA_PATH)
  io.open=real_open
  assert(ok, err)
  local task = {
    get_from_ip=function() return nil end,
    get_mempool=function() return {get_variable=function() return nil end} end,
    get_queue_id=function() return 'qid' end,
    get_metric_score=function() return {9,15} end,
    get_digest=function() return 'digest' end,
    get_user=function() return '' end,
    get_size=function() return 100 end,
    get_content=function() return 'mail' end,
    insert_result=function(_,symbol,weight,option)
      marks[#marks+1]={symbol=symbol,points=weight*registered[symbol].score,option=option}
    end,
    add_timer=function(_,delay,cb) schedule(delay,cb) end,
  }
  registered.AISSA_OBSERVE.callback(task)
  local n=0
  while #events > 0 do
    table.sort(events,function(a,b) return a.at < b.at end)
    local event=table.remove(events,1)
    now=event.at
    event.fn()
    n=n+1
    assert(n<200, 'Unbounded polling')
  end
  local total, status, class=0,nil,nil
  for _,mark in ipairs(marks) do
    total=total+mark.points
    if mark.symbol == 'AISSA_STATUS' then status=mark.option else class=mark.symbol end
  end
  return total,status,class,now,attempts
end
local p,s,c = run({pending_once=true})
assert(p==3 and s=='scored' and c=='AISSA_PHISHING')
p,s,c=run({verdict={status='ok',classification='spam',confidence=.1}})
assert(p==1 and s=='scored' and c=='AISSA_SPAM')
p,s,c=run({verdict={status='ok',classification='ham',confidence=.99}})
assert(p==0 and s=='scored' and c=='AISSA_HAM')
p,s,c=run({verdict={status='error',classification='uncertain'}})
assert(p==0 and s=='inference_error' and c==nil)
p,s,c=run({verdict={status='ok',classification='phishing',confidence=95}})
assert(p==0 and s=='invalid_verdict' and c==nil)
p,s,c=run({verdict={status='ok',classification='invented',confidence=.9}})
assert(p==0 and s=='invalid_verdict' and c==nil)
p,s,c=run({bad_json=true})
assert(p==0 and s=='invalid_verdict' and c==nil)
p,s,c=run({http_error=true})
assert(p==0 and s=='verdict_unavailable' and c==nil)
p,s,c=run({schedule_failure=true})
assert(p==0 and s=='verdict_unavailable' and c==nil)
local elapsed,attempts
p,s,c,elapsed,attempts=run({pending_forever=true})
assert(p==0 and s=='score_timeout' and c==nil and elapsed<=1.001 and attempts<=5)
p,s,c,elapsed=run({late=true})
-- First request timeout is .5 seconds, still before the 1-second budget.
assert(p==3 and s=='scored')
p,s,c,elapsed=run({late=true,pending_forever=true})
assert(p==0 and s=='score_timeout' and c==nil and elapsed<=1.001)
p,s,c,elapsed,attempts=run({scoring=false})
assert(p==0 and s=='queued' and c==nil and attempts==0)
p,s,c=run({submit_code=429})
assert(p==0 and s=='capacity' and c==nil)
p,s,c=run({submit_code=200})
assert(p==3 and s=='scored' and c=='AISSA_PHISHING')
