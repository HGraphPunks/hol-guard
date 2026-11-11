//! Fixed numerical-only adapter. It has no network server, quota implementation,
//! process launcher, journal writer, campaign scheduler or authority decision.
pub(super) const CODE: &str = r#"
import argparse, dataclasses, json, sys
sys.path.insert(0, sys.argv[1])
import mlx.core as mx
from mlx_lm import server as s

def emit(value):
    raw=json.dumps(value,ensure_ascii=False,separators=(',',':'),allow_nan=False)
    if len(raw.encode())>1048576: raise ValueError('adapter-frame-bound')
    sys.stdout.write(raw+'\n'); sys.stdout.flush()

def receive():
    raw=sys.stdin.buffer.readline(2097153)
    if not raw: raise EOFError()
    if len(raw)>2097152 or not raw.endswith(b'\n'): raise ValueError('adapter-input-bound')
    return json.loads(raw)

mx.set_memory_limit(64*1024**3)
mx.set_wired_limit(48*1024**3)
mx.set_cache_limit(2*1024**3)
cli=argparse.Namespace(model=sys.argv[2],adapter_path=None,draft_model=None,
    pipeline=False,trust_remote_code=False,chat_template=None,
    use_default_chat_template=False,chat_template_args={'enable_thinking':False,'preserve_thinking':True},
    prefill_step_size=1024,prompt_concurrency=1,decode_concurrency=1)
provider=s.ModelProvider(cli)
provider.load_default()
if provider.is_distributed or provider.draft_model is not None: raise ValueError('serial-model-required')
generator=s.ResponseGenerator.__new__(s.ResponseGenerator)
generator.model_provider=provider
generator.prompt_cache=s.LRUPromptCache(1,2*1024**3)
generator._state_machine_cache={}
generator._is_distributed=False
generator._rank=0
emit({'schema':'hol-gauntlet-mlx-numerical-ready.v1','model_loaded':True,
    'chat_template':provider.tokenizer.has_chat_template,'tool_calling':provider.tokenizer.has_tool_calling,
    'batching':False,'draft':False})

while True:
    try:
        frame=receive()
    except EOFError:
        break
    if frame=={'schema':'hol-gauntlet-mlx-numerical-stop.v1'}:
        emit({'schema':'hol-gauntlet-mlx-numerical-stopped.v1'})
        break
    if frame.get('schema')!='hol-gauntlet-mlx-numerical-prepare.v1': raise ValueError('prepare-required')
    body=frame['request']
    request=s.CompletionRequest('chat','',body['messages'],body.get('tools'),None)
    args=s.GenerationArguments(
        model=s.ModelDescription('default_model',None,None),
        sampling=s.SamplingArguments(body.get('temperature',0),body.get('top_p',1),0,0,0,0),
        logits=s.LogitsProcessorArguments(None,1,20,0,20,0,20),
        stop_words=body.get('stop',[]),max_tokens=body['max_tokens'],num_draft_tokens=0,
        logprobs=False,top_logprobs=0,seed=0,chat_template_kwargs=None)
    tokenized=generator._tokenize(provider.tokenizer,request,args)
    prompt=tokenized[0]
    if not isinstance(prompt,list) or not 1<=len(prompt)<=32768 or any(type(t) is not int or not 0<=t<=4294967295 for t in prompt): raise ValueError('exact-prompt-required')
    frozen=json.dumps({'prompt_token_ids':prompt,'generation_args':dataclasses.asdict(args)},sort_keys=True,separators=(',',':'),allow_nan=False)
    emit({'schema':'hol-gauntlet-mlx-numerical-prepared.v1','request_sha256':frame['request_sha256'],
        'prompt_token_ids':prompt,'generation_args':dataclasses.asdict(args)})
    admitted=receive()
    if admitted=={'schema':'hol-gauntlet-mlx-numerical-discard.v1'}: continue
    if admitted.get('schema')!='hol-gauntlet-mlx-numerical-admit.v1' or admitted.get('request_sha256')!=frame['request_sha256']: raise ValueError('bound-admission-required')
    def frozen_tokenize(actual_tokenizer,actual_request,actual_args):
        if actual_tokenizer is not provider.tokenizer or actual_request is not request or actual_args is not args or json.dumps({'prompt_token_ids':prompt,'generation_args':dataclasses.asdict(args)},sort_keys=True,separators=(',',':'),allow_nan=False)!=frozen: raise ValueError('prepared-input-changed')
        return tokenized
    original=generator._tokenize
    generator._tokenize=frozen_tokenize
    class Output:
        def __init__(self): self.context=False; self.ended=False; self.error=False; self.tokens=0
        def put(self,value):
            if isinstance(value,Exception): self.error=True; return
            if value is None:
                if self.ended: raise ValueError('duplicate-end')
                self.ended=True; return
            if self.ended or self.error: raise ValueError('post-terminal-output')
            if isinstance(value,s.GenerationContext):
                if self.context or value.prompt!=prompt: raise ValueError('context-changed')
                self.context=True
                emit({'schema':'hol-gauntlet-mlx-numerical-context.v1','prepared_input_sha256':admitted['prepared_input_sha256'],'prompt_tokens':len(prompt)})
            elif isinstance(value,s.Response):
                if not self.context or self.tokens>=args.max_tokens: raise ValueError('token-bound')
                self.tokens+=1
                emit({'schema':'hol-gauntlet-mlx-numerical-token.v1','token':value.token,'text':value.text,
                    'state':value.state,'matched_tokens':0 if value.match is None else len(value.match),'finish_reason':value.finish_reason})
            elif not (isinstance(value,tuple) and len(value)==2 and all(type(v) is int and v>=0 for v in value)): raise ValueError('unknown-output')
    output=Output()
    try:
        generator._serve_single((output,request,args))
        if output.error or not output.context or not output.ended: raise ValueError('incomplete-generation')
        emit({'schema':'hol-gauntlet-mlx-numerical-complete.v1','prepared_input_sha256':admitted['prepared_input_sha256'],
            'prompt_tokens':len(prompt),'output_tokens':output.tokens})
    finally:
        generator._tokenize=original
"#;
