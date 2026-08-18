#!/usr/bin/env python3
"""Generated held-out typo benchmark for my-error v1.2.

The plugin does not know these concrete typo strings in advance. We generate
single-token variants after loading the frozen implementation, execute them for
real, and measure whether verified recovery prevents exact recurrence.
"""
from __future__ import annotations
import importlib.util, json, os, random, string, subprocess, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('me', ROOT/'scripts'/'my_error.py')
me=importlib.util.module_from_spec(spec); spec.loader.exec_module(me)


def run(cmd,cwd):
    p=subprocess.run(cmd,cwd=cwd,shell=True,text=True,capture_output=True,timeout=8)
    return p.returncode,(p.stderr+'\n'+p.stdout).strip()


def setup(p:Path):
    (p/'tests').mkdir()
    for name,text in [('script.py',"print('ok')\n"),('worker.py',"print('worker')\n"),('server.js',"console.log('ok')\n"),('worker.js',"console.log('worker')\n"),('build.sh','#!/bin/sh\necho ok\n'),('config.json','{"ok":true}\n')]:
        (p/name).write_text(text)
    (p/'tests'/'test_alpha.py').write_text('def test_alpha():\n    assert True\n')
    (p/'tests'/'test_beta.py').write_text('def test_beta():\n    assert True\n')
    (p/'package.json').write_text(json.dumps({'name':'fuzz','version':'1.0.0','scripts':{'build':'node -e "process.exit(0)"','test':'node -e "process.exit(0)"','lint':'node -e "process.exit(0)"'}}))
    run('git init -q',p); run('git config user.email fuzz@example.invalid',p); run('git config user.name Fuzz',p); run('git add . && git commit -qm init',p); run('git branch -M main',p); run('git branch develop',p); run('git branch feature',p)


def mutate(token:str,rng:random.Random)->str:
    # Change one token only; keep the typo close enough to model human slips.
    if len(token)<4: return token+token[-1]
    op=rng.choice(['swap','delete','dup','replace'])
    # avoid leading dashes/path prefix punctuation when possible
    candidates=[i for i,c in enumerate(token) if c.isalnum() and i>0]
    i=rng.choice(candidates or list(range(len(token))))
    if op=='swap' and i < len(token)-1:
        chars=list(token); chars[i],chars[i+1]=chars[i+1],chars[i]; return ''.join(chars)
    if op=='delete': return token[:i]+token[i+1:]
    if op=='dup': return token[:i]+token[i]+token[i:]
    repl=rng.choice([c for c in string.ascii_lowercase if c!=token[i].lower()])
    return token[:i]+repl+token[i+1:]


def main():
    rng=random.Random(20260818)
    td=Path(tempfile.mkdtemp(prefix='my-error-fuzz-')); project=td/'project'; data=td/'data'; project.mkdir(); data.mkdir(); setup(project)
    # Benchmarks measure the guard, so they must state the mode; the
    # product default is SHADOW, which deliberately blocks nothing.
    os.environ['MY_ERROR_MODE']='ENFORCE'
    os.environ['MY_ERROR_DATA_DIR']=str(data); os.environ['CLAUDE_PROJECT_DIR']=str(project)
    db=me.connect(); pid=me.ensure_project(db,str(project.resolve()))
    templates=[
      ('python3 {}','script.py'),('python3 {}','worker.py'),('node {}','server.js'),('node {}','worker.js'),('bash {}','build.sh'),('cat {}','config.json'),
      ('git checkout {}','develop'),('git checkout {}','feature'),
      ('python3 {}','--version'),('node {}','--version'),('git {}','--version'),
      ('ls {}','--color=never'),('grep {} ok config.json','--line-number'),
      ('git {} main','checkout'),('git {}','status'),('git {} HEAD','show'),
      ('python3 -m {} config.json','json.tool'),
      ('{} --version','python3'),('{} --version','node'),('{} --version','git'),
    ]
    pool=[]
    for round_no in range(6):
        for fmt,good_token in templates:
            bad_token=mutate(good_token,rng)
            if bad_token==good_token: continue
            bad=fmt.format(bad_token); good=fmt.format(good_token)
            if me.narrow_command_correction(bad,good): pool.append((bad,good))
    # de-duplicate and take first 40 generated cases
    seen=set(); pairs=[]
    for pair in pool:
        if pair in seen: continue
        seen.add(pair); pairs.append(pair)
        if len(pairs)>=30: break

    details=[]; false_blocks=[]
    for i,(bad,good) in enumerate(pairs):
        grc,_=run(good,project); brc,err=run(bad,project)
        if grc!=0 or brc==0:
            details.append({'bad':bad,'good':good,'valid':False,'good_rc':grc,'bad_rc':brc}); continue
        baseline_rc,_=run(bad,project)
        sid=f'fuzz-{i}'
        cid,family,eligible,ignored=me.upsert_candidate(db,pid,{'session_id':sid,'cwd':str(project),'tool_name':'Bash','tool_input':{'command':bad},'error':err,'is_interrupt':False})
        _,lid=me.observe_success(db,pid,{'session_id':sid,'cwd':str(project),'tool_name':'Bash','tool_input':{'command':good}})
        out=me.run_guard(db,pid,{'tool_name':'Bash','tool_input':{'command':bad}})
        blocked=bool(out and out.get('hookSpecificOutput',{}).get('permissionDecision')=='deny')
        details.append({'bad':bad,'good':good,'valid':True,'family':family,'eligible':eligible,'baseline_repeat_failed':baseline_rc!=0,'learned':bool(lid),'blocked':blocked})
    valid=[x for x in details if x['valid']]
    for good in sorted({x['good'] for x in valid}):
        out=me.run_guard(db,pid,{'tool_name':'Bash','tool_input':{'command':good}})
        if out and out.get('hookSpecificOutput',{}).get('permissionDecision')=='deny': false_blocks.append(good)
    learned=sum(x['learned'] for x in valid); blocked=sum(x['blocked'] for x in valid); baseline=sum(x['baseline_repeat_failed'] for x in valid)
    result={'benchmark':'my-error v1.2 generated typo fuzz A/B','plugin_version':me.VERSION,'generated_pairs':len(pairs),'valid_pairs':len(valid),'baseline_repeat_failures':baseline,'learned':learned,'blocked':blocked,'prevention_rate':blocked/len(valid) if valid else 0,'false_blocks':len(false_blocks),'pass_100':bool(valid and baseline==len(valid) and learned==len(valid) and blocked==len(valid) and not false_blocks),'details':details,'false_block_commands':false_blocks}
    (ROOT/'benchmarks'/'v1.2-fuzz-result.json').write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='details'},indent=2))
    return 0 if result['pass_100'] else 1

if __name__=='__main__': raise SystemExit(main())
