#!/usr/bin/env python3
import argparse, json, math, statistics, tarfile
from pathlib import PurePosixPath

def json_members(path, needle):
    out=[]
    with tarfile.open(path, 'r:gz') as tf:
        for m in tf.getmembers():
            p=PurePosixPath(m.name)
            if m.isfile() and needle(p):
                f=tf.extractfile(m)
                if f:
                    out.append((m.name, json.load(f)))
    return sorted(out)

def stat(vals, tcrit=None):
    n=len(vals); mean=statistics.mean(vals)
    sd=statistics.stdev(vals) if n>1 else 0.0
    d={'n':n,'mean':mean,'sd':sd,'min':min(vals),'max':max(vals)}
    if tcrit is not None and n>1:
        half=tcrit*sd/math.sqrt(n)
        d['ci95']=[mean-half, mean+half]
    return d

def show(title, rows, keys, tcrit=None):
    print('\n'+title)
    for k in keys:
        vals=[float(x[k]) for _,x in rows]
        d=stat(vals,tcrit)
        print(k, json.dumps(d, ensure_ascii=False))

ap=argparse.ArgumentParser()
ap.add_argument('--results-dir', default=str(PurePosixPath(__file__).parent.parent/'results'))
a=ap.parse_args()
r=PurePosixPath(a.results_dir)

v=json_members(str(r/'profileguard_v2_verifier100.tar.gz'),
    lambda p: 'verifier100/measured' in str(p) and p.suffix=='.json')
show('verifier100', v,
     ['profile_guard_ms','decider_verify_ms','sigma_verify_ms','merkle_verify_ms','total_verify_ms','total_wallclock_ms'])
assert len(v)==100 and all(x.get('accept') is True for _,x in v)

r64=json_members(str(r/'profileguard_v2_64k_fullchain.tar.gz'),
    lambda p: 'measured/run_' in str(p) and p.name=='result.json')
v64=json_members(str(r/'profileguard_v2_64k_fullchain.tar.gz'),
    lambda p: 'measured/run_' in str(p) and p.name=='verify.json')
show('64KiB full-chain', r64,
     ['hashfold_ms','decider_setup_ms','decider_prove_ms','online_cryptographic_prove_ms','total_online_prove_ms','peak_rss_kib'],2.262157)
show('64KiB verifier', v64,['profile_guard_ms','total_verify_ms','total_wallclock_ms'],2.262157)
assert len(r64)==10 and len(v64)==10

r1=json_members(str(r/'profileguard_v2_1m_fullchain.tar.gz'),
    lambda p: 'measured/run_' in str(p) and p.name=='result.json')
v1=json_members(str(r/'profileguard_v2_1m_fullchain.tar.gz'),
    lambda p: 'measured/run_' in str(p) and p.name=='verify.json')
show('1MiB full-chain', r1,
     ['hashfold_ms','decider_setup_ms','decider_prove_ms','online_cryptographic_prove_ms','total_online_prove_ms','peak_rss_kib'],2.776445)
show('1MiB verifier', v1,['profile_guard_ms','total_verify_ms','total_wallclock_ms'],2.776445)
assert len(r1)==5 and len(v1)==5
print('\nALL ARCHIVES PARSED; SAMPLE COUNTS PASS')
