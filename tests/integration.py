#!/usr/bin/env python3
"""Real IP transport tests in a disposable Linux CI VM; no external VPN service."""
import concurrent.futures, hashlib, http.server, json, os, pathlib, secrets, socket, subprocess, tempfile, threading, time

def run(*args, **kw):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kw).stdout.strip()

def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0)); return s.getsockname()[1]

def wait_port(p, process):
    for _ in range(150):
        if process.poll() is not None: raise RuntimeError('process exited before ready')
        try:
            with socket.create_connection(('127.0.0.1', p), .1): return
        except OSError: time.sleep(.1)
    raise RuntimeError('listener never became ready')

def write(path, obj):
    temp=path.with_suffix('.tmp');temp.write_text(json.dumps(obj));temp.chmod(0o600);temp.replace(path)

class Echo(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body=self.path.encode();self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*args): pass

def stop(p):
    if p and p.poll() is None:
        p.terminate()
        try: p.wait(8)
        except subprocess.TimeoutExpired: p.kill();p.wait()

assert os.geteuid()==0,'Run in a disposable Linux VM as root'
project=pathlib.Path(__file__).resolve().parents[1]
edge=project/'dist/mist-edge';client=project/'dist/mist-client'
host_ip=run('ip','-4','route','get','1.1.1.1').split('src ')[1].split()[0]
http=http.server.ThreadingHTTPServer(('0.0.0.0',0),Echo);threading.Thread(target=http.serve_forever,daemon=True).start()
before={key:run('sysctl','-n',key) for key in ['net.ipv4.ip_forward','net.core.rmem_max','net.core.wmem_max']}
processes=[]
try:
 with tempfile.TemporaryDirectory(prefix='mist-integration-') as temp:
    work=pathlib.Path(temp);cert=work/'cert.pem';key=work/'key.pem'
    run('openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','1','-subj','/CN=MIST integration','-addext','subjectAltName=IP:127.0.0.1','-addext','basicConstraints=critical,CA:TRUE','-keyout',str(key),'-out',str(cert))
    policy=work/'policy.json';tokens=[secrets.token_hex(32),secrets.token_hex(32)]
    keys=[dict(id=str(i),token_hash=hashlib.sha256(token.encode()).hexdigest(),address='10.249.71.'+str(i+2),enabled=True) for i,token in enumerate(tokens)]
    for modes in [('h3s','h2'),('h3','h3s')]:
        keys[0]['enabled']=True;write(policy,dict(version=1,keys=keys));listen=port()
        server=dict(listen='127.0.0.1:'+str(listen),authority='127.0.0.1:'+str(listen),path='/integration',certificate=str(cert),private_key=str(key),access_policy_file=str(policy),stats_file=str(work/'stats.json'),tun_name='mistci',tun_cidr='10.249.71.1/24',client_cidr='10.249.71.2/32',advertise_cidr='0.0.0.0/0',enable_nat=False,mtu=1280)
        write(work/'server.json',server);edge_log=open(work/'edge.log','w');p=subprocess.Popen([str(edge),'-config',str(work/'server.json')],stdout=edge_log,stderr=edge_log);processes.append(p);wait_port(listen,p)
        proxies=[];clients=[]
        for i,mode in enumerate(modes):
            config=dict(endpoint=dict(authority=server['authority'],dial_address=server['authority'],path='/integration'),token=tokens[i],dns=['1.1.1.1'],h2_fallback=True,fallback_client_cidr=keys[i]['address']+'/32',ipv6_mode='block',mtu=1280)
            write(work/f'client-{i}.json',config);proxy=port();proxies.append(proxy);env=dict(os.environ,SSL_CERT_FILE=str(cert));log=open(work/f'client-{i}.log','w')
            proc=subprocess.Popen([str(client),'-config',str(work/f'client-{i}.json'),'-socks',f'127.0.0.1:{proxy}','-transport',mode],env=env,stdout=log,stderr=log);processes.append(proc);clients.append(proc);wait_port(proxy,proc)
        def request(i,label,check=True):
            url=f'http://{host_ip}:{http.server_port}/{label}'
            result=subprocess.run(['curl','--noproxy','','--proxy',f'socks5h://127.0.0.1:{proxies[i]}','--max-time','3','--silent','--show-error',url],text=True,capture_output=True)
            if check: assert result.returncode==0 and result.stdout=='/'+label,(i,result.stderr,result.stdout)
            return result
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda n:request(n%2,f'device-{n%2}-request-{n}'),range(24)))
        print('PASS simultaneous real traffic:',modes,flush=True)
        keys[0]['enabled']=False;write(policy,dict(version=1,keys=keys))
        for _ in range(15):
            if request(0,'revoked',False).returncode!=0:break
            time.sleep(.2)
        else:raise AssertionError('revoked client still transfers traffic')
        request(1,'other-device-survives')
        time.sleep(2.2);stats=json.loads((work/'stats.json').read_text());assert stats[keys[1]['address']]['rx']>0 and stats[keys[1]['address']]['tx']>0
        print('PASS active revocation, other device survives, real counters',flush=True)
        for proc in clients:stop(proc)
        stop(p);edge_log.close()
finally:
 for p in processes:stop(p)
 http.shutdown()
 for k,v in before.items():subprocess.run(['sysctl','-w',k+'='+v],stdout=subprocess.DEVNULL)
