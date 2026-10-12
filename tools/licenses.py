#!/usr/bin/env python3
"""Collect redistribution notices from downloaded Go modules, not user data."""
import json,pathlib,shutil,subprocess,sys
root=pathlib.Path(__file__).resolve().parents[1]
out=root/'dist/licenses';out.mkdir(parents=True,exist_ok=True)
seen=set()
for module in (root,root/'engine'):
    stream=subprocess.check_output(['go','list','-m','-json','all'],cwd=module,text=True)
    decoder=json.JSONDecoder()
    while stream.strip():
        item,end=decoder.raw_decode(stream.lstrip());stream=stream.lstrip()[end:]
        if item.get('Main') or not item.get('Dir'):continue
        name=item['Path']+'@'+item.get('Version','')
        if name in seen:continue
        seen.add(name)
        folder=out/name.replace('/','__')
        for file in pathlib.Path(item['Dir']).iterdir():
            if file.is_file() and (file.name.upper().startswith(('LICENSE','COPYING')) or file.name.upper()=='NOTICE'):
                folder.mkdir(parents=True,exist_ok=True);shutil.copy2(file,folder/file.name)
goroot=pathlib.Path(subprocess.check_output(['go','env','GOROOT'],text=True).strip())
shutil.copy2(goroot/'LICENSE',out/'Go-LICENSE')
print('Dependency notices collected:',len(seen))
