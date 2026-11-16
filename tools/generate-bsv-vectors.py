# Copyright 2026 Goshawk contributors. Apache-2.0.
# Offline oracle: bitcoinX 0.9. Uses only the PUBLIC BIP32 test seed, never a wallet/device.
import hashlib, json, struct
from pathlib import Path
from bitcoinx import Bitcoin, BIP32PrivateKey, PrivateKey, Tx, Script, SigHash

u32=lambda n:struct.pack('<I',n)
u64=lambda n:struct.pack('<Q',n)
hash256=lambda b:hashlib.sha256(hashlib.sha256(b).digest()).digest()
var=lambda n:bytes([n]) if n<253 else b'\xfd'+struct.pack('<H',n)
push=lambda b:bytes([len(b)])+b
pkh=lambda key:b'\x76\xa9\x14'+hashlib.new('ripemd160',hashlib.sha256(key).digest()).digest()+b'\x88\xac'
root=BIP32PrivateKey.from_seed(bytes(range(16)), Bitcoin)
account=root
for n in (44,0,0): account=account.child(n|0x80000000)
keys=[account.child(0).child(i) for i in range(2)]
cosigner=PrivateKey.from_int(3)
parent=lambda value,script:u32(1)+b'\x01'+bytes(32)+u32(0xffffffff)+b'\x02\x01\x01'+u32(0xffffffff)+b'\x01'+u64(value)+var(len(script))+script+u32(0)
fixtures=[]
for kind in ('p2pkh','bare_multisig','p2sh_multisig'):
    metadata=[]; privkeys=[]
    for i,value in enumerate((1000,1100)):
        key=keys[i] if kind=='p2pkh' else keys[0]
        pubs=[key.public_key.to_bytes()] if kind=='p2pkh' else [key.public_key.to_bytes(),cosigner.public_key.to_bytes()]
        script=pkh(pubs[0]) if kind=='p2pkh' else b'\x52'+b''.join(push(p) for p in pubs)+b'\x52\xae'
        locking=script if kind!='p2sh_multisig' else b'\xa9\x14'+hashlib.new('ripemd160',hashlib.sha256(script).digest()).digest()+b'\x87'
        metadata.append(dict(value=value,lockingScript=locking.hex(),signingScript=script.hex(),publicKeys=[p.hex() for p in pubs],previousTransaction=parent(value,locking).hex()))
        privkeys.append(key)
    outs=b'\x02'+b''.join(u64(v)+push(pkh(k.public_key.to_bytes())) for v,k in zip((900,1000),keys))
    prevouts=[hash256(bytes.fromhex(m['previousTransaction']))+u32(0) for m in metadata]
    seq=[u32(0xfffffffe-i) for i in range(2)]
    raw=u32(0x01020304)+b'\x02'+b''.join(o+b'\x00'+s for o,s in zip(prevouts,seq))+outs+u32(0x01000002)
    tx=Tx.from_bytes(raw); hashes={}; signatures={}; existing=[]
    for mode in (0x41,0x42,0x43,0xc1,0xc2,0xc3):
        for i,m in enumerate(metadata):
            digest=tx.signature_hash(i,m['value'],Script(bytes.fromhex(m['signingScript'])),SigHash(mode))
            hashes[f'{i}:{mode:02x}']=digest.hex()
            signatures[f'{i}:{mode:02x}']=(privkeys[i].sign(digest,hasher=None)+bytes([mode])).hex()
            if kind!='p2pkh' and mode==0x41:
                existing.append(dict(slot=dict(inputIndex=i,publicKey=cosigner.public_key.to_bytes().hex()),signature=(cosigner.sign(digest,hasher=None)+b'\x41').hex()))
    targets=[dict(slot=dict(inputIndex=i,publicKey=m['publicKeys'][0]),path=f"m/44'/0'/0'/0/{i if kind=='p2pkh' else 0}",sighash=0x41) for i,m in enumerate(metadata)]
    scripts=[]
    for i,m in enumerate(metadata):
        sig=bytes.fromhex(signatures[f'{i}:41'])
        unlock=push(sig)+push(bytes.fromhex(m['publicKeys'][0])) if kind=='p2pkh' else b'\x00'+push(sig)+push(bytes.fromhex(existing[i]['signature']))
        if kind=='p2sh_multisig': unlock+=push(bytes.fromhex(m['signingScript']))
        scripts.append(unlock)
    final=u32(0x01020304)+b'\x02'+b''.join(o+var(len(s))+s+q for o,s,q in zip(prevouts,scripts,seq))+outs+u32(0x01000002)
    fixtures.append(dict(kind=kind,transaction=raw.hex(),inputs=metadata,targets=targets,existing=existing,hashes=hashes,signatures=signatures,finalTransaction=final.hex(),txid=hash256(final)[::-1].hex()))
out=dict(oracle='bitcoinX 0.9',public_test_seed='000102030405060708090a0b0c0d0e0f',account=account.public_key.to_extended_key_string(),fixtures=fixtures)
Path(__file__).resolve().parents[1].joinpath('src/test/resources/com/sparrowwallet/lark/bsv/vectors.json').write_text(json.dumps(out,indent=2)+'\n')
