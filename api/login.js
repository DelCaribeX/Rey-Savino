
const crypto=require('crypto');
const USER='admin';
const SALT='c967371616a470565cc0f5c9bad9ef4f';
const PASS_HASH=Buffer.from('fa1e2bbdd96c3faedd869c2acb7fd4532d771c8a8f84d08773a79f3d85235e5c','hex');
function check(u,p){
  if(String(u||'')!==USER)return false;
  let got;
  try{got=crypto.scryptSync(String(p||''),SALT,32);}catch(e){return false;}
  try{return crypto.timingSafeEqual(got,PASS_HASH);}catch(e){return false;}
}
function parseCookies(req){
  const out={};
  for(const part of String(req.headers.cookie||'').split(';')){
    const i=part.indexOf('=');
    if(i<0)continue;
    const k=part.slice(0,i).trim(),v=part.slice(i+1).trim();
    try{out[k]=decodeURIComponent(v)}catch(e){out[k]=v}
  }
  return out;
}
function getSession(req){
  const raw=parseCookies(req).rs_auth;
  if(!raw)return null;
  try{
    const obj=JSON.parse(Buffer.from(raw,'base64url').toString('utf8'));
    if(!obj||!obj.u||!obj.p||!obj.exp||Number(obj.exp)<Date.now())return null;
    return check(obj.u,obj.p)?obj:null;
  }catch(e){return null;}
}

module.exports=async(req,res)=>{
  res.setHeader('Cache-Control','no-store');
  if(req.method!=='POST')return res.status(405).json({ok:false});
  let body=req.body||{};
  if(typeof body==='string'){try{body=JSON.parse(body)}catch(e){body={}}}
  const u=String(body.username||''),p=String(body.password||'');
  if(!check(u,p)){
    await new Promise(r=>setTimeout(r,450));
    return res.status(401).json({ok:false});
  }
  const payload=Buffer.from(JSON.stringify({u,p,exp:Date.now()+8*60*60*1000}),'utf8').toString('base64url');
  res.setHeader('Set-Cookie',`rs_auth=${encodeURIComponent(payload)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${8*60*60}; Priority=High`);
  return res.status(200).json({ok:true});
};