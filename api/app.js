
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

const fs=require('fs');
const path=require('path');
module.exports=(req,res)=>{
  res.setHeader('Cache-Control','no-store, max-age=0');
  if(!getSession(req)){
    res.statusCode=302;
    res.setHeader('Location','/');
    return res.end();
  }
  const html=fs.readFileSync(path.join(process.cwd(),'crm.html'),'utf8');
  res.setHeader('Content-Type','text/html; charset=utf-8');
  return res.status(200).send(html);
};