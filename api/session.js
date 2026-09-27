
const crypto=require('crypto');
const USER='admin';
const SALT='c967371616a470565cc0f5c9bad9ef4f';
const PASS_HASH=Buffer.from('a2068156dcd10780158c9945064a4a286626e425619834ee09f80231a8e1d2f8','hex');
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

module.exports=(req,res)=>{
  res.setHeader('Cache-Control','no-store');
  return getSession(req)?res.status(200).json({ok:true}):res.status(401).json({ok:false});
};