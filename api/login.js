const crypto=require('crypto');
const SECRET='ddd8c66f88a2ad62899ef8b492f68db99817205dd48aac4e8b6dfed1400ccb23';
const USER='admin';
const PASS_HASH='7014b7188f37f8abf20db058900e2aaff5eeabaa3002b7d0739dd12a5c8d298a';
function sign(data){return crypto.createHmac('sha256',SECRET).update(data).digest('hex')}
module.exports=async(req,res)=>{
  if(req.method!=='POST')return res.status(405).end();
  let body=req.body||{};
  if(typeof body==='string'){try{body=JSON.parse(body)}catch(e){body={}}}
  const got=crypto.createHash('sha256').update(String(body.password||'')).digest('hex');
  const userOk=String(body.username||'')===USER;
  let passOk=false;
  try{passOk=crypto.timingSafeEqual(Buffer.from(got),Buffer.from(PASS_HASH));}catch(e){}
  if(!userOk||!passOk)return res.status(401).json({ok:false});
  const exp=String(Date.now()+8*60*60*1000);
  const token=exp+'.'+sign(exp);
  res.setHeader('Set-Cookie',`rs_auth=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${8*60*60}`);
  return res.status(200).json({ok:true});
};
