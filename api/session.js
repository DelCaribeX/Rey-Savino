const crypto=require('crypto');
const SECRET='ddd8c66f88a2ad62899ef8b492f68db99817205dd48aac4e8b6dfed1400ccb23';
function parseCookies(req){return Object.fromEntries((req.headers.cookie||'').split(';').map(x=>x.trim()).filter(Boolean).map(x=>{const i=x.indexOf('=');return i<0?[x,'']:[x.slice(0,i),decodeURIComponent(x.slice(i+1))]}));}
function sign(data){return crypto.createHmac('sha256',SECRET).update(data).digest('hex')}
function valid(req){const t=parseCookies(req).rs_auth;if(!t)return false;const [exp,sig]=t.split('.');if(!exp||!sig||Number(exp)<Date.now())return false;const good=sign(exp);try{return crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(good));}catch(e){return false}}
module.exports=(req,res)=>valid(req)?res.status(200).json({ok:true}):res.status(401).json({ok:false});
