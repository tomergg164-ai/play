import express from 'express';import helmet from 'helmet';import rateLimit from 'express-rate-limit';import session from 'express-session';import pgSession from 'connect-pg-simple';import bcrypt from 'bcryptjs';import pg from 'pg';
const E=process.env,PROD=E.NODE_ENV==='production',CUR=E.CURRENCY||'ILS',ORIGIN=E.ALLOWED_ORIGIN||'',PPU=E.PAYPAL_ENV==='live'?'https://api-m.paypal.com':'https://api-m.sandbox.paypal.com';
if(!E.SESSION_SECRET||!E.DATABASE_URL)throw new Error('Missing SESSION_SECRET or DATABASE_URL');
const pool=new pg.Pool({connectionString:E.DATABASE_URL,ssl:E.PGSSL==='1'?{rejectUnauthorized:false}:undefined}),q=(t,p)=>pool.query(t,p);
const app=express();app.set('trust proxy',1);app.use(helmet());
const ah=f=>(a,b,c)=>f(a,b,c).catch(e=>{if(e.body){console.error('paypal',JSON.stringify(e.body));return b.status(402).json({error:'שגיאת תשלום'})}if(e.status&&e.status<500)return b.status(e.status).json({error:e.message});console.error(e);b.status(500).json({error:'שגיאת שרת'})});
const bad=(m,s=400)=>Object.assign(new Error(m),{status:s}),has=(o,k)=>Object.hasOwn(o,k),money=c=>(c/100).toFixed(2),UUID=/^[0-9a-f-]{36}$/i;
const str=(s,m)=>typeof s==='string'&&s.trim().length>0&&s.length<=m,mail=s=>typeof s==='string'&&s.length<255&&/^\S+@\S+\.\S+$/.test(s);
/* CORS + CSRF (חובה Origin מורשה בבקשות שמשנות מצב) */
app.use((req,res,next)=>{const o=req.headers.origin;if(o&&o===ORIGIN)res.set({'Access-Control-Allow-Origin':o,'Access-Control-Allow-Credentials':'true','Access-Control-Allow-Headers':'Content-Type','Access-Control-Allow-Methods':'GET,POST,PUT,PATCH,DELETE',Vary:'Origin'});
if(req.method==='OPTIONS')return res.sendStatus(204);if(req.method!=='GET'&&req.path!=='/api/paypal/webhook'&&!(o&&(o===ORIGIN||o===`${req.protocol}://${req.get('host')}`)))return res.status(403).json({error:'origin'});next()});
app.use(express.json({limit:'100kb',verify:(r,_,b)=>{r.raw=b.toString()}}));
app.use(session({store:new(pgSession(session))({pool,createTableIfMissing:true}),secret:E.SESSION_SECRET,resave:false,saveUninitialized:false,name:'bl.sid',cookie:{httpOnly:true,secure:PROD,sameSite:PROD?'none':'lax',maxAge:7*864e5}}));
app.use('/api',rateLimit({windowMs:9e5,limit:300}));const authLim=rateLimit({windowMs:9e5,limit:10});
const login=(req,u)=>new Promise((ok,no)=>req.session.regenerate(e=>{if(e)return no(e);req.session.uid=u.id;req.session.orders=[];ok()}));
const user=(req,res,n)=>req.session.uid?n():res.status(401).json({error:'נדרשת התחברות'});
const role=(...rs)=>ah(async(req,res,n)=>{const u=req.session.uid&&(await q('select role from users where id=$1',[req.session.uid])).rows[0];if(!u||!rs.includes(u.role))return res.status(403).json({error:'אין הרשאה'});n()});
/* ---------- קטלוג ---------- */
app.get('/api/config',(q_,r)=>r.json({paypalClientId:E.PAYPAL_CLIENT_ID||null,paypalEnv:E.PAYPAL_ENV||'sandbox',currency:CUR,deliveryCities:(E.DELIVERY_CITIES||'').split(',').filter(Y=>Y.trim())}));
app.get('/api/products',ah(async(req,res)=>res.json((await q(`select p.id,p.name,p.category,p.description,p.ingredients,p.price_cents,p.image,p.stock,(select round(avg(rating),1) from reviews where product_id=p.id and status='approved') rating from products p where active order by id`)).rows)));
app.get('/api/products/:id/reviews',ah(async(req,res)=>res.json((await q(`select r.rating,r.body,r.verified,r.created_at,u.name from reviews r join users u on u.id=r.user_id where product_id=$1 and status='approved' order by r.id desc limit 50`,[+req.params.id||0])).rows)));
app.post('/api/products/:id/reviews',user,ah(async(req,res)=>{const{rating,body}=req.body,id=+req.params.id;if(!Number.isInteger(rating)||rating<1||rating>5||(body&&!str(body,1000)))throw bad('ביקורת לא תקינה');
const v=(await q(`select 1 from order_items i join orders o on o.id=i.order_id where i.product_id=$1 and o.user_id=$2 and o.status in('payment_confirmed','preparing','ready_for_pickup','out_for_delivery','delivered') limit 1`,[id,req.session.uid])).rowCount>0;
try{await q('insert into reviews(product_id,user_id,rating,body,verified) values($1,$2,$3,$4,$5)',[id,req.session.uid,rating,body||null,v])}catch(e){throw bad('כבר כתבתם ביקורת למוצר זה (או שהמוצר לא קיים)',409)}res.status(201).json({ok:true,note:'הביקורת תפורסם לאחר אישור'})}));
/* ---------- חשבונות ---------- */
app.post('/api/auth/register',authLim,ah(async(req,res)=>{const{name,email,password}=req.body;if(!str(name,100)||!mail(email)||typeof password!=='string'||password.length<8||password.length>72)throw bad('פרטים לא תקינים (סיסמה: 8 תווים לפחות)');
let u;try{u=(await q('insert into users(name,email,password_hash) values($1,$2,$3) returning id,name,email,role',[name.trim(),email.toLowerCase(),await bcrypt.hash(password,12)])).rows[0]}catch(e){throw bad('האימייל כבר רשום',409)}await login(req,u);res.status(201).json(u)}));
app.post('/api/auth/login',authLim,ah(async(req,res)=>{const{email,password}=req.body;const u=mail(email)&&(await q('select * from users where email=$1',[email.toLowerCase()])).rows[0];
if(!u||typeof password!=='string'||!(await bcrypt.compare(password,u.password_hash)))throw bad('אימייל או סיסמה שגויים',401);await login(req,u);res.json({id:u.id,name:u.name,email:u.email,role:u.role})}));
app.post('/api/auth/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/auth/me',ah(async(req,res)=>res.json(req.session.uid?(await q('select id,name,email,role from users where id=$1',[req.session.uid])).rows[0]||null:null)));
app.patch('/api/auth/me',user,ah(async(req,res)=>{if(!str(req.body.name,100))throw bad('שם לא תקין');await q('update users set name=$1 where id=$2',[req.body.name.trim(),req.session.uid]);res.json({ok:true})}));
/* ---------- תמחור בשרת: לעולם לא סומכים על הדפדפן ---------- */
const CU={basePrice:1800,perFruit:300,base:{water:0,milk:100,oat:200,coconut:200,yogurt:200},fruit:['strawberry','banana','mango','pineapple','blueberry','raspberry','kiwi','peach'],extra:{protein:500,chia:200,pb:300,cocoa:200,honey:200},size:{regular:0,large:500}};
async function priceCart(b){const items=Array.isArray(b.items)?b.items:[];if(!items.length||items.length>30)throw bad('עגלה לא תקינה');
const ex=Object.fromEntries((await q('select key,name,price_cents from extras')).rows.map(r=>[r.key,r])),lines=[];
for(const it of items){const qty=it.qty;if(!Number.isInteger(qty)||qty<1||qty>20)throw bad('כמות לא תקינה');
if(it.custom){const c=it.custom,fr=Array.isArray(c.fruits)?[...new Set(c.fruits)]:[],xs=Array.isArray(c.extras)?[...new Set(c.extras)]:[];
if(!has(CU.base,c.base)||!has(CU.size,c.size)||!fr.length||fr.length>4||!fr.every(f=>CU.fruit.includes(f))||!xs.every(x=>has(CU.extra,x)))throw bad('בלנד אישי לא תקין');
lines.push({product_id:null,name:'בלנד אישי',opts:{custom:{base:c.base,fruits:fr,extras:xs,size:c.size}},unit:CU.basePrice+CU.base[c.base]+fr.length*CU.perFruit+xs.reduce((a,x)=>a+CU.extra[x],0)+CU.size[c.size],qty});continue}
const p=(await q('select id,name,price_cents,stock from products where id=$1 and active',[+it.productId||0])).rows[0];if(!p)throw bad('מוצר לא נמצא');
const xs=[...new Set(Array.isArray(it.extras)?it.extras:[])];if(!xs.every(x=>has(ex,x)))throw bad('תוספת לא תקינה');if(p.stock<qty)throw bad('המוצר אזל מהמלאי: '+p.name);
lines.push({product_id:p.id,name:p.name,opts:{extras:xs},unit:p.price_cents+xs.reduce((a,x)=>a+ex[x].price_cents,0),qty})}
const sub=lines.reduce((a,l)=>a+l.unit*l.qty,0);let disc=0,code=null;
if(b.coupon){const c=(await q('select * from coupons where code=$1 and active and (expires_at is null or expires_at>now()) and (max_uses is null or uses<max_uses) and min_order_cents<=$2',[String(b.coupon).toUpperCase(),sub])).rows[0];if(!c)throw bad('קוד הנחה לא תקף');disc=Math.min(sub,c.percent?Math.round(sub*c.percent/100):c.amount_cents);code=c.code}
const del=b.mode==='delivery';if(!del&&b.mode!=='pickup')throw bad('שיטת מסירה לא תקינה');
const cities=(E.DELIVERY_CITIES||'').split(',').map(s=>s.trim()).filter(Boolean);if(del&&cities.length&&!cities.includes(String(b.customer?.city||'').trim()))throw bad('אין משלוחים לעיר זו');
const fee=del?Math.round(+(E.DELIVERY_FEE||15)*100):0;return{lines,sub,disc,code,fee,total:sub-disc+fee}}
app.post('/api/quote',ah(async(req,res)=>{const{sub,disc,fee,total}=await priceCart(req.body);res.json({subtotal_cents:sub,discount_cents:disc,fee_cents:fee,total_cents:total,currency:CUR})}));
/* ---------- הזמנות ---------- */
app.post('/api/orders',ah(async(req,res)=>{const c=req.body.customer||{},t=await priceCart(req.body);
if(!str(c.name,100)||!mail(c.email)||!str(c.phone,30)||(req.body.mode==='delivery'&&(!str(c.address,200)||!str(c.city,80))))throw bad('פרטי הלקוח חסרים או לא תקינים');
const cl=await pool.connect();try{await cl.query('begin');const o=(await cl.query(`insert into orders(user_id,name,email,phone,address,city,postal,notes,mode,coupon_code,subtotal_cents,discount_cents,fee_cents,total_cents,currency) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) returning id`,
[req.session.uid||null,c.name.trim(),c.email.toLowerCase(),c.phone,c.address||null,c.city||null,String(c.postal||'').slice(0,20)||null,String(c.notes||'').slice(0,500)||null,req.body.mode,t.code,t.sub,t.disc,t.fee,t.total,CUR])).rows[0];
for(const l of t.lines)await cl.query('insert into order_items(order_id,product_id,name,options,unit_cents,qty) values($1,$2,$3,$4,$5,$6)',[o.id,l.product_id,l.name,l.opts,l.unit,l.qty]);await cl.query('commit');
req.session.orders=(req.session.orders||[]).concat(o.id);res.status(201).json({id:o.id,total_cents:t.total,currency:CUR})}catch(e){await cl.query('rollback');throw e}finally{cl.release()}}));
const getOrder=async id=>UUID.test(id)?(await q('select * from orders where id=$1',[id])).rows[0]:null,mine=(req,o)=>o&&((o.user_id&&o.user_id===req.session.uid)||(req.session.orders||[]).includes(o.id));
const withItems=async o=>({...o,items:(await q('select name,options,unit_cents,qty from order_items where order_id=$1',[o.id])).rows});
app.get('/api/orders/mine',user,ah(async(req,res)=>res.json((await q('select id,status,mode,total_cents,currency,created_at from orders where user_id=$1 order by created_at desc',[req.session.uid])).rows)));
app.get('/api/orders/:id',ah(async(req,res)=>{const o=await getOrder(req.params.id);if(!mine(req,o))throw bad('לא נמצא',404);res.json(await withItems(o))}));
/* ---------- PayPal ---------- */
let tk={v:null,exp:0};async function token(){if(tk.v&&Date.now()<tk.exp)return tk.v;const r=await fetch(PPU+'/v1/oauth2/token',{method:'POST',headers:{Authorization:'Basic '+Buffer.from(`${E.PAYPAL_CLIENT_ID}:${E.PAYPAL_CLIENT_SECRET}`).toString('base64'),'Content-Type':'application/x-www-form-urlencoded'},body:'grant_type=client_credentials'}),j=await r.json();
if(!r.ok)throw Object.assign(new Error('paypal auth'),{body:j});tk={v:j.access_token,exp:Date.now()+(j.expires_in-60)*1000};return tk.v}
async function pp(path,o={}){const r=await fetch(PPU+path,{...o,headers:{Authorization:'Bearer '+await token(),'Content-Type':'application/json',...o.headers}}),j=await r.json().catch(()=>({}));if(!r.ok)throw Object.assign(new Error('paypal'),{status:r.status,body:j});return j}
app.post('/api/orders/:id/paypal',ah(async(req,res)=>{const o=await getOrder(req.params.id);if(!mine(req,o))throw bad('לא נמצא',404);if(o.status!=='pending_payment')throw bad('ההזמנה כבר שולמה או בוטלה',409);
const r=await pp('/v2/checkout/orders',{method:'POST',headers:{'PayPal-Request-Id':'create-'+o.id},body:JSON.stringify({intent:'CAPTURE',purchase_units:[{reference_id:o.id,custom_id:o.id,amount:{currency_code:o.currency,value:money(o.total_cents)}}]})});
await q('update orders set paypal_order_id=$1 where id=$2',[r.id,o.id]);res.json({id:r.id})}));
async function markPaid(id,cap){const c=await pool.connect();try{await c.query('begin');const o=(await c.query('select * from orders where id=$1 for update',[id])).rows[0];
if(!o||o.status!=='pending_payment'){await c.query('rollback');return{paid:!!o&&!['cancelled','payment_review'].includes(o.status)}}
if(cap.amount?.currency_code!==o.currency||cap.amount?.value!==money(o.total_cents)){await c.query("update orders set status='payment_review',updated_at=now() where id=$1",[id]);await c.query('commit');return{paid:false}}
await c.query("insert into payments(order_id,provider,transaction_id,amount_cents,currency,status) values($1,'paypal',$2,$3,$4,'completed') on conflict(transaction_id) do nothing",[id,cap.id,o.total_cents,o.currency]);
await c.query("update orders set status='payment_confirmed',updated_at=now() where id=$1",[id]);
await c.query('update products p set stock=greatest(p.stock-s.q,0) from (select product_id,sum(qty) q from order_items where order_id=$1 and product_id is not null group by 1) s where p.id=s.product_id',[id]);
if(o.coupon_code)await c.query('update coupons set uses=uses+1 where code=$1',[o.coupon_code]);await c.query('commit');return{paid:true}}catch(e){await c.query('rollback');throw e}finally{c.release()}}
app.post('/api/orders/:id/capture',ah(async(req,res)=>{const o=await getOrder(req.params.id);if(!mine(req,o)||!o.paypal_order_id)throw bad('לא נמצא',404);
const r=await pp(`/v2/checkout/orders/${o.paypal_order_id}/capture`,{method:'POST',headers:{'PayPal-Request-Id':'cap-'+o.id}}),cap=r.purchase_units?.[0]?.payments?.captures?.[0];
if(r.status!=='COMPLETED'||cap?.status!=='COMPLETED')return res.status(402).json({error:'התשלום לא הושלם',status:r.status});res.json(await markPaid(o.id,cap))}));
app.post('/api/paypal/webhook',ah(async(req,res)=>{const h=req.headers,ev=JSON.parse(req.raw);
const v=await pp('/v1/notifications/verify-webhook-signature',{method:'POST',body:JSON.stringify({auth_algo:h['paypal-auth-algo'],cert_url:h['paypal-cert-url'],transmission_id:h['paypal-transmission-id'],transmission_sig:h['paypal-transmission-sig'],transmission_time:h['paypal-transmission-time'],webhook_id:E.PAYPAL_WEBHOOK_ID,webhook_event:ev})});
if(v.verification_status!=='SUCCESS')return res.sendStatus(400);
const ins=await q('insert into payment_events(event_id,type,payload) values($1,$2,$3) on conflict do nothing returning id',[ev.id,ev.event_type,ev]);
if(ins.rowCount&&ev.event_type==='PAYMENT.CAPTURE.COMPLETED'&&UUID.test(ev.resource?.custom_id||''))await markPaid(ev.resource.custom_id,ev.resource);res.sendStatus(200)}));
/* ---------- ניהול ---------- */
const adm=role('admin'),stf=role('admin','staff'),ST=['payment_confirmed','preparing','ready_for_pickup','out_for_delivery','delivered','cancelled'];
app.get('/api/admin/stats',stf,ah(async(req,res)=>{const s=(await q(`select count(*)::int orders,coalesce(sum(total_cents) filter(where status not in('pending_payment','cancelled','payment_review')),0)::int revenue,count(*) filter(where status in('payment_confirmed','preparing'))::int pending,count(*) filter(where status='delivered')::int completed from orders`)).rows[0];
const sold=(await q(`select coalesce(sum(i.qty),0)::int n from order_items i join orders o on o.id=i.order_id where o.status not in('pending_payment','cancelled','payment_review')`)).rows[0].n;
const top=(await q(`select i.name,sum(i.qty)::int n from order_items i join orders o on o.id=i.order_id where o.status not in('pending_payment','cancelled','payment_review') group by 1 order by 2 desc limit 5`)).rows;
res.json({...s,products_sold:sold,popular:top,recent:(await q('select id,name,status,total_cents,created_at from orders order by created_at desc limit 10')).rows})}));
const pv=b=>{if(!str(b.name,120)||!str(b.category,60)||!str(b.description,600)||!str(b.ingredients,300)||!Number.isInteger(b.price_cents)||b.price_cents<=0||!Number.isInteger(b.stock)||b.stock<0||(b.image&&!/^(https:\/\/|\/)\S{1,490}$/.test(b.image)))throw bad('נתוני מוצר לא תקינים');return[b.name.trim(),b.category.trim(),b.description,b.ingredients,b.price_cents,b.image||null,b.stock,b.active!==false]};
app.get('/api/admin/products',adm,ah(async(req,res)=>res.json((await q('select * from products order by id')).rows)));
app.post('/api/admin/products',adm,ah(async(req,res)=>res.status(201).json((await q('insert into products(name,category,description,ingredients,price_cents,image,stock,active) values($1,$2,$3,$4,$5,$6,$7,$8) returning *',pv(req.body))).rows[0])));
app.put('/api/admin/products/:id',adm,ah(async(req,res)=>{const r=await q('update products set name=$2,category=$3,description=$4,ingredients=$5,price_cents=$6,image=$7,stock=$8,active=$9 where id=$1 returning *',[+req.params.id||0,...pv(req.body)]);if(!r.rowCount)throw bad('לא נמצא',404);res.json(r.rows[0])}));
app.delete('/api/admin/products/:id',adm,ah(async(req,res)=>{await q('update products set active=false where id=$1',[+req.params.id||0]);res.json({ok:true})}));
app.get('/api/admin/orders',stf,ah(async(req,res)=>{const{q:s,status}=req.query;res.json((await q(`select id,name,email,phone,status,mode,total_cents,created_at,(select status from payments where order_id=orders.id limit 1) payment from orders where ($1::text is null or name ilike '%'||$1||'%' or email ilike '%'||$1||'%' or id::text=$1) and ($2::text is null or status=$2) order by created_at desc limit 100`,[s||null,ST.concat('pending_payment','payment_review').includes(status)?status:null])).rows)}));
app.get('/api/admin/orders/:id',stf,ah(async(req,res)=>{const o=await getOrder(req.params.id);if(!o)throw bad('לא נמצא',404);res.json(await withItems(o))}));
app.patch('/api/admin/orders/:id/status',stf,ah(async(req,res)=>{if(!ST.includes(req.body.status))throw bad('סטטוס לא תקין');const o=await getOrder(req.params.id);if(!o||o.status==='pending_payment')throw bad('לא ניתן לעדכן הזמנה שלא שולמה',409);
await q('update orders set status=$2,updated_at=now() where id=$1',[o.id,req.body.status]);res.json({ok:true})}));
app.post('/api/admin/orders/:id/refund',adm,ah(async(req,res)=>{const o=await getOrder(req.params.id),p=o&&(await q("select * from payments where order_id=$1 and status='completed'",[o.id])).rows[0];if(!p)throw bad('אין תשלום להחזר',404);
await pp(`/v2/payments/captures/${p.transaction_id}/refund`,{method:'POST',headers:{'PayPal-Request-Id':'refund-'+o.id},body:'{}'});await q("update payments set status='refunded' where id=$1",[p.id]);await q("update orders set status='cancelled',updated_at=now() where id=$1",[o.id]);res.json({ok:true})}));
app.get('/api/admin/customers',adm,ah(async(req,res)=>res.json((await q(`select u.id,u.name,u.email,u.created_at,count(o.id)::int orders,coalesce(sum(o.total_cents) filter(where o.status not in('pending_payment','cancelled','payment_review')),0)::int spent from users u left join orders o on o.user_id=u.id where u.role='customer' and ($1::text is null or u.name ilike '%'||$1||'%' or u.email ilike '%'||$1||'%') group by u.id order by u.id desc limit 100`,[req.query.q||null])).rows)));
app.get('/api/admin/reviews',adm,ah(async(req,res)=>res.json((await q(`select r.*,u.name from reviews r join users u on u.id=r.user_id where r.status='pending' order by r.id`)).rows)));
app.patch('/api/admin/reviews/:id',adm,ah(async(req,res)=>{if(!['approved','rejected'].includes(req.body.status))throw bad('סטטוס לא תקין');await q('update reviews set status=$2 where id=$1',[+req.params.id||0,req.body.status]);res.json({ok:true})}));
app.use((e,req,res,n)=>res.status(400).json({error:'בקשה לא תקינה'}));
app.listen(E.PORT||3000,()=>console.log('Blendora API on',E.PORT||3000));
