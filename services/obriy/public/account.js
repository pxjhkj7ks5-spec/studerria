const rawBase=document.querySelector('meta[name="app-base"]')?.content??'/obriy';
const base=/^\/[a-zA-Z0-9/_-]*$/.test(rawBase)?rawBase.replace(/\/$/,''):'/obriy';
const el=id=>document.getElementById(id);
let mode='login',busy=false,legacy=false;
function resetSecrets(){el('password').value='';el('confirm-password').value='';el('password').type='password';el('show-password').textContent='Показати';el('show-password').setAttribute('aria-pressed','false');}
function setMode(next){
  if(busy)return;
  mode=next;resetSecrets();
  const signup=mode==='register';
  el('signin-tab').setAttribute('aria-pressed',String(!signup));el('signup-tab').setAttribute('aria-pressed',String(signup));
  el('confirm-field').hidden=!signup;el('confirm-password').required=signup;
  el('password-note').hidden=!signup;el('password').autocomplete=signup?'new-password':'current-password';
  el('account-submit').textContent=signup?'Створити акаунт':'Увійти';el('account-error').hidden=true;
}
el('signin-tab').addEventListener('click',()=>setMode('login'));
el('signup-tab').addEventListener('click',()=>setMode('register'));
el('show-password').addEventListener('click',()=>{const show=el('password').type==='password';el('password').type=show?'text':'password';el('show-password').textContent=show?'Сховати':'Показати';el('show-password').setAttribute('aria-pressed',String(show));});
async function request(path,body){
  const response=await fetch(`${base}${path}`,{method:body?'POST':'GET',credentials:'same-origin',cache:'no-store',signal:AbortSignal.timeout(12000),headers:{Accept:'application/json',...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});
  const data=await response.json();
  if(!response.ok){if(response.status===403)window.location.replace(`${base}/`);throw new Error(data.error||'Не вдалося виконати запит. Спробуйте пізніше.');}
  return data;
}
el('account-form').addEventListener('submit',async event=>{
  event.preventDefault();if(busy)return;
  const password=el('password').value;
  el('account-error').hidden=true;
  if(mode==='register'&&(password.normalize('NFC')!==el('confirm-password').value.normalize('NFC')||[...password.normalize('NFC')].length<15||[...password.normalize('NFC')].length>128)){
    el('account-error').textContent='Використайте 15–128 символів і однаково повторіть пароль.';el('account-error').hidden=false;return;
  }
  busy=true;el('account-submit').disabled=true;
  try{
    await request(`/api/v1/auth/${mode}`,{username:el('username').value,password});resetSecrets();window.location.replace(`${base}/`);
  }catch(error){el('account-error').textContent=error.name==='TimeoutError'?'Сервер не відповідає вчасно. Спробуйте ще раз.':error instanceof TypeError?'Перевірте з’єднання та спробуйте ще раз.':error.message;el('account-error').hidden=false;resetSecrets();el('password').focus();}
  finally{busy=false;el('account-submit').disabled=false;}
});
request('/api/v1/access').then(access=>{
  if(access.authenticated||!access.allowed){window.location.replace(`${base}/`);return;}
  legacy=access.legacy;
  if(legacy){setMode('register');el('account-intro').textContent='Створіть власний логін і пароль. Ваші наявні зони та Telegram збережуться.';}
}).catch(()=>{});
window.addEventListener('pagehide',resetSecrets);
window.addEventListener('pageshow',event=>{if(event.persisted)window.location.reload();});
