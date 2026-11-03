function pickDate(b){var d=b.nextElementSibling;try{d.showPicker()}catch(x){d.focus()}}
function setDate(d){if(d.value){var p=d.value.split('-');d.previousElementSibling.previousElementSibling.value=p[2]+'.'+p[1]+'.'+p[0]}}
function setNb(n){var b=document.getElementById('nb');if(b){b.textContent=n;b.style.display=n>0?'':'none'}}
function pollNb(){fetch('/unread',{credentials:'same-origin'}).then(function(r){return r.json()}).then(function(d){setNb(d.n)}).catch(function(){})}
if(document.getElementById('nb')){setInterval(pollNb,60000)}
function chk(f){var s=f.status?f.status.value:'',r=f.dataset.req.split(',');
if(s&&r.indexOf(s)>=0&&!f.body.value.trim()){alert('Для выбранного действия нужен комментарий.');f.body.focus();return false}return true}
var uid=document.body.getAttribute('data-uid')||'0';
function ls(k,v){try{if(v===undefined){return localStorage.getItem('tt'+uid+k)}localStorage.setItem('tt'+uid+k,v)}catch(x){}return null}
function toEnd(){var c=document.getElementById('chat');if(c){c.scrollTop=c.scrollHeight}}
var seq=0;
function openRow(tr,scroll){var d=document.getElementById('detail');if(!d){return}var n=++seq;
var o=document.querySelector('.mtop tr.on');if(o){o.classList.remove('on')}tr.classList.add('on');
if(scroll){tr.scrollIntoView({block:'nearest'})}
fetch(tr.dataset.frag,{credentials:'same-origin'}).then(function(r){return r.text()}).then(function(h){if(n!==seq){return}
d.innerHTML=h;toEnd();history.replaceState(null,'',tr.dataset.href);pollNb()}).catch(function(){location.href=tr.dataset.href})}
function sortTbl(th,dir){var t=th.closest('table'),i=th.cellIndex,num=th.getAttribute('data-t')==='n';
var tb=t.tBodies[0],rows=[].slice.call(tb.querySelectorAll('tr[data-frag]'));
rows.sort(function(a,b){var x=a.cells[i].getAttribute('data-v')||'',y=b.cells[i].getAttribute('data-v')||'';
var r=num?(parseFloat(x)||0)-(parseFloat(y)||0):x.localeCompare(y,'ru');return dir==='a'?r:-r});
rows.forEach(function(r){tb.appendChild(r)});
[].forEach.call(t.querySelectorAll('th'),function(h){h.classList.remove('sa');h.classList.remove('sd');h.removeAttribute('data-d')});
th.classList.add(dir==='a'?'sa':'sd');th.setAttribute('data-d',dir);ls('sort',i+':'+dir)}
document.addEventListener('click',function(ev){
var tg=ev.target;if(!tg.closest){return}
var m=document.querySelector('details.um[open]');if(m&&!m.contains(tg)){m.removeAttribute('open')}
var th=tg.closest('.mtop th');if(th){sortTbl(th,th.getAttribute('data-d')==='a'?'d':'a');return}
var op=document.querySelector('.reply.s1');if(op&&!tg.closest('.reply')){op.className='card reply'}
var b=tg.closest('.rbtn,.act');
if(b){var r=b.closest('.reply');if(!r){return}
if(b.classList.contains('rbtn')){var o=r.classList.contains('s1');r.className=o?'card reply':'card reply s1';
if(!o){var f1=r.querySelector('.racts .act');if(f1){f1.focus()}}return}
if(b.getAttribute('data-act')===null){r.className='card reply';return}
var f=r.querySelector('form');f.status.value=b.getAttribute('data-act');
r.querySelector('.rsend').textContent=b.getAttribute('data-lbl');
r.querySelector('.rinfo').textContent=b.getAttribute('data-st')?'Статус изменится: '+b.getAttribute('data-st'):'';
f.body.placeholder=b.getAttribute('data-req')==='1'?'Комментарий (обязателен)':'Комментарий';
r.className='card reply s2';f.body.focus();return}
var rc=tg.closest('.rcancel');if(rc){rc.closest('.reply').className='card reply';return}
var tr=tg.closest('tr[data-frag]');if(!tr||ev.ctrlKey||ev.metaKey||ev.shiftKey||ev.button){return}
var a=tg.closest('a');if(a&&!a.classList.contains('sel')){return}
if(!document.getElementById('detail')){return}
ev.preventDefault();openRow(tr,false)});
document.addEventListener('keydown',function(ev){
var t=ev.target,tn=t.tagName;
var om=document.querySelector('.reply.s1');
if(om&&(ev.key==='ArrowDown'||ev.key==='ArrowUp')){var bs=[].slice.call(om.querySelectorAll('.racts .act')),
k=bs.indexOf(document.activeElement);k=ev.key==='ArrowDown'?Math.min(k+1,bs.length-1):Math.max(k-1,0);
bs[k].focus();ev.preventDefault();return}
if(ev.key==='Escape'){var rp=t.closest?t.closest('.reply'):null;if(rp&&rp.className!=='card reply'){rp.className='card reply';return}}
if(tn==='TEXTAREA'&&ev.key==='Enter'&&(ev.ctrlKey||ev.metaKey)){var f=t.form;if(f){ev.preventDefault();if(f.requestSubmit){f.requestSubmit()}else if(chk(f)){f.submit()}}return}
if((ev.key==='ArrowDown'||ev.key==='ArrowUp')&&!ev.ctrlKey&&!ev.altKey&&!ev.metaKey&&!ev.shiftKey&&tn!=='INPUT'&&tn!=='TEXTAREA'&&tn!=='SELECT'&&!t.isContentEditable){
var rows=[].slice.call(document.querySelectorAll('.mtop tbody tr[data-frag]'));if(!rows.length){return}
var cur=document.querySelector('.mtop tr.on'),i=rows.indexOf(cur);
i=ev.key==='ArrowDown'?Math.min(i+1,rows.length-1):(i<0?0:Math.max(i-1,0));
ev.preventDefault();if(rows[i]!==cur){openRow(rows[i],true)}}});
var drag=null,mt=document.querySelector('.mtop'),lastH=0;
document.addEventListener('mousedown',function(ev){if(ev.target.closest&&ev.target.closest('.vs')){drag=document.getElementById('detail');ev.preventDefault();document.body.classList.add('dragging')}});
document.addEventListener('mousemove',function(ev){if(drag){var r=drag.getBoundingClientRect();drag.style.setProperty('--sidew',Math.max(180,Math.min(ev.clientX-r.left,r.width-340))+'px')}});
document.addEventListener('mouseup',function(){
if(drag){ls('sw',parseInt(drag.style.getPropertyValue('--sidew'),10)||'');drag=null;document.body.classList.remove('dragging')}
if(mt&&Math.abs(mt.offsetHeight-lastH)>2){lastH=mt.offsetHeight;ls('mh',lastH)}});
toEnd();
if(mt){var hh=ls('mh');if(hh){mt.style.height=hh+'px'}lastH=mt.offsetHeight;
var so=ls('sort');if(so){var pp=so.split(':'),ths=mt.querySelectorAll('th');if(ths[pp[0]]){sortTbl(ths[pp[0]],pp[1])}}}
var dd=document.getElementById('detail');if(dd){var ww=ls('sw');if(ww){dd.style.setProperty('--sidew',ww+'px')}}
var onr=document.querySelector('.mtop tr.on');if(onr){onr.scrollIntoView({block:'nearest'})}
