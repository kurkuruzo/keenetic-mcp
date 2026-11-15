'use strict';
(() => {
  const KEY = 'clear-step-two-screens-v1';
  const $ = selector => document.querySelector(selector);
  const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const screen = document.body.dataset.screen;
  const projectId = new URLSearchParams(location.search).get('id') || 'app';
  const projectUrl = id => `project.html?id=${encodeURIComponent(id)}`;
  const seed = () => ({schema:1, revision:0, projects:[
    {id:'app',name:'Приложение для задач',version:0,vision:'Мои задачи, проекты, идеи и материалы собраны в одном месте. После выполненной задачи понятно, чем заняться дальше.',target:'Согласованы два экрана: действия и проект. На прототипе можно выбрать задачу из плана, выполнить её и увидеть результат в обоих местах.'},
    {id:'trip',name:'Семейная поездка',version:0,vision:'Мы провели несколько спокойных дней вместе, без плотной программы и спешки.',target:'Согласованы даты и выбран подходящий вариант жилья.'}
  ],tasks:[
    {id:'a1',projectId:'app',title:'Записать три наблюдения о выборе следующего действия',notes:'Открыть экран действий и пройти список сверху вниз. Что помогает понять следующий шаг, а что отвлекает?',inActions:true,done:false,rank:1,version:0,due:''},
    {id:'a2',projectId:'app',title:'Проверить связь задачи в проекте и на экране действий',notes:'Добавить задачу в действия, изменить её название, отметить выполнение. Проверить, что в проекте видны те же изменения.',inActions:true,done:false,rank:2,version:0,due:''},
    {id:'a3',projectId:'app',title:'Описать процесс разбора входящей записи',notes:'Пока это пункт плана. Перед добавлением в действия можно уточнить конкретный шаг.',inActions:false,done:false,rank:3,version:0,due:''},
    {id:'a4',projectId:'app',title:'Подготовить примеры идей и справочной информации',notes:'Эту часть проекта будем обсуждать после экранов действий и проекта.',inActions:false,done:false,rank:4,version:0,due:''},
    {id:'a0',projectId:'app',title:'Выбрать названия полей проекта по книге',notes:'Видение конечного результата; ближайшее целевое состояние; следующий конкретный шаг.',inActions:false,done:true,rank:0,version:0,due:''},
    {id:'b1',projectId:'trip',title:'Написать семье и предложить два варианта дат',notes:'Спросить, какой из двух выходных удобнее. Пока не выбирать жильё до согласования дат.',inActions:true,done:false,rank:5,version:0,due:''}
  ],inbox:[]});
  let data, showDone=false, selectedId=null, undo=null, storageError='', busy=false, returnFocus=null;
  function read(){const raw=localStorage.getItem(KEY);if(!raw)return seed();const parsed=JSON.parse(raw);if(parsed.schema!==1||!Array.isArray(parsed.tasks)||!Array.isArray(parsed.projects)||!Array.isArray(parsed.inbox))throw Error('Формат сохранённых данных не поддерживается. Данные не перезаписаны.');return parsed;}
  function message(text, allowUndo=false){$('#feedback-text').textContent=text;$('.feedback').hidden=false;$('[data-action=undo]').hidden=!allowUndo;}
  async function mutate(change){
    if(busy)return false;busy=true;
    const commit=()=>{const latest=read();change(latest);latest.revision++;localStorage.setItem(KEY,JSON.stringify(latest));data=latest;};
    try{if(navigator.locks)await navigator.locks.request(KEY,commit);else commit();storageError='';render();return true;}
    catch(error){message(`Не удалось сохранить: ${error.message}`);return false;}
    finally{busy=false;}
  }
  function active(){return data.tasks.filter(t=>t.inActions&&!t.done).sort((a,b)=>a.rank-b.rank||a.id.localeCompare(b.id));}
  const project = id => data.projects.find(p=>p.id===id);
  const task = id => data.tasks.find(t=>t.id===id);
  function dateLabel(date){return date?new Date(date+'T12:00:00').toLocaleDateString('ru-RU',{day:'numeric',month:'long'}):'';}
  function row(t,mode,index=0,total=0){
    const current=mode==='actions'&&t.id===selectedId;
    return `<article class="task-row ${current?'current':''} ${t.inActions&&!t.done?'in-actions':''} ${t.done?'completed':''}"><button type="button" class="check-button" data-action="${t.done?'restore':'complete'}" data-id="${t.id}" aria-label="${t.done?'Вернуть в работу':'Выполнить'}: ${escape(t.title)}"><span>${t.done?'✓':''}</span></button><div class="task-body">${current?'<div class="row-label">Следующее действие</div>':''}<button type="button" class="task-title" data-action="open-task" data-id="${t.id}">${escape(t.title)}</button><div class="task-meta">${mode==='actions'?`<a href="${projectUrl(t.projectId)}">${escape(project(t.projectId)?.name)}</a>`:''}${t.inActions&&!t.done?'<span class="task-state">● В действиях</span>':''}${t.due?`<span>Срок: ${dateLabel(t.due)}</span>`:''}${t.done?'<span>Выполнено</span>':''}</div></div><div class="row-controls">${t.done?'':mode==='plan'?`<button type="button" data-action="${t.inActions?'unselect':'select'}" data-id="${t.id}" ${t.inActions?'':'class="primary"'}>${t.inActions?'Убрать из действий':'Добавить в действия'}</button>`:`<button type="button" class="order" data-action="up" data-id="${t.id}" aria-label="Выше в списке: ${escape(t.title)}" ${index===0?'disabled':''}>↑</button><button type="button" class="order" data-action="down" data-id="${t.id}" aria-label="Ниже в списке: ${escape(t.title)}" ${index===total-1?'disabled':''}>↓</button><button type="button" data-action="unselect" data-id="${t.id}">Убрать из действий</button>`}</div></article>`;
  }
  function render(){
    $('#inbox-count').textContent=data.inbox.length?`(${data.inbox.length})`:'';
    $('#inbox-summary').textContent=`Записанные мысли (${data.inbox.length})`;
    $('#inbox-list').innerHTML=data.inbox.map(i=>`<div class="inbox-item">${escape(i.text)}</div>`).join('')||'<p class="footnote">Пока пусто.</p>';
    const warning=location.protocol==='file:';
    $('#storage-note').className='storage-note'+(warning||storageError?' warning':'');
    $('#storage-note').textContent=storageError|| (warning?'При открытии отдельных файлов браузер может разделять их хранилища. Для проверки связи двух экранов запустите сервер по инструкции в README.':'Изменения сохраняются в этом браузере. Две вкладки этого адреса используют одни данные. Синхронизации с другими устройствами нет.');
    if(screen==='actions'){
      const list=showDone?data.tasks.filter(t=>t.done&&t.inActions):active();
      if(!active().some(t=>t.id===selectedId))selectedId=active()[0]?.id||null;
      $('#queue-title').textContent=showDone?'Выполненные выбранные действия':'Что делать дальше';
      $('#queue-count').textContent=`${list.length} в списке`;
      $('#toggle-done').textContent=showDone?'Вернуться к действиям':'Показать выполненные';
      $('#toggle-done').setAttribute('aria-pressed',String(showDone));
      $('#action-list').innerHTML=list.length?`<div class="task-list">${list.map((t,i)=>row(t,'actions',i,list.length)).join('')}</div>`:`<div class="empty"><h2>${showDone?'Пока ничего не выполнено':'Действия пока не выбраны'}</h2><p>${showDone?'Здесь появятся выполненные задачи из этой очереди.':'Можно выбрать следующий шаг в плане проекта или закончить работу.'}</p></div>`;
      const t=task(selectedId),p=t&&project(t.projectId);
      $('#action-context').innerHTML=t?`<h2>Контекст следующего действия</h2><h3>${escape(p.name)}</h3><span class="context-label">Ближайшее целевое состояние</span><p>${escape(p.target)}</p><span class="context-label">Подсказка к действию</span><p>${escape(t.notes||'Дополнительных пояснений нет.')}</p><a href="${projectUrl(p.id)}">Открыть проект</a>`:'<h2>Контекст действия</h2><p class="footnote">Выберите шаг в проекте, чтобы его контекст был под рукой.</p>';
    }else{
      const p=project(projectId);if(!p){$('main').innerHTML='<h1>Проект не найден</h1><a href="project.html">Открыть пример проекта</a>';return;}
      $('#project-name').textContent=p.name;$('#vision').textContent=p.vision;$('#target').textContent=p.target;
      const next=active().find(t=>t.projectId===p.id);
      $('#next-step').innerHTML=next?`<button type="button" class="task-title" data-action="open-task" data-id="${next.id}">${escape(next.title)}</button><div class="row-controls"><span class="task-state">● В действиях</span><button type="button" data-action="open-task" data-id="${next.id}">Изменить шаг</button><a class="text-link" href="actions.html">Открыть рабочую очередь</a></div>`:'<p>Выберите конкретную задачу ниже и добавьте её в действия.</p>';
      const plan=data.tasks.filter(t=>t.projectId===p.id&&!t.done),done=data.tasks.filter(t=>t.projectId===p.id&&t.done);
      $('#project-plan').innerHTML=plan.length?`<div class="task-list">${plan.map(t=>row(t,'plan')).join('')}</div>`:'<div class="empty"><p>Открытых задач нет. Можно уточнить целевое состояние и следующий шаг.</p></div>';
      $('#completed-summary').textContent=`Выполненные (${done.length})`;
      $('#completed-plan').innerHTML=`<div class="task-list">${done.map(t=>row(t,'plan')).join('')}</div>`;
    }
  }
  function openTask(id=null){
    const t=id?task(id):null;returnFocus=document.activeElement;
    $('#task-dialog-content').innerHTML=`<div class="dialog-heading"><h2 id="task-dialog-title">${t?'Задача':'Задача в плане проекта'}</h2><button type="button" data-action="close-task" aria-label="Закрыть">×</button></div><p class="dialog-project">${escape(project(t?.projectId||projectId)?.name)}${t?` · ${t.done?'Выполнено':t.inActions?'В действиях':'Только в плане'}`:''}</p><form id="task-form" data-id="${t?.id||''}" data-version="${t?.version??0}"><label>Что сделать?<textarea name="title" maxlength="240" required>${escape(t?.title||'')}</textarea></label><label>Пояснения и материалы<textarea name="notes" maxlength="5000">${escape(t?.notes||'')}</textarea></label><label>Реальный срок, если есть<input type="date" name="due" value="${t?.due||''}"></label><p class="form-error" id="task-error" role="alert"></p><div class="form-actions"><button type="button" data-action="close-task">Закрыть</button><button type="submit" class="primary">Сохранить</button></div></form>${t?`<div class="task-options"><button type="button" data-action="dialog-${t.done?'restore':'complete'}" data-id="${t.id}">${t.done?'Вернуть в работу':'Отметить выполненной'}</button>${t.done?'':`<button type="button" data-action="dialog-${t.inActions?'unselect':'select'}" data-id="${t.id}">${t.inActions?'Убрать из действий':'Добавить в действия'}</button>`}</div>`:'<p class="footnote">Новая задача появится только в плане. Добавление в действия — отдельный выбор.</p>'}`;
    $('#task-dialog').showModal();$('#task-form [name=title]').focus();
  }
  function close(id){const d=$(id);if(d.querySelector('form')?.dataset.dirty==='true'&&!confirm('Закрыть без сохранения введённых изменений?'))return false;d.close();returnFocus?.focus();return true;}
  async function taskCommand(id,action){
    let before,version;
    const ok=await mutate(latest=>{const t=latest.tasks.find(t=>t.id===id);if(!t)throw Error('Задача не найдена.');before={...t};
      if(action==='complete')t.done=true;
      if(action==='restore')t.done=false;
      if(action==='select'){t.inActions=true;t.rank=Math.max(0,...latest.tasks.map(x=>x.rank))+1;}
      if(action==='unselect')t.inActions=false;
      t.version++;version=t.version;
    });
    if(ok){undo={before,version};message({complete:'Выполнено. Следующее действие осталось в списке.',restore:'Задача возвращена в работу.',select:'Задача добавлена в действия. Это та же запись.',unselect:'Задача убрана из действий и осталась в плане.'}[action],true);}
    return ok;
  }
  document.addEventListener('click',async e=>{
    const b=e.target.closest('[data-action]');if(!b)return;const a=b.dataset.action,id=b.dataset.id;
    if(a==='open-task')openTask(id);
    else if(a==='new-task')openTask();
    else if(a==='toggle-done'){showDone=!showDone;render();}
    else if(['complete','restore','select','unselect'].includes(a))await taskCommand(id,a);
    else if(a.startsWith('dialog-')){if($('#task-form').dataset.dirty==='true'){message('Сначала сохраните изменения задачи или закройте карточку без сохранения.');return;}if(await taskCommand(id,a.slice(7)))$('#task-dialog').close();}
    else if(a==='up'||a==='down'){
      await mutate(latest=>{const sorted=latest.tasks.filter(t=>t.inActions&&!t.done).sort((x,y)=>x.rank-y.rank||x.id.localeCompare(y.id));const i=sorted.findIndex(t=>t.id===id),j=i+(a==='up'?-1:1);if(i<0||j<0||j>=sorted.length)return;[sorted[i],sorted[j]]=[sorted[j],sorted[i]];sorted.forEach((t,k)=>{t.rank=k+1;t.version++;});});selectedId=active()[0]?.id;render();
    }else if(a==='undo'&&undo){const saved=undo;const ok=await mutate(latest=>{const i=latest.tasks.findIndex(t=>t.id===saved.before.id);if(i<0||latest.tasks[i].version!==saved.version)throw Error('Задача уже изменилась. Отмена не перезаписала новые данные.');latest.tasks[i]={...saved.before,version:saved.version+1};});if(ok){undo=null;message('Изменение отменено.');}}
    else if(a==='capture'){returnFocus=b;$('#capture-dialog').showModal();$('#capture-form textarea').focus();}
    else if(a==='close-capture')close('#capture-dialog');
    else if(a==='close-task')close('#task-dialog');
    else if(a==='close-project')close('#project-dialog');
    else if(a==='edit-project'){const p=project(projectId),f=$('#project-form');for(const field of ['name','vision','target'])f.elements.namedItem(field).value=p[field];f.dataset.version=p.version;f.dataset.dirty='false';$('#project-error').textContent='';returnFocus=b;$('#project-dialog').showModal();f.elements.namedItem(['name','vision','target'].includes(b.dataset.field)?b.dataset.field:'name').focus();}
  });
  document.addEventListener('submit',async e=>{
    const f=e.target;if(!['task-form','capture-form','project-form'].includes(f.id))return;e.preventDefault();const values=new FormData(f),value=k=>String(values.get(k)||'').trim();
    if(f.id==='task-form'){
      if(!value('title')){$('#task-error').textContent='Введите формулировку задачи.';return;}
      const ok=await mutate(latest=>{const fields={title:value('title'),notes:value('notes'),due:value('due')};if(f.dataset.id){const t=latest.tasks.find(t=>t.id===f.dataset.id);if(!t||t.version!==Number(f.dataset.version))throw Error('Задача изменилась в другой вкладке. Скопируйте свой текст и откройте карточку заново.');Object.assign(t,fields);t.version++;}else latest.tasks.push({id:crypto.randomUUID(),projectId,inActions:false,done:false,rank:Math.max(0,...latest.tasks.map(t=>t.rank))+1,version:0,...fields});});
      if(ok){f.dataset.dirty='false';$('#task-dialog').close();undo=null;message('Задача сохранена. Изменения видны в обоих представлениях.');}
    }else if(f.id==='capture-form'){
      if(!value('text'))return;const ok=await mutate(latest=>{latest.inbox.push({id:crypto.randomUUID(),text:value('text')});});if(ok){f.reset();f.dataset.dirty='false';$('#capture-dialog').close();message('Мысль сохранена во входящие.');}
    }else{
      if(!value('name')||!value('vision')||!value('target')){$('#project-error').textContent='Заполните название и оба поля результата.';return;}
      const ok=await mutate(latest=>{const p=latest.projects.find(p=>p.id===projectId);if(p.version!==Number(f.dataset.version))throw Error('Проект изменился в другой вкладке. Сохраните свой текст и откройте редактор заново.');p.name=value('name');p.vision=value('vision');p.target=value('target');p.version++;});if(ok){f.dataset.dirty='false';$('#project-dialog').close();message('Проект обновлён. Изменения видны и на экране действий.');}
    }
  });
  document.addEventListener('input',e=>{const f=e.target.closest('form');if(f)f.dataset.dirty='true';});
  document.querySelectorAll('dialog').forEach(d=>d.addEventListener('cancel',e=>{e.preventDefault();close('#'+d.id);}));
  window.addEventListener('storage',e=>{if(e.key===KEY||e.key===null){try{data=read();render();if($('#task-dialog').open)message('Данные обновлены в другой вкладке. Введённый текст сохранён в открытой форме.');}catch(error){message(error.message);}}});
  try{data=read();}catch(error){data=seed();storageError='Хранилище недоступно или повреждено. Изменения не будут подтверждаться как сохранённые: '+error.message;}
  render();
})();
