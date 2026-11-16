'use strict';
(() => {
  const $ = (selector, root = document) => root.querySelector(selector);
  const csrf = $('meta[name="csrf-token"]')?.content || '';
  const isLogin = document.body.dataset.page === 'login';
  const state = { sources: [], shares: [], settings: {}, cache: {} };
  let ready = false;
  let loading = false;
  let currentView = 'shares';
  let modalBusy = false;
  let dialogTrigger = null;
  let dialogCleanup = null;
  const dialog = $('#app-dialog');
  const enc = value => encodeURIComponent(String(value));
  const sourcePath = id => `/api/admin/sources/${enc(id)}`;
  const sharePath = id => `/api/admin/shares/${enc(id)}`;

  function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined && text !== null) element.textContent = String(text);
    return element;
  }
  function button(text, className = 'button secondary', action) {
    const element = node('button', className, text);
    element.type = 'button';
    if (action) element.addEventListener('click', action);
    return element;
  }
  function toast(message, error = false) {
    const item = node('div', `toast${error ? ' error' : ''}`);
    item.append(node('span', '', message), button('×', '', () => item.remove()));
    item.lastChild.setAttribute('aria-label', '关闭提示');
    $('#toast-region').append(item);
    setTimeout(() => item.remove(), error ? 10000 : 5500);
  }
  function errorText(error) { return error instanceof Error ? error.message : '操作未完成，请稍后重试。'; }
  function formError(form, message) {
    const target = $('.form-error', form);
    target.textContent = message || '';
    target.hidden = !message;
    if (message) target.scrollIntoView({ block: 'nearest' });
  }
  async function api(path, method = 'GET', body) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), path.endsWith('/sources/batch') ? 150000 : 30000);
    try {
      const headers = { Accept: 'application/json' };
      if (method !== 'GET') {
        headers['X-CSRF-Token'] = csrf;
        headers['Content-Type'] = 'application/json';
      }
      const response = await fetch(path, {
        method, credentials: 'same-origin', headers, signal: controller.signal,
        cache: 'no-store', ...(body === undefined ? {} : { body: JSON.stringify(body) })
      });
      if (response.status === 401 && !isLogin) {
        location.assign('/admin/login');
        throw new Error('会话已过期，请重新登录。');
      }
      let data;
      try { data = await response.json(); } catch { throw new Error('服务返回了无法读取的结果，请重新加载后确认。'); }
      if (!response.ok) throw new Error(typeof data.error === 'string' ? data.error : '操作未完成，请稍后重试。');
      return data;
    } catch (error) {
      if (error.name === 'AbortError') throw new Error('请求等待过久。操作可能已生效，请重新加载确认后再重试。');
      if (error instanceof TypeError) throw new Error('无法连接网关，请检查网络后重试。');
      throw error;
    } finally { clearTimeout(timeout); }
  }
  async function busy(target, action, label = '处理中…') {
    if (target.disabled) return;
    const original = target.textContent;
    target.disabled = true;
    target.textContent = label;
    try { return await action(); }
    finally { target.disabled = false; target.textContent = original; }
  }
  async function submitForm(event, action) {
    event.preventDefault();
    const form = event.currentTarget;
    if (form.dataset.busy === 'true') return;
    formError(form, '');
    const controls = [...form.elements];
    const previous = controls.map(control => control.disabled);
    const submit = $('button[type="submit"]', form);
    const label = submit?.textContent;
    form.dataset.busy = 'true';
    controls.forEach(control => { control.disabled = true; });
    if (submit) submit.textContent = '处理中…';
    const wasModal = dialog?.contains(form);
    if (wasModal) { modalBusy = true; $('#dialog-close').disabled = true; }
    try { await action(form); }
    catch (error) { formError(form, errorText(error)); }
    finally {
      form.dataset.busy = 'false';
      controls.forEach((control, index) => { control.disabled = previous[index]; });
      if (submit) submit.textContent = label;
      if (wasModal) { modalBusy = false; $('#dialog-close').disabled = false; }
    }
  }
  function formatTime(value) {
    if (value === null || value === undefined || value === '') return '尚无记录';
    const number = Number(value);
    const date = new Date(Number.isFinite(number) ? number * 1000 : value);
    return Number.isNaN(date.getTime()) ? '时间未知' : date.toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', year: 'numeric', hour12: false });
  }
  function size(value) {
    const number = Math.max(0, Number(value) || 0);
    if (number < 1024) return `${number} B`;
    if (number < 1048576) return `${(number / 1024).toFixed(1)} KB`;
    return `${(number / 1048576).toFixed(1)} MB`;
  }
  function localTime(value) {
    if (!value) return '';
    const date = new Date(Number(value) * 1000);
    if (Number.isNaN(date.getTime())) return '';
    return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}T${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`;
  }
  function openDialog(title, subtitle = '') {
    if (dialog.open) return false;
    dialogTrigger = document.activeElement;
    $('#dialog-title').textContent = title;
    $('#dialog-subtitle').textContent = subtitle;
    $('#dialog-subtitle').hidden = !subtitle;
    $('#dialog-body').replaceChildren();
    dialog.showModal();
    return true;
  }
  function closeDialog(force = false) {
    if (modalBusy && !force) return;
    dialog.close();
  }
  function field(form, title, name, options = {}) {
    const wrapper = node('div', 'form-field');
    const label = node('label', '', title);
    const input = node(options.tag || 'input');
    input.id = `field-${name}`;
    input.name = name;
    label.htmlFor = input.id;
    if (input.tagName === 'INPUT') input.type = options.type || 'text';
    if (options.required) input.required = true;
    if (options.placeholder) input.placeholder = options.placeholder;
    if (options.value !== undefined) input.value = options.value ?? '';
    if (options.maxLength) input.maxLength = options.maxLength;
    wrapper.append(label, input);
    if (options.help) {
      const help = node('p', 'field-help', options.help);
      help.id = `${input.id}-help`;
      input.setAttribute('aria-describedby', help.id);
      wrapper.append(help);
    }
    form.append(wrapper);
    return input;
  }
  function checkbox(parent, label, name, checked = false) {
    const wrapper = node('label', 'check-label');
    const input = node('input');
    input.type = 'checkbox'; input.name = name; input.checked = checked;
    wrapper.append(input, node('span', '', label));
    parent.append(wrapper);
    return input;
  }
  function footer(form, text, action, danger = false) {
    const error = node('p', 'form-error'); error.hidden = true; error.setAttribute('role', 'alert');
    const actions = node('div', 'dialog-footer');
    const save = button(text, `button ${danger ? 'danger' : 'primary'}`);
    save.type = 'submit';
    actions.append(button('取消', 'button secondary', () => closeDialog()), save);
    form.append(error, actions);
    form.addEventListener('submit', event => submitForm(event, action));
    return save;
  }
  function mountForm() {
    const form = node('form', 'dialog-form');
    $('#dialog-body').append(form);
    return form;
  }
  function confirmAction(title, description, name, action, options = {}) {
    if (!openDialog(title, description)) return;
    const form = mountForm();
    if (name) form.append(node('p', 'confirm-name', name));
    footer(form, options.label || title, async () => {
      await action(); closeDialog(true);
      toast(options.success || '操作已完成');
      if (options.reload !== false) await loadState();
    }, options.danger !== false).focus();
  }
  function table(headers) {
    const table = node('table', 'data-table');
    const head = node('thead'); const row = node('tr'); const body = node('tbody');
    headers.forEach(text => { const th = node('th', '', text); th.scope = 'col'; row.append(th); });
    head.append(row); table.append(head, body);
    return { table, body };
  }
  function cell(row, label) {
    const td = node('td'); td.dataset.label = label; row.append(td); return td;
  }
  function menu(actions) {
    const details = node('details', 'row-menu');
    details.append(node('summary', '', '更多操作'));
    const content = node('div', 'menu-actions');
    actions.forEach(([label, action, danger]) => content.append(button(label, `text-button${danger ? ' danger-text' : ''}`, action)));
    details.append(content); return details;
  }
  function empty(container, title, text, actionLabel, action) {
    const content = node('div', 'empty-state');
    content.append(node('span', 'empty-mark', '↗'), node('h2', '', title), node('p', '', text));
    if (actionLabel) content.append(button(actionLabel, 'button primary', action));
    container.append(content);
  }
  function switchView(view, focus = true) {
    currentView = view;
    ['shares', 'sources', 'settings'].forEach(name => {
      $(`#view-${name}`).hidden = name !== view;
      const navigation = $(`[data-view="${name}"]`);
      navigation.classList.toggle('active', name === view);
      if (name === view) navigation.setAttribute('aria-current', 'page');
      else navigation.removeAttribute('aria-current');
    });
    document.title = `${({ shares: '分享链接', sources: 'Gist 来源', settings: '设置' })[view]} · Gist 网关`;
    if (focus) $(`#${view}-title`).scrollIntoView({ block: 'nearest' });
  }
  function showSourceShares(source) {
    $('#source-filter').value = String(source.id);
    $('#share-search').value = '';
    switchView('shares'); renderShares();
    $('#source-filter').focus();
  }
  function renderShares() {
    const content = $('#shares-content'); content.replaceChildren(); content.setAttribute('aria-busy', 'false');
    const query = $('#share-search').value.trim().toLocaleLowerCase();
    const filter = $('#source-filter').value;
    const shares = state.shares.filter(share => (!filter || String(share.source_id) === filter) && [share.label, share.slug, share.filename, share.source_name].some(value => String(value || '').toLocaleLowerCase().includes(query)));
    $('#share-count').textContent = `${shares.length} 条分享`;
    if (!shares.length) {
      if (!state.sources.length) empty(content, '从一份 Gist 开始', '先添加一个 Gist 来源，再为文件创建独立的分享链接。', '添加 Gist 来源', () => sourceForm());
      else if (query || filter) empty(content, '没有匹配的分享', '试试其他关键词，或清除来源筛选。', '清除筛选', () => { $('#share-search').value = ''; $('#source-filter').value = ''; renderShares(); });
      else empty(content, '为来源创建第一个分享', '命名并设置有效期，就可以分发链接。', '新建分享', () => shareForm());
      return;
    }
    const grid = table(['分享 / 路径', 'Gist 来源 / 文件', '状态', '拉取记录', '操作']);
    shares.forEach(share => {
      const row = node('tr');
      const name = cell(row, '分享 / 路径');
      name.append(node('div', 'cell-title', share.label || '未命名分享'), node('div', 'cell-detail', share.slug ? `/${share.slug}` : '自动生成路径'));
      const origin = cell(row, 'Gist 来源 / 文件');
      origin.append(node('div', 'cell-title', share.source_name || '未知来源'), node('span', 'file-name', share.filename || '沿用来源文件名'));
      const status = cell(row, '状态');
      const expired = share.expires_at != null && Number(share.expires_at) <= Date.now() / 1000;
      const enabled = share.enabled !== false;
      status.append(node('span', `badge${expired ? ' bad' : !enabled ? ' neutral' : ''}`, expired ? '已到期' : enabled ? '使用中' : '已暂停'), node('p', 'status-note', share.expires_at ? `到期 ${formatTime(share.expires_at)}` : '永久有效'));
      const activity = cell(row, '拉取记录');
      const lastAt = share.last_fetch ?? share.last_access;
      activity.append(
        node('div', 'cell-title', `${Number(share.access_count) || 0} 次访问`),
        node('div', 'cell-detail', lastAt ? `最近成功 ${formatTime(lastAt)}` : '尚未成功拉取'),
        node('div', 'cell-detail', share.last_ip ? `IP ${share.last_ip}` : (lastAt ? 'IP 未记录' : '')),
        button('最近 30 次', 'text-button', () => showFetches(share))
      );
      const actions = node('div', 'row-actions');
      const reveal = button('查看链接', 'text-button', () => revealShare(share, reveal));
      actions.append(reveal, menu([
        ['编辑', () => shareForm(share)],
        [enabled ? '暂停' : '启用', () => confirmAction(enabled ? '暂停分享' : '启用分享', enabled ? '暂停后，此分享地址将暂时无法访问。' : '启用后，分享地址将恢复访问；已到期的分享还需调整有效期。', share.label, () => api(`${sharePath(share.id)}/toggle`, 'POST', {}), { danger: false, success: enabled ? '分享已暂停' : '分享已启用' })],
        ['重置链接', () => confirmAction('重置分享链接', '原链接会立即失效。重置后请重新查看并分发新链接。', share.label, () => api(`${sharePath(share.id)}/rotate`, 'POST', {}), { success: '链接已重置，请重新查看链接' })],
        ['删除', () => confirmAction('删除分享', '此分享地址将永久失效，Gist 来源仍会保留。', share.label, () => api(sharePath(share.id), 'DELETE'), { success: '分享已删除' }), true]
      ]));
      cell(row, '操作').append(actions); grid.body.append(row);
    });
    content.append(grid.table);
  }
  function renderSources() {
    const content = $('#sources-content'); content.replaceChildren(); content.setAttribute('aria-busy', 'false');
    const query = $('#source-search').value.trim().toLocaleLowerCase();
    const sources = state.sources.filter(source => [source.name, source.owner, source.filename, source.gist_id].some(value => String(value || '').toLocaleLowerCase().includes(query)));
    $('#source-count').textContent = `${sources.length} 个来源`;
    if (!sources.length) {
      if (query) empty(content, '没有匹配的来源', '试试来源名称、Gist 所有者或文件名。', '清除搜索', () => { $('#source-search').value = ''; renderSources(); });
      else empty(content, '接入你的 Gist 文件', '粘贴 Gist 页面或 raw 地址，确认文件后即可创建分享。', '添加 Gist 来源', () => sourceForm());
      return;
    }
    const grid = table(['来源', '来源文件', '更新状态', '分享链接', '操作']);
    sources.forEach(source => {
      const row = node('tr');
      cell(row, '来源').append(node('div', 'cell-title', source.name), node('div', 'cell-detail', `${source.owner || 'Gist'} / ${source.gist_id || ''}`));
      const file = cell(row, '来源文件');
      file.append(node('div', 'cell-title', source.filename), node('div', 'cell-detail', '跟随 Gist 最新版'));
      const status = cell(row, '更新状态');
      status.append(node('span', `badge${source.last_error ? ' bad' : source.last_ok ? '' : ' neutral'}`, source.last_error ? '更新失败' : source.last_ok ? '已同步' : '待获取'));
      if (source.last_error) status.append(node('div', 'cell-detail', source.last_error));
      status.append(node('p', 'status-note', source.last_ok ? formatTime(source.last_ok) : '尚未成功获取'));
      cell(row, '分享链接').append(button(`${Number(source.share_count) || 0} 条分享`, 'source-link', () => showSourceShares(source)));
      const actions = node('div', 'row-actions');
      actions.append(button('新建分享', 'text-button', () => shareForm(null, source.id)), menu([
        ['编辑', () => sourceForm(source)],
        ['立即刷新', async event => {
          const target = event.currentTarget;
          await busy(target, async () => { try { await api(`${sourcePath(source.id)}/refresh`, 'POST', {}); toast('来源已刷新'); await loadState(); } catch (error) { toast(errorText(error), true); } });
        }],
        ['删除', () => confirmAction('删除 Gist 来源', Number(source.share_count) ? `这个来源关联 ${Number(source.share_count)} 条分享，暂时不能删除。请先删除这些分享或将它们改绑其他来源。` : '删除后将无法从这个来源创建分享。Gist 原文件不会被修改。', source.name, () => api(sourcePath(source.id), 'DELETE'), { success: '来源已删除' }), true]
      ]));
      cell(row, '操作').append(actions); grid.body.append(row);
    });
    content.append(grid.table);
  }
  function renderState() {
    const selected = $('#source-filter').value;
    const filter = $('#source-filter'); filter.replaceChildren(new Option('全部来源', ''));
    state.sources.forEach(source => filter.append(new Option(source.name, String(source.id))));
    if (state.sources.some(source => String(source.id) === selected)) filter.value = selected;
    renderShares(); renderSources();
    if (document.activeElement?.closest('#settings-form') !== $('#settings-form')) {
      $('#base-url').value = state.settings.base_url || '';
      $('#cache-ttl').value = state.settings.cache_ttl_secs ?? '';
    }
    $('#cache-info').textContent = `已缓存 ${Number(state.cache.entries) || 0} 个文件，使用 ${size(state.cache.bytes)} / ${size(state.cache.limit_bytes)}。`;
    ['#new-share', '#new-source', '#batch-source', '#settings-form button[type="submit"]', '#secret-form button[type="submit"]'].forEach(selector => { $(selector).disabled = false; });
  }
  async function loadState() {
    if (loading) return;
    loading = true; $('#retry-button').disabled = true;
    try {
      const data = await api('/api/admin/state');
      if (!Array.isArray(data.sources) || !Array.isArray(data.shares)) throw new Error('管理数据格式有误，请稍后重新加载。');
      Object.assign(state, { sources: data.sources, shares: data.shares, settings: data.settings || {}, cache: data.cache || {} });
      ready = true; renderState(); $('#load-error').hidden = true;
    } catch (error) {
      $('#load-error-text').textContent = errorText(error); $('#load-error').hidden = false;
      if (!ready) {
        ['#shares-content', '#sources-content'].forEach(selector => {
          $(selector).setAttribute('aria-busy', 'false');
          $(selector).replaceChildren(node('p', 'loading-placeholder', '数据未能加载。请点击上方“重新加载”。'));
        });
      }
    } finally { loading = false; $('#retry-button').disabled = false; }
  }
  function sourceForm(source = null) {
    if (!openDialog(source ? '编辑 Gist 来源' : '添加 Gist 来源', '解析地址并确认文件，配置内容仍在 Gist 维护。')) return;
    const form = mountForm();
    const name = field(form, '来源名称', 'name', { required: true, value: source?.name || '', placeholder: '例如：常用订阅', maxLength: 80 });
    const canonical = source ? `https://gist.githubusercontent.com/${enc(source.owner)}/${enc(source.gist_id)}/raw/${enc(source.filename)}` : '';
    const url = field(form, 'Gist 页面或 raw 地址', 'url', { type: 'url', required: true, value: canonical, placeholder: 'https://gist.github.com/…', help: source ? '为保护原始地址，这里使用规范化 raw 地址。保存前请重新解析并确认；来源将跟随最新版。' : '支持 Gist 页面及 raw 文件地址。解析后选择要接入的文件。' });
    const inspectButton = button('解析地址', 'button secondary');
    form.append(inspectButton);
    const result = node('div', 'inspect-block'); result.hidden = true; form.append(result);
    let inspected = null;
    let filename = null;
    let follow = null;
    let inspectedURL = '';
    const save = footer(form, source ? '保存来源' : '添加来源', async () => {
      if (!inspected || inspectedURL !== url.value.trim()) throw new Error('请先解析当前地址并选择文件。');
      if (inspected.pinned && !follow.checked) throw new Error('请明确同意跟随最新版后再导入。');
      await api(source ? sourcePath(source.id) : '/api/admin/sources', source ? 'PUT' : 'POST', { name: name.value.trim(), url: inspectedURL, filename: filename.value, follow_latest: inspected.pinned ? follow.checked : true });
      closeDialog(true); toast(source ? '来源已保存' : '来源已添加'); await loadState();
    });
    save.disabled = true;
    url.addEventListener('input', () => { inspected = null; save.disabled = true; result.hidden = true; });
    inspectButton.addEventListener('click', () => busy(inspectButton, async () => {
      formError(form, '');
      if (!url.reportValidity()) return;
      const requested = url.value.trim();
      url.disabled = true;
      try {
        inspected = await api('/api/admin/inspect', 'POST', { url: requested });
        if (!Array.isArray(inspected.files) || !inspected.files.length) throw new Error('没有找到可用文件，请确认 Gist 地址。');
        inspectedURL = requested;
        result.replaceChildren(node('p', 'inspect-summary', `${inspected.owner || 'Gist'} / ${inspected.gist_id || ''}`));
        filename = field(result, '选择文件', 'filename', { tag: 'select', required: true });
        if (inspected.files.length > 1 && !source?.filename && !inspected.selected) {
          const placeholder = new Option('请选择要分发的文件', '', true, true);
          placeholder.disabled = true;
          filename.append(placeholder);
        }
        inspected.files.forEach(file => filename.append(new Option(file, file)));
        const preferred = source?.filename || inspected.selected;
        if (preferred && inspected.files.includes(preferred)) filename.value = preferred;
        if (inspected.pinned) {
          result.append(node('p', 'field-help', '这个地址固定在某个历史版本。网关导入后会跟随 Gist 最新版。'));
          follow = checkbox(result, '我同意跟随最新版，不保留地址中的固定版本', 'follow_latest');
          follow.addEventListener('change', () => { save.disabled = !follow.checked; });
          save.disabled = true;
        } else { follow = null; save.disabled = false; }
        result.hidden = false; filename.focus();
      } catch (error) { inspected = null; save.disabled = true; formError(form, errorText(error)); }
      finally { url.disabled = false; }
    }, '解析中…'));
    name.focus();
  }
  function batchForm() {
    if (!openDialog('批量导入来源', '每行一个 raw 文件地址。Gist 页面或多文件选择请使用单条导入。')) return;
    const form = mountForm();
    const urls = field(form, 'Raw 地址', 'urls', { tag: 'textarea', required: true, placeholder: 'https://gist.githubusercontent.com/…/raw/…' });
    const results = node('div', 'batch-results'); results.setAttribute('aria-live', 'polite'); form.append(results);
    footer(form, '导入来源', async () => {
      const items = [...new Set(urls.value.split(/\r?\n/).map(value => value.trim()).filter(Boolean))];
      if (!items.length) throw new Error('请至少填写一个 raw 地址。');
      if (items.length > 50) throw new Error('每次最多导入 50 个地址，请分批处理。');
      if (new TextEncoder().encode(JSON.stringify({ urls: items })).length > 120 * 1024) {
        throw new Error('本批地址总长度过大，请减少条数或分批处理。');
      }
      for (const item of items) {
        let parsed;
        try { parsed = new URL(item); } catch { throw new Error('存在格式不正确的地址，请检查后重试。'); }
        const parts = parsed.pathname.split('/').filter(Boolean);
        if (parsed.hostname !== 'gist.githubusercontent.com' || parsed.protocol !== 'https:' || parts[2] !== 'raw' || parts.length !== 4) {
          throw new Error('批量导入仅支持带文件名、未固定版本的 HTTPS raw 地址。页面地址或固定版本请使用单条导入确认。');
        }
      }
      const data = await api('/api/admin/sources/batch', 'POST', { urls: items });
      if (!Array.isArray(data.results)) throw new Error('无法读取导入结果，请重新加载来源确认。');
      results.replaceChildren();
      let successes = 0;
      data.results.forEach(item => {
        if (item.ok) successes++;
        const row = node('div', `batch-result ${item.ok ? 'ok' : 'fail'}`);
        row.append(node('strong', '', item.ok ? '已导入' : '未导入'), node('div', '', item.name || item.url || '来源'), node('div', 'cell-detail', item.ok ? '可以为此来源创建分享。' : item.error || '请检查地址后重试。'));
        results.append(row);
      });
      const failed = data.results.filter(item => !item.ok);
      urls.value = failed.map(item => item.url).filter(Boolean).join('\n');
      toast(`已导入 ${successes} 个来源，${data.results.length - successes} 个未导入`, successes !== data.results.length);
      await loadState();
      if (!failed.length) {
        urls.required = false;
        urls.placeholder = '导入已完成。可继续粘贴下一批 raw 地址。';
      } else {
        urls.required = true;
        urls.placeholder = '未导入的地址已保留，请修正后重试。';
      }
    });
    urls.focus();
  }
  function safeFileName(value) {
    const text = String(value || '');
    return text.length > 0 && text.length <= 96 && !text.startsWith('.') && /^[A-Za-z0-9._-]+$/.test(text);
  }
  function pickShareSource() {
    if (!openDialog('选择来源', '这条分享会返回所选 Gist 文件的内容。')) return;
    const list = node('div', 'source-picker');
    state.sources.forEach(item => list.append(button(`${item.name} / ${item.filename}`, 'button secondary', () => {
      closeDialog(true); shareForm(null, item.id);
    })));
    $('#dialog-body').append(list);
  }
  function shareForm(share = null, sourceId = null) {
    if (!state.sources.length) { switchView('sources'); sourceForm(); return; }
    if (!share && sourceId == null && state.sources.length > 1) { pickShareSource(); return; }
    const source = state.sources.find(item => item.id === (share ? share.source_id : sourceId)) || state.sources[0];
    if (!source) { toast('请先选择来源', true); return; }
    if (!openDialog(share ? '编辑分享链接' : '新建分享链接', `${source.name} / ${source.filename}`)) return;
    const form = mountForm();
    const label = field(form, '分享名称', 'label', { required: true, value: share?.label || '', placeholder: '例如：手机自用', maxLength: 120 });
    const row = node('div', 'form-row'); form.append(row);
    const slug = field(row, '链接路径', 'slug', { value: share?.slug || '', placeholder: '留空自动生成', help: '用于区分分享。不要填写密码或个人信息。' });
    const defaultName = share ? share.filename : (safeFileName(source.filename) ? source.filename : '');
    const filename = field(row, '下载文件名', 'filename', { value: defaultName || '', placeholder: '沿用来源文件名', help: '默认与来源文件同名，需要时可改；不改变 Gist 内容。' });
    const expirySelect = field(form, '有效期', 'expiry', { tag: 'select', help: '默认永久有效；选择天数从保存时开始计算。' });
    [['永久有效', ''], ['7 天', '7'], ['30 天', '30'], ['90 天', '90'], ['自定义时间…', 'custom']].forEach(([text, value]) => expirySelect.append(new Option(text, value)));
    const expires = field(form, '到期时间', 'expires_at', { type: 'datetime-local', value: localTime(share?.expires_at), help: '使用当前设备时区。' });
    const expiresWrap = expires.closest('.form-field');
    if (share?.expires_at) { expirySelect.value = 'custom'; } else { expiresWrap.hidden = true; }
    expirySelect.addEventListener('change', () => {
      expiresWrap.hidden = expirySelect.value !== 'custom';
      if (!expiresWrap.hidden) expires.focus();
    });
    const enabled = checkbox(form, '启用这个分享', 'enabled', share ? share.enabled !== false : true);
    footer(form, share ? '保存分享' : '创建分享', async () => {
      let expiry = null;
      if (expirySelect.value === 'custom') {
        if (!expires.value) throw new Error('请选择到期时间，或改为永久有效。');
        expiry = Math.floor(new Date(expires.value).getTime() / 1000);
        if (!Number.isFinite(expiry) || expiry <= Date.now() / 1000) throw new Error('请选择未来的到期时间。');
      } else if (expirySelect.value) {
        expiry = Math.floor(Date.now() / 1000) + Number(expirySelect.value) * 86400;
      }
      await api(share ? sharePath(share.id) : '/api/admin/shares', share ? 'PUT' : 'POST', { source_id: Number(source.id), label: label.value.trim(), slug: slug.value.trim(), filename: filename.value.trim(), expires_at: expiry, enabled: enabled.checked });
      closeDialog(true); toast(share ? '分享已保存' : '分享已创建，点击“查看链接”获取地址'); await loadState();
    });
    label.focus();
  }
  async function revealShare(share, trigger) {
    await busy(trigger, async () => {
      try {
        const data = await api(`${sharePath(share.id)}/reveal`, 'POST', {});
        if (typeof data.url !== 'string') throw new Error('未能取得分享地址，请稍后重试。');
        const parsed = new URL(data.url, location.origin);
        if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('分享地址格式有误，请检查网关设置。');
        if (parsed.origin !== location.origin) throw new Error('分享地址与当前站点不一致，请检查网关设置。');
        if (!openDialog('分享链接', share.label || '未命名分享')) return;
        const content = node('div', 'reveal-content');
        const input = node('input'); input.type = 'text'; input.readOnly = true; input.value = data.url;
        input.setAttribute('aria-label', '完整分享地址'); input.autocomplete = 'off'; input.spellcheck = false;
        const row = node('div', 'reveal-row');
        const copy = button('复制链接', 'button primary', async () => {
          try { await navigator.clipboard.writeText(input.value); toast('链接已复制'); }
          catch { input.focus(); input.select(); toast('无法自动复制，已选中链接，请手动复制。', true); }
        });
        row.append(input, copy);
        const qrArea = node('div', 'qr-area'); const image = node('img');
        image.alt = '分享链接二维码'; image.referrerPolicy = 'no-referrer';
        image.src = `${sharePath(share.id)}/qr`;
        image.addEventListener('error', () => qrArea.replaceChildren(node('p', 'muted', '二维码暂不可用，请复制上方链接。')), { once: true });
        qrArea.append(image);
        content.append(row, qrArea, node('p', 'field-help', '持有此链接的人可以访问文件。请仅分发给预期的接收者。'));
        const actions = node('div', 'dialog-footer'); actions.append(button('完成', 'button secondary', () => closeDialog())); content.append(actions);
        $('#dialog-body').append(content);
        dialogCleanup = () => { input.value = ''; image.removeAttribute('src'); };
        input.focus(); input.select();
      } catch (error) { toast(errorText(error), true); }
    }, '读取中…');
  }
  async function showFetches(share) {
    if (!openDialog('最近拉取记录', `${share.label || '未命名分享'} · 最近 30 次`)) return;
    const content = node('div', 'fetch-body');
    content.append(node('p', 'loading-placeholder', '正在读取…'));
    $('#dialog-body').append(content);
    try {
      const data = await api(`${sharePath(share.id)}/fetches`);
      if (!Array.isArray(data.fetches)) throw new Error('拉取记录格式有误，请稍后重试。');
      content.replaceChildren();
      if (!data.fetches.length) {
        content.append(node('p', 'fetch-empty', '升级后还没有成功拉取记录。'));
      } else {
        const list = node('div', 'fetch-list');
        data.fetches.forEach(item => {
          const row = node('div', 'fetch-item');
          row.append(node('time', '', formatTime(item.fetched_at)), node('span', '', item.ip || 'IP 未记录'));
          list.append(row);
        });
        content.append(list);
      }
      content.append(node('p', 'field-help', '仅记录成功返回的订阅拉取，每个分享最多保留 30 条；IP 仅管理员可见。经 sub-jp/sub-jp2 的记录为 JP 入口 IP，直连域名才记录客户端 IP。'));
      const actions = node('div', 'dialog-footer');
      actions.append(button('关闭', 'button secondary', () => closeDialog()));
      content.append(actions);
    } catch (error) {
      content.replaceChildren(node('p', 'form-error', errorText(error)));
      const actions = node('div', 'dialog-footer');
      actions.append(button('关闭', 'button secondary', () => closeDialog()));
      content.append(actions);
    }
  }

  document.querySelectorAll('[data-secret-target]').forEach(toggle => toggle.addEventListener('click', () => {
    const input = document.getElementById(toggle.dataset.secretTarget);
    const hidden = input.type !== 'text';
    input.type = hidden ? 'text' : ['pass', 'word'].join('');
    toggle.textContent = hidden ? '隐藏' : '显示';
    toggle.setAttribute('aria-label', hidden ? '隐藏管理密码' : '显示管理密码');
    toggle.setAttribute('aria-pressed', String(hidden));
  }));
  if (isLogin) {
    $('#login-form').addEventListener('submit', event => submitForm(event, async form => {
      await api('/admin/login', 'POST', { secret: form.elements.secret.value });
      form.elements.secret.value = ''; location.assign('/admin');
    }));
    return;
  }
  $('#dialog-close').addEventListener('click', () => closeDialog());
  dialog.addEventListener('cancel', event => { if (modalBusy) event.preventDefault(); });
  dialog.addEventListener('close', () => {
    if (dialogCleanup) { dialogCleanup(); dialogCleanup = null; }
    $('#dialog-body').replaceChildren();
    if (dialogTrigger?.isConnected) dialogTrigger.focus();
    else $(`[data-view="${currentView}"]`).focus();
  });
  document.querySelectorAll('[data-view]').forEach(item => item.addEventListener('click', () => switchView(item.dataset.view)));
  $('#share-search').addEventListener('input', () => { if (ready) renderShares(); });
  $('#source-search').addEventListener('input', () => { if (ready) renderSources(); });
  $('#source-filter').addEventListener('change', () => { if (ready) renderShares(); });
  $('#retry-button').addEventListener('click', () => loadState());
  $('#new-source').addEventListener('click', () => sourceForm());
  $('#batch-source').addEventListener('click', () => batchForm());
  $('#new-share').addEventListener('click', () => shareForm());
  $('#logout-button').addEventListener('click', () => confirmAction('退出登录', '退出后，需要管理密码才能重新进入管理台。', '', async () => { await api('/admin/logout', 'POST', {}); location.assign('/admin/login'); }, { danger: false, reload: false, success: '已退出登录' }));
  $('#settings-form').addEventListener('submit', event => submitForm(event, async () => {
    const baseURL = $('#base-url').value.trim();
    const parsed = new URL(baseURL);
    if (!['https:', 'http:'].includes(parsed.protocol) || parsed.username || parsed['pass' + 'word'] || parsed.search || parsed.hash) throw new Error('请填写不含账号、查询参数或片段的 HTTP / HTTPS 地址。');
    if (parsed.origin !== location.origin) throw new Error('对外地址必须与当前访问域名一致；如需迁移域名，请先在反代和数据库中完成切换。');
    const ttl = Number($('#cache-ttl').value);
    if (!Number.isSafeInteger(ttl) || ttl < 10 || ttl > 3600) throw new Error('缓存有效期必须是 10 至 3600 秒之间的整数。');
    await api('/api/admin/settings', 'PUT', { base_url: baseURL, cache_ttl_secs: ttl });
    state.settings = { base_url: baseURL, cache_ttl_secs: ttl };
    toast('设置已保存');
  }));
  $('#secret-form').addEventListener('submit', event => submitForm(event, async form => {
    const current = $('#current-secret').value;
    const secret = $('#new-secret').value;
    if ([...secret].length < 12 || new TextEncoder().encode(secret).length > 1024) throw new Error('新密码至少需要 12 个字符，且不能超过 1024 字节。');
    if (secret !== $('#confirm-secret').value) throw new Error('两次输入的新密码不一致。');
    if (current === secret) throw new Error('新密码不能与当前密码相同。');
    await api('/api/admin/credentials', 'POST', { current_secret: current, new_secret: secret });
    form.reset(); location.assign('/admin/login');
  }));
  loadState();
})();
